#!/usr/bin/env python3
"""
ORT report generator for GitHub Actions.

Purpose
- Read the ORT evaluation result JSON.
- Render a human-friendly summary in the job summary.
- Emit GitHub annotations for quick visibility in Checks.

Design / security notes
- No shell execution; only JSON parsing and file reads.
- Reads from the artifact directory and a small set of known ORT paths.
- Does not follow symlinks when walking directories (os.walk default).
- Sanitizes output to prevent annotation command injection.
"""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional
import json
import os
import re
import sys

SUMMARY_HEADER = "## ORT License Policy Findings"
SUMMARY_OK = "Everything looks good - no policy findings were detected."

# Keep the summary compact for job UI readability.
MAX_FILES_PER_FINDING = 5
MAX_ROWS_PER_SECTION = 50

# LicenseRef / NOASSERTION are not part of the allow/deny policy set.
UNKNOWN_LICENSE_RE = re.compile(r"^(LicenseRef-|NOASSERTION$)", re.IGNORECASE)


@dataclass(frozen=True)
class Finding:
    category: str
    status: str
    reason: str
    rule: str
    license: str
    files: str
    severity: str
    message: str
    annotation_message: str
    annotation_severity: str


@dataclass(frozen=True)
class Resolution:
    rule: str
    pkg: str
    message_re: Optional[re.Pattern[str]]
    reason: str
    comment: str


def gh_warning(message: str) -> None:
    """Emit a GitHub Actions warning annotation."""
    print(f"::warning::{message}")


def gh_error(message: str) -> None:
    """Emit a GitHub Actions error annotation."""
    print(f"::error::{message}")


def cmd_escape(value: str) -> str:
    """Escape special characters for GitHub command annotations."""
    return value.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")


def clean_cell(value: Any) -> str:
    """Normalize table cell content to keep Markdown output stable."""
    if value is None:
        return ""
    text = str(value)
    text = text.replace("|", "¦")
    text = re.sub(r"[\r\n]+", " ", text)
    return text


def to_list(value: Any) -> List[Any]:
    """Coerce scalars to a list; used for ORT fields that may be a single object."""
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return [value]


def license_id(violation: Dict[str, Any]) -> str:
    """Extract the license identifier as a string, handling object forms."""
    lic = violation.get("license", "")
    if isinstance(lic, dict):
        lic = lic.get("id", "")
    return str(lic or "")


def is_unknown_license(lic: str) -> bool:
    """Determine whether the license is considered unknown by policy."""
    return UNKNOWN_LICENSE_RE.match(lic) is not None


def prov_key(prov: Dict[str, Any]) -> str:
    """Build a stable provenance key to join scan results with package IDs."""
    vcs = prov.get("vcs_info", {}) if isinstance(prov, dict) else {}
    return "|".join(
        [
            str(vcs.get("type", "")),
            str(vcs.get("url", "")),
            str(vcs.get("revision", "")),
            str(vcs.get("path", "")),
            str(prov.get("resolved_revision", "")) if isinstance(prov, dict) else "",
        ]
    )


def files_for(pkg: str, lic: str, scan_by_prov: Dict[str, List[Dict[str, Any]]], pkg_to_prov: Dict[str, Dict[str, Any]]) -> List[str]:
    """
    Map a violation to files by:
    - resolving its package provenance
    - looking up scan summary license locations
    - filtering by the license string

    Note: this is best-effort and depends on scanner summary detail.
    """
    prov = pkg_to_prov.get(pkg)
    if not prov:
        return []

    entries = scan_by_prov.get(prov_key(prov), [])
    matches: List[str] = []

    for entry in entries:
        entry_license = str(entry.get("license", "") or "")
        if lic not in entry_license:
            continue
        loc = entry.get("location") or {}
        path = str(loc.get("path", "") or "")
        if not path:
            continue
        # Avoid surfacing config file lines in the report.
        if path.startswith(".github/ort/"):
            continue
        if "start_line" in loc and "end_line" in loc:
            matches.append(f"{path}:{loc['start_line']}-{loc['end_line']}")
        else:
            matches.append(path)

    # Preserve order while removing duplicates.
    seen = set()
    uniq: List[str] = []
    for item in matches:
        if item not in seen:
            seen.add(item)
            uniq.append(item)
    return uniq


def load_json(path: Path) -> Optional[Dict[str, Any]]:
    """Load JSON safely with a warning on parse errors."""
    try:
        with path.open("r", encoding="utf-8") as handle:
            return json.load(handle)
    except (OSError, json.JSONDecodeError) as exc:
        gh_warning(f"Failed to read ORT evaluation result: {exc}")
        return None


def find_eval_json(artifact_dir: str) -> Optional[Path]:
    """
    Prefer evaluation-result.json (contains resolutions); fall back to evaluated-model.json.
    """
    if artifact_dir and os.path.isdir(artifact_dir):
        candidate = _find_in_dir(Path(artifact_dir), "evaluation-result")
        if candidate:
            return candidate
        candidate = _find_in_dir(Path(artifact_dir), "evaluated-model")
        if candidate:
            return candidate

    # When artifacts are missing, check standard ORT result paths (container vs runner).
    home = Path.home()
    candidates = [
        home / ".ort/ort-results/evaluation-result.json",
        home / ".ort/ort-results/evaluated-model.json",
        Path("/home/ort/.ort/ort-results/evaluation-result.json"),
        Path("/home/ort/.ort/ort-results/evaluated-model.json"),
    ]
    for candidate in candidates:
        if candidate.is_file():
            return candidate

    return None


def _find_in_dir(root: Path, name_contains: str) -> Optional[Path]:
    """Search a directory tree for a JSON file name containing the token."""
    for base, _, files in os.walk(root):
        for fname in files:
            if fname.endswith(".json") and name_contains in fname:
                return Path(base) / fname
    return None


def normalize_resolutions(data: Dict[str, Any]) -> List[Resolution]:
    """Normalize resolution entries and compile message regexes when valid."""
    raw = (
        ((data.get("resolved_configuration") or {}).get("resolutions") or {}).get("rule_violations")
        or ((data.get("resolvedConfiguration") or {}).get("resolutions") or {}).get("ruleViolations")
        or []
    )
    resolutions: List[Resolution] = []

    for item in to_list(raw):
        if not isinstance(item, dict):
            continue
        rule = str(item.get("rule", "") or "")
        pkg = str(item.get("pkg", "") or "")
        reason = str(item.get("reason", "policy exception") or "policy exception")
        comment = str(item.get("comment", "") or "")
        message_re = None
        if item.get("message"):
            try:
                message_re = re.compile(str(item["message"]))
            except re.error:
                # Ignore invalid regex to avoid failing the whole report.
                message_re = None
        resolutions.append(Resolution(rule, pkg, message_re, reason, comment))

    return resolutions


def resolution_for(violation: Dict[str, Any], resolutions: List[Resolution]) -> Optional[Resolution]:
    """
    Find the first resolution that matches the violation.

    Empty rule/pkg fields are treated as wildcards; message is a regex when provided.
    """
    rule = str(violation.get("rule", "") or "")
    pkg = str(violation.get("pkg", "") or "")
    message = str(violation.get("message", "") or "")

    for res in resolutions:
        if res.rule and res.rule != rule:
            continue
        if res.pkg and res.pkg != pkg:
            continue
        if res.message_re and not res.message_re.search(message):
            continue
        return res
    return None


def build_scan_index(data: Dict[str, Any]) -> tuple[Dict[str, List[Dict[str, Any]]], Dict[str, Dict[str, Any]]]:
    """
    Build indexes to map package IDs to license finding locations.

    This uses ORT scanner summary data, which is best-effort and may be incomplete.
    """
    scan_results = ((data.get("scanner") or {}).get("scan_results")) or []
    provenances = ((data.get("scanner") or {}).get("provenances")) or []

    scan_by_prov: Dict[str, List[Dict[str, Any]]] = {}
    for sr in scan_results:
        if not isinstance(sr, dict):
            continue
        key = prov_key(sr.get("provenance", {}) or {})
        licenses = ((sr.get("summary") or {}).get("licenses")) or []
        scan_by_prov.setdefault(key, []).extend(to_list(licenses))

    pkg_to_prov: Dict[str, Dict[str, Any]] = {}
    for prov in provenances:
        if not isinstance(prov, dict):
            continue
        pkg_id = prov.get("id")
        if pkg_id:
            pkg_to_prov[str(pkg_id)] = prov.get("package_provenance") or {}

    return scan_by_prov, pkg_to_prov


def collect_violations(data: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Collect violations across the supported ORT evaluation object shapes."""
    evaluator = data.get("evaluator") or data.get("evaluation") or data.get("evaluatorResult") or {}
    violations = (
        evaluator.get("violations")
        or evaluator.get("rule_violations")
        or evaluator.get("ruleViolations")
        or []
    )
    return [v for v in to_list(violations) if isinstance(v, dict)]


def render_summary(findings: List[Finding], summary_path: Optional[Path], ort_failed: bool) -> None:
    """Render the GitHub job summary with only sections that have findings."""
    lines: List[str] = [SUMMARY_HEADER, ""]

    if not findings:
        lines.append(SUMMARY_OK)
        _write_summary(summary_path, "\n".join(lines) + "\n")
        return

    def rows_for(category: str) -> List[Finding]:
        return [f for f in findings if f.category == category]

    violations = rows_for("violation")
    unknowns = rows_for("unknown")
    accepted = rows_for("accepted")

    # Make the overall outcome explicit for humans scanning the summary.
    if ort_failed and (violations or unknowns):
        lines.append(
            f"Status: ❌ Failed - policy violations detected "
            f"({len(violations)} violation(s), {len(unknowns)} unknown(s))."
        )
        lines.append("")
    elif violations or unknowns:
        lines.append(
            f"Status: ⚠️ Findings detected "
            f"({len(violations)} violation(s), {len(unknowns)} unknown(s))."
        )
        lines.append("")
    else:
        lines.append("Status: ✅ Passed - all findings are accepted by policy.")
        lines.append("")

    def print_section(title: str, description: str, category: str) -> None:
        section = rows_for(category)
        if not section:
            return
        lines.append("***")
        lines.append("")
        lines.append(f"### {title}")
        lines.append("")
        lines.append(description)
        lines.append("")
        lines.append("| Status | Reason | Rule | License | Files | Rule severity | Message |")
        lines.append("|---|---|---|---|---|---|---|")
        for row in section[:MAX_ROWS_PER_SECTION]:
            lines.append(
                "| "
                + " | ".join(
                    [
                        clean_cell(row.status),
                        clean_cell(row.reason),
                        clean_cell(row.rule),
                        clean_cell(row.license),
                        clean_cell(row.files),
                        clean_cell(row.severity),
                        clean_cell(row.message),
                    ]
                )
                + " |"
            )
        lines.append("")

    # Order: Violations, Unknowns, Accepted.
    print_section("❌ Violation", "Non-compatible and not accepted", "violation")
    print_section("❓ Unknown", "Missing or ambiguous data", "unknown")
    print_section("✅ Accepted", "Non-compatible but explicitly accepted by policy", "accepted")

    _write_summary(summary_path, "\n".join(lines) + "\n")


def _write_summary(path: Optional[Path], content: str) -> None:
    """Append content to the summary file, or print if unavailable."""
    if not path:
        print(content)
        return
    with path.open("a", encoding="utf-8") as handle:
        handle.write(content)


def emit_annotations(findings: List[Finding], ort_failed: bool) -> None:
    """Emit lightweight annotations for the Checks UI."""
    # Emit a high-level failure annotation so the reason for failure is obvious.
    violations = [f for f in findings if f.category == "violation"]
    unknowns = [f for f in findings if f.category == "unknown"]
    if ort_failed and (violations or unknowns):
        msg = (
            f"❌ ORT policy check failed: {len(violations)} violation(s), "
            f"{len(unknowns)} unknown(s). See job summary for details."
        )
        print(f"::error::{cmd_escape(msg)}")

    for finding in findings:
        msg = cmd_escape(finding.annotation_message)
        if finding.annotation_severity == "error":
            print(f"::error::{msg}")
        elif finding.annotation_severity == "warning":
            print(f"::warning::{msg}")
        else:
            print(f"::notice::{msg}")


def build_findings(data: Dict[str, Any]) -> List[Finding]:
    """
    Convert ORT evaluation data into normalized findings.

    Classification rules:
    - Accepted: resolved by a policy exception (resolution matched).
    - Unknown: unknown license or missing rule/message fields.
    - Violation: everything else.
    """
    resolutions = normalize_resolutions(data)
    scan_by_prov, pkg_to_prov = build_scan_index(data)
    violations = collect_violations(data)

    findings: List[Finding] = []

    for violation in violations:
        res = resolution_for(violation, resolutions)
        lic = license_id(violation)
        lic_unknown = is_unknown_license(lic)
        has_rule = bool(violation.get("rule"))
        has_message = bool(violation.get("message"))

        if res is not None:
            category = "accepted"
            status = "Accepted"
        elif lic_unknown or (not has_rule and not has_message):
            category = "unknown"
            status = "Unknown"
        else:
            category = "violation"
            status = "Violation"

        if res is not None:
            reason = res.reason
            if res.comment:
                reason = f"{reason}: {res.comment}"
        elif lic_unknown:
            reason = "License not covered by policy"
        elif not has_rule and not has_message:
            reason = "Missing rule or message"
        else:
            reason = "Not accepted by policy"

        rule = violation.get("rule")
        if isinstance(rule, dict):
            rule = rule.get("name") or rule.get("id") or ""

        pkg = violation.get("pkg")
        if isinstance(pkg, dict):
            pkg = pkg.get("id") or ""

        severity = violation.get("severity") or violation.get("level") or ""
        # License matching is substring-based; this mirrors how ORT emits license expressions.
        files = files_for(str(pkg or ""), lic, scan_by_prov, pkg_to_prov)
        if files:
            file_cell = "<br>".join(files[:MAX_FILES_PER_FINDING])
            if len(files) > MAX_FILES_PER_FINDING:
                file_cell += f"<br>... (+{len(files) - MAX_FILES_PER_FINDING})"
        else:
            file_cell = "n/a"

        message = violation.get("message") or violation.get("description") or ""

        if res is not None:
            annotation_msg = (
                f"✅ Accepted: {message or 'ORT violation'} ({res.reason}) {res.comment}".strip()
            )
            annotation_sev = "notice"
        elif lic_unknown:
            annotation_msg = f"❓ Unknown license: {message or 'ORT finding'}"
            annotation_sev = "warning"
        elif not has_rule and not has_message:
            annotation_msg = "❓ Unknown ORT finding: missing rule/message fields."
            annotation_sev = "warning"
        else:
            annotation_msg = f"❌ {message or 'ORT violation'}"
            sev_upper = str(severity).upper()
            if sev_upper == "ERROR":
                annotation_sev = "error"
            elif sev_upper == "WARNING":
                annotation_sev = "warning"
            else:
                annotation_sev = "notice"

        findings.append(
            Finding(
                category=category,
                status=status,
                reason=reason,
                rule=str(rule or ""),
                license=lic,
                files=file_cell,
                severity=str(severity or ""),
                message=str(message),
                annotation_message=annotation_msg,
                annotation_severity=annotation_sev,
            )
        )

    return findings


def main() -> int:
    """Entry point for the composite action."""
    artifact_dir = os.environ.get("ARTIFACT_DIR", "ort-artifacts")
    ort_failed = os.environ.get("ORT_FAILED", "false").lower() == "true"

    eval_path = find_eval_json(artifact_dir)
    if not eval_path:
        gh_warning("ORT evaluation result not found in artifacts or common ORT paths.")
        if ort_failed:
            gh_error("ORT run failed and evaluation-result.json was not found. Check ORT logs for details.")
        return 0

    data = load_json(eval_path)
    if data is None:
        return 0

    findings = build_findings(data)
    summary_path = os.environ.get("GITHUB_STEP_SUMMARY")
    render_summary(findings, Path(summary_path) if summary_path else None, ort_failed)
    emit_annotations(findings, ort_failed)
    return 0


if __name__ == "__main__":
    sys.exit(main())
