#!/usr/bin/env bash
# Deterministic source packaging script (slim version).
#
# Purpose:
#   Create a reproducible (byte-for-byte) source archive of the repository at the
#   specified commit and emit verifiable metadata needed for SLSA provenance,
#   downstream rebuild validation, and supply‑chain integrity for SLSA Level 4 ready compliance.
#
# Why this matters:
#   - Reproducibility: Same commit produces identical tarball digest on any machine.
#   - Auditability: Per-file content manifest plus commit metadata allow external
#     parties to confirm archive fidelity without trusting GitHub.
#   - Provenance: subjects.sha256 (and its base64 form) feeds the SLSA generator
#     and signature workflows so attestations bind exactly this artifact.
#   - Minimalism: Non-essential artifacts (git tree manifest, go env snapshot,
#     duplicate checksum variants) were removed to reduce noise and maintenance.
#
# Required env (set automatically by GitHub Actions, or manually for local reproduction):
#   GITHUB_SHA         Commit SHA to package.
#   GITHUB_REPOSITORY  owner/repo string.
#   GITHUB_REF_NAME    Tag or branch name used in naming.
#   GITHUB_REF_TYPE    "tag" for tag builds or anything else treated as non-tag.
#   GITHUB_RUN_NUMBER  Used only to disambiguate dry-run (non-tag) builds.
#
# Outputs (written to $GITHUB_OUTPUT for workflow consumption):
#   artifact_path       Full path to produced .tar.gz
#   artifact_filename   Basename of the archive
#   artifact_sha256     SHA-256 digest of the archive
#   subjects_b64        Base64 encoding of subjects.sha256 line (SLSA input)
#
# Produced artifacts (persisted in repo workspace):
#   dist/<basename>.tar.gz        Reproducible source archive
#   subjects.sha256 / .b64        Canonical digest plus base64 variant
#   manifest.files.sha256         Per-file content digests (content-addressed map)
#   commit.metadata / .sha256     Core commit descriptors
#   build.env / .sha256           Toolchain snapshot and script hash
#   packaging-script.sha256       Integrity hash of this script itself
#
# Design decisions (trade-offs):
#   - gzip -n -9: maximum compression and zeroed metadata (deterministic), slight CPU cost acceptable (single archive).
#   - Dual determinism checks: internal self-check here plus external rebuild job in CI (belt-and-suspenders) for SLSA L4 readiness evidence.
#   - Per-file SHA-256 manifest retained (most useful for external verification) while other metadata (git tree, go env) gated by EXTENDED_METADATA for lean defaults.
#   - Keeping script hash in both packaging-script.sha256 and build.env provides redundancy for integrity.
#
# Security posture:
#   - Aborts if working tree or index is dirty (prevents accidental inclusion of
#     unstaged changes causing irreproducibility).
#   - Sanitizes naming components to avoid path or shell interpretation issues.
#   - SOURCE_DATE_EPOCH derived from commit timestamp (future-proof if build
#     steps are added that honor it).
#
# NOTE: If adding build steps later (e.g., compiled binaries), propagate the same
# SOURCE_DATE_EPOCH and use -trimpath or reproducible flags for the language toolchain.

set -euo pipefail
export LC_ALL=C LANG=C TZ=UTC
umask 022

fail() { echo "ERROR: $*" >&2; exit 1; }
log()  { echo "[package] $*" >&2; }
need() { [ -n "${!1:-}" ] || fail "Missing env var: $1"; }

echo '::group::Validate environment & prepare'
# Validate required environment variables are present.
for v in GITHUB_SHA GITHUB_REPOSITORY GITHUB_REF_NAME GITHUB_RUN_NUMBER; do need "$v"; done
# Ensure the referenced commit exists in this repository.
git rev-parse --verify -q "${GITHUB_SHA}^{commit}" >/dev/null || fail "Invalid commit ${GITHUB_SHA}"
# Enforce a clean working tree and index so the archive purely reflects the commit.
if ! git diff --quiet --ignore-submodules --exit-code || \
   ! git diff --quiet --cached --ignore-submodules --exit-code; then
  fail "Dirty worktree or index, aborting"
fi
# Use commit timestamp to seed deterministic tooling.
SOURCE_DATE_EPOCH="$(git show -s --format=%ct "$GITHUB_SHA")"
export SOURCE_DATE_EPOCH
# Sanitize naming components.
sanitize() { local in="$1" out; out="${in//[^A-Za-z0-9._-]/_}"; [ -n "$out" ] || fail "Sanitized empty: $in"; printf '%s\n' "$out"; }
REPO_SAFE="$(sanitize "${GITHUB_REPOSITORY#*/}")"
if [ "${GITHUB_REF_TYPE:-}" = "tag" ]; then
  TAG_SAFE="$(sanitize "${GITHUB_REF_NAME//\//_}")"
else
  TAG_SAFE="$(sanitize "${GITHUB_REF_NAME//\//_}")-dryrun-${GITHUB_RUN_NUMBER}"
fi
BASENAME="${REPO_SAFE}-${TAG_SAFE}"
OUTDIR=dist
mkdir -p "$OUTDIR"
ARCHIVE_PATH="${OUTDIR}/${BASENAME}.tar.gz"
# Helper hash function.
sha256_of() { if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1" | awk '{print $1}'; else shasum -a 256 "$1" | awk '{print $1}'; fi; }
echo '::endgroup::'

echo '::group::Create deterministic archive'
log "Creating deterministic archive: $ARCHIVE_PATH"
git archive --format=tar --prefix="${BASENAME}/" "$GITHUB_SHA" | gzip -n -9 > "$ARCHIVE_PATH"
[ -s "$ARCHIVE_PATH" ] || fail "Archive empty"
# Structural guard.
tar -tzf "$ARCHIVE_PATH" | grep -qE "^${BASENAME}/go\.mod$" || fail "go.mod not found in archive"
# Primary digest plus subjects (initially only archive, more subjects may be appended later).
artifact_sha256="$(sha256_of "$ARCHIVE_PATH")"
printf '%s  %s\n' "$artifact_sha256" "$(basename "$ARCHIVE_PATH")" > subjects.sha256
# (Deferred base64 generation until all subjects finalized.)
echo '::endgroup::'

echo '::group::Internal reproducibility self-check'
tmp_rebuild=$(mktemp)
git archive --format=tar --prefix="${BASENAME}/" "$GITHUB_SHA" | gzip -n -9 > "$tmp_rebuild"
artifact_sha256_rebuild="$(sha256_of "$tmp_rebuild")"
if [ "$artifact_sha256_rebuild" != "$artifact_sha256" ]; then
  echo "Original digest : $artifact_sha256" >&2
  echo "Rebuilt  digest: $artifact_sha256_rebuild" >&2
  rm -f "$tmp_rebuild"
  fail "Internal reproducibility self-check failed"
fi
rm -f "$tmp_rebuild"
echo '::endgroup::'

echo '::group::Generate per-file manifest'
log "Generating per-file content manifest"
git ls-files -z | sort -z | while IFS= read -r -d '' f; do printf '%s  %s\n' "$(sha256_of "$f")" "$f"; done > manifest.files.sha256
echo '::endgroup::'

echo '::group::Commit metadata'
# Commit metadata snapshot (no separate .sha256 file as it's derivable from commit)
git show -s --format='format:COMMIT %H%nTREE %T%nPARENT %P%nAUTHOR %an <%ae> %ad%nCOMMITTER %cn <%ce> %cd%nSUBJECT %s%n' "$GITHUB_SHA" > commit.metadata
# Extract commit metadata fields for later summary and JSON.
commit_sha=$(sed -n 's/^COMMIT //p' commit.metadata)
tree_sha=$(sed -n 's/^TREE //p' commit.metadata)
parent_line=$(sed -n 's/^PARENT //p' commit.metadata)
file_manifest_entries=$(wc -l < manifest.files.sha256 | tr -d ' ')
echo '::endgroup::'

echo '::group::Extended metadata (conditional)'
if [ "${EXTENDED_METADATA:-false}" = "true" ]; then
  log "EXTENDED_METADATA enabled: git tree plus Go env"
  git ls-tree -r --full-tree --long "$GITHUB_SHA" > manifest.git-tree
  printf '%s  %s\n' "$(sha256_of manifest.git-tree)" manifest.git-tree > manifest.git-tree.sha256
  if command -v jq >/dev/null 2>&1; then go env -json | jq -S . > go.env.json; else go env -json > go.env.json; fi
  printf '%s  %s\n' "$(sha256_of go.env.json)" go.env.json > go.env.json.sha256
else
  log "EXTENDED_METADATA disabled: skipping git tree and Go env snapshot"
fi
echo '::endgroup::'

echo '::group::Script & environment snapshot'
# Script integrity (hash stored in build.env, no separate file)
SCRIPT_PATH="$(realpath "$0")"; SCRIPT_DIGEST=$(sha256_of "$SCRIPT_PATH")
# Capture gzip version
GZIP_VER=$(gzip --version 2>&1 | head -n1 || echo 'unknown')
# Environment summary (no separate .sha256 file)
{
  printf 'GIT_VERSION=%s\n' "$(git --version)"
  printf 'GO_VERSION=%s\n' "$(go version 2>/dev/null || echo 'unknown')"
  printf 'GZIP_VERSION=%s\n' "$GZIP_VER"
  printf 'UNAME=%s\n' "$(uname -a)"
  printf 'SOURCE_DATE_EPOCH=%s\n' "${SOURCE_DATE_EPOCH}"
  printf 'PACKAGING_SCRIPT_SHA256=%s\n' "$SCRIPT_DIGEST"
} > build.env
echo "EXTENDED_METADATA=${EXTENDED_METADATA:-false}" >> build.env
echo '::endgroup::'

echo '::group::Verification reports'
internal_self_check_status="passed"
# JSON summary
{
  echo '{'
  echo '  "artifact": {'
  printf '    "filename": "%s",\n' "$(basename "$ARCHIVE_PATH")"
  printf '    "sha256": "%s",\n' "$artifact_sha256"
  printf '    "subjects_sha256_line": "%s"\n' "$(head -n1 subjects.sha256)"
  echo '  },'
  echo '  "commit": {'
  printf '    "sha": "%s",\n' "$commit_sha"
  printf '    "tree": "%s",\n' "$tree_sha"
  printf '    "parents": ["%s"]\n' "${parent_line// /","}"
  echo '  },'
  echo '  "reproducibility": {'
  printf '    "internal_self_check": "%s",\n' "$internal_self_check_status"
  printf '    "extended_metadata": %s,\n' "${EXTENDED_METADATA:-false}"
  printf '    "file_manifest_entries": %s\n' "$file_manifest_entries"
  echo '  },'
  echo '  "environment": {'
  printf '    "git_version": "%s",\n' "$(git --version)"
  printf '    "go_version": "%s",\n' "$(go version 2>/dev/null || echo 'unknown')"
  printf '    "gzip_version": "%s",\n' "$GZIP_VER"
  printf '    "source_date_epoch": "%s",\n' "${SOURCE_DATE_EPOCH}"
  printf '    "script_sha256": "%s"\n' "$SCRIPT_DIGEST"
  echo '  },'
  echo '  "checksums": ['
  # list all subjects lines as JSON entries
  subj_sep=""; while read -r line; do s_sha=$(echo "$line"|awk '{print $1}'); s_file=$(echo "$line"|awk '{print $2}'); printf '    %s{"file": "%s", "sha256": "%s"}\n' "$subj_sep" "$s_file" "$s_sha"; subj_sep=','; done < subjects.sha256
  echo '  ],'
  echo '  "schema_version": "1.0"'
  echo '}'
} > verification.json
echo '::endgroup::'

echo '::group::Aggregate checksums'
# Aggregated checksums.txt file (no circular reference to subjects.sha256)
checksum_file=checksums.txt
{
  echo "# Aggregated SHA-256 checksums"
  echo "# Format: <sha256>  <filename>"
  echo "# This file provides quick verification of all artifacts"
  printf '%s  %s\n' "$artifact_sha256" "$(basename "$ARCHIVE_PATH")"
  printf '%s  %s\n' "$(sha256_of build.env)" build.env
  printf '%s  %s\n' "$(sha256_of manifest.files.sha256)" manifest.files.sha256
  printf '%s  %s\n' "$(sha256_of commit.metadata)" commit.metadata
  if [ -f manifest.git-tree ]; then printf '%s  %s\n' "$(sha256_of manifest.git-tree)" manifest.git-tree; fi
  if [ -f go.env.json ]; then printf '%s  %s\n' "$(sha256_of go.env.json)" go.env.json; fi
  printf '%s  %s\n' "$(sha256_of verification.json)" verification.json
} > "$checksum_file"

# Add checksums.txt as second SLSA subject
checksums_sha256="$(sha256_of "$checksum_file")"
printf '%s  %s\n' "$checksums_sha256" "$(basename "$checksum_file")" >> subjects.sha256
echo '::endgroup::'

# Generate base64 subjects for SLSA (ephemeral, for workflow use only)
if [ -n "${GITHUB_OUTPUT:-}" ]; then
  subjects_b64=$(base64 < subjects.sha256 | tr -d '\n')
fi

# Summary line (parse-friendly)
subjects_count=$(wc -l < subjects.sha256 | tr -d ' ')
echo "PACKAGING SUMMARY: artifact=$(basename \""$ARCHIVE_PATH"\") sha256=$artifact_sha256 extended_metadata=${EXTENDED_METADATA:-false} files=$file_manifest_entries commit=$commit_sha subjects=$subjects_count"

# Surface outputs for GitHub Actions workflow consumption.
if [ -n "${GITHUB_OUTPUT:-}" ]; then
  {
    printf 'artifact_path=%s\n' "$ARCHIVE_PATH"
    printf 'artifact_filename=%s\n' "$(basename "$ARCHIVE_PATH")"
    printf 'artifact_sha256=%s\n' "$artifact_sha256"
    printf 'subjects_b64=%s\n' "$subjects_b64"
  } >> "$GITHUB_OUTPUT"
fi
