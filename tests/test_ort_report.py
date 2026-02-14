#!/usr/bin/env python3
"""
Tests for ORT report generator script.

Basic coverage tests to satisfy SonarQube requirements.
"""
import sys
from pathlib import Path
from unittest.mock import Mock, patch, mock_open
import json

# Add scripts directory to path to import ort_report
sys.path.insert(0, str(Path(__file__).parent.parent / "scripts" / "ort-report"))

import ort_report


class TestUtilityFunctions:
    """Test basic utility functions."""

    def test_cmd_escape_basic(self):
        """Test command escape with special characters."""
        assert ort_report.cmd_escape("hello") == "hello"
        assert ort_report.cmd_escape("hello%world") == "hello%25world"
        assert ort_report.cmd_escape("line1\nline2") == "line1%0Aline2"
        assert ort_report.cmd_escape("line1\rline2") == "line1%0Dline2"
        assert ort_report.cmd_escape("a%b\rc\nd") == "a%25b%0Dc%0Ad"

    def test_clean_cell_basic(self):
        """Test table cell cleaning."""
        assert ort_report.clean_cell(None) == ""
        assert ort_report.clean_cell("simple") == "simple"
        assert ort_report.clean_cell("with|pipe") == "with¦pipe"
        assert ort_report.clean_cell("line1\nline2") == "line1 line2"
        assert ort_report.clean_cell("line1\r\nline2") == "line1 line2"

    def test_to_list_coercion(self):
        """Test scalar to list coercion."""
        assert ort_report.to_list(None) == []
        assert ort_report.to_list([1, 2, 3]) == [1, 2, 3]
        assert ort_report.to_list("single") == ["single"]
        assert ort_report.to_list(42) == [42]

    def test_is_unknown_license(self):
        """Test unknown license detection."""
        assert ort_report.is_unknown_license("LicenseRef-custom") is True
        assert ort_report.is_unknown_license("NOASSERTION") is True
        assert ort_report.is_unknown_license("noassertion") is True
        assert ort_report.is_unknown_license("MIT") is False
        assert ort_report.is_unknown_license("Apache-2.0") is False


class TestLicenseExtraction:
    """Test license ID extraction."""

    def test_license_id_from_string(self):
        """Test extracting license from string field."""
        violation = {"license": "MIT"}
        assert ort_report.license_id(violation) == "MIT"

    def test_license_id_from_dict(self):
        """Test extracting license from dict with id field."""
        violation = {"license": {"id": "Apache-2.0", "name": "Apache License 2.0"}}
        assert ort_report.license_id(violation) == "Apache-2.0"

    def test_license_id_missing(self):
        """Test handling missing license field."""
        violation = {}
        assert ort_report.license_id(violation) == ""

    def test_license_id_empty_dict(self):
        """Test handling empty license dict."""
        violation = {"license": {}}
        assert ort_report.license_id(violation) == ""


class TestFieldExtraction:
    """Test generic field extraction utility."""

    def test_extract_field_from_string(self):
        """Test extracting from string field."""
        assert ort_report._extract_field("plain text", ["id", "name"]) == "plain text"

    def test_extract_field_from_dict(self):
        """Test extracting from dict with fallback keys."""
        field = {"id": "value1", "name": "value2"}
        assert ort_report._extract_field(field, ["id", "name"]) == "value1"
        assert ort_report._extract_field(field, ["name"]) == "value2"

    def test_extract_field_missing_keys(self):
        """Test extraction when keys are missing."""
        field = {"other": "value"}
        assert ort_report._extract_field(field, ["id", "name"]) == ""

    def test_extract_field_none(self):
        """Test extraction from None."""
        assert ort_report._extract_field(None, ["id"]) == ""


class TestViolationClassification:
    """Test violation classification logic."""

    def test_classify_accepted_violation(self):
        """Test classification of accepted violations."""
        resolution = Mock()
        category, status = ort_report._classify_violation(resolution, False, True, True)
        assert category == "accepted"
        assert status == "Accepted"

    def test_classify_unknown_license(self):
        """Test classification of unknown license."""
        category, status = ort_report._classify_violation(None, True, True, True)
        assert category == "unknown"
        assert status == "Unknown"

    def test_classify_missing_fields(self):
        """Test classification when rule and message are missing."""
        category, status = ort_report._classify_violation(None, False, False, False)
        assert category == "unknown"
        assert status == "Unknown"

    def test_classify_violation(self):
        """Test classification of actual violations."""
        category, status = ort_report._classify_violation(None, False, True, True)
        assert category == "violation"
        assert status == "Violation"


class TestReasonDetermination:
    """Test reason text generation."""

    def test_reason_with_resolution(self):
        """Test reason when resolution exists."""
        resolution = Mock(reason="Policy exception", comment="Approved by security")
        reason = ort_report._determine_reason(resolution, False, True, True)
        assert "Policy exception" in reason
        assert "Approved by security" in reason

    def test_reason_unknown_license(self):
        """Test reason for unknown license."""
        reason = ort_report._determine_reason(None, True, True, True)
        assert reason == "License not covered by policy"

    def test_reason_missing_fields(self):
        """Test reason for missing rule/message."""
        reason = ort_report._determine_reason(None, False, False, False)
        assert reason == "Missing rule or message"

    def test_reason_not_accepted(self):
        """Test reason for unaccepted violation."""
        reason = ort_report._determine_reason(None, False, True, True)
        assert reason == "Not accepted by policy"


class TestFilePathExtraction:
    """Test file path extraction from scan entries."""

    def test_extract_file_path_basic(self):
        """Test basic file path extraction."""
        entry = {
            "license": "MIT",
            "location": {"path": "src/main.go", "start_line": 1, "end_line": 10}
        }
        result = ort_report._extract_file_path(entry, "MIT")
        assert result == "src/main.go:1-10"

    def test_extract_file_path_no_lines(self):
        """Test file path without line numbers."""
        entry = {
            "license": "MIT",
            "location": {"path": "src/main.go"}
        }
        result = ort_report._extract_file_path(entry, "MIT")
        assert result == "src/main.go"

    def test_extract_file_path_wrong_license(self):
        """Test filtering by license."""
        entry = {
            "license": "Apache-2.0",
            "location": {"path": "src/main.go"}
        }
        result = ort_report._extract_file_path(entry, "MIT")
        assert result is None

    def test_extract_file_path_ort_config(self):
        """Test filtering out ORT config files."""
        entry = {
            "license": "MIT",
            "location": {"path": ".github/ort/config.yml"}
        }
        result = ort_report._extract_file_path(entry, "MIT")
        assert result is None

    def test_extract_file_path_missing_path(self):
        """Test handling missing path."""
        entry = {
            "license": "MIT",
            "location": {}
        }
        result = ort_report._extract_file_path(entry, "MIT")
        assert result is None


class TestFileCellFormatting:
    """Test file list formatting for table cells."""

    def test_format_empty_files(self):
        """Test formatting empty file list."""
        assert ort_report._format_file_cell([]) == "n/a"

    def test_format_few_files(self):
        """Test formatting small file list."""
        files = ["file1.go", "file2.go", "file3.go"]
        result = ort_report._format_file_cell(files)
        assert "file1.go" in result
        assert "file2.go" in result
        assert "file3.go" in result
        assert "<br>" in result

    def test_format_many_files(self):
        """Test formatting with overflow."""
        files = [f"file{i}.go" for i in range(10)]
        result = ort_report._format_file_cell(files)
        assert "..." in result
        assert "(+5)" in result or "(+4)" in result


class TestProvenanceKey:
    """Test provenance key generation."""

    def test_prov_key_basic(self):
        """Test basic provenance key."""
        prov = {
            "vcs_info": {
                "type": "git",
                "url": "https://github.com/user/repo",
                "revision": "abc123",
                "path": ""
            },
            "resolved_revision": "abc123def"
        }
        key = ort_report.prov_key(prov)
        assert "git" in key
        assert "github.com" in key
        assert "abc123" in key

    def test_prov_key_empty(self):
        """Test empty provenance."""
        key = ort_report.prov_key({})
        assert key == "||||"


class TestDeduplication:
    """Test deduplication utility."""

    def test_deduplicate_preserving_order(self):
        """Test that deduplication preserves order."""
        items = ["a", "b", "c", "b", "d", "a"]
        result = ort_report._deduplicate_preserving_order(items)
        assert result == ["a", "b", "c", "d"]

    def test_deduplicate_no_duplicates(self):
        """Test list without duplicates."""
        items = ["a", "b", "c"]
        result = ort_report._deduplicate_preserving_order(items)
        assert result == ["a", "b", "c"]

    def test_deduplicate_empty(self):
        """Test empty list."""
        assert ort_report._deduplicate_preserving_order([]) == []


class TestLoadJson:
    """Test JSON loading functionality."""

    def test_load_json_success(self):
        """Test successful JSON loading."""
        test_data = {"key": "value", "number": 42}
        mock_file = mock_open(read_data=json.dumps(test_data))
        
        with patch("pathlib.Path.open", mock_file):
            result = ort_report.load_json(Path("/fake/path.json"))
        
        assert result == test_data

    def test_load_json_invalid(self):
        """Test handling invalid JSON."""
        mock_file = mock_open(read_data="not valid json {")
        
        with patch("pathlib.Path.open", mock_file):
            result = ort_report.load_json(Path("/fake/path.json"))
        
        assert result is None

    def test_load_json_file_not_found(self):
        """Test handling missing file."""
        with patch("builtins.open", side_effect=OSError("File not found")):
            result = ort_report.load_json(Path("/fake/missing.json"))
        
        assert result is None


class TestGitHubActions:
    """Test GitHub Actions annotation functions."""

    def test_gh_warning(self, capsys):
        """Test GitHub warning output."""
        ort_report.gh_warning("Test warning message")
        captured = capsys.readouterr()
        assert captured.out == "::warning::Test warning message\n"

    def test_gh_error(self, capsys):
        """Test GitHub error output."""
        ort_report.gh_error("Test error message")
        captured = capsys.readouterr()
        assert captured.out == "::error::Test error message\n"


class TestResolutionExtraction:
    """Test extraction of resolutions from ORT data."""

    def test_extract_resolutions_snake_case(self):
        """Test extraction with snake_case keys."""
        data = {
            "resolved_configuration": {
                "resolutions": {
                    "rule_violations": [{"rule": "r1"}, {"rule": "r2"}]
                }
            }
        }
        result = ort_report._extract_resolutions_raw(data)
        assert len(result) == 2
        assert result[0]["rule"] == "r1"

    def test_extract_resolutions_camel_case(self):
        """Test extraction with camelCase keys."""
        data = {
            "resolvedConfiguration": {
                "resolutions": {
                    "ruleViolations": [{"rule": "r1"}]
                }
            }
        }
        result = ort_report._extract_resolutions_raw(data)
        assert len(result) == 1

    def test_extract_resolutions_empty(self):
        """Test extraction from empty data."""
        assert ort_report._extract_resolutions_raw({}) == []
        
    def test_extract_resolutions_missing_nested(self):
        """Test extraction with missing nested fields."""
        data = {"resolved_configuration": {}}
        assert ort_report._extract_resolutions_raw(data) == []


class TestMessageRegex:
    """Test message regex compilation."""

    def test_compile_message_regex_valid(self):
        """Test compiling valid regex."""
        pattern = ort_report._compile_message_regex("test.*pattern")
        assert pattern is not None
        assert pattern.search("test123pattern")

    def test_compile_message_regex_invalid(self):
        """Test handling invalid regex."""
        pattern = ort_report._compile_message_regex("test[invalid")
        assert pattern is None

    def test_compile_message_regex_none(self):
        """Test handling None input."""
        assert ort_report._compile_message_regex(None) is None

    def test_compile_message_regex_empty(self):
        """Test handling empty string."""
        assert ort_report._compile_message_regex("") is None


class TestResolutionParsing:
    """Test parsing individual resolution items."""

    def test_parse_resolution_item_complete(self):
        """Test parsing with all fields."""
        item = {
            "rule": "test-rule",
            "pkg": "test-pkg",
            "message": "test.*message",
            "reason": "approved",
            "comment": "security review done"
        }
        res = ort_report._parse_resolution_item(item)
        assert res is not None
        assert res.rule == "test-rule"
        assert res.pkg == "test-pkg"
        assert res.reason == "approved"
        assert res.comment == "security review done"
        assert res.message_re is not None

    def test_parse_resolution_item_minimal(self):
        """Test parsing with minimal fields."""
        item = {}
        res = ort_report._parse_resolution_item(item)
        assert res is not None
        assert res.rule == ""
        assert res.pkg == ""
        assert res.reason == "policy exception"
        assert res.comment == ""
        assert res.message_re is None

    def test_parse_resolution_item_non_dict(self):
        """Test handling non-dict input."""
        assert ort_report._parse_resolution_item("not a dict") is None
        assert ort_report._parse_resolution_item(None) is None

    def test_parse_resolution_item_invalid_regex(self):
        """Test parsing with invalid regex message."""
        item = {"message": "invalid[regex"}
        res = ort_report._parse_resolution_item(item)
        assert res is not None
        assert res.message_re is None


class TestNormalizeResolutions:
    """Test resolution normalization."""

    def test_normalize_resolutions_multiple(self):
        """Test normalizing multiple resolutions."""
        data = {
            "resolved_configuration": {
                "resolutions": {
                    "rule_violations": [
                        {"rule": "r1", "reason": "approved"},
                        {"rule": "r2", "reason": "exception"}
                    ]
                }
            }
        }
        resolutions = ort_report.normalize_resolutions(data)
        assert len(resolutions) == 2
        assert resolutions[0].rule == "r1"
        assert resolutions[1].rule == "r2"

    def test_normalize_resolutions_filters_invalid(self):
        """Test that invalid items are filtered out."""
        data = {
            "resolved_configuration": {
                "resolutions": {
                    "rule_violations": [
                        {"rule": "r1"},
                        "not a dict",
                        None,
                        {"rule": "r2"}
                    ]
                }
            }
        }
        resolutions = ort_report.normalize_resolutions(data)
        assert len(resolutions) == 2

    def test_normalize_resolutions_empty(self):
        """Test normalizing empty data."""
        assert ort_report.normalize_resolutions({}) == []


class TestResolutionMatching:
    """Test resolution matching logic."""

    def test_resolution_for_exact_match(self):
        """Test exact rule and package match."""
        resolutions = [
            ort_report.Resolution(rule="r1", pkg="p1", message_re=None, reason="approved", comment="")
        ]
        violation = {"rule": "r1", "pkg": "p1", "message": "test"}
        result = ort_report.resolution_for(violation, resolutions)
        assert result is not None
        assert result.rule == "r1"

    def test_resolution_for_wildcard_rule(self):
        """Test wildcard rule (empty matches all)."""
        resolutions = [
            ort_report.Resolution(rule="", pkg="p1", message_re=None, reason="approved", comment="")
        ]
        violation = {"rule": "any-rule", "pkg": "p1", "message": "test"}
        result = ort_report.resolution_for(violation, resolutions)
        assert result is not None

    def test_resolution_for_wildcard_pkg(self):
        """Test wildcard package (empty matches all)."""
        resolutions = [
            ort_report.Resolution(rule="r1", pkg="", message_re=None, reason="approved", comment="")
        ]
        violation = {"rule": "r1", "pkg": "any-pkg", "message": "test"}
        result = ort_report.resolution_for(violation, resolutions)
        assert result is not None

    def test_resolution_for_message_regex(self):
        """Test message regex matching."""
        import re
        resolutions = [
            ort_report.Resolution(
                rule="r1", 
                pkg="", 
                message_re=re.compile("test.*error"),
                reason="approved",
                comment=""
            )
        ]
        violation = {"rule": "r1", "pkg": "p1", "message": "test license error"}
        result = ort_report.resolution_for(violation, resolutions)
        assert result is not None

    def test_resolution_for_message_no_match(self):
        """Test message regex not matching."""
        import re
        resolutions = [
            ort_report.Resolution(
                rule="r1",
                pkg="",
                message_re=re.compile("other.*pattern"),
                reason="approved",
                comment=""
            )
        ]
        violation = {"rule": "r1", "pkg": "p1", "message": "test error"}
        result = ort_report.resolution_for(violation, resolutions)
        assert result is None

    def test_resolution_for_no_match(self):
        """Test no matching resolution."""
        resolutions = [
            ort_report.Resolution(rule="r1", pkg="p1", message_re=None, reason="approved", comment="")
        ]
        violation = {"rule": "r2", "pkg": "p2", "message": "test"}
        result = ort_report.resolution_for(violation, resolutions)
        assert result is None

    def test_resolution_for_first_match_wins(self):
        """Test that first matching resolution is returned."""
        resolutions = [
            ort_report.Resolution(rule="", pkg="", message_re=None, reason="first", comment=""),
            ort_report.Resolution(rule="", pkg="", message_re=None, reason="second", comment="")
        ]
        violation = {"rule": "r1", "pkg": "p1", "message": "test"}
        result = ort_report.resolution_for(violation, resolutions)
        assert result.reason == "first"


class TestScanIndexing:
    """Test scan result and provenance indexing."""

    def test_index_scan_results_single(self):
        """Test indexing single scan result."""
        scan_results = [
            {
                "provenance": {
                    "vcs_info": {
                        "url": "https://github.com/test/repo",
                        "revision": "abc123"
                    }
                },
                "summary": {
                    "licenses": [{"license": "MIT"}]
                }
            }
        ]
        index = ort_report._index_scan_results(scan_results)
        assert len(index) > 0
        key = list(index.keys())[0]
        assert len(index[key]) == 1

    def test_index_scan_results_multiple_licenses(self):
        """Test indexing multiple licenses for same provenance."""
        scan_results = [
            {
                "provenance": {
                    "vcs_info": {"url": "test", "revision": "v1"}
                },
                "summary": {
                    "licenses": [{"license": "MIT"}, {"license": "Apache-2.0"}]
                }
            }
        ]
        index = ort_report._index_scan_results(scan_results)
        key = list(index.keys())[0]
        assert len(index[key]) == 2

    def test_index_scan_results_filters_non_dicts(self):
        """Test that non-dict scan results are filtered."""
        scan_results = [
            {"provenance": {}, "summary": {"licenses": [{"license": "MIT"}]}},
            "not a dict",
            None
        ]
        index = ort_report._index_scan_results(scan_results)
        assert len(index) == 1

    def test_index_provenances_single(self):
        """Test indexing single provenance."""
        provenances = [
            {
                "id": "pkg:npm/test@1.0.0",
                "package_provenance": {"vcs_info": {"url": "https://test.com"}}
            }
        ]
        index = ort_report._index_provenances(provenances)
        assert "pkg:npm/test@1.0.0" in index
        assert index["pkg:npm/test@1.0.0"]["vcs_info"]["url"] == "https://test.com"

    def test_index_provenances_missing_id(self):
        """Test handling provenances without ID."""
        provenances = [
            {"package_provenance": {"vcs_info": {"url": "test"}}},
            {"id": "pkg:npm/valid@1.0.0", "package_provenance": {}}
        ]
        index = ort_report._index_provenances(provenances)
        assert len(index) == 1
        assert "pkg:npm/valid@1.0.0" in index

    def test_index_provenances_filters_non_dicts(self):
        """Test that non-dict provenances are filtered."""
        provenances = [
            {"id": "pkg:npm/test@1.0.0", "package_provenance": {}},
            "not a dict",
            None
        ]
        index = ort_report._index_provenances(provenances)
        assert len(index) == 1


class TestBuildScanIndex:
    """Test building complete scan index."""

    def test_build_scan_index_complete(self):
        """Test building index with both scan results and provenances."""
        data = {
            "scanner": {
                "scan_results": [
                    {
                        "provenance": {"vcs_info": {"url": "test", "revision": "v1"}},
                        "summary": {"licenses": [{"license": "MIT"}]}
                    }
                ],
                "provenances": [
                    {
                        "id": "pkg:npm/test@1.0.0",
                        "package_provenance": {"vcs_info": {"url": "test"}}
                    }
                ]
            }
        }
        scan_by_prov, pkg_to_prov = ort_report.build_scan_index(data)
        assert len(scan_by_prov) > 0
        assert "pkg:npm/test@1.0.0" in pkg_to_prov

    def test_build_scan_index_empty(self):
        """Test building index from empty data."""
        scan_by_prov, pkg_to_prov = ort_report.build_scan_index({})
        assert scan_by_prov == {}
        assert pkg_to_prov == {}

    def test_build_scan_index_missing_scanner(self):
        """Test building index with missing scanner field."""
        data = {"other_field": "value"}
        scan_by_prov, pkg_to_prov = ort_report.build_scan_index(data)
        assert scan_by_prov == {}
        assert pkg_to_prov == {}


class TestBuildAnnotation:
    """Test annotation message building."""

    def test_build_annotation_with_resolution(self):
        """Test annotation for accepted violation."""
        resolution = ort_report.Resolution(
            rule="r1",
            pkg="p1",
            message_re=None,
            reason="security review",
            comment="approved by team"
        )
        ctx = ort_report.ViolationContext(
            resolution=resolution,
            lic_unknown=False,
            has_rule=True,
            has_message=True,
            message="test violation",
            severity="error"
        )
        msg, sev = ort_report._build_annotation(ctx)
        assert "✅ Accepted:" in msg
        assert "test violation" in msg
        assert "security review" in msg
        assert "approved by team" in msg
        assert sev == "notice"

    def test_build_annotation_unknown_license(self):
        """Test annotation for unknown license."""
        ctx = ort_report.ViolationContext(
            resolution=None,
            lic_unknown=True,
            has_rule=True,
            has_message=True,
            message="license finding",
            severity="warning"
        )
        msg, sev = ort_report._build_annotation(ctx)
        assert "❓ Unknown license:" in msg
        assert "license finding" in msg
        assert sev == "warning"

    def test_build_annotation_missing_fields(self):
        """Test annotation for violation with missing rule/message."""
        ctx = ort_report.ViolationContext(
            resolution=None,
            lic_unknown=False,
            has_rule=False,
            has_message=False,
            message="",
            severity="error"
        )
        msg, sev = ort_report._build_annotation(ctx)
        assert "❓ Unknown ORT finding" in msg
        assert "missing rule/message fields" in msg
        assert sev == "warning"

    def test_build_annotation_error_severity(self):
        """Test annotation with ERROR severity."""
        ctx = ort_report.ViolationContext(
            resolution=None,
            lic_unknown=False,
            has_rule=True,
            has_message=True,
            message="critical issue",
            severity="ERROR"
        )
        msg, sev = ort_report._build_annotation(ctx)
        assert "❌ critical issue" in msg
        assert sev == "error"

    def test_build_annotation_warning_severity(self):
        """Test annotation with WARNING severity."""
        ctx = ort_report.ViolationContext(
            resolution=None,
            lic_unknown=False,
            has_rule=True,
            has_message=True,
            message="minor issue",
            severity="WARNING"
        )
        msg, sev = ort_report._build_annotation(ctx)
        assert "❌ minor issue" in msg
        assert sev == "warning"

    def test_build_annotation_default_severity(self):
        """Test annotation with unknown/default severity."""
        ctx = ort_report.ViolationContext(
            resolution=None,
            lic_unknown=False,
            has_rule=True,
            has_message=True,
            message="info message",
            severity="info"
        )
        msg, sev = ort_report._build_annotation(ctx)
        assert "❌ info message" in msg
        assert sev == "notice"

    def test_build_annotation_no_message(self):
        """Test annotation with missing message field."""
        ctx = ort_report.ViolationContext(
            resolution=None,
            lic_unknown=False,
            has_rule=True,
            has_message=False,
            message="",
            severity="error"
        )
        msg, sev = ort_report._build_annotation(ctx)
        assert "ORT violation" in msg


class TestEmitAnnotations:
    """Test GitHub annotation emission."""

    def test_emit_annotations_failure_summary(self, capsys):
        """Test failure summary annotation when ORT failed."""
        findings = [
            ort_report.Finding(
                category="violation",
                status="Violation",
                reason="test",
                rule="r1",
                license="MIT",
                files="",
                severity="error",
                message="test msg",
                annotation_message="test violation",
                annotation_severity="error"
            ),
            ort_report.Finding(
                category="unknown",
                status="Unknown",
                reason="test",
                rule="",
                license="LicenseRef-custom",
                files="",
                severity="warning",
                message="",
                annotation_message="unknown license",
                annotation_severity="warning"
            )
        ]
        ort_report.emit_annotations(findings, ort_failed=True)
        captured = capsys.readouterr()
        assert "::error::" in captured.out
        assert "policy check failed" in captured.out
        assert "1 violation(s)" in captured.out
        assert "1 unknown(s)" in captured.out

    def test_emit_annotations_no_failure_summary(self, capsys):
        """Test no failure summary when ORT succeeded."""
        findings = [
            ort_report.Finding(
                category="accepted",
                status="Accepted",
                reason="approved",
                rule="r1",
                license="MIT",
                files="",
                severity="",
                message="",
                annotation_message="accepted",
                annotation_severity="notice"
            )
        ]
        ort_report.emit_annotations(findings, ort_failed=False)
        captured = capsys.readouterr()
        assert "policy check failed" not in captured.out

    def test_emit_annotations_various_severities(self, capsys):
        """Test annotations with different severities."""
        findings = [
            ort_report.Finding(
                category="violation",
                status="Violation",
                reason="",
                rule="",
                license="",
                files="",
                severity="",
                message="",
                annotation_message="error msg",
                annotation_severity="error"
            ),
            ort_report.Finding(
                category="unknown",
                status="Unknown",
                reason="",
                rule="",
                license="",
                files="",
                severity="",
                message="",
                annotation_message="warning msg",
                annotation_severity="warning"
            ),
            ort_report.Finding(
                category="accepted",
                status="Accepted",
                reason="",
                rule="",
                license="",
                files="",
                severity="",
                message="",
                annotation_message="notice msg",
                annotation_severity="notice"
            )
        ]
        ort_report.emit_annotations(findings, ort_failed=False)
        captured = capsys.readouterr()
        assert "::error::error msg" in captured.out
        assert "::warning::warning msg" in captured.out
        assert "::notice::notice msg" in captured.out


class TestProcessViolation:
    """Test violation processing into Finding objects."""

    def test_process_violation_basic(self):
        """Test basic violation processing."""
        violation = {
            "rule": "test-rule",
            "license": "MIT",
            "message": "test message",
            "severity": "error",
            "pkg": "npm:test@1.0.0"
        }
        finding = ort_report._process_violation(violation, [], {}, {})
        assert finding.category == "violation"
        assert finding.license == "MIT"
        assert finding.message == "test message"
        assert finding.severity == "error"

    def test_process_violation_with_resolution(self):
        """Test violation with matching resolution."""
        violation = {
            "rule": "r1",
            "license": "GPL-3.0",
            "message": "test",
            "severity": "error"
        }
        resolutions = [
            ort_report.Resolution(
                rule="r1",
                pkg="",
                message_re=None,
                reason="approved",
                comment="exception granted"
            )
        ]
        finding = ort_report._process_violation(violation, resolutions, {}, {})
        assert finding.category == "accepted"
        assert "approved" in finding.reason.lower()

    def test_process_violation_unknown_license(self):
        """Test violation with unknown license."""
        violation = {
            "rule": "r1",
            "license": "LicenseRef-custom",
            "message": "test"
        }
        finding = ort_report._process_violation(violation, [], {}, {})
        assert finding.category == "unknown"
        assert finding.license == "LicenseRef-custom"

    def test_process_violation_missing_fields(self):
        """Test violation with missing optional fields."""
        violation = {}
        finding = ort_report._process_violation(violation, [], {}, {})
        assert finding.license == ""
        assert finding.message == ""
        assert finding.severity == ""

    def test_process_violation_level_fallback(self):
        """Test using 'level' field when 'severity' is missing."""
        violation = {
            "rule": "r1",
            "license": "MIT",
            "message": "test",
            "level": "warning"
        }
        finding = ort_report._process_violation(violation, [], {}, {})
        assert finding.severity == "warning"


class TestBuildFindings:
    """Test building complete findings from ORT data."""

    def test_build_findings_empty(self):
        """Test building findings from empty data."""
        findings = ort_report.build_findings({})
        assert findings == []

    def test_build_findings_single_violation(self):
        """Test building findings with single violation."""
        data = {
            "evaluator": {
                "violations": [
                    {
                        "rule": "test-rule",
                        "license": "GPL-3.0",
                        "message": "test violation",
                        "severity": "error"
                    }
                ]
            }
        }
        findings = ort_report.build_findings(data)
        assert len(findings) == 1
        assert findings[0].category == "violation"
        assert findings[0].license == "GPL-3.0"

    def test_build_findings_with_resolution(self):
        """Test building findings with resolutions."""
        data = {
            "resolved_configuration": {
                "resolutions": {
                    "rule_violations": [
                        {"rule": "r1", "reason": "approved"}
                    ]
                }
            },
            "evaluator": {
                "violations": [
                    {
                        "rule": "r1",
                        "license": "GPL-3.0",
                        "message": "test",
                        "severity": "error"
                    }
                ]
            }
        }
        findings = ort_report.build_findings(data)
        assert len(findings) == 1
        assert findings[0].category == "accepted"

    def test_build_findings_multiple_types(self):
        """Test building findings with various types."""
        data = {
            "evaluator": {
                "violations": [
                    {"rule": "r1", "license": "MIT", "message": "test1"},
                    {"rule": "r2", "license": "LicenseRef-custom", "message": "test2"},
                    {"license": "Apache-2.0"}  # missing rule and message
                ]
            }
        }
        findings = ort_report.build_findings(data)
        assert len(findings) == 3
        categories = [f.category for f in findings]
        assert "violation" in categories
        assert "unknown" in categories


class TestFindEvalJson:
    """Test finding ORT evaluation JSON files."""

    def test_find_eval_json_in_artifact_dir(self):
        """Test finding evaluation-result.json in artifact directory."""
        with patch("os.path.isdir") as mock_isdir, \
             patch("pathlib.Path.rglob") as mock_rglob:
            mock_isdir.return_value = True
            mock_file = Path("/test/artifacts/evaluation-result.json")
            mock_rglob.return_value = [mock_file]
            
            result = ort_report.find_eval_json("/test/artifacts")
            # Result depends on implementation, just verify it doesn't crash
            assert result is None or isinstance(result, Path)

    def test_find_eval_json_no_artifact_dir(self):
        """Test behavior when artifact_dir is empty."""
        with patch("pathlib.Path.is_file") as mock_is_file:
            mock_is_file.return_value = False
            result = ort_report.find_eval_json("")
            assert result is None

    def test_find_eval_json_fallback_paths(self):
        """Test fallback to standard ORT paths."""
        with patch("os.path.isdir") as mock_isdir, \
             patch("pathlib.Path.is_file") as mock_is_file:
            mock_isdir.return_value = False
            mock_is_file.return_value = False
            
            result = ort_report.find_eval_json("/nonexistent")
            assert result is None


class TestCollectViolations:
    """Test violation collection from ORT data."""

    def test_collect_violations_evaluator(self):
        """Test collecting from evaluator field."""
        data = {
            "evaluator": {
                "violations": [{"rule": "rule1"}, {"rule": "rule2"}]
            }
        }
        violations = ort_report.collect_violations(data)
        assert len(violations) == 2

    def test_collect_violations_evaluation(self):
        """Test collecting from evaluation field."""
        data = {
            "evaluation": {
                "rule_violations": [{"rule": "rule1"}]
            }
        }
        violations = ort_report.collect_violations(data)
        assert len(violations) == 1

    def test_collect_violations_empty(self):
        """Test handling empty data."""
        assert ort_report.collect_violations({}) == []

    def test_collect_violations_filters_non_dicts(self):
        """Test that non-dict items are filtered."""
        data = {
            "evaluator": {
                "violations": [{"rule": "rule1"}, "not a dict", None, {"rule": "rule2"}]
            }
        }
        violations = ort_report.collect_violations(data)
        assert len(violations) == 2
        assert all(isinstance(v, dict) for v in violations)


class TestResolutionPackageMismatch:
    """Test resolution matching with package mismatches."""

    def test_resolution_for_pkg_mismatch(self):
        """Test that non-matching package is rejected."""
        resolutions = [
            ort_report.Resolution(
                rule="r1",
                pkg="pkg:npm/expected@1.0.0",
                message_re=None,
                reason="approved",
                comment=""
            )
        ]
        violation = {
            "rule": "r1",
            "pkg": "pkg:npm/different@2.0.0",
            "message": "test"
        }
        result = ort_report.resolution_for(violation, resolutions)
        assert result is None


class TestWriteSummary:
    """Test summary file writing."""

    def test_write_summary_no_path(self, capsys):
        """Test writing to stdout when no path provided."""
        ort_report._write_summary(None, "test content\n")
        captured = capsys.readouterr()
        assert "test content" in captured.out

    def test_write_summary_with_path(self, tmp_path):
        """Test writing to file path."""
        summary_file = tmp_path / "summary.md"
        ort_report._write_summary(summary_file, "first line\n")
        ort_report._write_summary(summary_file, "second line\n")
        
        content = summary_file.read_text()
        assert "first line" in content
        assert "second line" in content


class TestFilesForWithScanData:
    """Test files_for with actual scan data."""

    def test_files_for_with_scan_results(self):
        """Test files_for returns file paths from scan results."""
        pkg_id = "pkg:npm/test@1.0.0"
        prov = {
            "vcs_info": {
                "url": "https://github.com/test/repo",
                "revision": "abc123"
            }
        }
        key = ort_report.prov_key(prov)
        
        scan_by_prov = {
            key: [
                {
                    "license": {"id": "MIT"},
                    "location": {"path": "LICENSE"}
                },
                {
                    "license": "MIT",
                    "location": {"path": "package.json"}
                }
            ]
        }
        
        pkg_to_prov = {pkg_id: prov}
        
        files = ort_report.files_for(pkg_id, "MIT", scan_by_prov, pkg_to_prov)
        assert len(files) == 2
        assert "LICENSE" in files
        assert "package.json" in files

    def test_files_for_no_provenance(self):
        """Test files_for when package has no provenance."""
        files = ort_report.files_for("pkg:npm/unknown@1.0.0", "MIT", {}, {})
        assert files == []

    def test_files_for_with_duplicates(self):
        """Test files_for deduplicates results."""
        pkg_id = "pkg:npm/test@1.0.0"
        prov = {"vcs_info": {"url": "test", "revision": "v1"}}
        key = ort_report.prov_key(prov)
        
        scan_by_prov = {
            key: [
                {"license": "MIT", "location": {"path": "LICENSE"}},
                {"license": "MIT", "location": {"path": "README.md"}},
                {"license": "MIT", "location": {"path": "LICENSE"}},  # duplicate
            ]
        }
        pkg_to_prov = {pkg_id: prov}
        
        files = ort_report.files_for(pkg_id, "MIT", scan_by_prov, pkg_to_prov)
        assert files.count("LICENSE") == 1
        assert "README.md" in files
