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
