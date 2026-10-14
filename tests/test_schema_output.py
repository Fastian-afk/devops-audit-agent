"""
tests/test_schema_output.py — Tests for JSON schema validation, deduplication,
and false-positive filtering.

Tests cover:
- Report schema validation against the exact JSON contract
- Deduplication of identical (rule_id, file, line) findings
- Category inference from rule_id prefix
- Secret scrubbing of all report string fields
- File-existence verification
- False-positive prevention for Repo C
"""

from __future__ import annotations

import json
from pathlib import Path

import jsonschema
import pytest

from agent_core.schemas import (
    scrub_report,
    scrub_secrets,
    validate_and_clean,
)

# ============================================================
# Helper factories
# ============================================================


def _make_violation(**kwargs) -> dict:
    """Create a minimal valid violation dict with defaults."""
    defaults = {
        "rule_id": "SEC-001",
        "category": "security",
        "severity": "critical",
        "file": "app.py",
        "line": 10,
        "description": "Hardcoded API key detected",
        "evidence": "API key value [REDACTED_SECRET_DETECTED]",
        "recommendation": "Use environment variables",
    }
    defaults.update(kwargs)
    return defaults


def _make_report(violations: list[dict] | None = None) -> dict:
    return {
        "repository": "https://github.com/test/repo",
        "violations": violations or [],
    }


# ============================================================
# Schema validation tests
# ============================================================


class TestSchemaValidation:
    def test_valid_report_passes_validation(self) -> None:
        report = _make_report([_make_violation()])
        validated = validate_and_clean(report)
        assert validated["repository"] == "https://github.com/test/repo"

    def test_empty_violations_valid(self) -> None:
        report = _make_report([])
        validated = validate_and_clean(report)
        assert validated["violations"] == []

    def test_null_file_and_line_valid(self) -> None:
        v = _make_violation(file=None, line=None)
        report = _make_report([v])
        validated = validate_and_clean(report)
        assert validated["violations"][0]["file"] is None
        assert validated["violations"][0]["line"] is None

    def test_invalid_severity_normalized(self) -> None:
        v = _make_violation(severity="CRITICAL")  # wrong case
        report = _make_report([v])
        validated = validate_and_clean(report)
        # Should be normalized to lowercase
        assert validated["violations"][0]["severity"] == "critical"

    def test_invalid_severity_bad_value_defaults(self) -> None:
        v = _make_violation(severity="catastrophic")
        report = _make_report([v])
        validated = validate_and_clean(report)
        assert validated["violations"][0]["severity"] == "medium"

    def test_all_severity_levels_accepted(self) -> None:
        for sev in ("critical", "high", "medium", "low"):
            v = _make_violation(severity=sev)
            report = _make_report([v])
            validated = validate_and_clean(report)
            assert validated["violations"][0]["severity"] == sev

    def test_missing_repository_fails(self) -> None:
        report = {"violations": []}
        with pytest.raises(jsonschema.ValidationError):
            validate_and_clean(report)

    def test_report_is_json_serializable(self) -> None:
        report = _make_report([_make_violation()])
        validated = validate_and_clean(report)
        # Should serialize without error
        serialized = json.dumps(validated)
        assert "violations" in serialized


# ============================================================
# Category inference tests
# ============================================================


class TestCategoryInference:
    @pytest.mark.parametrize(
        "rule_id,expected_category",
        [
            ("SEC-001", "security"),
            ("HYG-003", "repository_hygiene"),
            ("DEP-002", "dependency_management"),
            ("QUAL-001", "code_quality"),
            ("TEST-001", "testing"),
            ("CI-003", "ci_cd"),
            ("CFG-001", "configuration"),
            ("COLLAB-001", "collaboration"),
            ("BUILD-002", "build_and_release"),
        ],
    )
    def test_category_inferred_from_rule_id(self, rule_id: str, expected_category: str) -> None:
        v = _make_violation(rule_id=rule_id, category="wrong_category")
        report = _make_report([v])
        validated = validate_and_clean(report)
        assert validated["violations"][0]["category"] == expected_category, (
            f"rule_id={rule_id} should map to {expected_category}"
        )


# ============================================================
# Deduplication tests
# ============================================================


class TestDeduplication:
    def test_exact_duplicate_removed(self) -> None:
        """Two identical violations should deduplicate to one."""
        v = _make_violation(rule_id="SEC-001", file="app.py", line=10)
        report = _make_report([v, v.copy()])
        validated = validate_and_clean(report)
        assert len(validated["violations"]) == 1

    def test_same_file_different_line_not_deduplicated(self) -> None:
        """Same rule_id and file but different lines should both be kept."""
        v1 = _make_violation(rule_id="SEC-001", file="app.py", line=10)
        v2 = _make_violation(rule_id="SEC-001", file="app.py", line=20)
        report = _make_report([v1, v2])
        validated = validate_and_clean(report)
        assert len(validated["violations"]) == 2

    def test_same_line_different_rule_not_deduplicated(self) -> None:
        """Same file+line but different rule_ids should both be kept."""
        v1 = _make_violation(rule_id="SEC-001", file="app.py", line=10)
        v2 = _make_violation(rule_id="QUAL-005", file="app.py", line=10)
        report = _make_report([v1, v2])
        validated = validate_and_clean(report)
        assert len(validated["violations"]) == 2

    def test_many_duplicates_collapsed(self) -> None:
        """Five identical violations should collapse to exactly one."""
        v = _make_violation()
        report = _make_report([v.copy() for _ in range(5)])
        validated = validate_and_clean(report)
        assert len(validated["violations"]) == 1


# ============================================================
# Secret scrubbing tests
# ============================================================


class TestSecretScrubbing:
    def test_scrub_secrets_removes_github_token(self) -> None:
        text = "token: ghp_abcdefghijklmnopqrstuvwxyz012345"
        result = scrub_secrets(text)
        assert "ghp_" not in result

    def test_scrub_secrets_removes_aws_key(self) -> None:
        text = "AKIAIOSFODNN7EXAMPLEKEY"
        result = scrub_secrets(text)
        assert "AKIAIOSFODNN7EXAMPLEKEY" not in result

    def test_scrub_report_recursively_cleans(self) -> None:
        report = {
            "repository": "https://github.com/test/repo",
            "violations": [
                {
                    "evidence": "Found token = ghp_abcdefghijklmnopqrstuvwxyz012345",
                    "nested": {"key": "AKIAIOSFODNN7EXAMPLEKEY"},
                }
            ],
        }
        cleaned = scrub_report(report)
        evidence = cleaned["violations"][0]["evidence"]
        nested_val = cleaned["violations"][0]["nested"]["key"]
        assert "ghp_" not in evidence
        assert "AKIAIOSFODNN7EXAMPLEKEY" not in nested_val

    def test_scrub_does_not_alter_clean_text(self) -> None:
        text = "This is a completely normal description of a code quality issue."
        result = scrub_secrets(text)
        assert result == text

    def test_validate_and_clean_scrubs_evidence(self) -> None:
        """validate_and_clean should scrub secrets even in the evidence field."""
        v = _make_violation(evidence="Raw secret: ghp_abcdefghijklmnopqrstuvwxyz012345")
        report = _make_report([v])
        validated = validate_and_clean(report)
        evidence = validated["violations"][0]["evidence"]
        assert "ghp_" not in evidence


# ============================================================
# File-existence verification tests
# ============================================================


class TestFileExistenceVerification:
    def test_hallucinated_sec_file_removed(self, tmp_path: Path) -> None:
        """A SEC-001 finding referencing a non-existent file should be dropped."""
        v = _make_violation(
            rule_id="SEC-001",
            file="nonexistent_hallucinated_file.py",
            line=1,
        )
        report = _make_report([v])
        validated = validate_and_clean(report, repo_root=tmp_path)
        # The file doesn't exist — SEC-001 requires file to exist
        assert len(validated["violations"]) == 0

    def test_existing_file_finding_kept(self, tmp_path: Path) -> None:
        """A finding whose file actually exists should be kept."""
        (tmp_path / "real_file.py").write_text("x = 1\n")
        v = _make_violation(rule_id="HYG-001", file="real_file.py", line=1)
        report = _make_report([v])
        validated = validate_and_clean(report, repo_root=tmp_path)
        assert len(validated["violations"]) == 1

    def test_null_file_finding_always_kept(self, tmp_path: Path) -> None:
        """Findings with null file (repo-level) should always be kept."""
        v = _make_violation(rule_id="HYG-001", file=None, line=None)
        report = _make_report([v])
        validated = validate_and_clean(report, repo_root=tmp_path)
        assert len(validated["violations"]) == 1

    def test_path_traversal_in_file_blocked(self, tmp_path: Path) -> None:
        """A finding with a path traversal in 'file' should be dropped."""
        v = _make_violation(rule_id="HYG-001", file="../../../etc/passwd")
        report = _make_report([v])
        validated = validate_and_clean(report, repo_root=tmp_path)
        # Path traversal — should be blocked and finding dropped
        assert len(validated["violations"]) == 0


# ============================================================
# False-positive prevention tests (Repo C)
# ============================================================


class TestFalsePositivePrevention:
    def test_valid_report_with_no_violations(self) -> None:
        """A completely clean report should validate successfully."""
        report = {
            "repository": "https://github.com/test/healthy-repo",
            "violations": [],
        }
        validated = validate_and_clean(report)
        assert validated["violations"] == []
        assert validated["repository"] == "https://github.com/test/healthy-repo"

    def test_large_violation_set_validated(self) -> None:
        """Many diverse violations should all validate correctly."""
        violations = []
        for i, (rule_id, cat, sev) in enumerate(
            [
                ("SEC-001", "security", "critical"),
                ("HYG-003", "repository_hygiene", "high"),
                ("DEP-001", "dependency_management", "high"),
                ("QUAL-003", "code_quality", "medium"),
                ("TEST-001", "testing", "high"),
                ("CI-003", "ci_cd", "high"),
                ("CFG-001", "configuration", "high"),
                ("COLLAB-001", "collaboration", "medium"),
                ("BUILD-002", "build_and_release", "high"),
            ]
        ):
            violations.append(
                _make_violation(
                    rule_id=rule_id,
                    category=cat,
                    severity=sev,
                    file=None,
                    line=None,
                )
            )

        report = _make_report(violations)
        validated = validate_and_clean(report)
        assert len(validated["violations"]) == len(violations)
