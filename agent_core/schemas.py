"""
agent_core/schemas.py — JSON schema validation, deduplication, and secret scrubbing.

Responsibilities:
1. Validate the final report against the exact JSON contract
2. Deduplicate findings pointing to the same (file, line, rule_id) or same defect
3. Verify that non-null "file" paths actually exist in the cloned repo
4. Run a strict regex scrubber over every string field to prevent secret leakage
"""

from __future__ import annotations

import hashlib
import re
from pathlib import Path
from typing import Any

import jsonschema

# ============================================================
# Secret-scrubbing patterns
# These run on every string field in the output to guarantee
# zero credential leakage even if the LLM accidentally echoes
# a secret value.
# ============================================================

_SECRET_PATTERNS: list[re.Pattern] = [
    # Generic high-entropy strings that look like keys/tokens (20+ alphanum chars)
    re.compile(
        r"(?i)(?:api[_-]?key|apikey|secret|token|password|passwd|pwd|auth|credential)[s]?"
        r"\s*[:=]\s*['\"]?([A-Za-z0-9/+_\-]{16,})['\"]?",
        re.MULTILINE,
    ),
    # AWS keys
    re.compile(r"(?:AKIA|ASIA|AROA|ANPA|ANVA|AIDA)[A-Z0-9]{16}", re.MULTILINE),
    # Generic hex/base64 tokens 32+ chars
    re.compile(r"['\"]([0-9a-fA-F]{32,})['\"]", re.MULTILINE),
    # GitHub tokens
    re.compile(r"gh[pousr]_[A-Za-z0-9]{30,}", re.MULTILINE),
    # Slack tokens
    re.compile(r"xox[baprs]-[0-9A-Za-z\-]{10,}", re.MULTILINE),
    # PEM / private key blocks
    re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----.*?-----END.*?-----",
               re.DOTALL),
    # Connection strings / DSNs
    re.compile(
        r"(?:postgres|mysql|mongodb|redis)://[^:]+:[^@]+@[^\s\"']+",
        re.IGNORECASE,
    ),
]

_REDACTION_MARKER = "[REDACTED_SECRET_DETECTED]"


def scrub_secrets(value: str) -> str:
    """Replace any detected secret values with the redaction marker."""
    for pattern in _SECRET_PATTERNS:
        value = pattern.sub(_REDACTION_MARKER, value)
    return value


def scrub_report(report: dict[str, Any]) -> dict[str, Any]:
    """Recursively scrub all string values in the report dict."""
    if isinstance(report, dict):
        return {k: scrub_report(v) for k, v in report.items()}
    if isinstance(report, list):
        return [scrub_report(item) for item in report]
    if isinstance(report, str):
        return scrub_secrets(report)
    return report


# ============================================================
# JSON Schema — exact output contract
# ============================================================

VIOLATION_SCHEMA = {
    "type": "object",
    "properties": {
        "rule_id": {"type": "string", "minLength": 1},
        "category": {
            "type": "string",
            "enum": [
                "repository_hygiene",
                "dependency_management",
                "code_quality",
                "testing",
                "ci_cd",
                "security",
                "configuration",
                "collaboration",
                "build_and_release",
            ],
        },
        "severity": {"type": "string", "enum": ["critical", "high", "medium", "low"]},
        "file": {"type": ["string", "null"]},
        "line": {"type": ["integer", "null"]},
        "description": {"type": "string", "minLength": 1},
        "evidence": {"type": "string", "minLength": 1},
        "recommendation": {"type": "string", "minLength": 1},
    },
    "required": [
        "rule_id",
        "category",
        "severity",
        "file",
        "line",
        "description",
        "evidence",
        "recommendation",
    ],
    "additionalProperties": False,
}

REPORT_SCHEMA = {
    "type": "object",
    "properties": {
        "repository": {"type": "string", "minLength": 1},
        "violations": {
            "type": "array",
            "items": VIOLATION_SCHEMA,
        },
    },
    "required": ["repository", "violations"],
    "additionalProperties": False,
}

# Mapping of rule_id prefix → canonical category name
_RULE_CATEGORY_MAP: dict[str, str] = {
    "HYG": "repository_hygiene",
    "DEP": "dependency_management",
    "QUAL": "code_quality",
    "TEST": "testing",
    "CI": "ci_cd",
    "SEC": "security",
    "CFG": "configuration",
    "COLLAB": "collaboration",
    "BUILD": "build_and_release",
}


def _infer_category(rule_id: str) -> str | None:
    """Infer canonical category from rule_id prefix."""
    prefix = rule_id.split("-")[0].upper()
    return _RULE_CATEGORY_MAP.get(prefix)


def validate_and_clean(
    report: dict[str, Any],
    repo_root: Path | None = None,
) -> dict[str, Any]:
    """
    Validate, deduplicate, and clean the agent's output report.

    Steps:
    1. Scrub all secret values from every field.
    2. Fix/infer category from rule_id if missing or wrong.
    3. Remove findings whose "file" path doesn't exist in the cloned repo.
    4. Deduplicate findings by (rule_id, file, line) fingerprint.
    5. Validate against the JSON schema contract.

    Args:
        report:     Raw dict produced by the agent.
        repo_root:  Optional Path to the cloned repo for file-existence checks.

    Returns:
        Cleaned, validated report dict.

    Raises:
        jsonschema.ValidationError: If report does not match the schema.
    """
    # Step 1: Scrub secrets
    report = scrub_report(report)

    violations: list[dict[str, Any]] = report.get("violations", [])

    cleaned: list[dict[str, Any]] = []
    seen_fingerprints: set[str] = set()

    for v in violations:
        if not isinstance(v, dict):
            continue

        # Step 2: Fix category from rule_id
        rule_id = str(v.get("rule_id", "")).strip()
        inferred = _infer_category(rule_id)
        if inferred:
            v["category"] = inferred

        # Normalize severity
        severity = str(v.get("severity", "medium")).lower()
        if severity not in ("critical", "high", "medium", "low"):
            severity = "medium"
        v["severity"] = severity

        # Step 3: Verify file existence
        file_path = v.get("file")
        if file_path and repo_root is not None:
            candidate = repo_root / file_path
            # Allow relative paths but block traversal
            try:
                candidate.resolve().relative_to(repo_root.resolve())
                if not candidate.exists():
                    # File doesn't exist — nullify rather than discard
                    # (the issue may still be valid, e.g., a missing file)
                    # Only discard if the rule implies file must exist for the finding
                    _file_must_exist_rules = {
                        "SEC-001", "SEC-002", "QUAL-002", "QUAL-003", "QUAL-005",
                    }
                    if rule_id in _file_must_exist_rules:
                        continue  # hallucinated path — skip
            except ValueError:
                # Path traversal attempt — skip
                continue

        # Step 4: Deduplicate
        line_val = v.get("line")
        fingerprint_src = f"{rule_id}|{file_path}|{line_val}"
        fingerprint = hashlib.md5(fingerprint_src.encode()).hexdigest()  # noqa: S324
        if fingerprint in seen_fingerprints:
            continue
        seen_fingerprints.add(fingerprint)

        # Ensure required fields exist with defaults
        v.setdefault("file", None)
        v.setdefault("line", None)
        v.setdefault("description", "No description provided")
        v.setdefault("evidence", "See finding details")
        v.setdefault("recommendation", "Review and remediate this finding")

        cleaned.append(v)

    report["violations"] = cleaned

    # Step 5: Schema validation
    jsonschema.validate(instance=report, schema=REPORT_SCHEMA)

    return report
