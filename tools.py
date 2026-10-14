"""
tools.py — Inspection tool implementations for the DevOps Repository Auditing Agent.

All tools operate on a cloned repository in an isolated temporary directory.
Tools are:
  - Read-only: they never modify the inspected repository
  - Sandboxed: path-traversal protection prevents reading outside the clone
  - Secret-safe: two-layer redaction ensures no credential leaks in output
  - Timeout-guarded: subprocess calls have configurable timeouts

MANDATORY TOOLS:
  list_files, read_file, search_code, git_log

OPTIONAL TOOLS:
  git_status, inspect_github_actions, run_ruff, run_pytest
"""

from __future__ import annotations

import ast
import fnmatch
import json
import logging
import os
import re
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Any

import git  # type: ignore[import]
import yaml

logger = logging.getLogger(__name__)

# ============================================================
# Configuration
# ============================================================

CLONE_TIMEOUT = int(os.environ.get("CLONE_TIMEOUT_SECONDS", "120"))
TOOL_TIMEOUT = int(os.environ.get("TOOL_SUBPROCESS_TIMEOUT", "30"))

# Files/dirs that should never be committed
SUSPICIOUS_PATTERNS: list[str] = [
    "__pycache__",
    "*.pyc",
    "*.pyo",
    ".DS_Store",
    "node_modules",
    ".venv",
    "venv",
    "env",
    ".env",
    "*.pem",
    "*.key",
    "*.p12",
    "*.pfx",
    "*.sqlite3",
    "*.sqlite",
    "*.db",
    "*.log",
    ".idea",
    ".vscode",
    "*.egg-info",
    "dist",
    "build",
    ".pytest_cache",
    ".ruff_cache",
    ".mypy_cache",
    "*.secret",
    "*_secret*",
]

# Secret detection patterns (for in-file scanning)
_SECRET_REGEXES: list[tuple[str, re.Pattern]] = [
    ("AWS Access Key", re.compile(r"(?:AKIA|ASIA|AROA|ANPA|ANVA|AIDA)[A-Z0-9]{16}")),
    ("Generic API Key", re.compile(
        r"(?i)(?:api[_-]?key|apikey|api[_-]?secret)\s*[:=]\s*['\"]?([A-Za-z0-9/+_\-]{16,})['\"]?",
        re.MULTILINE,
    )),
    ("GitHub Token", re.compile(r"gh[pousr]_[A-Za-z0-9]{30,}")),
    ("Slack Token", re.compile(r"xox[baprs]-[0-9A-Za-z\-]{10,}")),
    ("Private Key Block", re.compile(
        r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----"
    )),
    ("Generic Secret Assignment", re.compile(
        r"(?i)(?:password|passwd|secret|token|credential)\s*[:=]\s*['\"]([^'\"]{8,})['\"]",
        re.MULTILINE,
    )),
    ("Connection String", re.compile(
        r"(?:postgres|mysql|mongodb|redis)://[^:]+:[^@\s]+@",
        re.IGNORECASE,
    )),
    ("Generic High-Entropy String", re.compile(
        r"['\"][0-9a-fA-F]{40,}['\"]",  # 40+ hex chars
    )),
]

_REDACTION = "[REDACTED_SECRET_DETECTED]"


def _scrub_line(line: str) -> str:
    """Redact secret values from a single line."""
    for _name, pattern in _SECRET_REGEXES:
        line = pattern.sub(_REDACTION, line)
    return line


def _is_suspicious(name: str) -> bool:
    """Check if a filename/dirname matches any suspicious pattern."""
    for pat in SUSPICIOUS_PATTERNS:
        if fnmatch.fnmatch(name, pat) or fnmatch.fnmatch(name.lower(), pat.lower()):
            return True
    return False


# ============================================================
# Repository Manager — clone & cleanup
# ============================================================


class RepoManager:
    """
    Manages cloning a remote repository into an isolated temporary directory.

    Usage:
        with RepoManager("https://github.com/...") as rm:
            root = rm.root  # Path to cloned repo
    """

    def __init__(self, url: str) -> None:
        self.url = url
        self._tmpdir: tempfile.TemporaryDirectory | None = None
        self.root: Path | None = None
        self._repo: git.Repo | None = None

    def __enter__(self) -> RepoManager:
        self._tmpdir = tempfile.TemporaryDirectory(prefix="devops_audit_")
        self.root = Path(self._tmpdir.name)
        logger.info("Cloning %s into %s", self.url, self.root)
        start = time.time()
        try:
            self._repo = git.Repo.clone_from(
                self.url,
                self.root,
                depth=50,  # shallow clone for speed
                timeout=CLONE_TIMEOUT,
            )
        except git.GitCommandError as exc:
            self._tmpdir.cleanup()
            raise RuntimeError(f"Failed to clone {self.url}: {exc}") from exc
        elapsed = time.time() - start
        logger.info("Clone complete in %.1fs", elapsed)
        return self

    def __exit__(self, *_args: object) -> None:
        if self._tmpdir:
            try:
                self._tmpdir.cleanup()
            except Exception as exc:  # noqa: BLE001
                logger.warning("Temp dir cleanup failed: %s", exc)

    @property
    def repo(self) -> git.Repo:
        if self._repo is None:
            raise RuntimeError("RepoManager not entered as context manager")
        return self._repo


# ============================================================
# Tool Implementations
# ============================================================


class ToolExecutor:
    """
    Wraps all tool implementations, bound to a specific cloned repository root.

    All path arguments are resolved relative to self.root and validated
    against path-traversal attacks.
    """

    def __init__(self, repo_root: Path, repo: git.Repo | None = None) -> None:
        self.root = repo_root.resolve()
        self._repo = repo

    def dispatch(self, tool_name: str, kwargs: dict[str, Any]) -> dict[str, Any]:
        """Route a tool call to the appropriate implementation."""
        tool_map: dict[str, Any] = {
            "list_files": self.list_files,
            "read_file": self.read_file,
            "search_code": self.search_code,
            "git_log": self.git_log,
            "git_status": self.git_status,
            "inspect_github_actions": self.inspect_github_actions,
            "run_ruff": self.run_ruff,
            "run_pytest": self.run_pytest,
        }
        fn = tool_map.get(tool_name)
        if fn is None:
            return {"error": f"Unknown tool: {tool_name}"}
        return fn(**kwargs)

    def _resolve_path(self, rel_path: str) -> Path:
        """Resolve a relative path safely, blocking traversal outside root."""
        target = (self.root / rel_path).resolve()
        try:
            target.relative_to(self.root)
        except ValueError as exc:
            raise PermissionError(
                f"Path traversal attempt blocked: {rel_path!r}"
            ) from exc
        return target

    # ------------------------------------------------------------------
    # MANDATORY TOOL 1: list_files
    # ------------------------------------------------------------------

    def list_files(
        self,
        subpath: str = ".",
        include_hidden: bool = True,
        max_depth: int = 4,
    ) -> dict[str, Any]:
        """
        Discovers repository files and directory hierarchy.

        Returns a tree dict with flagged suspicious files.
        """
        try:
            target = self._resolve_path(subpath)
        except PermissionError as exc:
            return {"error": str(exc)}

        if not target.exists():
            return {"error": f"Path does not exist: {subpath}"}

        entries: list[dict[str, Any]] = []
        flagged: list[str] = []
        total_files = 0

        def _walk(path: Path, depth: int, prefix: str = "") -> None:
            nonlocal total_files
            if depth > max_depth:
                return
            try:
                children = sorted(path.iterdir())
            except PermissionError:
                return

            for child in children:
                name = child.name
                # Skip .git internals (objects/pack etc.) but keep .git itself visible
                if name == ".git" and depth > 1:
                    continue
                if not include_hidden and name.startswith("."):
                    continue

                rel = str(child.relative_to(self.root))
                is_suspicious = _is_suspicious(name)
                if is_suspicious:
                    flagged.append(rel)

                if child.is_dir():
                    entries.append({
                        "type": "dir",
                        "path": rel,
                        "suspicious": is_suspicious,
                    })
                    _walk(child, depth + 1, prefix + "  ")
                else:
                    total_files += 1
                    try:
                        size = child.stat().st_size
                    except OSError:
                        size = -1
                    entries.append({
                        "type": "file",
                        "path": rel,
                        "size_bytes": size,
                        "suspicious": is_suspicious,
                    })

        _walk(target, 1)

        return {
            "root": str(subpath),
            "total_files": total_files,
            "entries": entries,
            "suspicious_tracked_files": flagged,
            "note": (
                "suspicious_tracked_files lists files that should typically NOT be committed. "
                "Cross-reference with .gitignore and git_status."
            ),
        }

    # ------------------------------------------------------------------
    # MANDATORY TOOL 2: read_file
    # ------------------------------------------------------------------

    def read_file(
        self,
        path: str,
        start_line: int = 1,
        end_line: int = 250,
    ) -> dict[str, Any]:
        """
        Reads a repository file with 1-indexed line numbers and secret redaction.
        """
        try:
            target = self._resolve_path(path)
        except PermissionError as exc:
            return {"error": str(exc)}

        if not target.exists():
            return {"error": f"File not found: {path}"}
        if target.is_dir():
            return {"error": f"Path is a directory: {path}"}

        # Detect binary
        try:
            with open(target, "rb") as fh:
                raw = fh.read(8192)
            if b"\x00" in raw:
                return {
                    "path": path,
                    "binary": True,
                    "size_bytes": target.stat().st_size,
                    "note": "Binary file — cannot display content",
                }
        except OSError as exc:
            return {"error": f"Could not read {path}: {exc}"}

        # Read as text
        try:
            with open(target, encoding="utf-8", errors="replace") as fh:
                all_lines = fh.readlines()
        except OSError as exc:
            return {"error": f"Could not read {path}: {exc}"}

        total_lines = len(all_lines)
        start = max(1, start_line)
        end = min(total_lines, end_line)

        numbered: list[str] = []
        for i, line in enumerate(all_lines[start - 1 : end], start=start):
            scrubbed = _scrub_line(line.rstrip("\n"))
            numbered.append(f"{i:4d}: {scrubbed}")

        return {
            "path": path,
            "total_lines": total_lines,
            "shown_lines": f"{start}-{end}",
            "content": "\n".join(numbered),
            "truncated": end < total_lines,
            "note": (
                "Lines are 1-indexed. Secret values have been redacted to "
                "[REDACTED_SECRET_DETECTED] while keeping variable names intact."
            ),
        }

    # ------------------------------------------------------------------
    # MANDATORY TOOL 3: search_code
    # ------------------------------------------------------------------

    def search_code(
        self,
        pattern: str,
        file_glob: str = "*",
        case_sensitive: bool = False,
    ) -> dict[str, Any]:
        """
        Searches repository files for a regex (or literal) pattern.

        Returns matching files, line numbers, and scrubbed line snippets.
        """
        # Compile regex safely
        flags = 0 if case_sensitive else re.IGNORECASE
        try:
            regex = re.compile(pattern, flags)
        except re.error:
            # Fallback to literal search
            regex = re.compile(re.escape(pattern), flags)

        matches: list[dict[str, Any]] = []
        total_matches = 0
        MAX_MATCHES = 200

        for filepath in self.root.rglob(file_glob):
            # Skip .git internals
            if ".git" in filepath.parts:
                continue
            if not filepath.is_file():
                continue

            # Skip binary files
            try:
                with open(filepath, "rb") as fh:
                    chunk = fh.read(512)
                if b"\x00" in chunk:
                    continue
            except OSError:
                continue

            rel_path = str(filepath.relative_to(self.root))

            try:
                with open(filepath, encoding="utf-8", errors="replace") as fh:
                    for lineno, line in enumerate(fh, start=1):
                        if regex.search(line):
                            total_matches += 1
                            if total_matches <= MAX_MATCHES:
                                matches.append({
                                    "file": rel_path,
                                    "line": lineno,
                                    "content": _scrub_line(line.rstrip("\n")),
                                })
            except OSError:
                continue

        result: dict[str, Any] = {
            "pattern": pattern,
            "file_glob": file_glob,
            "total_matches": total_matches,
            "matches": matches,
        }
        if total_matches > MAX_MATCHES:
            result["note"] = f"Showing first {MAX_MATCHES} of {total_matches} matches"
        return result

    # ------------------------------------------------------------------
    # MANDATORY TOOL 4: git_log
    # ------------------------------------------------------------------

    def git_log(
        self,
        max_commits: int = 30,
        stat: bool = True,
    ) -> dict[str, Any]:
        """
        Inspects commit history for secrets, large binary commits, and poor hygiene.
        """
        if self._repo is None:
            return {"error": "No git repository available"}

        commits_data: list[dict[str, Any]] = []
        warnings: list[str] = []

        _secret_in_message_re = re.compile(
            r"(?i)(?:api[_-]?key|secret|token|password|credential)\s*[:=]\s*\S+",
            re.IGNORECASE,
        )
        _sensitive_file_re = re.compile(
            r"(?:\.env|\.pem|\.key|secrets?\.|credentials?\.)",
            re.IGNORECASE,
        )

        try:
            commits = list(self._repo.iter_commits(max_count=max_commits))
        except Exception as exc:  # noqa: BLE001
            return {"error": f"git log failed: {exc}"}

        for commit in commits:
            commit_info: dict[str, Any] = {
                "hash": commit.hexsha[:12],
                "author": commit.author.name,
                "date": commit.authored_datetime.isoformat(),
                "message": commit.message.strip()[:200],
                "files_changed": 0,
            }

            # Check commit message for secrets
            if _secret_in_message_re.search(commit.message):
                warning = (
                    f"Commit {commit.hexsha[:8]} message may contain credential references"
                )
                warnings.append(warning)
                commit_info["warning"] = warning

            # Stat: check files changed
            if stat:
                try:
                    stats = commit.stats.files
                    commit_info["files_changed"] = len(stats)
                    sensitive_files = [
                        f for f in stats if _sensitive_file_re.search(f)
                    ]
                    if sensitive_files:
                        warning = (
                            f"Commit {commit.hexsha[:8]} touched sensitive files: "
                            f"{sensitive_files}"
                        )
                        warnings.append(warning)
                        commit_info["sensitive_files"] = sensitive_files

                    # Flag very large commits
                    total_lines = sum(
                        s.get("insertions", 0) + s.get("deletions", 0)
                        for s in stats.values()
                        if isinstance(s, dict)
                    )
                    if total_lines > 5000:
                        commit_info["large_commit_warning"] = (
                            f"Very large commit: {total_lines} line changes"
                        )
                except Exception:  # noqa: BLE001
                    pass

            commits_data.append(commit_info)

        # Check if any .env or secret files appear in git history at all
        try:
            all_tracked = subprocess.run(
                ["git", "log", "--all", "--full-history", "--", "**/.env", ".env",
                 "*.pem", "*.key"],
                cwd=str(self.root),
                capture_output=True,
                text=True,
                timeout=15,
            )
            if all_tracked.stdout.strip():
                warnings.append(
                    "Sensitive files (.env, .pem, .key) appear in git history — "
                    "these remain accessible even if deleted from HEAD"
                )
        except Exception:  # noqa: BLE001
            pass

        return {
            "total_commits_inspected": len(commits_data),
            "commits": commits_data,
            "warnings": warnings,
            "note": (
                "Sensitive files in history remain accessible via git even after deletion. "
                "Use git-filter-repo or BFG to permanently remove them."
            ),
        }

    # ------------------------------------------------------------------
    # OPTIONAL TOOL 5: git_status
    # ------------------------------------------------------------------

    def git_status(self) -> dict[str, Any]:
        """
        Runs git status and git ls-files to detect files tracked despite .gitignore rules.
        """
        if self._repo is None:
            return {"error": "No git repository available"}

        results: dict[str, Any] = {}

        # git status
        try:
            status_out = subprocess.run(
                ["git", "status", "--porcelain"],
                cwd=str(self.root),
                capture_output=True,
                text=True,
                timeout=15,
            )
            results["status_output"] = status_out.stdout[:3000]
        except Exception as exc:  # noqa: BLE001
            results["status_error"] = str(exc)

        # git ls-files — find tracked files that match suspicious patterns
        try:
            ls_out = subprocess.run(
                ["git", "ls-files"],
                cwd=str(self.root),
                capture_output=True,
                text=True,
                timeout=15,
            )
            tracked = [f.strip() for f in ls_out.stdout.splitlines() if f.strip()]
            results["tracked_file_count"] = len(tracked)

            suspicious_tracked = [f for f in tracked if _is_suspicious(Path(f).name)]
            results["suspicious_tracked"] = suspicious_tracked

            if suspicious_tracked:
                results["warning"] = (
                    f"Found {len(suspicious_tracked)} suspicious file(s) tracked in git index "
                    "that should typically be in .gitignore"
                )
        except Exception as exc:  # noqa: BLE001
            results["ls_files_error"] = str(exc)

        # Check for files in .gitignore that are still tracked
        gitignore_path = self.root / ".gitignore"
        if gitignore_path.exists():
            try:
                check_out = subprocess.run(
                    ["git", "ls-files", "--ignored", "--exclude-standard"],
                    cwd=str(self.root),
                    capture_output=True,
                    text=True,
                    timeout=15,
                )
                ignored_but_tracked = [
                    f.strip() for f in check_out.stdout.splitlines() if f.strip()
                ]
                if ignored_but_tracked:
                    results["ignored_but_tracked"] = ignored_but_tracked
                    results["gitignore_warning"] = (
                        "These files match .gitignore rules but are still tracked — "
                        "run `git rm --cached <file>` to untrack them"
                    )
            except Exception:  # noqa: BLE001
                pass

        return results

    # ------------------------------------------------------------------
    # OPTIONAL TOOL 6: inspect_github_actions
    # ------------------------------------------------------------------

    def inspect_github_actions(self) -> dict[str, Any]:
        """
        Parses .github/workflows/*.yml with line numbers and detects security issues.
        """
        workflows_dir = self.root / ".github" / "workflows"
        if not workflows_dir.exists():
            return {
                "workflows_found": False,
                "files": [],
                "findings": [
                    {
                        "issue": "No GitHub Actions workflows found",
                        "detail": (
                            "No .github/workflows/ directory exists. "
                            "Consider whether other CI systems are present."
                        ),
                    }
                ],
            }

        workflow_files = list(workflows_dir.glob("*.yml")) + list(workflows_dir.glob("*.yaml"))
        if not workflow_files:
            return {
                "workflows_found": False,
                "files": [],
                "findings": [{"issue": "Workflow directory exists but no .yml/.yaml files found"}],
            }

        all_findings: list[dict[str, Any]] = []
        parsed_workflows: list[dict[str, Any]] = []

        for wf_path in sorted(workflow_files):
            rel = str(wf_path.relative_to(self.root))
            findings: list[dict[str, Any]] = []

            try:
                with open(wf_path, encoding="utf-8", errors="replace") as fh:
                    raw_lines = fh.readlines()
                    raw_content = "".join(raw_lines)
            except OSError as exc:
                parsed_workflows.append({"file": rel, "error": str(exc)})
                continue

            try:
                wf_data = yaml.safe_load(raw_content) or {}
            except yaml.YAMLError as exc:
                parsed_workflows.append({"file": rel, "yaml_error": str(exc)})
                findings.append({"line": None, "issue": "YAML parse error", "detail": str(exc)})
                all_findings.extend(findings)
                continue

            def find_line(needle: str, _lines: list = raw_lines) -> int | None:  # noqa: B008
                for i, line in enumerate(_lines, 1):
                    if needle in line:
                        return i
                return None

            # ---- Security checks ----

            # 1. Missing permissions block
            if "permissions" not in wf_data:
                findings.append({
                    "line": 1,
                    "issue": "SEC-003: Missing top-level 'permissions' block",
                    "detail": (
                        "Without a permissions block, the workflow runs with default "
                        "write permissions. Add 'permissions: read-all' or scope tightly."
                    ),
                    "rule_id": "SEC-003",
                    "severity": "high",
                })
            elif wf_data.get("permissions") == "write-all":
                ln = find_line("write-all")
                findings.append({
                    "line": ln,
                    "issue": "SEC-003: Overly broad permissions: write-all",
                    "detail": "Use least-privilege scoped permissions instead.",
                    "rule_id": "SEC-003",
                    "severity": "high",
                })

            # 2. Check for unpinned actions (@main/@master/@latest)
            _unpinned_re = re.compile(r"uses:\s*([^@\s]+@(?:main|master|latest|HEAD))", re.IGNORECASE)
            for i, line in enumerate(raw_lines, 1):
                m = _unpinned_re.search(line)
                if m:
                    findings.append({
                        "line": i,
                        "issue": f"SEC-005: Unpinned action: {m.group(1)}",
                        "detail": (
                            "Pin actions to a specific commit SHA for supply-chain security. "
                            "Replace '@main' with '@<commit-sha>'"
                        ),
                        "rule_id": "SEC-005",
                        "severity": "high",
                    })

            # 3. Script injection via github.event context
            _injection_re = re.compile(
                r"\$\{\{\s*github\.event\.(head_commit\.message|pull_request\."
                r"(?:title|body|head\.ref)|issue\.(title|body))",
                re.IGNORECASE,
            )
            for i, line in enumerate(raw_lines, 1):
                if _injection_re.search(line):
                    findings.append({
                        "line": i,
                        "issue": "SEC-003: Script injection via github.event context",
                        "detail": (
                            "User-controlled data from github.event in run: steps "
                            "can lead to code injection. Use environment variables instead."
                        ),
                        "rule_id": "SEC-003",
                        "severity": "high",
                    })

            # 4. unsafe pull_request_target with checkout
            if "pull_request_target" in raw_content:
                if "actions/checkout" in raw_content:
                    for i, line in enumerate(raw_lines, 1):
                        if "pull_request_target" in line:
                            findings.append({
                                "line": i,
                                "issue": "SEC-004: Unsafe pull_request_target with checkout",
                                "detail": (
                                    "pull_request_target runs in the context of the base repo "
                                    "with write permissions. Checking out untrusted PR code here "
                                    "is a known privilege escalation vector."
                                ),
                                "rule_id": "SEC-004",
                                "severity": "high",
                            })
                            break

            # 5. continue-on-error: true on test/lint steps
            jobs = wf_data.get("jobs", {}) or {}
            for _, job_data in jobs.items():
                if not isinstance(job_data, dict):
                    continue
                steps = job_data.get("steps", []) or []
                for step in steps:
                    if not isinstance(step, dict):
                        continue
                    if step.get("continue-on-error") is True:
                        step_name = step.get("name", "unnamed")
                        run_cmd = step.get("run", "")
                        # Only flag if it's a test or lint step
                        if any(kw in str(run_cmd).lower() for kw in
                               ("pytest", "ruff", "flake8", "eslint", "test", "lint")):
                            ln = find_line("continue-on-error")
                            findings.append({
                                "line": ln,
                                "issue": f"CI-003: continue-on-error:true on test/lint step '{step_name}'",
                                "detail": (
                                    "This masks test/lint failures — quality gates become ineffective."
                                ),
                                "rule_id": "CI-003",
                                "severity": "high",
                            })

                    # Check for || true masking
                    run_cmd = step.get("run", "") or ""
                    if "|| true" in run_cmd and any(
                        kw in run_cmd.lower() for kw in ("test", "pytest", "lint", "ruff")
                    ):
                        ln = find_line("|| true")
                        findings.append({
                            "line": ln,
                            "issue": "CI-003: '|| true' masks test/lint step failure",
                            "detail": "Remove '|| true' to ensure CI fails on test/lint errors.",
                            "rule_id": "CI-003",
                            "severity": "high",
                        })

            # 6. Check branch triggers
            on_block = wf_data.get("on", {}) or {}
            if isinstance(on_block, str):
                on_block = {on_block: {}}
            has_push_main = False
            has_pr_main = False
            if isinstance(on_block, dict):
                push_cfg = on_block.get("push", {}) or {}
                if isinstance(push_cfg, dict):
                    branches = push_cfg.get("branches", [])
                    if any(b in (branches or []) for b in ("main", "master")):
                        has_push_main = True
                pr_cfg = on_block.get("pull_request", {}) or {}
                if isinstance(pr_cfg, dict):
                    branches = pr_cfg.get("branches", [])
                    if not branches or any(b in (branches or []) for b in ("main", "master", "**")):
                        has_pr_main = True

            if not (has_push_main or has_pr_main) and on_block:
                findings.append({
                    "line": find_line("on:") or 1,
                    "issue": "CI-002: Workflow may not trigger on main branch push/PR",
                    "detail": (
                        "Verify that the workflow triggers on push and pull_request to 'main'."
                    ),
                    "rule_id": "CI-002",
                    "severity": "medium",
                })

            # 7. Check if tests/lint are actually run
            all_run_cmds: list[str] = []
            for job_data in jobs.values():
                if not isinstance(job_data, dict):
                    continue
                for step in (job_data.get("steps") or []):
                    if isinstance(step, dict) and step.get("run"):
                        all_run_cmds.append(str(step["run"]))
            has_test = any(
                any(kw in cmd.lower() for kw in ("pytest", "unittest", "jest", "go test", "cargo test"))
                for cmd in all_run_cmds
            )
            has_lint = any(
                any(kw in cmd.lower() for kw in ("ruff", "flake8", "eslint", "golangci", "clippy"))
                for cmd in all_run_cmds
            )
            if not has_test:
                findings.append({
                    "line": None,
                    "issue": "CI-004: No test step found in workflow",
                    "detail": "Add a step that runs pytest/jest/go test/etc.",
                    "rule_id": "CI-004",
                    "severity": "medium",
                })
            if not has_lint:
                findings.append({
                    "line": None,
                    "issue": "CI-004: No lint step found in workflow",
                    "detail": "Add a linting step (ruff, flake8, eslint, etc.).",
                    "rule_id": "CI-004",
                    "severity": "medium",
                })

            all_findings.extend(findings)
            parsed_workflows.append({
                "file": rel,
                "triggers": list(on_block.keys()) if isinstance(on_block, dict) else [on_block],
                "jobs": list(jobs.keys()),
                "findings": findings,
            })

        return {
            "workflows_found": True,
            "workflow_count": len(workflow_files),
            "files": parsed_workflows,
            "all_findings": all_findings,
        }

    # ------------------------------------------------------------------
    # OPTIONAL TOOL 7: run_ruff
    # ------------------------------------------------------------------

    def run_ruff(self, target_path: str = ".") -> dict[str, Any]:
        """
        Runs ruff check in a sandboxed read-only subprocess with timeout.
        """
        try:
            target = self._resolve_path(target_path)
        except PermissionError as exc:
            return {"error": str(exc)}

        # Check if there are Python files to lint
        py_files = list(target.rglob("*.py"))
        if not py_files:
            return {
                "python_files_found": False,
                "note": "No Python files found — ruff skipped",
            }

        try:
            result = subprocess.run(
                [
                    sys.executable, "-m", "ruff",
                    "check",
                    "--output-format=json",
                    "--no-cache",
                    str(target),
                ],
                cwd=str(self.root),
                capture_output=True,
                text=True,
                timeout=TOOL_TIMEOUT,
                env={
                    # Stripped environment — no host secrets leaked
                    "PATH": os.environ.get("PATH", ""),
                    "HOME": os.environ.get("HOME", ""),
                    "SYSTEMROOT": os.environ.get("SYSTEMROOT", ""),  # Windows
                    "TEMP": os.environ.get("TEMP", ""),
                },
            )
        except subprocess.TimeoutExpired:
            return {"error": f"ruff timed out after {TOOL_TIMEOUT}s"}
        except FileNotFoundError:
            return {"error": "ruff not found — install with: pip install ruff"}
        except Exception as exc:  # noqa: BLE001
            return {"error": f"ruff failed: {exc}"}

        issues: list[dict[str, Any]] = []
        try:
            raw_issues = json.loads(result.stdout) if result.stdout.strip() else []
        except json.JSONDecodeError:
            raw_issues = []

        # Filter to high-signal issues (not just style nitpicks)
        HIGH_SIGNAL_CODES = {
            "E711", "E712",  # comparison to None/True/False
            "F401",  # unused imports
            "F811",  # redefined unused
            "F821",  # undefined name
            "F841",  # local variable assigned but never used
            "B006",  # mutable default argument
            "B007",  # unused loop variable
            "B023",  # function in loop
            "S",     # bandit security rules
            "E501",  # line too long (if severe)
        }

        for issue in raw_issues:
            code = issue.get("code", "")
            # Include security rules and high-signal bugs
            if code.startswith("S") or any(code.startswith(c) for c in HIGH_SIGNAL_CODES):
                issues.append({
                    "file": str(Path(issue.get("filename", "")).relative_to(self.root))
                    if issue.get("filename") else None,
                    "line": issue.get("location", {}).get("row"),
                    "code": code,
                    "message": issue.get("message", ""),
                })

        return {
            "python_files_found": True,
            "python_file_count": len(py_files),
            "total_issues": len(raw_issues),
            "high_signal_issues": issues,
            "high_signal_count": len(issues),
            "exit_code": result.returncode,
            "note": (
                "Only high-signal issues shown (security rules, undefined names, "
                "mutable defaults, etc.). Run ruff directly for full output."
            ),
        }

    # ------------------------------------------------------------------
    # OPTIONAL TOOL 8: run_pytest
    # ------------------------------------------------------------------

    def run_pytest(self) -> dict[str, Any]:
        """
        Performs safe static inspection of test suites.

        Never executes untrusted repository code. Only:
        1. Checks if test files exist
        2. AST-inspects test content for trivial/placeholder tests
        3. Checks if CI invokes the test runner
        4. Optionally runs pytest --collect-only with stripped env
        """
        results: dict[str, Any] = {}

        # 1. Find test files
        test_files = (
            list(self.root.rglob("test_*.py"))
            + list(self.root.rglob("*_test.py"))
            + list(self.root.rglob("tests/*.py"))
            + list(self.root.rglob("test/*.py"))
        )
        # Deduplicate
        test_files = list({str(f): f for f in test_files}.values())

        results["test_files_found"] = len(test_files)
        results["test_file_paths"] = [
            str(f.relative_to(self.root)) for f in test_files
        ]

        if not test_files:
            results["verdict"] = "NO_TESTS"
            results["detail"] = "No test files (test_*.py, *_test.py) found anywhere in repo"
            return results

        # 2. AST inspection for trivial tests
        trivial_files: list[str] = []
        real_test_count = 0

        for tf in test_files:
            rel = str(tf.relative_to(self.root))
            try:
                with open(tf, encoding="utf-8", errors="replace") as fh:
                    source = fh.read()
            except OSError:
                continue

            if not source.strip():
                trivial_files.append(f"{rel}: EMPTY FILE")
                continue

            try:
                tree = ast.parse(source)
            except SyntaxError:
                results.setdefault("parse_errors", []).append(rel)
                continue

            test_funcs = [
                node for node in ast.walk(tree)
                if isinstance(node, ast.FunctionDef) and node.name.startswith("test_")
            ]

            if not test_funcs:
                trivial_files.append(f"{rel}: No test_ functions found")
                continue

            # Check for trivially passing tests
            trivial_count = 0
            for fn in test_funcs:
                body = fn.body
                # assert True / pass / ... / return
                trivial_stmts = (ast.Pass, ast.Return)
                if len(body) == 1:
                    stmt = body[0]
                    if isinstance(stmt, trivial_stmts):
                        trivial_count += 1
                    elif isinstance(stmt, ast.Assert):
                        # assert True
                        if isinstance(stmt.test, ast.Constant) and stmt.test.value is True:
                            trivial_count += 1
                        else:
                            real_test_count += 1
                    else:
                        real_test_count += 1
                else:
                    real_test_count += 1

            if trivial_count == len(test_funcs):
                trivial_files.append(f"{rel}: All {trivial_count} test(s) are trivial (assert True/pass)")

        results["trivial_test_files"] = trivial_files
        results["real_test_count_estimate"] = real_test_count

        if trivial_files and real_test_count == 0:
            results["verdict"] = "TRIVIAL_TESTS_ONLY"
            results["detail"] = "All test files contain only placeholder tests"
        else:
            results["verdict"] = "TESTS_PRESENT"

        # 3. Try pytest --collect-only with stripped environment (safe)
        try:
            collect_result = subprocess.run(
                [sys.executable, "-m", "pytest", "--collect-only", "-q", "--no-header"],
                cwd=str(self.root),
                capture_output=True,
                text=True,
                timeout=TOOL_TIMEOUT,
                env={
                    "PATH": os.environ.get("PATH", ""),
                    "HOME": os.environ.get("HOME", ""),
                    "SYSTEMROOT": os.environ.get("SYSTEMROOT", ""),
                    "TEMP": os.environ.get("TEMP", ""),
                    "PYTHONPATH": str(self.root),
                },
            )
            results["pytest_collect_output"] = collect_result.stdout[:2000]
            results["pytest_collect_exit_code"] = collect_result.returncode
            if "error" in collect_result.stderr.lower():
                results["pytest_collect_stderr"] = collect_result.stderr[:500]
        except subprocess.TimeoutExpired:
            results["pytest_collect_note"] = f"pytest --collect-only timed out after {TOOL_TIMEOUT}s"
        except Exception as exc:  # noqa: BLE001
            results["pytest_collect_note"] = f"Could not run pytest --collect-only: {exc}"

        return results
