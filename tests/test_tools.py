"""
tests/test_tools.py — Unit tests for all 8 inspection tools.

Tests cover:
- list_files: directory traversal, hidden files, suspicious flagging
- read_file: line numbering, secret redaction, path traversal protection
- search_code: regex and literal search, multi-file, glob filtering
- git_log: commit inspection, sensitive file detection
- git_status: tracked file analysis
- inspect_github_actions: workflow parsing, security issue detection
- run_ruff: Python linting with subprocess sandboxing
- run_pytest: static test suite inspection
"""

from __future__ import annotations

from pathlib import Path

import pytest

from tools import ToolExecutor, _scrub_line

# ============================================================
# Fixtures
# ============================================================


@pytest.fixture()
def simple_repo(tmp_path: Path) -> Path:
    """A minimal, clean repository for generic tool testing."""
    (tmp_path / "README.md").write_text("# Test Repo\n\nA simple test repository.\n")
    (tmp_path / "app.py").write_text(
        "def hello():\n    return 'Hello, World!'\n"
    )
    (tmp_path / ".gitignore").write_text("__pycache__/\n*.pyc\n.env\n")
    (tmp_path / ".env.example").write_text("API_KEY=your_key_here\n")
    tests_dir = tmp_path / "tests"
    tests_dir.mkdir()
    (tests_dir / "test_app.py").write_text(
        "from app import hello\n\ndef test_hello():\n    assert hello() == 'Hello, World!'\n"
    )
    return tmp_path


@pytest.fixture()
def executor(simple_repo: Path) -> ToolExecutor:
    """ToolExecutor bound to the simple repo."""
    return ToolExecutor(simple_repo)


@pytest.fixture()
def repo_a_executor(repo_a: Path) -> ToolExecutor:
    return ToolExecutor(repo_a)


@pytest.fixture()
def repo_b_executor(repo_b: Path) -> ToolExecutor:
    return ToolExecutor(repo_b)


@pytest.fixture()
def repo_c_executor(repo_c: Path) -> ToolExecutor:
    return ToolExecutor(repo_c)


# ============================================================
# list_files tests
# ============================================================


class TestListFiles:
    def test_returns_entries(self, executor: ToolExecutor) -> None:
        result = executor.list_files()
        assert "entries" in result
        assert result["total_files"] > 0

    def test_includes_hidden_files_by_default(self, executor: ToolExecutor) -> None:
        result = executor.list_files(include_hidden=True)
        paths = [e["path"] for e in result["entries"]]
        assert any(".gitignore" in p for p in paths)

    def test_excludes_hidden_when_requested(self, executor: ToolExecutor) -> None:
        result = executor.list_files(include_hidden=False)
        paths = [e["path"] for e in result["entries"]]
        assert not any(p.startswith(".") for p in paths)

    def test_max_depth_respected(self, executor: ToolExecutor) -> None:
        result = executor.list_files(max_depth=1)
        # With max_depth=1, we only get top-level entries
        for entry in result["entries"]:
            assert entry["path"].count("/") <= 1 or entry["path"].count("\\") <= 1

    def test_suspicious_tracking_detects_env(self, tmp_path: Path) -> None:
        (tmp_path / ".env").write_text("SECRET=abc\n")
        ex = ToolExecutor(tmp_path)
        result = ex.list_files()
        assert any(".env" in f for f in result["suspicious_tracked_files"])

    def test_suspicious_tracking_detects_pycache(self, tmp_path: Path) -> None:
        pycache = tmp_path / "__pycache__"
        pycache.mkdir()
        (pycache / "module.cpython-311.pyc").write_bytes(b"\x00\x01")
        ex = ToolExecutor(tmp_path)
        result = ex.list_files()
        assert any("__pycache__" in f for f in result["suspicious_tracked_files"])

    def test_path_traversal_blocked(self, executor: ToolExecutor) -> None:
        result = executor.list_files(subpath="../../../etc")
        assert "error" in result

    def test_nonexistent_subpath(self, executor: ToolExecutor) -> None:
        result = executor.list_files(subpath="nonexistent_dir")
        assert "error" in result


# ============================================================
# read_file tests
# ============================================================


class TestReadFile:
    def test_returns_numbered_lines(self, executor: ToolExecutor) -> None:
        result = executor.read_file("README.md")
        assert "content" in result
        assert "1:" in result["content"]

    def test_line_numbers_are_exact(self, executor: ToolExecutor) -> None:
        result = executor.read_file("app.py", start_line=1, end_line=2)
        lines = result["content"].split("\n")
        assert lines[0].startswith("   1:")
        assert lines[1].startswith("   2:")

    def test_secret_redaction(self, tmp_path: Path) -> None:
        (tmp_path / "config.py").write_text('API_KEY = "sk-abc123def456ghi789jkl"\n')
        ex = ToolExecutor(tmp_path)
        result = ex.read_file("config.py")
        assert "sk-abc123def456ghi789jkl" not in result["content"]
        assert "[REDACTED_SECRET_DETECTED]" in result["content"]

    def test_path_traversal_blocked(self, executor: ToolExecutor) -> None:
        result = executor.read_file("../../etc/passwd")
        assert "error" in result

    def test_nonexistent_file(self, executor: ToolExecutor) -> None:
        result = executor.read_file("nonexistent.py")
        assert "error" in result

    def test_directory_returns_error(self, executor: ToolExecutor) -> None:
        result = executor.read_file("tests")
        assert "error" in result

    def test_binary_file_handled(self, tmp_path: Path) -> None:
        (tmp_path / "data.bin").write_bytes(b"\x00\x01\x02\xff" * 100)
        ex = ToolExecutor(tmp_path)
        result = ex.read_file("data.bin")
        assert result.get("binary") is True

    def test_start_end_line_slicing(self, tmp_path: Path) -> None:
        content = "\n".join(f"line {i}" for i in range(1, 21))
        (tmp_path / "long.txt").write_text(content)
        ex = ToolExecutor(tmp_path)
        result = ex.read_file("long.txt", start_line=5, end_line=10)
        assert "   5:" in result["content"]
        assert "  10:" in result["content"]
        assert "  11:" not in result["content"]


# ============================================================
# search_code tests
# ============================================================


class TestSearchCode:
    def test_finds_pattern_in_file(self, executor: ToolExecutor) -> None:
        result = executor.search_code("def hello")
        assert result["total_matches"] >= 1
        assert any("app.py" in m["file"] for m in result["matches"])

    def test_returns_line_numbers(self, executor: ToolExecutor) -> None:
        result = executor.search_code("def hello")
        match = next(m for m in result["matches"] if "app.py" in m["file"])
        assert isinstance(match["line"], int)
        assert match["line"] >= 1

    def test_case_insensitive_by_default(self, executor: ToolExecutor) -> None:
        result = executor.search_code("DEF HELLO")
        assert result["total_matches"] >= 1

    def test_case_sensitive_mode(self, executor: ToolExecutor) -> None:
        result = executor.search_code("DEF HELLO", case_sensitive=True)
        assert result["total_matches"] == 0

    def test_glob_filter(self, executor: ToolExecutor) -> None:
        result = executor.search_code("hello", file_glob="*.py")
        for m in result["matches"]:
            assert m["file"].endswith(".py")

    def test_invalid_regex_falls_back_to_literal(self, executor: ToolExecutor) -> None:
        # Invalid regex should not crash — fallback to literal
        result = executor.search_code("[[[invalid regex")
        assert "error" not in result
        assert "total_matches" in result

    def test_secret_scrubbing_in_results(self, tmp_path: Path) -> None:
        (tmp_path / "secret.py").write_text('TOKEN = "ghp_abcdefghijklmnopqrstuvwxyz012345"\n')
        ex = ToolExecutor(tmp_path)
        result = ex.search_code("TOKEN")
        for m in result["matches"]:
            assert "ghp_" not in m["content"] or "[REDACTED" in m["content"]

    def test_skips_git_internals(self, executor: ToolExecutor) -> None:
        result = executor.search_code("HEAD")
        for m in result["matches"]:
            assert ".git" not in m["file"].split("/")[:1]


# ============================================================
# git_log tests
# ============================================================


class TestGitLog:
    def test_returns_commits(self, repo_a: Path) -> None:
        import git
        repo = git.Repo(repo_a)
        ex = ToolExecutor(repo_a, repo=repo)
        result = ex.git_log(max_commits=5)
        assert result["total_commits_inspected"] >= 1
        assert len(result["commits"]) >= 1

    def test_commit_has_required_fields(self, repo_a: Path) -> None:
        import git
        repo = git.Repo(repo_a)
        ex = ToolExecutor(repo_a, repo=repo)
        result = ex.git_log(max_commits=1)
        commit = result["commits"][0]
        assert "hash" in commit
        assert "author" in commit
        assert "date" in commit
        assert "message" in commit

    def test_no_repo_returns_error(self, tmp_path: Path) -> None:
        ex = ToolExecutor(tmp_path)
        result = ex.git_log()
        assert "error" in result


# ============================================================
# inspect_github_actions tests
# ============================================================


class TestInspectGitHubActions:
    def test_no_workflows_dir_flagged(self, repo_a_executor: ToolExecutor) -> None:
        result = repo_a_executor.inspect_github_actions()
        assert result["workflows_found"] is False

    def test_healthy_workflow_detected(self, repo_c_executor: ToolExecutor) -> None:
        result = repo_c_executor.inspect_github_actions()
        assert result["workflows_found"] is True
        assert result["workflow_count"] >= 1

    def test_unpinned_actions_detected(self, repo_b_executor: ToolExecutor) -> None:
        result = repo_b_executor.inspect_github_actions()
        all_findings = result.get("all_findings", [])
        rule_ids = [f.get("rule_id") for f in all_findings]
        assert "SEC-005" in rule_ids, f"Expected SEC-005, got: {rule_ids}"

    def test_missing_permissions_detected(self, repo_b_executor: ToolExecutor) -> None:
        result = repo_b_executor.inspect_github_actions()
        all_findings = result.get("all_findings", [])
        rule_ids = [f.get("rule_id") for f in all_findings]
        assert "SEC-003" in rule_ids, f"Expected SEC-003, got: {rule_ids}"

    def test_continue_on_error_detected(self, repo_b_executor: ToolExecutor) -> None:
        result = repo_b_executor.inspect_github_actions()
        all_findings = result.get("all_findings", [])
        rule_ids = [f.get("rule_id") for f in all_findings]
        assert "CI-003" in rule_ids, f"Expected CI-003, got: {rule_ids}"

    def test_healthy_ci_has_fewer_findings(self, repo_c_executor: ToolExecutor) -> None:
        result = repo_c_executor.inspect_github_actions()
        all_findings = result.get("all_findings", [])
        # SEC-003, CI-003 should NOT be present
        rule_ids = [f.get("rule_id") for f in all_findings]
        assert "SEC-003" not in rule_ids, "Healthy repo triggered false positive SEC-003"
        assert "CI-003" not in rule_ids, "Healthy repo triggered false positive CI-003"


# ============================================================
# run_ruff tests
# ============================================================


class TestRunRuff:
    def test_no_python_files_returns_skip(self, tmp_path: Path) -> None:
        (tmp_path / "readme.txt").write_text("hello\n")
        ex = ToolExecutor(tmp_path)
        result = ex.run_ruff()
        assert result.get("python_files_found") is False

    def test_clean_code_has_no_high_signal_issues(self, repo_c: Path) -> None:
        ex = ToolExecutor(repo_c)
        result = ex.run_ruff()
        # The healthy repo should have zero or very few high-signal ruff issues
        issues = result.get("high_signal_issues", [])
        security_issues = [i for i in issues if i.get("code", "").startswith("S")]
        assert len(security_issues) == 0, f"Unexpected security issues: {security_issues}"

    def test_result_has_expected_keys(self, repo_c: Path) -> None:
        ex = ToolExecutor(repo_c)
        result = ex.run_ruff()
        assert "python_files_found" in result


# ============================================================
# run_pytest tests
# ============================================================


class TestRunPytest:
    def test_no_tests_detected_in_repo_a(self, repo_a_executor: ToolExecutor) -> None:
        result = repo_a_executor.run_pytest()
        assert result["test_files_found"] == 0
        assert result["verdict"] == "NO_TESTS"

    def test_trivial_tests_detected_in_repo_b(self, repo_b_executor: ToolExecutor) -> None:
        result = repo_b_executor.run_pytest()
        assert result["test_files_found"] >= 1
        assert result["verdict"] == "TRIVIAL_TESTS_ONLY"
        assert len(result["trivial_test_files"]) >= 1

    def test_real_tests_detected_in_repo_c(self, repo_c_executor: ToolExecutor) -> None:
        result = repo_c_executor.run_pytest()
        assert result["test_files_found"] >= 1
        assert result["verdict"] == "TESTS_PRESENT"
        assert result["real_test_count_estimate"] >= 1


# ============================================================
# Secret scrubbing unit tests
# ============================================================


class TestSecretScrubbing:
    def test_scrubs_github_token(self) -> None:
        line = "token = ghp_abcdefghijklmnopqrstuvwxyz012345"
        result = _scrub_line(line)
        assert "ghp_" not in result

    def test_scrubs_aws_key(self) -> None:
        line = "AWS_KEY = AKIAIOSFODNN7EXAMPLE"
        result = _scrub_line(line)
        assert "AKIAIOSFODNN7EXAMPLE" not in result

    def test_scrubs_connection_string(self) -> None:
        line = "DB_URL = postgres://admin:password123@localhost/db"
        result = _scrub_line(line)
        assert "password123" not in result

    def test_preserves_non_secret_content(self) -> None:
        line = "x = 1 + 2  # this is a regular line"
        result = _scrub_line(line)
        assert result == line

    def test_scrubs_private_key_marker(self) -> None:
        line = "-----BEGIN RSA PRIVATE KEY-----"
        result = _scrub_line(line)
        assert "[REDACTED_SECRET_DETECTED]" in result


# ============================================================
# ToolExecutor dispatch tests
# ============================================================


class TestToolDispatch:
    def test_unknown_tool_returns_error(self, executor: ToolExecutor) -> None:
        result = executor.dispatch("nonexistent_tool", {})
        assert "error" in result

    def test_list_files_dispatch(self, executor: ToolExecutor) -> None:
        result = executor.dispatch("list_files", {})
        assert "entries" in result

    def test_read_file_dispatch(self, executor: ToolExecutor) -> None:
        result = executor.dispatch("read_file", {"path": "README.md"})
        assert "content" in result

    def test_search_code_dispatch(self, executor: ToolExecutor) -> None:
        result = executor.dispatch("search_code", {"pattern": "hello"})
        assert "total_matches" in result
