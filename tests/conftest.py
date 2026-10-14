"""
tests/conftest.py — Pytest fixtures for synthetic test repositories.

Creates three synthetic git repositories (Repo A, B, C) in temporary directories:
  - Repo A: Obvious issues (missing gitignore, hardcoded secret, no tests, no CI)
  - Repo B: Subtle issues (unpinned actions, continue-on-error, trivial tests)
  - Repo C: Mostly healthy repository (tests false-positive detection)
"""

from __future__ import annotations

import subprocess
import textwrap
from pathlib import Path

import pytest


def _git_init(path: Path) -> None:
    """Initialise a git repository with a dummy commit."""
    subprocess.run(["git", "init", "-b", "main", str(path)], check=True, capture_output=True)
    subprocess.run(
        ["git", "config", "user.email", "test@example.com"],
        cwd=str(path),
        check=True,
        capture_output=True,
    )
    subprocess.run(
        ["git", "config", "user.name", "Test User"],
        cwd=str(path),
        check=True,
        capture_output=True,
    )


def _git_commit(path: Path, message: str = "Initial commit") -> None:
    """Stage all files and create a commit."""
    subprocess.run(["git", "add", "-A"], cwd=str(path), check=True, capture_output=True)
    subprocess.run(
        ["git", "commit", "-m", message],
        cwd=str(path),
        check=True,
        capture_output=True,
    )


@pytest.fixture(scope="session")
def repo_a(tmp_path_factory) -> Path:
    """
    Repo A: OBVIOUS issues.
    - No .gitignore
    - Hardcoded API key in source
    - No test files
    - No CI workflow
    - Unpinned dependency (requests without version)
    - Machine-specific absolute path in config
    - .env file tracked
    - Missing README
    """
    root = tmp_path_factory.mktemp("repo_a")
    _git_init(root)

    # Hardcoded secret in source
    (root / "app.py").write_text(
        textwrap.dedent("""\
        import requests

        API_KEY = "sk-abc123def456ghi789jkl012mno345pqr678stu901"
        DATABASE_URL = "postgres://admin:supersecretpassword@localhost/mydb"

        def fetch_data():
            return requests.get("https://api.example.com", headers={"Authorization": API_KEY})
    """)
    )

    # Unpinned dependency
    (root / "requirements.txt").write_text("requests\nflask\nnumpy\n")

    # Machine-specific path in config
    (root / "config.py").write_text(
        textwrap.dedent("""\
        DEBUG = True
        DATA_DIR = "/Users/johndoe/myproject/data"
        LOG_DIR = "C:\\Users\\johndoe\\logs"
    """)
    )

    # .env file with real credentials (tracked!)
    (root / ".env").write_text(
        textwrap.dedent("""\
        SECRET_KEY=my-very-secret-key-12345
        DATABASE_PASSWORD=hunter2
        AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
    """)
    )

    # No README, no .gitignore, no tests/, no .github/

    _git_commit(root, "Initial project setup")
    return root


@pytest.fixture(scope="session")
def repo_b(tmp_path_factory) -> Path:
    """
    Repo B: SUBTLE issues.
    - Unpinned GitHub Actions (@latest)
    - continue-on-error: true on test step
    - Trivial placeholder tests (assert True)
    - yaml.load() without SafeLoader
    - verify=False in requests
    - Missing permissions block in workflow
    """
    root = tmp_path_factory.mktemp("repo_b")
    _git_init(root)

    # Good-looking README
    (root / "README.md").write_text("# My Project\n\nA well-documented project.\n" + "x" * 200)

    # Decent .gitignore
    (root / ".gitignore").write_text("__pycache__/\n*.pyc\n.venv/\n.env\n")

    # Pinned requirements
    (root / "requirements.txt").write_text("requests==2.32.3\nflask==3.1.0\npyyaml==6.0.2\n")

    # Source with subtle issues
    (root / "utils.py").write_text(
        textwrap.dedent("""\
        import yaml
        import requests

        def load_config(path):
            with open(path) as f:
                return yaml.load(f)  # Missing SafeLoader!

        def fetch_remote(url):
            return requests.get(url, verify=False)  # SSL disabled
    """)
    )

    # Placeholder tests
    tests_dir = root / "tests"
    tests_dir.mkdir()
    (tests_dir / "__init__.py").write_text("")
    (tests_dir / "test_utils.py").write_text(
        textwrap.dedent("""\
        def test_load_config():
            assert True  # TODO: implement real test

        def test_fetch_remote():
            pass  # placeholder
    """)
    )

    # CI with subtle issues: unpinned action, continue-on-error on test
    gh_dir = root / ".github" / "workflows"
    gh_dir.mkdir(parents=True)
    (gh_dir / "ci.yml").write_text(
        textwrap.dedent("""\
        name: CI

        on:
          push:
            branches: [main]
          pull_request:
            branches: [main]

        jobs:
          test:
            runs-on: ubuntu-latest
            steps:
              - uses: actions/checkout@latest
              - name: Set up Python
                uses: actions/setup-python@main
                with:
                  python-version: "3.11"
              - name: Install deps
                run: pip install -r requirements.txt
              - name: Run tests
                continue-on-error: true
                run: pytest tests/
    """)
    )

    _git_commit(root, "Add CI and tests")
    return root


@pytest.fixture(scope="session")
def repo_c(tmp_path_factory) -> Path:
    """
    Repo C: HEALTHY repository — designed to test false-positive prevention.
    - Good README
    - Comprehensive .gitignore
    - Pinned requirements.txt AND pyproject.toml (tests P1 equivalence rule)
    - Real tests with meaningful assertions
    - Clean CI with pinned actions, permissions block, test + lint steps
    - .env.example present
    - No hardcoded secrets
    """
    root = tmp_path_factory.mktemp("repo_c")
    _git_init(root)

    # Excellent README
    (root / "README.md").write_text(
        "# Healthy Project\n\nThis project demonstrates best practices.\n"
        + "It has comprehensive documentation, tests, and CI.\n" * 10
    )

    # Good .gitignore
    (root / ".gitignore").write_text(
        textwrap.dedent("""\
        __pycache__/
        *.pyc
        .venv/
        .env
        *.egg-info/
        dist/
        build/
        .pytest_cache/
        .ruff_cache/
    """)
    )

    # Pinned requirements
    (root / "requirements.txt").write_text("requests==2.32.3\nflask==3.1.0\n")

    # pyproject.toml with ruff + pytest config (tests polyglot equivalence)
    (root / "pyproject.toml").write_text(
        textwrap.dedent("""\
        [project]
        name = "healthy-project"
        version = "1.0.0"
        requires-python = ">=3.11"

        [tool.ruff]
        line-length = 100

        [tool.ruff.lint]
        select = ["E", "F", "I"]

        [tool.pytest.ini_options]
        testpaths = ["tests"]
    """)
    )

    # .env.example
    (root / ".env.example").write_text("API_KEY=your_api_key_here\nDEBUG=false\nDATABASE_URL=\n")

    # Clean source code
    (root / "app.py").write_text(
        textwrap.dedent("""\
        import os
        import requests

        API_KEY = os.environ.get("API_KEY", "")

        def fetch_data(url: str) -> dict:
            response = requests.get(url, timeout=30)
            response.raise_for_status()
            return response.json()
    """)
    )

    # Real tests
    tests_dir = root / "tests"
    tests_dir.mkdir()
    (tests_dir / "__init__.py").write_text("")
    (tests_dir / "test_app.py").write_text(
        textwrap.dedent("""\
        import pytest
        from unittest.mock import patch, MagicMock
        import app

        def test_fetch_data_success():
            mock_resp = MagicMock()
            mock_resp.json.return_value = {"status": "ok"}
            with patch("app.requests.get", return_value=mock_resp):
                result = app.fetch_data("https://api.example.com")
            assert result == {"status": "ok"}

        def test_fetch_data_raises_on_error():
            mock_resp = MagicMock()
            mock_resp.raise_for_status.side_effect = Exception("HTTP error")
            with patch("app.requests.get", return_value=mock_resp):
                with pytest.raises(Exception):
                    app.fetch_data("https://api.example.com/bad")
    """)
    )

    # Clean, hardened CI
    gh_dir = root / ".github" / "workflows"
    gh_dir.mkdir(parents=True)
    (gh_dir / "ci.yml").write_text(
        textwrap.dedent("""\
        name: CI

        on:
          push:
            branches: [main]
          pull_request:
            branches: [main]

        permissions:
          contents: read

        jobs:
          lint-and-test:
            runs-on: ubuntu-latest
            steps:
              - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683
              - name: Set up Python
                uses: actions/setup-python@42375524bc47e64dbfcdde4a5ee3c293c4b39523
                with:
                  python-version: "3.11"
              - name: Install dependencies
                run: pip install -r requirements.txt ruff pytest
              - name: Lint with ruff
                run: ruff check .
              - name: Run tests
                run: pytest tests/ -v
    """)
    )

    _git_commit(root, "Initial healthy project")
    return root
