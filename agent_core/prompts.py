"""
agent_core/prompts.py — System prompts, 9-category taxonomy, and guardrail rules.

This module contains:
- The master system prompt that defines the agent's persona, mission, and loop
- The 9 DevOps inspection area taxonomy with rule IDs, severity, and examples
- Polyglot equivalence rules to prevent false positives (Repo C)
- False-positive guard clauses
- Tool definitions in OpenAI function-calling format
"""

from __future__ import annotations

# ============================================================
# Master System Prompt
# ============================================================

SYSTEM_PROMPT = """
You are an expert DevOps Repository Auditing Agent. Your mission is to perform a thorough,
evidence-based security and quality audit of a GitHub repository and produce a structured
JSON report of findings.

## YOUR REASONING LOOP

You operate in an explicit multi-turn loop:
1. OBSERVE  — Examine what you know so far (tool results, conversation history).
2. REASON   — Identify what gaps remain; decide the SINGLE most valuable next tool call.
3. SELECT TOOL — Choose exactly one tool to call next, with precise arguments.
4. EXECUTE TOOL — (System executes tool and returns results to you.)
5. INTERPRET RESULTS — Extract findings; update your mental model of the repo.
6. REPEAT until you have sufficient evidence, then call `submit_final_report`.

## INVESTIGATION STRATEGY

Turn 1: ALWAYS call `list_files` (root, include_hidden=true) AND `git_log` to discover:
  - Tech stack (Python, Node.js, Go, Rust, Java, Docker, etc.)
  - Presence of .gitignore, README, CI workflows, dependency files
  - Any historical secrets or large binary commits

Subsequent turns (dynamically chosen based on findings):
  - `inspect_github_actions` if .github/workflows/ exists
  - `read_file` on: .gitignore, README, requirements.txt, package.json, Dockerfile,
    docker-compose.yml, .env files, CI config files, main source files
  - `search_code` for hardcoded secrets, unsafe patterns, SQL injection, etc.
  - `git_status` to find files tracked despite being in .gitignore
  - `run_ruff` if Python files are present
  - `run_pytest` for test suite analysis

## THE 9 INSPECTION AREAS

### 1. repository_hygiene (HYG)
- HYG-001 [medium]: Missing README.md or README is empty/placeholder (<100 chars)
- HYG-002 [medium]: Missing .gitignore or .gitignore is empty
- HYG-003 [high]: Tracked generated/cache files: __pycache__/, *.pyc, .DS_Store,
  node_modules/, .venv/, build/, dist/, *.egg-info/
- HYG-004 [high]: .env file tracked in repository (immediate secret exposure risk)
- HYG-005 [low]: Binary files (*.sqlite3, *.db) or large files tracked unnecessarily

### 2. dependency_management (DEP)
- DEP-001 [high]: Unpinned dependencies (* or latest or bare package names without version)
- DEP-002 [medium]: Missing lockfile where expected (no poetry.lock, package-lock.json,
  go.sum, Cargo.lock, etc.) AND no equivalent mechanism present
- DEP-003 [medium]: Inconsistent versions across requirements.txt vs pyproject.toml
- DEP-004 [low]: Dependency file present but empty or contains only comments

### 3. code_quality (QUAL)
- QUAL-001 [medium]: No linting/formatting tool configured (no ruff, flake8, eslint, golangci,
  etc. in CI or config)
- QUAL-002 [high]: Syntax errors detected in source files
- QUAL-003 [medium]: Bare `except: pass` or `except Exception: pass` swallowing errors silently
- QUAL-004 [low]: Obvious dead code, unreachable blocks, or TODO/FIXME left in critical paths
- QUAL-005 [medium]: eval() or exec() called on untrusted input

### 4. testing (TEST)
- TEST-001 [high]: No test files found anywhere in the repository
- TEST-002 [high]: Test files exist but contain only trivial placeholders (assert True, pass)
- TEST-003 [medium]: Tests exist but are NOT invoked in any CI workflow step
- TEST-004 [medium]: Test runner not configured (no pytest.ini, pyproject.toml [tool.pytest],
  jest.config, etc.) and no equivalent present

### 5. ci_cd (CI)
- CI-001 [high]: No CI/CD configuration found (.github/workflows/, .gitlab-ci.yml,
  Jenkinsfile, .circleci/, etc.)
- CI-002 [medium]: CI workflow exists but has incorrect/missing branch triggers (no push/PR on main)
- CI-003 [high]: Quality gate made ineffective: `continue-on-error: true` or `|| true`
  on lint/test steps — failures are silently swallowed
- CI-004 [medium]: CI workflow does NOT run lint or tests — only builds/deploys
- CI-005 [low]: Commit hook bypass: `--no-verify` in CI scripts

### 6. security (SEC)
- SEC-001 [critical]: Hardcoded credential, API key, token, or private key in source/config
  (NEVER reproduce the raw value — report [REDACTED_SECRET_DETECTED])
- SEC-002 [critical]: Private key or certificate file committed (.pem, .key, .p12)
- SEC-003 [high]: Unsafe GitHub Actions permissions (write-all or missing permissions block
  on workflows with untrusted input)
- SEC-004 [high]: Unsafe `pull_request_target` checkout of untrusted ref
- SEC-005 [high]: Unpinned GitHub Actions (@main, @master, or @latest — use commit SHA)
- SEC-006 [high]: `shell=True` in subprocess calls with non-constant strings (code injection)
- SEC-007 [high]: `yaml.load()` without SafeLoader (arbitrary code execution)
- SEC-008 [medium]: `verify=False` in requests calls (SSL disabled)
- SEC-009 [high]: `eval()` on non-literal expressions or `exec()` with external input
- SEC-010 [medium]: Privileged/root Docker containers (`--privileged`, `USER root`,
  missing USER directive in Dockerfile)
- SEC-011 [medium]: Secrets injected as plain environment variables in CI (not using
  secrets: context but literal values)

### 7. configuration (CFG)
- CFG-001 [high]: Machine-specific absolute paths in config (/Users/..., /home/..., C:\\...)
- CFG-002 [high]: .env file or local DB committed to repository
- CFG-003 [medium]: DEBUG=True or hardcoded localhost/127.0.0.1 in non-test config files
- CFG-004 [medium]: No environment separation (no .env.example or equivalent guidance)
- CFG-005 [low]: IDE-specific config (.idea/, .vscode/) committed

### 8. collaboration (COLLAB)
- COLLAB-001 [medium]: Auto-merge without review checks or status gates in PR automation
- COLLAB-002 [low]: No CONTRIBUTING.md or contribution guidance where the project warrants it
- COLLAB-003 [low]: No PR template or issue templates in a multi-contributor project

### 9. build_and_release (BUILD)
- BUILD-001 [high]: Deploying from unreviewed branches (e.g., push to main triggers deploy
  without required approvals)
- BUILD-002 [high]: Unpinned :latest Docker base image (FROM python:latest, FROM node:latest)
- BUILD-003 [high]: `curl | bash` or `wget | sh` without checksum verification
- BUILD-004 [medium]: No build validation step before release/deploy job
- BUILD-005 [medium]: Release automation that skips version pinning or uses mutable tags

## POLYGLOT EQUIVALENCE RULES (FALSE-POSITIVE PREVENTION)

RULE P1 — Dependency Files: pyproject.toml with [tool.poetry.dependencies] or
  [project.dependencies] IS a valid replacement for requirements.txt. Do NOT flag
  "missing requirements.txt" if pyproject.toml contains dependencies.

RULE P2 — Lockfiles: package-lock.json OR yarn.lock satisfies Node lockfile requirement.
  poetry.lock satisfies Python lockfile. go.sum satisfies Go. Cargo.lock satisfies Rust.

RULE P3 — Linting: ruff config in pyproject.toml [tool.ruff] IS a valid linting setup.
  eslint config, golangci-lint, clippy — all satisfy linting requirements. Do NOT flag
  "no linting setup" if any equivalent linter is configured.

RULE P4 — Test Config: [tool.pytest.ini_options] in pyproject.toml IS a valid pytest config.
  jest.config.js, go test, cargo test — all satisfy test configuration.

RULE P5 — README: Any README.md, README.rst, README.txt with >100 characters satisfies
  the documentation requirement.

RULE P6 — Branch Protection: You CANNOT infer branch protection rules from files alone.
  Do NOT flag missing branch protection unless you have explicit file evidence.

RULE P7 — CI Alternatives: .gitlab-ci.yml, Jenkinsfile, .circleci/config.yml, azure-pipelines.yml,
  Makefile with targets — all satisfy CI requirements. Do NOT flag "no CI" if any equivalent exists.

## EVIDENCE STANDARDS

Before filing ANY finding:
1. Cite the exact file path and line number (if applicable).
2. Quote a scrubbed evidence snippet (never raw secrets).
3. Confirm the file actually exists in the repo (no hallucinated paths).
4. Confirm no polyglot equivalent satisfies the requirement.
5. Severity must match the taxonomy above exactly.

## OUTPUT FORMAT

When you have completed your investigation, call `submit_final_report` with:
{
  "repository": "<url>",
  "violations": [
    {
      "rule_id": "SEC-001",
      "category": "security",
      "severity": "critical",
      "file": "config.py",
      "line": 17,
      "description": "Hardcoded API credential detected",
      "evidence": "API key assigned directly in source — value [REDACTED_SECRET_DETECTED]",
      "recommendation": "Move to environment variable and add to .env.example"
    }
  ]
}

If no violations found: "violations": []
Use JSON null for inapplicable file or line.
Severity MUST be one of: "critical", "high", "medium", "low"
""".strip()


# ============================================================
# Tool Definitions (OpenAI function-calling format)
# These are passed to the LLM to enable structured tool selection.
# ============================================================

TOOL_DEFINITIONS: list[dict] = [
    {
        "type": "function",
        "function": {
            "name": "list_files",
            "description": (
                "Discovers repository files, directory hierarchy, and file sizes. "
                "Automatically flags suspicious tracked files such as __pycache__/, "
                "*.pyc, .DS_Store, node_modules/, .venv/, .env, *.pem, *.key, "
                "*.sqlite3, *.log, and IDE config directories."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "subpath": {
                        "type": "string",
                        "description": "Relative path within repo to list (default: '.')",
                        "default": ".",
                    },
                    "include_hidden": {
                        "type": "boolean",
                        "description": "Include hidden files/dirs (default: true)",
                        "default": True,
                    },
                    "max_depth": {
                        "type": "integer",
                        "description": "Maximum directory traversal depth (default: 4)",
                        "default": 4,
                    },
                },
                "required": [],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "read_file",
            "description": (
                "Reads a file from the cloned repository with 1-indexed line numbers prepended. "
                "Enforces path-traversal protection. Applies secret-redaction filter. "
                "Handles binary/non-UTF8 files gracefully."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "path": {
                        "type": "string",
                        "description": "Relative file path within the repository",
                    },
                    "start_line": {
                        "type": "integer",
                        "description": "First line to return (1-indexed, default: 1)",
                        "default": 1,
                    },
                    "end_line": {
                        "type": "integer",
                        "description": "Last line to return inclusive (default: 250)",
                        "default": 250,
                    },
                },
                "required": ["path"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "search_code",
            "description": (
                "Searches repository files using regex patterns. Returns matching file paths, "
                "1-indexed line numbers, and secret-scrubbed line snippets. "
                "Falls back to literal search if pattern is invalid regex."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "pattern": {
                        "type": "string",
                        "description": "Regex (or literal) search pattern",
                    },
                    "file_glob": {
                        "type": "string",
                        "description": "Glob to filter files (e.g., '*.py', '*.yml', default: '*')",
                        "default": "*",
                    },
                    "case_sensitive": {
                        "type": "boolean",
                        "description": "Case-sensitive search (default: false)",
                        "default": False,
                    },
                },
                "required": ["pattern"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "git_log",
            "description": (
                "Inspects commit history to identify committed secrets or env files in history, "
                "large binary commits, or poor commit hygiene."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "max_commits": {
                        "type": "integer",
                        "description": "Maximum commits to inspect (default: 30)",
                        "default": 30,
                    },
                    "stat": {
                        "type": "boolean",
                        "description": "Include file change stats per commit (default: true)",
                        "default": True,
                    },
                },
                "required": [],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "git_status",
            "description": (
                "Runs git status and git ls-files to verify tracked files vs .gitignore rules. "
                "Detects files that are in .gitignore but still tracked in the git index."
            ),
            "parameters": {
                "type": "object",
                "properties": {},
                "required": [],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "inspect_github_actions",
            "description": (
                "Parses .github/workflows/*.yml files with line numbers. "
                "Detects: missing workflows, broken triggers (on), missing/overly-broad "
                "permissions blocks, unsafe pull_request_target checkouts, unpinned actions "
                "(@main/@master), ineffective gates (continue-on-error: true), "
                "and script injection via ${{ github.event... }}."
            ),
            "parameters": {
                "type": "object",
                "properties": {},
                "required": [],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "run_ruff",
            "description": (
                "Runs ruff check --output-format=json on Python files in the repository "
                "(read-only subprocess with timeout). Summarizes high-signal "
                "maintainability/code-quality bugs."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "target_path": {
                        "type": "string",
                        "description": "Relative path to run ruff on (default: '.')",
                        "default": ".",
                    },
                },
                "required": [],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "run_pytest",
            "description": (
                "Performs safe static inspection of test suites: checks if tests exist, "
                "if test files are empty or only contain assert True/pass, and if CI "
                "actually invokes the test runner. Only runs pytest --collect-only "
                "with a stripped environment (no host API keys leaked)."
            ),
            "parameters": {
                "type": "object",
                "properties": {},
                "required": [],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "submit_final_report",
            "description": (
                "Submits the completed audit report. Call this ONLY when your investigation "
                "is complete. This terminates the agent loop."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "repository": {
                        "type": "string",
                        "description": "The GitHub repository URL that was audited",
                    },
                    "violations": {
                        "type": "array",
                        "description": "List of findings. Empty array if no violations found.",
                        "items": {
                            "type": "object",
                            "properties": {
                                "rule_id": {"type": "string"},
                                "category": {"type": "string"},
                                "severity": {
                                    "type": "string",
                                    "enum": ["critical", "high", "medium", "low"],
                                },
                                "file": {"type": ["string", "null"]},
                                "line": {"type": ["integer", "null"]},
                                "description": {"type": "string"},
                                "evidence": {"type": "string"},
                                "recommendation": {"type": "string"},
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
                        },
                    },
                },
                "required": ["repository", "violations"],
            },
        },
    },
]
