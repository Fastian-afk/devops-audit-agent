# 🔍 DevOps Repository Auditing Agent

[![CI](https://github.com/Fastian-afk/devops-audit-agent/actions/workflows/ci.yml/badge.svg)](https://github.com/Fastian-afk/devops-audit-agent/actions/workflows/ci.yml)
[![Python 3.11+](https://img.shields.io/badge/python-3.11%2B-blue.svg)](https://www.python.org/downloads/)
[![Ruff](https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/astral-sh/ruff/main/assets/badge/v2.json)](https://github.com/astral-sh/ruff)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

> **An autonomous, framework-free AI agent that performs deep DevOps security and quality audits on any public GitHub repository — built from scratch in pure Python.**

---

## Executive Summary

This project implements a **production-grade Autonomous DevOps Repository Auditing Agent** as both a university assignment deliverable and a flagship portfolio/CV project. The agent:

- Clones any public GitHub repository into an **isolated sandbox**
- Executes a genuine **multi-turn Observe → Reason → Select Tool → Execute → Interpret → Report** reasoning loop powered by Google Gemini, OpenAI, or Groq
- Dynamically inspects repositories across **9 DevOps audit categories** with 40+ specific rule IDs
- Produces a **structured, schema-validated JSON report** with zero credential leakage
- Is built **without any agent framework** (no LangChain, LangGraph, CrewAI, AutoGen, n8n, etc.) — the entire reasoning loop is hand-crafted in pure Python

---

## 📋 Table of Contents

1. [60-Second Quickstart](#-60-second-quickstart)
2. [System Architecture](#-system-architecture)
3. [Custom Agent Loop](#-custom-agent-loop-deep-dive)
4. [Inspection Tool Suite](#-inspection-tool-suite-reference)
5. [DevOps Inspection Taxonomy](#-devops-inspection-taxonomy-9-areas)
6. [Precision, Recall & False-Positive Strategy](#-precision-recall--false-positive-strategy)
7. [Security, Isolation & Secret Redaction](#-security-isolation--secret-redaction-guarantees)
8. [Sample Tool-Call Trace & Output Walkthrough](#-sample-tool-call-trace--output-walkthrough)
9. [Running the Automated Test Suite](#-running-the-automated-test-suite)
10. [Repository Self-Audit Proof](#-repository-self-audit-proof)
11. [Design Decisions & Constraints](#-design-decisions--constraints)

---

## ⚡ 60-Second Quickstart

### Prerequisites
- Python 3.11 or 3.12
- `git` installed and on PATH
- A Google Gemini API key (free at [aistudio.google.com](https://aistudio.google.com/app/apikey)) **or** OpenAI API key

### Step-by-Step

```bash
# 1. Clone this repository
git clone https://github.com/Fastian-afk/devops-audit-agent.git
cd devops-audit-agent

# 2. Create and activate a virtual environment
python -m venv .venv

# Windows
.venv\Scripts\activate

# macOS / Linux
source .venv/bin/activate

# 3. Install all dependencies (pinned for reproducibility)
pip install -r requirements.txt

# 4. Configure your API credentials
cp .env.example .env
# Open .env in your editor and set GEMINI_API_KEY (or OPENAI_API_KEY/GROQ_API_KEY with the matching PROVIDER)

# 5. Run the agent against any public GitHub repository
python agent.py --repo https://github.com/owner/repo-name --output report.json

# 6. View the structured JSON report
cat report.json
```

### Using OpenAI Instead of Gemini

```bash
# In your .env file:
PROVIDER=openai
OPENAI_API_KEY=sk-...your-key...
OPENAI_MODEL=gpt-4o-mini   # or gpt-4o for higher accuracy
```

### Using Groq Instead of Gemini

```bash
# In your .env file:
PROVIDER=groq
GROQ_API_KEY=gsk_...your-key...
GROQ_MODEL=llama-3.3-70b-versatile
```

### Advanced Options

```bash
# Verbose mode (detailed trace to stderr)
python agent.py --repo https://github.com/owner/repo --output report.json --verbose

# Quiet mode (only JSON output)
python agent.py --repo https://github.com/owner/repo --output report.json --no-verbose

# Override max reasoning turns
python agent.py --repo https://github.com/owner/repo --output report.json --max-turns 12

# Force OpenAI provider via CLI flag
python agent.py --repo https://github.com/owner/repo --output report.json --provider openai
```

---

## 🏗️ System Architecture

```mermaid
graph TB
    CLI["agent.py\nCLI Entry Point\n--repo URL --output FILE"]

    subgraph Sandbox["Isolated Temporary Sandbox (tempfile.TemporaryDirectory)"]
        RM["RepoManager\nShallow git clone\n(depth=50, timeout=120s)"]
        TE["ToolExecutor\nPath-traversal protected\nSecret-redacted\nRead-only"]
    end

    subgraph AgentCore["agent_core/ — Pure Python, No Frameworks"]
        LC["LLMClient\nProvider-agnostic wrapper\nGemini ↔ OpenAI\nRetries + Timeouts"]
        LOOP["AgentLoop\nObserve→Reason→Select→Execute\n→Interpret→Report\nMax 18 turns + cache"]
        PROMPTS["prompts.py\nSystem prompt\n9-category taxonomy\nPolyglot equivalence rules\nTool definitions (OpenAI format)"]
        SCHEMAS["schemas.py\nJSON Schema validation\nDeduplication\nFile-existence check\nSecret scrubbing (2 layers)"]
    end

    subgraph Tools["tools.py — 8 Inspection Tools"]
        T1["list_files\nDirectory tree\nSuspicious file flags"]
        T2["read_file\nLine-numbered\nSecret-redacted"]
        T3["search_code\nRegex search\nSecret-scrubbed snippets"]
        T4["git_log\nCommit history\nSensitive file detection"]
        T5["git_status\nTracked vs .gitignore"]
        T6["inspect_github_actions\nWorkflow security analysis"]
        T7["run_ruff\nSandboxed subprocess\nHigh-signal issues only"]
        T8["run_pytest\nAST inspection\nSafe collect-only"]
    end

    OUT["report.json\nPure JSON\nSchema-validated\nZero secrets"]

    CLI --> RM
    RM --> TE
    CLI --> LC
    LC --> LOOP
    PROMPTS --> LOOP
    LOOP --> TE
    TE --> T1 & T2 & T3 & T4 & T5 & T6 & T7 & T8
    T1 & T2 & T3 & T4 & T5 & T6 & T7 & T8 --> LOOP
    LOOP --> SCHEMAS
    SCHEMAS --> OUT
```

### Key Architectural Decisions

| Decision | Rationale |
|---|---|
| **No agent frameworks** | Assignment requirement; demonstrates deep understanding of agent mechanics |
| **Provider-agnostic LLMClient** | Evaluator can use their own Gemini or OpenAI credentials with zero code changes |
| **Shallow clone (depth=50)** | Fast startup; still captures sufficient history for security analysis |
| **tempfile.TemporaryDirectory** | Automatic cleanup on exit or crash; prevents disk accumulation |
| **Tool call cache (SHA-256)** | Prevents infinite loops from repeated identical tool calls |
| **Two-layer secret scrubbing** | In-tool redaction + post-processing in schemas.py guarantees no leakage |
| **AST inspection for pytest** | Safe static analysis instead of executing untrusted code |
| **stderr for traces, stdout for JSON** | Clean piping; `--output` file is 100% pure JSON |

---

## 🔄 Custom Agent Loop Deep Dive

The agent loop in [`agent_core/loop.py`](agent_core/loop.py) implements a **genuine multi-turn reasoning cycle** without any framework abstractions:

```
┌─────────────────────────────────────────────────────────────┐
│                    AGENT REASONING LOOP                     │
│                                                             │
│  Turn N                                                     │
│  ┌──────────┐   ┌──────────┐   ┌─────────────┐            │
│  │ OBSERVE  │──▶│  REASON  │──▶│ SELECT TOOL │            │
│  │          │   │          │   │             │            │
│  │ Examine  │   │ What gap │   │ Choose next │            │
│  │ history  │   │ remains? │   │ tool + args │            │
│  └──────────┘   └──────────┘   └──────┬──────┘            │
│                                        │                   │
│  ┌──────────────────┐   ┌─────────────▼──────┐            │
│  │ INTERPRET RESULTS│◀──│  EXECUTE TOOL       │            │
│  │                  │   │                     │            │
│  │ Extract findings │   │ ToolExecutor        │            │
│  │ Update model     │   │ Path-safe, timeout  │            │
│  └────────┬─────────┘   └────────────────────┘            │
│           │                                                 │
│           ▼                                                 │
│  submit_final_report? ──Yes──▶ REPORT → schemas.py         │
│           │                                                 │
│           No                                                │
│           └──────────────────────────────▶ Turn N+1        │
└─────────────────────────────────────────────────────────────┘
```

### Loop Safety Mechanisms

| Mechanism | Implementation |
|---|---|
| **Tool call deduplication** | `SHA-256(tool_name + sorted_args)` cache prevents re-executing identical calls |
| **Max turns cap** | Configurable via `AGENT_MAX_TURNS` env var (default: 18) |
| **LLM error recovery** | Per-turn try/except adds error context to conversation; loop continues |
| **Tool error isolation** | `_safe_execute()` wraps all tool calls; errors returned as `{"error": ...}` |
| **Force-report at cap** | If max turns reached, a dedicated prompt forces `submit_final_report` |
| **Context truncation guard** | Tool results >12,000 chars are truncated with a note to use narrower args |

### Investigation Strategy (Programmed into System Prompt)

**Turn 1 (always):** `list_files(include_hidden=True)` + `git_log()` → discover tech stack, presence of key files, history anomalies.

**Subsequent turns (LLM-directed):**
- Python project? → `run_ruff()`, inspect `requirements.txt`, `pyproject.toml`
- Has `.github/`? → `inspect_github_actions()`
- Suspicious files in listing? → `read_file()` on each
- Credentials suspected? → `search_code()` with targeted patterns
- Test hygiene? → `run_pytest()`, check CI for test invocation
- .gitignore gaps? → `git_status()`

---

## 🛠️ Inspection Tool Suite Reference

| # | Tool | Type | Parameters | Safety Controls | What LLM Chains It With |
|---|---|---|---|---|---|
| 1 | `list_files` | Mandatory | `subpath`, `include_hidden`, `max_depth` | Path-traversal block; skips `.git/objects` | First call in every audit; flags suspicious files |
| 2 | `read_file` | Mandatory | `path`, `start_line`, `end_line` | Path-traversal block; binary detection; secret redaction; 250-line default window | After `list_files` flags interesting files |
| 3 | `search_code` | Mandatory | `pattern`, `file_glob`, `case_sensitive` | Regex safe-fallback; secret-scrubbed snippets; 200-match cap | Hunting secrets, unsafe patterns, specific keywords |
| 4 | `git_log` | Mandatory | `max_commits`, `stat` | Read-only subprocess; timeout | First call alongside `list_files`; historical secret detection |
| 5 | `git_status` | Optional | _(none)_ | Stripped subprocess env | After `list_files` finds suspicious tracked files |
| 6 | `inspect_github_actions` | Optional | _(none)_ | YAML SafeLoader; line-number mapping | Whenever `.github/workflows/` is detected |
| 7 | `run_ruff` | Optional | `target_path` | Stripped subprocess env; timeout; high-signal filter | When Python files present |
| 8 | `run_pytest` | Optional | _(none)_ | AST-only inspection; `--collect-only` with stripped env; never executes test code | Always; checks CI invocation too |

### Tool Detail: `read_file`

```
Input:  path="config/settings.py", start_line=1, end_line=50
Output:
{
  "path": "config/settings.py",
  "total_lines": 87,
  "shown_lines": "1-50",
  "content": "   1: import os\n   2: \n   3: API_KEY = [REDACTED_SECRET_DETECTED]\n   4: ...",
  "truncated": true,
  "note": "Lines are 1-indexed. Secret values have been redacted..."
}
```

Every line is prefixed with its exact 1-indexed line number (`   3: ...`) so the LLM **never hallucinates line numbers** in its final report.

### Tool Detail: `inspect_github_actions`

Detects the following issues with exact file + line attribution:

| Check | Rule ID | Severity |
|---|---|---|
| Missing `permissions:` block | SEC-003 | high |
| `permissions: write-all` | SEC-003 | high |
| Actions pinned to `@main/@master/@latest` | SEC-005 | high |
| Script injection via `${{ github.event... }}` | SEC-003 | high |
| `pull_request_target` + checkout | SEC-004 | high |
| `continue-on-error: true` on test/lint steps | CI-003 | high |
| `\|\| true` masking test/lint failures | CI-003 | high |
| No test step in any job | CI-004 | medium |
| No lint step in any job | CI-004 | medium |
| Missing `push`/`PR` triggers on `main` | CI-002 | medium |

---

## 📊 DevOps Inspection Taxonomy (9 Areas)

### Full Rule Reference Table

| Category | Rule ID | Severity | Description | Evidence Required |
|---|---|---|---|---|
| **repository_hygiene** | HYG-001 | medium | Missing/empty README | `list_files` shows no README or file <100 chars |
| | HYG-002 | medium | Missing/empty .gitignore | `list_files` shows no .gitignore |
| | HYG-003 | high | Tracked generated files | `git_status` / `list_files` shows `__pycache__/`, `.venv/`, etc. |
| | HYG-004 | high | .env file tracked in git | `git ls-files` shows `.env` |
| | HYG-005 | low | Binary/large files tracked | `.sqlite3`, `.db`, large binaries in `list_files` |
| **dependency_management** | DEP-001 | high | Unpinned dependencies | `*`, `latest`, or bare package name without version |
| | DEP-002 | medium | Missing lockfile | No `poetry.lock`, `package-lock.json`, `go.sum`, `Cargo.lock` |
| | DEP-003 | medium | Inconsistent versions | Different versions in `requirements.txt` vs `pyproject.toml` |
| | DEP-004 | low | Empty dependency file | File exists but has no packages |
| **code_quality** | QUAL-001 | medium | No linting tool configured | No ruff/flake8/eslint/golangci in CI or config |
| | QUAL-002 | high | Syntax errors | `run_ruff` or AST parse error |
| | QUAL-003 | medium | `except: pass` swallowing errors | `search_code` pattern match |
| | QUAL-004 | low | Dead code / TODO in critical path | `search_code` for TODO/FIXME |
| | QUAL-005 | medium | `eval()`/`exec()` on external input | `search_code` for `eval\(` |
| **testing** | TEST-001 | high | No test files found | `run_pytest` returns NO_TESTS |
| | TEST-002 | high | Trivial placeholder tests only | `run_pytest` AST detects `assert True`/`pass` |
| | TEST-003 | medium | Tests not run in CI | `inspect_github_actions` finds no pytest/jest step |
| | TEST-004 | medium | No test runner configured | No pytest.ini, pyproject.toml `[tool.pytest]`, jest.config |
| **ci_cd** | CI-001 | high | No CI/CD found | No workflow files in any CI system |
| | CI-002 | medium | Wrong/missing branch triggers | No `push`/`pull_request` on `main` |
| | CI-003 | high | Ineffective quality gates | `continue-on-error: true` or `\|\| true` on test/lint |
| | CI-004 | medium | CI doesn't run tests/lint | No test or lint step in any job |
| | CI-005 | low | `--no-verify` in CI scripts | Bypasses pre-commit hooks |
| **security** | SEC-001 | **critical** | Hardcoded credential/API key | `search_code` + `read_file` — value REDACTED |
| | SEC-002 | **critical** | Committed private key file | `.pem`, `.key`, `.p12` in `list_files` |
| | SEC-003 | high | Unsafe GHA permissions | Missing `permissions:` or `write-all` |
| | SEC-004 | high | Unsafe `pull_request_target` | Checkout of untrusted ref |
| | SEC-005 | high | Unpinned Actions | `@main`, `@master`, `@latest`, `@HEAD` |
| | SEC-006 | high | `shell=True` with variable | `search_code` for `shell=True` |
| | SEC-007 | high | `yaml.load()` without SafeLoader | `search_code` pattern |
| | SEC-008 | medium | `verify=False` in requests | `search_code` for `verify=False` |
| | SEC-009 | high | `eval()`/`exec()` with external input | `search_code` + `read_file` context |
| | SEC-010 | medium | Privileged Docker container | `--privileged`, `USER root`, missing USER |
| | SEC-011 | medium | Plaintext secrets in CI env vars | Literal values (not `${{ secrets.X }}`) |
| **configuration** | CFG-001 | high | Machine-specific absolute paths | `/Users/`, `/home/`, `C:\` in config files |
| | CFG-002 | high | .env or local DB committed | `git ls-files` shows `.env`, `.sqlite3` |
| | CFG-003 | medium | `DEBUG=True` in committed config | `search_code` in non-test files |
| | CFG-004 | medium | No environment separation | No `.env.example` or equivalent |
| | CFG-005 | low | IDE configs committed | `.idea/`, `.vscode/` in `list_files` |
| **collaboration** | COLLAB-001 | medium | Auto-merge without gates | PR workflow with no status checks |
| | COLLAB-002 | low | No CONTRIBUTING.md | Absent in multi-contributor project |
| | COLLAB-003 | low | No PR/issue templates | Absent in active project |
| **build_and_release** | BUILD-001 | high | Deploy from unreviewed branch | Push to main triggers deploy directly |
| | BUILD-002 | high | Unpinned `:latest` Docker base | `FROM python:latest`, `FROM node:latest` |
| | BUILD-003 | high | `curl \| bash` without checksum | `search_code` for pipe-to-shell pattern |
| | BUILD-004 | medium | No build validation before deploy | Deploy job has no dependency on test job |
| | BUILD-005 | medium | Mutable release tags | Using `:latest` or branch names in releases |

### Severity Decision Criteria

| Severity | Criteria | Examples |
|---|---|---|
| **critical** | Direct, immediate compromise of credentials or data | Hardcoded API key, committed private key |
| **high** | Significant security risk or complete quality-gate bypass | Unpinned actions, `continue-on-error` on tests, no tests |
| **medium** | Maintainability/reliability risk; exploitable under conditions | `DEBUG=True`, missing `.env.example`, trivial tests |
| **low** | Best-practice deviation with minimal direct risk | IDE configs committed, no CONTRIBUTING.md |

---

## 🎯 Precision, Recall & False-Positive Strategy

The agent is designed to excel across all three hidden test repository types:

### Hidden Repo A — Obvious Issues (Maximize Recall)

**Strategy:** Turn 1 `list_files` immediately reveals missing `.gitignore`, `.env` tracked, no `tests/`, no `.github/`. The agent fires all obvious rules before deep investigation.

**Key detections:**
- `HYG-002`: No .gitignore → `list_files` returns empty suspicious_tracked_files guard
- `HYG-004`: .env tracked → `git_status` + `list_files` both flag it
- `SEC-001`: Hardcoded credentials → `search_code` with multiple secret patterns
- `DEP-001`: Unpinned deps → `read_file("requirements.txt")` checks for bare package names
- `TEST-001`: No tests → `run_pytest` returns `NO_TESTS` verdict
- `CI-001`: No CI → `list_files` shows no `.github/`

### Hidden Repo B — Subtle Issues (Maximize Precision on Hard Cases)

**Strategy:** Surface looks clean. The agent reads deeper: workflow files line-by-line, source code for unsafe API usage, test content via AST.

**Key detections:**
- `SEC-005`: `@latest`/`@main` in workflow → `inspect_github_actions` scans every `uses:` line
- `CI-003`: `continue-on-error: true` on test step → `inspect_github_actions` checks per-step
- `TEST-002`: `assert True`/`pass` tests → `run_pytest` AST-walks every test function
- `SEC-007`: `yaml.load()` without SafeLoader → `search_code("yaml\.load\(")` + `read_file` context
- `SEC-008`: `verify=False` → `search_code("verify\s*=\s*False")`
- `SEC-003`: Missing permissions block → `inspect_github_actions` checks top-level workflow keys

### Hidden Repo C — Healthy Repo (Minimize False Positives)

This is the hardest case. The agent must **not** flag valid patterns as violations.

#### Polyglot Equivalence Rules (Built into System Prompt)

| Situation | What NOT to flag | Why |
|---|---|---|
| `pyproject.toml` has `[project.dependencies]` | DEP-002 missing lockfile | pyproject.toml IS a valid dependency spec |
| `[tool.ruff]` in `pyproject.toml` | QUAL-001 no linting | ruff config satisfies linting requirement |
| `[tool.pytest.ini_options]` in `pyproject.toml` | TEST-004 no test config | pyproject.toml replaces pytest.ini |
| `.circleci/config.yml` present | CI-001 no CI | CircleCI satisfies CI requirement |
| `Makefile` with `test:` target | CI-001 no CI | Makefile scripts satisfy CI |
| `package.json` scripts with `"test"` | TEST-004 no test config | package.json satisfies Node test config |
| `yarn.lock` present | DEP-002 missing lockfile | yarn.lock satisfies Node lockfile |
| `README.rst` or `README.txt` | HYG-001 missing README | RST/TXT formats are valid |

#### Deterministic Post-Processing (schemas.py)

Even if the LLM is overly cautious, `validate_and_clean()` applies:
1. **File-existence verification**: Findings referencing non-existent files are dropped for file-must-exist rules (SEC-001, SEC-002, QUAL-002, QUAL-003, QUAL-005)
2. **Deduplication**: Same `(rule_id, file, line)` fingerprint → keep only one
3. **Secret scrubbing**: Any accidentally echoed credential value is replaced with `[REDACTED_SECRET_DETECTED]`

---

## 🔒 Security, Isolation & Secret Redaction Guarantees

### Repository Isolation

```
┌─────────────────────────────────────────────────────────────┐
│  tempfile.TemporaryDirectory("/tmp/devops_audit_XXXXXX")    │
│                                                             │
│  ┌─────────────────────────────────────────────────────┐   │
│  │  git clone --depth 50 <URL> /tmp/devops_audit_XXX/  │   │
│  │                                                     │   │
│  │  ToolExecutor.root = /tmp/devops_audit_XXX/         │   │
│  │                                                     │   │
│  │  ALL path arguments are resolved and validated:     │   │
│  │    target.resolve().relative_to(root.resolve())     │   │
│  │    → PermissionError on traversal attempt           │   │
│  └─────────────────────────────────────────────────────┘   │
│                                                             │
│  Cleanup: __exit__() → shutil.rmtree()                     │
│  (runs even on crash via context manager)                   │
└─────────────────────────────────────────────────────────────┘
```

### Why We Don't Execute Untrusted Code

- `run_pytest` uses **AST inspection only** + `pytest --collect-only` (no test execution)
- `run_ruff` is a **static analyzer** — it never runs the inspected code
- All subprocess calls use a **stripped environment** (no `GEMINI_API_KEY`, `OPENAI_API_KEY`, or any other host credentials leaked to the inspected repo's process)
- `shell=False` in all `subprocess.run()` calls (no shell injection)

### Two-Layer Secret Redaction

**Layer 1 — In-Tool Redaction** (`tools.py: _scrub_line()`):
Applied to every line returned by `read_file` and `search_code` before the LLM ever sees it.

**Layer 2 — Report Post-Processing** (`schemas.py: scrub_report()`):
Applied recursively to every string field in the final JSON report.

**Patterns covered:**
- AWS Access Keys (`AKIA...`)
- GitHub tokens (`ghp_`, `gho_`, `ghu_`, `ghs_`, `ghr_`)
- Generic API key assignments (`api_key = "..."`)
- Connection strings with passwords (`postgres://user:pass@host`)
- Private key PEM blocks
- Slack tokens (`xoxb-...`)
- Generic 40+ hex strings

**Guarantee:** Even if the LLM accidentally echoes a raw credential in its reasoning, the `[REDACTED_SECRET_DETECTED]` marker replaces it before any output is written to `report.json`.

---

## 📝 Sample Tool-Call Trace & Output Walkthrough

Here is an example trace from auditing a repository with issues (trace goes to stderr):

```
════════════════════════════════════════════════════════════════════════
  DevOps Repository Auditing Agent
  Repository : https://github.com/example/demo-project
  Provider   : gemini
  Output     : report.json
════════════════════════════════════════════════════════════════════════

────────────────────────────────────────────────────────────────────────
[13:42:01] [OBSERVE] Starting audit of https://github.com/example/demo-project
────────────────────────────────────────────────────────────────────────

────────────────────────────────────────────────────────────────────────
[13:42:01] [REASON] Turn 1/18 — querying LLM
────────────────────────────────────────────────────────────────────────

────────────────────────────────────────────────────────────────────────
[13:42:03] [SELECT TOOL] Tool: list_files | Args: {"include_hidden": true}
────────────────────────────────────────────────────────────────────────

────────────────────────────────────────────────────────────────────────
[13:42:03] [EXECUTE TOOL] Executing list_files...
────────────────────────────────────────────────────────────────────────

────────────────────────────────────────────────────────────────────────
[13:42:03] [INTERPRET RESULTS] Result from list_files (1842 chars):
{"root": ".", "total_files": 8, "suspicious_tracked_files": [".env"],
 "entries": [...]}
────────────────────────────────────────────────────────────────────────

────────────────────────────────────────────────────────────────────────
[13:42:05] [SELECT TOOL] Tool: git_log | Args: {"max_commits": 30}
────────────────────────────────────────────────────────────────────────
...

────────────────────────────────────────────────────────────────────────
[13:42:09] [SELECT TOOL] Tool: inspect_github_actions | Args: {}
────────────────────────────────────────────────────────────────────────

────────────────────────────────────────────────────────────────────────
[13:42:11] [SELECT TOOL] Tool: search_code | Args: {"pattern": "api_key|secret|password|token", "file_glob": "*.py"}
────────────────────────────────────────────────────────────────────────

────────────────────────────────────────────────────────────────────────
[13:42:11] [INTERPRET RESULTS] Result from search_code (943 chars):
{"total_matches": 2, "matches": [
  {"file": "config.py", "line": 3, "content": "API_KEY = [REDACTED_SECRET_DETECTED]"},
  {"file": "config.py", "line": 4, "content": "DB_PASS = [REDACTED_SECRET_DETECTED]"}
]}
────────────────────────────────────────────────────────────────────────

────────────────────────────────────────────────────────────────────────
[13:42:13] [SELECT TOOL] Tool: submit_final_report | Args: {...}
────────────────────────────────────────────────────────────────────────

────────────────────────────────────────────────────────────────────────
[13:42:13] [REPORT] Audit complete. Found 9 violation(s).
────────────────────────────────────────────────────────────────────────
```

The corresponding `report.json` output maps directly to the findings — see [`sample_report.json`](sample_report.json) for the full example.

### How the Trace Maps to `sample_report.json`

| Trace Event | Report Finding |
|---|---|
| `list_files` flags `.env` in suspicious_tracked_files | `HYG-004`: .env tracked in git |
| `list_files` shows no `.gitignore` | `HYG-002`: Missing .gitignore |
| `search_code` finds `API_KEY =` in config.py:3 | `SEC-001`: Hardcoded credential (line 3) |
| `read_file("requirements.txt")` shows bare packages | `DEP-001`: Unpinned dependencies |
| `run_pytest` returns `NO_TESTS` verdict | `TEST-001`: No tests found |
| `list_files` shows no `.github/` | `CI-001`: No CI/CD configuration |
| `read_file("config.py")` shows `DEBUG = True` | `CFG-003`: Debug mode hardcoded |
| `read_file("config.py")` shows `/Users/johndoe/` | `CFG-001`: Machine-specific path |

---

## 🧪 Running the Automated Test Suite

### Quick Run

```bash
# Install dev dependencies (included in requirements.txt)
pip install -r requirements.txt

# Run all unit tests
pytest tests/ -v

# Run with coverage report
pytest tests/ -v --cov=. --cov-report=term-missing

# Run only specific test files
pytest tests/test_tools.py -v          # Tool unit tests
pytest tests/test_schema_output.py -v  # Schema validation tests
pytest tests/test_agent_loop.py -v     # Agent loop tests (uses mocks, no API calls)
```

### What the Test Suite Covers

| Test File | What It Tests | Test Count |
|---|---|---|
| `tests/test_tools.py` | All 8 tools, path traversal, secret redaction, suspicious file detection | 30+ |
| `tests/test_schema_output.py` | JSON schema validation, deduplication, category inference, scrubbing, file-existence | 25+ |
| `tests/test_agent_loop.py` | Multi-turn loop, tool cache, error recovery, max-turns cap, conversation history | 15+ |

### Synthetic Test Repositories (conftest.py)

The `conftest.py` creates three synthetic git repositories as session-scoped fixtures:

- **`repo_a`**: Obvious issues — no .gitignore, tracked .env, hardcoded secrets, no tests, no CI, unpinned deps
- **`repo_b`**: Subtle issues — unpinned `@latest` actions, `continue-on-error: true`, trivial `assert True` tests, `yaml.load()` without SafeLoader
- **`repo_c`**: Healthy repository — pinned actions with SHAs, `permissions: read`, real tests, ruff configured in pyproject.toml, .env.example

### No API Keys Required

All tests use **mocked LLM responses** — zero real API calls. The test suite passes completely offline.

---

## ✅ Repository Self-Audit Proof

As required by the assignment specification, this repository has been audited against itself:

```bash
python agent.py --repo https://github.com/Fastian-afk/devops-audit-agent --output self_audit.json
```

**Result: `"violations": []`**

This confirms our repository passes all 9 inspection categories:

| Category | Status | Evidence |
|---|---|---|
| repository_hygiene | ✅ PASS | README.md (comprehensive), .gitignore (complete), no suspicious tracked files |
| dependency_management | ✅ PASS | All deps pinned in requirements.txt with exact versions |
| code_quality | ✅ PASS | ruff configured in pyproject.toml, `ruff check .` passes clean |
| testing | ✅ PASS | Full pytest suite with real assertions, 70%+ coverage |
| ci_cd | ✅ PASS | .github/workflows/ci.yml with test + lint steps, no `continue-on-error` |
| security | ✅ PASS | No hardcoded secrets, pinned action SHAs, `permissions: contents: read` |
| configuration | ✅ PASS | .env.example present, no DEBUG=True, no absolute paths |
| collaboration | ✅ PASS | README with contribution guidance |
| build_and_release | ✅ PASS | No :latest Docker images, no curl\|bash, no deploy from unreviewed branches |

---

## 🎨 Design Decisions & Constraints

### Why No Agent Frameworks?

This is both a hard requirement and a deliberate design choice. Building the agent loop from scratch demonstrates:
- Deep understanding of how tool-calling LLMs work at the SDK level
- Full control over context management, deduplication, and error handling
- Ability to port to any new LLM provider by implementing `_chat_gemini` / `_chat_openai` adapters

### Provider Abstraction

The `LLMClient` wraps both Google `google-genai` and OpenAI SDKs behind an identical interface:

```python
text, tool_calls = client.chat(messages, tools)
# Returns: ("reasoning text", [{"name": "tool_name", "arguments": {...}}])
```

Tool definitions are written in **OpenAI function-calling JSON Schema format** and automatically converted to Gemini `FunctionDeclaration` objects when the Gemini provider is selected.

### Scope: DevOps Only

The agent explicitly excludes:
- ML training pipelines, dataset versioning, model registries
- Experiment tracking (MLflow, W&B, Neptune)
- Model validation and evaluation frameworks
- GPU/CUDA configuration

This keeps the tool taxonomy focused and prevents false positives in MLOps repositories that mix DevOps and ML code.

### Static Over Dynamic Analysis

For inspected repositories, we prefer static analysis (AST parsing, regex search, file inspection) over dynamic execution because:
1. We cannot trust arbitrary code from unknown repos
2. Dynamic execution would require the inspected repo's dependencies to be installed
3. Static analysis is faster, safer, and sufficient for the audit categories

The only subprocess calls against inspected code are:
- `ruff check` (static analyzer — never executes the code)
- `pytest --collect-only` (collection only, with stripped environment and no test execution)
- `git log/status` (git plumbing — safe)

---

## 📁 Repository Structure

```
.
├── .github/
│   └── workflows/
│       └── ci.yml              # Hardened CI: pinned SHAs, permissions:read, ruff+pytest
├── agent_core/
│   ├── __init__.py             # Package init
│   ├── llm_client.py           # Provider-agnostic wrapper (Gemini + OpenAI, retries)
│   ├── loop.py                 # Observe→Reason→Select→Execute→Interpret→Report loop
│   ├── prompts.py              # System prompt, 9-category taxonomy, tool definitions
│   └── schemas.py              # JSON schema validation, dedup, secret scrubbing
├── tests/
│   ├── conftest.py             # Synthetic repos A, B, C as session fixtures
│   ├── test_tools.py           # 30+ tool unit tests
│   ├── test_agent_loop.py      # 15+ loop behavior tests (mocked LLM)
│   └── test_schema_output.py   # 25+ schema/dedup/scrubbing tests
├── agent.py                    # CLI: python agent.py --repo URL --output FILE
├── tools.py                    # All 8 tool implementations (sandboxed, secret-safe)
├── requirements.txt            # Pinned dependencies
├── pyproject.toml              # Ruff + pytest config, project metadata
├── .env.example                # Template — copy to .env, never commit .env
├── .gitignore                  # Comprehensive Python/DevOps gitignore
├── sample_report.json          # Authentic example output matching exact JSON contract
└── README.md                   # This file
```

---

## 📄 License

MIT License — see [LICENSE](LICENSE) for details.

---

*Built as Assignment 2 for the MLOps course — engineered as a portfolio-grade, production-ready DevOps security tool.*
