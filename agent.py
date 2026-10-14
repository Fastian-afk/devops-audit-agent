"""
agent.py — CLI entry point for the DevOps Repository Auditing Agent.

Usage:
    python agent.py --repo <github_url> --output report.json

Exits with code 0 on success, non-zero on fatal errors.
All diagnostic/trace output goes to stderr.
The --output file contains ONLY pure JSON.
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import sys
from pathlib import Path

# Load .env before any other imports that might need env vars
from dotenv import load_dotenv

load_dotenv()


def _setup_logging(verbose: bool) -> None:
    """Configure structured logging to stderr."""
    level = logging.DEBUG if verbose else logging.WARNING
    handler = logging.StreamHandler(sys.stderr)
    handler.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(name)s: %(message)s"))
    logging.basicConfig(level=level, handlers=[handler])


def _validate_url(url: str) -> bool:
    """Basic validation that the URL looks like a GitHub repository URL."""
    url = url.strip()
    return url.startswith(("https://github.com/", "http://github.com/", "git@github.com:"))


def _fatal(message: str, exit_code: int = 1) -> None:
    """Print a fatal error message to stderr and exit."""
    print(f"\n[FATAL ERROR] {message}", file=sys.stderr)
    print("Exiting with non-zero exit code.", file=sys.stderr)
    sys.exit(exit_code)


def main() -> None:
    """Main CLI entrypoint."""
    parser = argparse.ArgumentParser(
        prog="agent.py",
        description=(
            "Autonomous DevOps Repository Auditing Agent — "
            "inspects a GitHub repository and produces a structured JSON report."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python agent.py --repo https://github.com/owner/repo --output report.json
  python agent.py --repo https://github.com/owner/repo --output report.json --provider openai
  python agent.py --repo https://github.com/owner/repo --output report.json --verbose

Environment variables (see .env.example):
  PROVIDER          gemini (default) or openai
  GEMINI_API_KEY    Required when PROVIDER=gemini
  OPENAI_API_KEY    Required when PROVIDER=openai
  AGENT_MAX_TURNS   Override maximum reasoning turns (default: 18)
        """,
    )
    parser.add_argument(
        "--repo",
        required=True,
        metavar="URL",
        help="Public GitHub repository URL to audit (e.g., https://github.com/owner/repo)",
    )
    parser.add_argument(
        "--output",
        required=True,
        metavar="FILE",
        help="Output file path for the JSON report (e.g., report.json)",
    )
    parser.add_argument(
        "--provider",
        choices=["gemini", "openai"],
        default=None,
        help="LLM provider to use (overrides PROVIDER env var)",
    )
    parser.add_argument(
        "--max-turns",
        type=int,
        default=None,
        metavar="N",
        help="Maximum agent reasoning turns (overrides AGENT_MAX_TURNS env var)",
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        default=None,
        help="Enable verbose trace output to stderr",
    )
    parser.add_argument(
        "--no-verbose",
        action="store_false",
        dest="verbose",
        help="Suppress trace output (quiet mode)",
    )

    args = parser.parse_args()

    # Determine verbosity
    if args.verbose is None:
        verbose = os.environ.get("AGENT_VERBOSE", "true").lower() == "true"
    else:
        verbose = args.verbose

    _setup_logging(verbose)

    # Override provider if specified
    if args.provider:
        os.environ["PROVIDER"] = args.provider

    # Validate URL
    repo_url = args.repo.strip().rstrip("/")
    if not _validate_url(repo_url):
        _fatal(
            f"Invalid repository URL: {repo_url!r}\n"
            "URL must start with 'https://github.com/' or 'git@github.com:'"
        )

    output_path = Path(args.output)

    # Check API credentials early
    provider = os.environ.get("PROVIDER", "gemini").lower()
    if provider == "gemini":
        key = os.environ.get("GEMINI_API_KEY", "")
        if not key or key == "your_gemini_api_key_here":
            _fatal(
                "GEMINI_API_KEY is not configured.\n"
                "1. Copy .env.example to .env\n"
                "2. Add your Gemini API key (https://aistudio.google.com/app/apikey)\n"
                "3. Run again"
            )
    elif provider == "openai":
        key = os.environ.get("OPENAI_API_KEY", "")
        if not key or key == "your_openai_api_key_here":
            _fatal(
                "OPENAI_API_KEY is not configured.\n"
                "1. Copy .env.example to .env\n"
                "2. Add your OpenAI API key (https://platform.openai.com/api-keys)\n"
                "3. Run again"
            )

    print(f"\n{'=' * 72}", file=sys.stderr)
    print("  DevOps Repository Auditing Agent", file=sys.stderr)
    print(f"  Repository : {repo_url}", file=sys.stderr)
    print(f"  Provider   : {provider}", file=sys.stderr)
    print(f"  Output     : {output_path}", file=sys.stderr)
    print(f"{'=' * 72}\n", file=sys.stderr)

    # Import here so startup errors from missing .env are shown cleanly
    from agent_core.llm_client import LLMClient, LLMError
    from agent_core.loop import AgentLoop
    from tools import RepoManager, ToolExecutor

    # Initialise LLM client
    try:
        llm = LLMClient(provider=provider)
    except LLMError as exc:
        _fatal(str(exc))

    # Clone repository
    print("[*] Cloning repository...", file=sys.stderr)
    try:
        repo_mgr = RepoManager(repo_url)
        repo_mgr.__enter__()
    except RuntimeError as exc:
        _fatal(
            f"Repository clone failed: {exc}\n"
            "Ensure the repository URL is correct and publicly accessible."
        )

    try:
        executor = ToolExecutor(repo_mgr.root, repo=repo_mgr.repo)

        def tool_dispatcher(tool_name: str, kwargs: dict) -> dict:
            return executor.dispatch(tool_name, kwargs)

        # Initialise and run agent loop
        max_turns = args.max_turns or int(os.environ.get("AGENT_MAX_TURNS", "18"))
        loop = AgentLoop(
            llm_client=llm,
            tool_executor=tool_dispatcher,
            repo_url=repo_url,
            repo_root=repo_mgr.root,
            max_turns=max_turns,
            verbose=verbose,
        )

        report = loop.run()

    except KeyboardInterrupt:
        print("\n[!] Interrupted by user.", file=sys.stderr)
        repo_mgr.__exit__(None, None, None)
        sys.exit(130)
    except Exception as exc:  # noqa: BLE001
        logging.getLogger(__name__).error("Unexpected error during audit: %s", exc, exc_info=True)
        repo_mgr.__exit__(None, None, None)
        _fatal(f"Unexpected error: {exc}")
    finally:
        import contextlib

        with contextlib.suppress(Exception):
            repo_mgr.__exit__(None, None, None)

    # Write output
    try:
        output_path.parent.mkdir(parents=True, exist_ok=True)
        with open(output_path, "w", encoding="utf-8") as fh:
            json.dump(report, fh, indent=2, ensure_ascii=False)
    except OSError as exc:
        _fatal(f"Could not write output to {output_path}: {exc}")

    violation_count = len(report.get("violations", []))
    print(f"\n{'=' * 72}", file=sys.stderr)
    print("  Audit complete!", file=sys.stderr)
    print(f"  Violations found : {violation_count}", file=sys.stderr)
    print(f"  Report written to: {output_path}", file=sys.stderr)
    print(f"{'=' * 72}\n", file=sys.stderr)

    sys.exit(0)


if __name__ == "__main__":
    main()
