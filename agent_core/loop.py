"""
agent_core/loop.py — The explicit Observe→Reason→Select→Execute→Interpret→Report loop.

This implements a genuine multi-turn agent reasoning loop entirely in pure Python
without any agent framework (no LangChain, LangGraph, CrewAI, AutoGen, etc.).

Design:
- Each turn logs a structured trace to stderr: [OBSERVE], [REASON], [SELECT TOOL],
  [EXECUTE TOOL], [INTERPRET RESULTS]
- Tool calls are deduplicated via a call cache to prevent infinite loops
- Errors in tool execution are handled gracefully without crashing
- A max_turns cap prevents runaway loops
- The loop ends only when the LLM calls submit_final_report
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import sys
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any

from agent_core.llm_client import LLMClient
from agent_core.prompts import SYSTEM_PROMPT, TOOL_DEFINITIONS
from agent_core.schemas import validate_and_clean

logger = logging.getLogger(__name__)

# Separator for structured trace output
_TRACE_SEP = "─" * 72


def _trace(tag: str, message: str, verbose: bool = True) -> None:
    """Write a structured trace line to stderr."""
    if verbose:
        timestamp = time.strftime("%H:%M:%S")
        print(f"\n{_TRACE_SEP}", file=sys.stderr)
        print(f"[{timestamp}] [{tag}] {message}", file=sys.stderr)
        print(_TRACE_SEP, file=sys.stderr)


class AgentLoop:
    """
    The core agent reasoning loop.

    Implements the Observe→Reason→Select Tool→Execute Tool→Interpret Results→Report cycle.
    """

    DEFAULT_MAX_TURNS = 18

    def __init__(
        self,
        llm_client: LLMClient,
        tool_executor: Callable[[str, dict[str, Any]], Any],
        repo_url: str,
        repo_root: Path | None = None,
        max_turns: int | None = None,
        verbose: bool = True,
    ) -> None:
        """
        Args:
            llm_client:    Configured LLMClient instance.
            tool_executor: Callable(tool_name, kwargs) → result dict.
            repo_url:      The GitHub URL being audited.
            repo_root:     Path to the cloned repo (for schema validation).
            max_turns:     Override the default max turns cap.
            verbose:       Whether to emit structured trace to stderr.
        """
        self.llm = llm_client
        self.execute_tool = tool_executor
        self.repo_url = repo_url
        self.repo_root = repo_root
        self.max_turns = max_turns or int(os.environ.get("AGENT_MAX_TURNS", self.DEFAULT_MAX_TURNS))
        self.verbose = verbose

        # Conversation history in OpenAI-style format
        self._messages: list[dict[str, Any]] = [
            {"role": "system", "content": SYSTEM_PROMPT},
            {
                "role": "user",
                "content": (
                    f"Please perform a thorough DevOps audit of this repository: {repo_url}\n\n"
                    "Start with list_files (include_hidden=true) and git_log to understand the "
                    "tech stack and history. Then investigate systematically across all 9 "
                    "inspection areas. When you have sufficient evidence, call submit_final_report."
                ),
            },
        ]

        # Tool call deduplication cache: hash(tool_name + args) → result
        self._call_cache: dict[str, Any] = {}

        # Final report (set when submit_final_report is called)
        self.final_report: dict[str, Any] | None = None

        # Turn counter
        self._turn = 0

    # ------------------------------------------------------------------
    # Main entry point
    # ------------------------------------------------------------------

    def run(self) -> dict[str, Any]:
        """
        Execute the agent loop until the report is submitted or max_turns reached.

        Returns:
            The validated final report dict.
        """
        _trace("OBSERVE", f"Starting audit of {self.repo_url}", self.verbose)
        _trace(
            "OBSERVE",
            f"Max turns: {self.max_turns} | Provider: {self.llm.provider} | Model: {self.llm.model}",
            self.verbose,
        )

        while self._turn < self.max_turns:
            self._turn += 1
            _trace("REASON", f"Turn {self._turn}/{self.max_turns} — querying LLM", self.verbose)

            # ---- REASON: Ask LLM for next action ----
            try:
                text, tool_calls = self.llm.chat(
                    messages=self._messages,
                    tools=TOOL_DEFINITIONS,
                )
            except Exception as exc:  # noqa: BLE001
                _trace("ERROR", f"LLM call failed on turn {self._turn}: {exc}", self.verbose)
                # Add error to conversation so LLM can recover on next turn
                self._messages.append(
                    {
                        "role": "user",
                        "content": (
                            f"The previous model request failed on turn {self._turn}. "
                            "Continue the investigation from the existing evidence and call a "
                            "tool or submit the final report."
                        ),
                    }
                )
                continue

            # Record assistant response
            if text:
                _trace("INTERPRET RESULTS", f"LLM reasoning:\n{text[:500]}", self.verbose)

            if not tool_calls:
                # LLM produced text but no tool call — prompt it to continue
                self._messages.append({"role": "assistant", "content": text or ""})
                self._messages.append(
                    {
                        "role": "user",
                        "content": (
                            "Continue the investigation. Call another tool or, if your investigation "
                            "is complete, call submit_final_report with your findings."
                        ),
                    }
                )
                continue

            # ---- SELECT TOOL & EXECUTE ----
            # Process all tool calls returned by the LLM in this turn
            self._messages.append({"role": "assistant", "content": text or ""})

            all_results: list[str] = []
            for tc in tool_calls:
                tool_name = tc.get("name", "")
                tool_args = tc.get("arguments", {})

                _trace(
                    "SELECT TOOL",
                    f"Tool: {tool_name} | Args: {json.dumps(tool_args)}",
                    self.verbose,
                )

                # Check for submit_final_report
                if tool_name == "submit_final_report":
                    return self._handle_final_report(tool_args)

                # Deduplication check
                cache_key = self._make_cache_key(tool_name, tool_args)
                if cache_key in self._call_cache:
                    _trace(
                        "EXECUTE TOOL",
                        f"[CACHED] {tool_name} — returning cached result",
                        self.verbose,
                    )
                    result = self._call_cache[cache_key]
                else:
                    # Execute the tool
                    _trace("EXECUTE TOOL", f"Executing {tool_name}...", self.verbose)
                    result = self._safe_execute(tool_name, tool_args)
                    self._call_cache[cache_key] = result

                result_str = json.dumps(result, ensure_ascii=False)
                # Truncate very long results to avoid context overflow
                if len(result_str) > 12_000:
                    result_str = result_str[:12_000] + "\n... [TRUNCATED — call with narrower args]"

                _trace(
                    "INTERPRET RESULTS",
                    f"Result from {tool_name} ({len(result_str)} chars):\n{result_str[:800]}",
                    self.verbose,
                )
                all_results.append(f"Tool: {tool_name}\nResult: {result_str}")

            # Feed all tool results back as a user message
            combined = "\n\n".join(all_results)
            self._messages.append(
                {
                    "role": "user",
                    "content": (
                        f"Tool execution results:\n\n{combined}\n\n"
                        "Continue the investigation or call submit_final_report if complete."
                    ),
                }
            )

        # Max turns reached — force report generation
        _trace(
            "REPORT",
            f"Max turns ({self.max_turns}) reached — requesting final report",
            self.verbose,
        )
        return self._force_final_report()

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _safe_execute(self, tool_name: str, tool_args: dict[str, Any]) -> dict[str, Any]:
        """Execute a tool with error handling. Never raises."""
        try:
            return self.execute_tool(tool_name, tool_args)
        except Exception as exc:  # noqa: BLE001
            logger.warning("Tool %s failed: %s", tool_name, exc)
            return {"error": str(exc), "tool": tool_name}

    def _handle_final_report(self, report_args: dict[str, Any]) -> dict[str, Any]:
        """Process, validate, and return the final report."""
        _trace("REPORT", "Agent submitted final report — validating...", self.verbose)

        # Ensure repository URL is set correctly
        report_args["repository"] = self.repo_url
        report_args.setdefault("violations", [])

        try:
            validated = validate_and_clean(report_args, repo_root=self.repo_root)
        except Exception as exc:  # noqa: BLE001
            logger.error("Report validation failed: %s", exc)
            # Return raw report with basic structure if validation fails
            validated = {
                "repository": self.repo_url,
                "violations": report_args.get("violations", []),
            }

        self.final_report = validated
        _trace(
            "REPORT",
            f"Audit complete. Found {len(validated.get('violations', []))} violation(s).",
            self.verbose,
        )
        return validated

    def _force_final_report(self) -> dict[str, Any]:
        """
        Force the LLM to produce a final report when max_turns is reached.
        Uses a simplified prompt to avoid additional turns.
        """
        # Build a summary of what we know so far from the conversation
        self._messages.append(
            {
                "role": "user",
                "content": (
                    "IMPORTANT: You have reached the maximum number of investigation turns. "
                    "You MUST now call submit_final_report immediately with all findings "
                    "gathered so far. Do not call any other tool. Call submit_final_report now."
                ),
            }
        )

        try:
            _, tool_calls = self.llm.chat(
                messages=self._messages,
                tools=TOOL_DEFINITIONS,
            )
            for tc in tool_calls:
                if tc.get("name") == "submit_final_report":
                    return self._handle_final_report(tc.get("arguments", {}))
        except Exception as exc:  # noqa: BLE001
            logger.error("Failed to force final report: %s", exc)

        # Last resort: return empty report
        return self._handle_final_report({"repository": self.repo_url, "violations": []})

    @staticmethod
    def _make_cache_key(tool_name: str, tool_args: dict[str, Any]) -> str:
        """Create a stable cache key for a tool call."""
        canonical = json.dumps({"tool": tool_name, "args": tool_args}, sort_keys=True)
        return hashlib.sha256(canonical.encode()).hexdigest()
