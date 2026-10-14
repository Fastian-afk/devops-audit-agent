"""
tests/test_agent_loop.py — Tests for the agent reasoning loop.

Tests cover:
- Multi-turn conversation management
- Tool call deduplication via cache
- Error recovery (LLM errors, tool errors)
- Max-turns cap enforcement
- submit_final_report handling
- Trace output to stderr
"""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock

from agent_core.llm_client import LLMClient
from agent_core.loop import AgentLoop

# ============================================================
# Mock helpers
# ============================================================


def _make_mock_llm(responses: list[tuple[str, list[dict]]]) -> MagicMock:
    """
    Create a mock LLM client that returns predefined responses.

    Args:
        responses: List of (text, tool_calls) tuples to return in sequence.
    """
    mock = MagicMock()
    mock.provider = "mock"
    mock.model = "mock-model"
    mock.chat.side_effect = responses
    return mock


def _make_final_report_call(violations: list[dict] | None = None) -> tuple[str, list[dict]]:
    """Create a mock LLM turn that submits the final report."""
    return (
        "Investigation complete.",
        [
            {
                "name": "submit_final_report",
                "arguments": {
                    "repository": "https://github.com/test/repo",
                    "violations": violations or [],
                },
            }
        ],
    )


def _make_tool_call(tool_name: str, args: dict | None = None) -> tuple[str, list[dict]]:
    """Create a mock LLM turn that calls a tool."""
    return (
        f"Calling {tool_name}...",
        [{"name": tool_name, "arguments": args or {}}],
    )


def test_gemini_schema_normalizes_nullable_union_types() -> None:
    schema = {
        "type": "object",
        "properties": {
            "file": {"type": ["string", "null"]},
            "line": {"type": ["integer", "null"]},
            "violations": {
                "type": "array",
                "items": {"type": ["object", "null"], "properties": {}},
            },
        },
    }

    converted = LLMClient._openai_params_to_gemini(schema)

    assert converted["properties"]["file"] == {"type": "string", "nullable": True}
    assert converted["properties"]["line"] == {"type": "integer", "nullable": True}
    assert converted["properties"]["violations"]["items"] == {
        "type": "object",
        "nullable": True,
        "properties": {},
    }


# ============================================================
# Basic loop tests
# ============================================================


class TestAgentLoopBasic:
    def test_loop_completes_with_final_report(self, tmp_path: Path) -> None:
        """The loop should terminate when submit_final_report is called."""
        mock_llm = _make_mock_llm(
            [
                _make_tool_call("list_files"),
                _make_final_report_call(),
            ]
        )

        mock_tool = MagicMock(return_value={"entries": [], "total_files": 0})

        loop = AgentLoop(
            llm_client=mock_llm,
            tool_executor=lambda name, kwargs: mock_tool(name, kwargs),
            repo_url="https://github.com/test/repo",
            repo_root=tmp_path,
            max_turns=10,
            verbose=False,
        )
        report = loop.run()
        assert report["repository"] == "https://github.com/test/repo"
        assert "violations" in report

    def test_loop_returns_violations(self, tmp_path: Path) -> None:
        """Violations from the final report should appear in output."""
        violation = {
            "rule_id": "SEC-001",
            "category": "security",
            "severity": "critical",
            "file": None,
            "line": None,
            "description": "Hardcoded secret",
            "evidence": "Secret value [REDACTED_SECRET_DETECTED]",
            "recommendation": "Use environment variables",
        }
        mock_llm = _make_mock_llm(
            [
                _make_final_report_call(violations=[violation]),
            ]
        )

        loop = AgentLoop(
            llm_client=mock_llm,
            tool_executor=lambda name, kwargs: {"result": "ok"},
            repo_url="https://github.com/test/repo",
            repo_root=tmp_path,
            max_turns=5,
            verbose=False,
        )
        report = loop.run()
        assert len(report["violations"]) == 1
        assert report["violations"][0]["rule_id"] == "SEC-001"

    def test_empty_violations_on_clean_repo(self, tmp_path: Path) -> None:
        """A clean repo should produce empty violations list."""
        mock_llm = _make_mock_llm(
            [
                _make_final_report_call(violations=[]),
            ]
        )

        loop = AgentLoop(
            llm_client=mock_llm,
            tool_executor=lambda name, kwargs: {"result": "ok"},
            repo_url="https://github.com/test/repo",
            repo_root=tmp_path,
            max_turns=5,
            verbose=False,
        )
        report = loop.run()
        assert report["violations"] == []


# ============================================================
# Tool deduplication tests
# ============================================================


class TestToolDeduplication:
    def test_identical_calls_use_cache(self, tmp_path: Path) -> None:
        """Identical tool calls should hit the cache and not call executor twice."""
        call_count = [0]

        def counting_tool(name: str, kwargs: dict) -> dict:
            call_count[0] += 1
            return {"entries": [], "total_files": 0}

        mock_llm = _make_mock_llm(
            [
                # Call list_files twice with same args
                _make_tool_call("list_files", {}),
                _make_tool_call("list_files", {}),
                _make_final_report_call(),
            ]
        )

        loop = AgentLoop(
            llm_client=mock_llm,
            tool_executor=counting_tool,
            repo_url="https://github.com/test/repo",
            repo_root=tmp_path,
            max_turns=10,
            verbose=False,
        )
        loop.run()
        # Second call should be cached
        assert call_count[0] == 1, f"Expected 1 tool call, got {call_count[0]}"

    def test_different_args_not_cached(self, tmp_path: Path) -> None:
        """Tool calls with different arguments should each execute."""
        call_count = [0]

        def counting_tool(name: str, kwargs: dict) -> dict:
            call_count[0] += 1
            return {"content": "line", "total_lines": 1}

        mock_llm = _make_mock_llm(
            [
                _make_tool_call("read_file", {"path": "README.md"}),
                _make_tool_call("read_file", {"path": "requirements.txt"}),
                _make_final_report_call(),
            ]
        )

        loop = AgentLoop(
            llm_client=mock_llm,
            tool_executor=counting_tool,
            repo_url="https://github.com/test/repo",
            repo_root=tmp_path,
            max_turns=10,
            verbose=False,
        )
        loop.run()
        assert call_count[0] == 2


# ============================================================
# Error recovery tests
# ============================================================


class TestErrorRecovery:
    def test_tool_error_does_not_crash_loop(self, tmp_path: Path) -> None:
        """A tool execution error should not crash the loop."""

        def failing_tool(name: str, kwargs: dict) -> dict:
            raise RuntimeError("Simulated tool failure")

        mock_llm = _make_mock_llm(
            [
                _make_tool_call("list_files"),
                _make_final_report_call(),
            ]
        )

        loop = AgentLoop(
            llm_client=mock_llm,
            tool_executor=failing_tool,
            repo_url="https://github.com/test/repo",
            repo_root=tmp_path,
            max_turns=10,
            verbose=False,
        )
        report = loop.run()  # Should not raise
        assert "violations" in report

    def test_llm_error_recovers(self, tmp_path: Path) -> None:
        """An LLM error on one turn should allow recovery on subsequent turns."""

        call_count = [0]

        def chat_with_error(messages, tools=None):
            call_count[0] += 1
            if call_count[0] == 1:
                raise Exception("Transient network error")
            # Recover on second call
            return _make_final_report_call()

        mock_llm = MagicMock()
        mock_llm.provider = "mock"
        mock_llm.model = "mock-model"
        mock_llm.chat.side_effect = chat_with_error

        loop = AgentLoop(
            llm_client=mock_llm,
            tool_executor=lambda name, kwargs: {"ok": True},
            repo_url="https://github.com/test/repo",
            repo_root=tmp_path,
            max_turns=10,
            verbose=False,
        )
        report = loop.run()
        assert "violations" in report


# ============================================================
# Max turns cap tests
# ============================================================


class TestMaxTurnsCap:
    def test_loop_terminates_at_max_turns(self, tmp_path: Path) -> None:
        """Loop should not run past max_turns even if LLM never submits report."""
        # LLM never calls submit_final_report — just keeps calling tools
        infinite_responses = [_make_tool_call("list_files") for _ in range(100)]
        # Final force-report response
        infinite_responses.append(_make_final_report_call())

        mock_llm = MagicMock()
        mock_llm.provider = "mock"
        mock_llm.model = "mock-model"
        mock_llm.chat.side_effect = infinite_responses

        loop = AgentLoop(
            llm_client=mock_llm,
            tool_executor=lambda name, kwargs: {"entries": []},
            repo_url="https://github.com/test/repo",
            repo_root=tmp_path,
            max_turns=3,
            verbose=False,
        )
        report = loop.run()
        # Should have terminated and returned a report
        assert "violations" in report
        assert mock_llm.chat.call_count <= 5  # max_turns + 1 force call

    def test_custom_max_turns_respected(self, tmp_path: Path) -> None:
        """Custom max_turns should be applied correctly."""
        responses = [_make_tool_call("list_files") for _ in range(20)]
        responses.append(_make_final_report_call())

        mock_llm = MagicMock()
        mock_llm.provider = "mock"
        mock_llm.model = "mock-model"
        mock_llm.chat.side_effect = responses

        loop = AgentLoop(
            llm_client=mock_llm,
            tool_executor=lambda name, kwargs: {"entries": []},
            repo_url="https://github.com/test/repo",
            repo_root=tmp_path,
            max_turns=5,
            verbose=False,
        )
        loop.run()
        assert loop._turn <= 5 + 1  # +1 for the force-report call


# ============================================================
# Conversation history tests
# ============================================================


class TestConversationHistory:
    def test_system_prompt_in_first_message(self, tmp_path: Path) -> None:
        """The system prompt should be the first message in conversation history."""
        from agent_core.prompts import SYSTEM_PROMPT

        mock_llm = _make_mock_llm([_make_final_report_call()])

        loop = AgentLoop(
            llm_client=mock_llm,
            tool_executor=lambda n, k: {},
            repo_url="https://github.com/test/repo",
            repo_root=tmp_path,
            max_turns=5,
            verbose=False,
        )

        # Check initial messages before run
        assert loop._messages[0]["role"] == "system"
        assert SYSTEM_PROMPT in loop._messages[0]["content"]

    def test_repo_url_in_initial_user_message(self, tmp_path: Path) -> None:
        """The repository URL should appear in the initial user message."""
        mock_llm = _make_mock_llm([_make_final_report_call()])
        repo_url = "https://github.com/test/specific-repo"

        loop = AgentLoop(
            llm_client=mock_llm,
            tool_executor=lambda n, k: {},
            repo_url=repo_url,
            repo_root=tmp_path,
            max_turns=5,
            verbose=False,
        )
        assert repo_url in loop._messages[1]["content"]
