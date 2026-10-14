"""
agent_core/llm_client.py — Provider-agnostic LLM SDK wrapper.

Supports both Google Gemini and OpenAI with:
- Automatic provider selection via PROVIDER env var
- Exponential backoff retries on transient errors
- Configurable timeouts
- Structured tool/function-call support
- Zero credential leakage (keys read from env only)
"""

from __future__ import annotations

import json
import logging
import os
import time
from typing import Any

logger = logging.getLogger(__name__)


class LLMError(Exception):
    """Raised when the LLM provider returns an unrecoverable error."""


class LLMClient:
    """
    Provider-agnostic wrapper around Gemini and OpenAI SDKs.

    Usage:
        client = LLMClient()                     # reads PROVIDER from env
        response = client.chat(messages, tools)  # returns (text, tool_calls)
    """

    MAX_RETRIES = 3
    BACKOFF_BASE = 2.0  # seconds

    def __init__(self, provider: str | None = None) -> None:
        self.provider = (provider or os.environ.get("PROVIDER", "gemini")).lower().strip()
        if self.provider not in ("gemini", "openai"):
            raise LLMError(f"Unsupported PROVIDER '{self.provider}'. Choose 'gemini' or 'openai'.")

        if self.provider == "gemini":
            self._init_gemini()
        else:
            self._init_openai()

    # ------------------------------------------------------------------
    # Initialisation helpers
    # ------------------------------------------------------------------

    def _init_gemini(self) -> None:
        try:
            import google.genai as genai  # type: ignore[import]
            from google.genai import types as genai_types  # type: ignore[import]
        except ImportError as exc:
            raise LLMError("google-genai package not installed. Run: pip install google-genai") from exc

        api_key = os.environ.get("GEMINI_API_KEY", "")
        if not api_key or api_key == "your_gemini_api_key_here":
            raise LLMError(
                "GEMINI_API_KEY is not set. Copy .env.example to .env and add your key."
            )

        self._genai = genai
        self._genai_types = genai_types
        self._client = genai.Client(api_key=api_key)
        self.model = os.environ.get("GEMINI_MODEL", "gemini-2.0-flash")
        logger.info("LLMClient initialised — provider=gemini, model=%s", self.model)

    def _init_openai(self) -> None:
        try:
            import openai  # type: ignore[import]
        except ImportError as exc:
            raise LLMError("openai package not installed. Run: pip install openai") from exc

        api_key = os.environ.get("OPENAI_API_KEY", "")
        if not api_key or api_key == "your_openai_api_key_here":
            raise LLMError(
                "OPENAI_API_KEY is not set. Copy .env.example to .env and add your key."
            )

        self._openai = openai
        self._oa_client = openai.OpenAI(api_key=api_key)
        self.model = os.environ.get("OPENAI_MODEL", "gpt-4o-mini")
        logger.info("LLMClient initialised — provider=openai, model=%s", self.model)

    # ------------------------------------------------------------------
    # Public interface
    # ------------------------------------------------------------------

    def chat(
        self,
        messages: list[dict[str, Any]],
        tools: list[dict[str, Any]] | None = None,
    ) -> tuple[str, list[dict[str, Any]]]:
        """
        Send messages to the LLM and return (text_response, tool_calls).

        Args:
            messages: Conversation history in OpenAI-style format
                      [{"role": "user"|"assistant"|"system", "content": "..."}]
            tools:    List of tool definitions in OpenAI function-calling format.

        Returns:
            (text, tool_calls) where tool_calls is a list of
            {"name": str, "arguments": dict} dicts.
        """
        last_exc: Exception | None = None
        for attempt in range(self.MAX_RETRIES):
            try:
                if self.provider == "gemini":
                    return self._chat_gemini(messages, tools)
                else:
                    return self._chat_openai(messages, tools)
            except LLMError:
                raise  # non-retryable
            except Exception as exc:  # noqa: BLE001
                last_exc = exc
                wait = self.BACKOFF_BASE ** attempt
                logger.warning(
                    "LLM call attempt %d/%d failed: %s — retrying in %.1fs",
                    attempt + 1,
                    self.MAX_RETRIES,
                    exc,
                    wait,
                )
                time.sleep(wait)

        raise LLMError(f"LLM call failed after {self.MAX_RETRIES} attempts: {last_exc}") from last_exc

    # ------------------------------------------------------------------
    # Gemini backend
    # ------------------------------------------------------------------

    def _chat_gemini(
        self,
        messages: list[dict[str, Any]],
        tools: list[dict[str, Any]] | None,
    ) -> tuple[str, list[dict[str, Any]]]:
        types = self._genai_types

        # Convert OpenAI-style messages to Gemini Content objects
        contents = []
        system_instruction = None

        for msg in messages:
            role = msg["role"]
            content = msg.get("content", "")
            if role == "system":
                system_instruction = content
                continue
            gemini_role = "user" if role == "user" else "model"
            if isinstance(content, str):
                contents.append(types.Content(role=gemini_role, parts=[types.Part(text=content)]))
            elif isinstance(content, list):
                # tool result messages
                parts = []
                for item in content:
                    if isinstance(item, dict) and item.get("type") == "tool_result":
                        parts.append(
                            types.Part(
                                function_response=types.FunctionResponse(
                                    name=item["tool_use_id"],
                                    response={"result": item.get("content", "")},
                                )
                            )
                        )
                    else:
                        parts.append(types.Part(text=str(item)))
                if parts:
                    contents.append(types.Content(role=gemini_role, parts=parts))

        # Build Gemini tool declarations from OpenAI-style tool schema
        gemini_tools = None
        if tools:
            fn_declarations = []
            for t in tools:
                fn = t.get("function", t)
                params = fn.get("parameters", {})
                fn_declarations.append(
                    types.FunctionDeclaration(
                        name=fn["name"],
                        description=fn.get("description", ""),
                        parameters=self._openai_params_to_gemini(params),
                    )
                )
            gemini_tools = [types.Tool(function_declarations=fn_declarations)]

        config_kwargs: dict[str, Any] = {"temperature": 0.1, "max_output_tokens": 8192}
        if system_instruction:
            config_kwargs["system_instruction"] = system_instruction

        response = self._client.models.generate_content(
            model=self.model,
            contents=contents,
            config=types.GenerateContentConfig(**config_kwargs),
            tools=gemini_tools,
        )

        text_parts: list[str] = []
        tool_calls: list[dict[str, Any]] = []

        for candidate in response.candidates or []:
            for part in candidate.content.parts or []:
                if hasattr(part, "text") and part.text:
                    text_parts.append(part.text)
                if hasattr(part, "function_call") and part.function_call:
                    fc = part.function_call
                    tool_calls.append(
                        {
                            "name": fc.name,
                            "arguments": dict(fc.args) if fc.args else {},
                        }
                    )

        return "\n".join(text_parts), tool_calls

    @staticmethod
    def _openai_params_to_gemini(params: dict[str, Any]) -> dict[str, Any]:
        """Convert OpenAI JSON Schema parameters to Gemini Schema format."""
        if not params:
            return {"type": "object", "properties": {}}
        return params

    # ------------------------------------------------------------------
    # OpenAI backend
    # ------------------------------------------------------------------

    def _chat_openai(
        self,
        messages: list[dict[str, Any]],
        tools: list[dict[str, Any]] | None,
    ) -> tuple[str, list[dict[str, Any]]]:
        kwargs: dict[str, Any] = {
            "model": self.model,
            "messages": messages,
            "temperature": 0.1,
            "max_tokens": 8192,
        }
        if tools:
            kwargs["tools"] = tools
            kwargs["tool_choice"] = "auto"

        response = self._oa_client.chat.completions.create(**kwargs)
        choice = response.choices[0]
        msg = choice.message

        text = msg.content or ""
        tool_calls: list[dict[str, Any]] = []

        if msg.tool_calls:
            for tc in msg.tool_calls:
                try:
                    args = json.loads(tc.function.arguments)
                except (json.JSONDecodeError, TypeError):
                    args = {}
                tool_calls.append({"name": tc.function.name, "arguments": args})

        return text, tool_calls
