"""
agent_core package — Modular AI agent architecture.

Exposes the top-level public surface for the agent reasoning loop.
"""

from agent_core.llm_client import LLMClient
from agent_core.loop import AgentLoop

__all__ = ["AgentLoop", "LLMClient"]
__version__ = "1.0.0"
