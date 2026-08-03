"""
SOCPilot AI — Short-Term Memory (MemorySaver)
===============================================
Wraps LangGraph's MemorySaver checkpointer to provide session-level
(thread-scoped) memory continuity across graph invocations.

MemorySaver stores state in RAM. It is NOT persistent across process restarts.
For production, replace with SqliteSaver or PostgresSaver.
"""

from __future__ import annotations

from typing import Any, Dict

from langgraph.checkpoint.memory import MemorySaver

# ── Singleton checkpointer ────────────────────────────────────────────────────
# Shared across all graph compilations in this process.
_checkpointer: MemorySaver | None = None


def get_checkpointer() -> MemorySaver:
    """
    Return the singleton MemorySaver instance.

    Creates the instance on first call (lazy initialisation).
    Thread-safe for single-process use.
    """
    global _checkpointer
    if _checkpointer is None:
        _checkpointer = MemorySaver()
    return _checkpointer


def build_config(thread_id: str) -> Dict[str, Any]:
    """
    Build the LangGraph invocation config for a given session thread.

    Args:
        thread_id: A unique identifier for the conversation/investigation session.
                   Pass the same thread_id across multiple invocations to
                   maintain memory continuity.

    Returns:
        A config dict suitable for passing to graph.invoke() or graph.stream().

    Example:
        >>> config = build_config("incident-2024-001")
        >>> result = graph.invoke(initial_state, config=config)
    """
    return {
        "configurable": {
            "thread_id": thread_id,
        }
    }


def reset_thread(thread_id: str) -> None:
    """
    Clear the checkpoint for a given thread (start fresh).

    Useful for testing or when you want to reset a session.

    Args:
        thread_id: The thread whose memory should be cleared.
    """
    checkpointer = get_checkpointer()
    # MemorySaver stores data in .storage dict keyed by thread_id
    if hasattr(checkpointer, "storage") and thread_id in checkpointer.storage:
        del checkpointer.storage[thread_id]
