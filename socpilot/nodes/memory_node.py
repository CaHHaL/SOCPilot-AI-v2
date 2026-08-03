"""
SOCPilot AI — Memory Node
==========================
Retrieves contextual memory for the current investigation from two sources:

1. SHORT-TERM MEMORY (MemorySaver):
   The LangGraph checkpointer stores the conversation/investigation history
   for the current thread. We summarise any prior state from this session.

2. LONG-TERM MEMORY (ChromaDB):
   Semantically similar historical incidents are retrieved from the
   ChromaDB incidents collection using the alert text as a query.

This dual-memory approach enables the system to:
- Reference context from earlier in the same investigation session
- Correlate with historical incidents from different sessions
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List

from socpilot.memory.long_term import get_long_term_memory
from socpilot.models.graph_state import SOCAgentState
from socpilot.models.ioc_models import ExtractedIoCs

logger = logging.getLogger(__name__)


async def memory_node(state: SOCAgentState) -> Dict[str, Any]:
    """
    LangGraph node: Retrieve relevant memories for the current alert.

    Queries both short-term session context and long-term historical incidents.
    Results are stored as formatted text for inclusion in the reasoning prompt.

    Args:
        state: Current SOCAgentState with 'raw_alert' and 'iocs' populated.

    Returns:
        State update with 'prior_incidents', 'memory_context', 'processing_notes'.
    """
    raw_alert = state.get("raw_alert", "")
    iocs: ExtractedIoCs = state.get("iocs") or ExtractedIoCs()
    notes: List[str] = []

    # ── Build query from alert context ─────────────────────────────────────────
    # Enrich the query with extracted IoC context for better semantic matching
    ioc_context = _build_ioc_query_string(iocs)
    query = f"{raw_alert[:500]} {ioc_context}".strip()

    # ── Long-term memory: ChromaDB incident retrieval ──────────────────────────
    prior_incidents: List[Dict[str, Any]] = []

    try:
        ltm = get_long_term_memory()
        raw_incidents = ltm.query_incidents(query_text=query, n_results=5)

        for incident in raw_incidents:
            meta = incident.get("metadata", {})
            similarity = incident.get("similarity", 0.0)

            # Only include reasonably similar incidents (>15% similarity)
            if similarity < 0.15:
                continue

            # Extract overlapping IoCs
            stored_iocs_str = meta.get("iocs", "")
            current_iocs_set = (
                set(iocs.ip_addresses)
                | set(iocs.file_hashes)
                | set(iocs.domains)
                | set(iocs.process_names)
            )
            ioc_overlap = [
                i for i in stored_iocs_str.split(", ")
                if i and i in current_iocs_set
            ]

            prior_incidents.append(
                {
                    "incident_id": meta.get("report_id", "UNKNOWN"),
                    "summary": incident["document"][:500],
                    "similarity_score": round(similarity, 3),
                    "severity": meta.get("severity", "UNKNOWN"),
                    "iocs_overlap": ioc_overlap,
                    "resolved": meta.get("resolved", False),
                }
            )

        logger.info("Long-term memory: retrieved %d related incidents", len(prior_incidents))
        notes.append(f"Long-term memory: {len(prior_incidents)} related incident(s) retrieved")

    except Exception as e:
        logger.warning("Long-term memory query failed: %s", e)
        notes.append(f"Long-term memory: query failed ({type(e).__name__})")

    # ── Short-term memory: Session context summary ─────────────────────────────
    # MemorySaver stores prior graph state in the checkpoint.
    # We extract useful context from any previous state in this thread.
    memory_context = _build_session_context(state)
    if memory_context:
        notes.append("Short-term memory: prior session context found")
        logger.info("Short-term memory: session context loaded (%d chars)", len(memory_context))
    else:
        memory_context = "No prior session context for this thread."
        notes.append("Short-term memory: new investigation session")

    return {
        "prior_incidents": prior_incidents,
        "memory_context": memory_context,
        "processing_notes": state.get("processing_notes", []) + notes,
    }


def _build_ioc_query_string(iocs: ExtractedIoCs) -> str:
    """
    Build a keyword-enriched query string from extracted IoCs.

    Args:
        iocs: Extracted IoCs from the alert.

    Returns:
        A space-separated string of IoC values for embedding search.
    """
    parts = []
    parts.extend(iocs.ip_addresses[:3])
    parts.extend(iocs.domains[:3])
    parts.extend(p.replace(".exe", "") for p in iocs.process_names[:5])
    parts.extend(iocs.cve_ids[:3])
    parts.extend(iocs.usernames[:2])
    parts.extend(iocs.hostnames[:2])
    return " ".join(parts)


def _build_session_context(state: SOCAgentState) -> str:
    """
    Extract useful context from the current LangGraph state for memory context.

    In LangGraph with MemorySaver, previous checkpointed state is available
    on subsequent invocations with the same thread_id. We summarise any
    relevant prior investigation data from the state.

    Args:
        state: Current SOCAgentState.

    Returns:
        Formatted context string, or empty string if no useful context found.
    """
    parts = []

    # Check if there's a prior report in this session
    prior_report = state.get("report")
    if prior_report:
        parts.append(
            f"Prior investigation in this session:\n"
            f"  - Alert: {prior_report.alert_summary[:200]}\n"
            f"  - Risk score: {prior_report.risk_score}\n"
            f"  - Severity: {prior_report.severity}\n"
            f"  - Escalated: {prior_report.escalation_required}"
        )

    # Check for prior processing notes
    prior_notes = state.get("processing_notes", [])
    if prior_notes and len(prior_notes) > 5:
        # Only include if there are substantial prior notes (indicating prior turns)
        parts.append(f"Prior session notes: {'; '.join(prior_notes[-3:])}")

    return "\n\n".join(parts) if parts else ""
