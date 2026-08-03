"""
SOCPilot AI — RAG Node
=======================
Retrieves relevant cybersecurity knowledge using MultiQueryRetriever + ChromaDB.

The RAG node uses the alert text and extracted IoCs to query the knowledge base,
generating multiple query variants to overcome vocabulary mismatch between
the alert phrasing and the documentation language.

Why MultiQueryRetriever matters here:
- An alert saying "powershell -enc" might not match "Obfuscated Files or Information"
- The LLM generates variants like "PowerShell encoded commands", "Base64 obfuscation"
- All variants are searched; unique results are merged
- This dramatically improves recall for cybersecurity terminology
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List

from langchain_groq import ChatGroq

from socpilot.config.settings import settings
from socpilot.memory.long_term import get_long_term_memory
from socpilot.models.graph_state import SOCAgentState
from socpilot.models.ioc_models import ExtractedIoCs
from socpilot.rag.retriever import (
    build_multi_query_retriever,
    format_docs_as_context,
    retrieve_knowledge,
)

logger = logging.getLogger(__name__)


def _build_rag_query(raw_alert: str, iocs: ExtractedIoCs) -> str:
    """
    Build an enriched query string for the RAG retriever.

    Combines the alert text with extracted IoC context to provide
    the MultiQueryRetriever with richer query material.

    Args:
        raw_alert: Original alert text.
        iocs: Extracted IoCs from the alert.

    Returns:
        Enriched query string.
    """
    parts = [raw_alert[:300]]  # First 300 chars of alert

    # Add process context
    if iocs.process_names:
        parts.append(f"Suspicious processes: {', '.join(iocs.process_names)}")

    # Add IP context
    if iocs.ip_addresses:
        parts.append(f"External IP addresses: {', '.join(iocs.ip_addresses[:3])}")

    # Add CVE context
    if iocs.cve_ids:
        parts.append(f"Vulnerabilities: {', '.join(iocs.cve_ids)}")

    # Add command context
    if iocs.command_lines:
        parts.append(f"Commands: {iocs.command_lines[0][:100]}")

    return " | ".join(parts)


async def rag_node(state: SOCAgentState) -> Dict[str, Any]:
    """
    LangGraph node: Retrieve relevant cybersecurity knowledge via RAG.

    Uses MultiQueryRetriever backed by ChromaDB to retrieve documentation
    relevant to the current alert. Results are formatted as a context string
    for inclusion in the reasoning prompt.

    Args:
        state: Current SOCAgentState with 'raw_alert' and 'iocs' populated.

    Returns:
        State update with 'rag_context' and 'processing_notes'.
    """
    raw_alert = state.get("raw_alert", "")
    iocs: ExtractedIoCs = state.get("iocs") or ExtractedIoCs()
    notes: List[str] = []

    # Check if knowledge base has content
    try:
        ltm = get_long_term_memory()
        if ltm.knowledge_count == 0:
            logger.warning("Knowledge base is empty — run setup_rag.py to seed it")
            notes.append("RAG: knowledge base is empty — run setup_rag.py")
            return {
                "rag_context": (
                    "Knowledge base is empty. Run 'python setup_rag.py' to seed "
                    "the knowledge base with cybersecurity documentation."
                ),
                "processing_notes": state.get("processing_notes", []) + notes,
            }
    except Exception as e:
        logger.error("Could not check knowledge base: %s", e)

    # Build the enriched query
    query = _build_rag_query(raw_alert, iocs)
    logger.info("RAG query: %s...", query[:100])

    # ── Build MultiQueryRetriever ─────────────────────────────────────────────
    if not settings.has_groq_key:
        # Without LLM, fall back to simple direct retrieval (no multi-query)
        logger.warning("No GROQ_API_KEY — using direct ChromaDB retrieval (no multi-query)")
        try:
            ltm = get_long_term_memory()
            docs_text = ltm.query_knowledge(query, n_results=5)
            rag_context = "\n\n---\n\n".join(docs_text) if docs_text else "No relevant documents found."
            notes.append(f"RAG: direct retrieval (no LLM), {len(docs_text)} document(s)")
            return {
                "rag_context": rag_context,
                "processing_notes": state.get("processing_notes", []) + notes,
            }
        except Exception as e:
            logger.error("Direct RAG retrieval failed: %s", e)
            return {
                "rag_context": f"RAG retrieval failed: {e}",
                "processing_notes": state.get("processing_notes", []) + notes,
            }

    try:
        # Build LLM for query generation (low temperature for focused queries)
        llm = ChatGroq(
            api_key=settings.groq_api_key,
            model=settings.groq_model,
            temperature=0.2,
            max_tokens=512,
        )

        retriever = build_multi_query_retriever(llm=llm, k=4)
        docs = retrieve_knowledge(retriever, query)
        rag_context = format_docs_as_context(docs)

        notes.append(
            f"RAG: MultiQueryRetriever retrieved {len(docs)} unique document(s)"
        )
        logger.info("RAG node: retrieved %d documents", len(docs))

        return {
            "rag_context": rag_context,
            "processing_notes": state.get("processing_notes", []) + notes,
        }

    except Exception as e:
        logger.error("MultiQueryRetriever failed: %s", e)
        notes.append(f"RAG: MultiQueryRetriever failed ({type(e).__name__})")

        # Try fallback
        try:
            ltm = get_long_term_memory()
            docs_text = ltm.query_knowledge(query, n_results=5)
            rag_context = "\n\n---\n\n".join(docs_text) if docs_text else "No relevant documents found."
            notes.append(f"RAG: fallback retrieval, {len(docs_text)} document(s)")
        except Exception as e2:
            rag_context = f"RAG retrieval failed: {e2}"

        return {
            "rag_context": rag_context,
            "processing_notes": state.get("processing_notes", []) + notes,
            "errors": state.get("errors", []) + [f"RAG error: {e}"],
        }
