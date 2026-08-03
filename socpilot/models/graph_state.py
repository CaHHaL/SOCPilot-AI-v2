"""
SOCPilot AI — LangGraph Agent State
=====================================
Defines the typed state dictionary that flows through all graph nodes.
Every field is Optional so nodes can be added to the state incrementally.
"""

from __future__ import annotations

import operator
from typing import Annotated, Any, Dict, List, Optional, TypedDict

from socpilot.models.ioc_models import AlertMetadata, ExtractedIoCs
from socpilot.models.report_models import SOCReport


class SOCAgentState(TypedDict, total=False):
    """
    The central state object for the SOCPilot AI LangGraph workflow.

    Each node reads from and writes to this state. Fields are populated
    progressively as the graph executes.

    Naming convention:
      - snake_case field names
      - *_results suffix for tool output dicts
      - *_context suffix for retrieved text/documents
    """

    # ── Phase 1: Alert Ingestion ──────────────────────────────────────────────
    raw_alert: str
    """The original, unprocessed security alert text provided by the user."""

    iocs: Optional[ExtractedIoCs]
    """Structured IoCs extracted from the raw alert."""

    alert_metadata: Optional[AlertMetadata]
    """Metadata parsed from the alert (hostname, source, alert name, etc.)."""

    thread_id: str
    """Session identifier used by MemorySaver for cross-turn memory."""

    # ── Phase 2: Memory & RAG ─────────────────────────────────────────────────
    memory_context: str
    """Formatted text from MemorySaver checkpoint (prior turns in session)."""

    prior_incidents: List[Dict[str, Any]]
    """Related historical incidents retrieved from ChromaDB long-term memory."""

    rag_context: str
    """Cybersecurity knowledge retrieved via MultiQueryRetriever from ChromaDB."""

    # ── Phase 3: Tool Results ─────────────────────────────────────────────────
    abuseipdb_results: List[Dict[str, Any]]
    """Raw results from AbuseIPDB IP reputation lookups."""

    virustotal_results: List[Dict[str, Any]]
    """Raw results from VirusTotal file hash lookups."""

    cve_results: List[Dict[str, Any]]
    """Raw results from NVD NIST CVE lookups."""

    mitre_results: List[Dict[str, Any]]
    """MITRE ATT&CK technique mappings for observed IoCs."""

    sigma_results: List[Dict[str, Any]]
    """Sigma detection rules matched against observed IoCs."""

    # ── Phase 4: Reasoning & Report ───────────────────────────────────────────
    report: Optional[SOCReport]
    """The final structured SOC investigation report."""

    report_file_path: str
    """Filesystem path where the generated report was saved."""

    # ── Meta / Errors ─────────────────────────────────────────────────────────
    errors: Annotated[List[str], operator.add]
    """Non-fatal errors encountered during investigation (e.g., API timeouts)."""

    processing_notes: Annotated[List[str], operator.add]
    """Informational notes about the investigation process."""
