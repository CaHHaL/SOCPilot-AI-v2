"""
SOCPilot AI — Tool Router (Conditional Routing Function)
==========================================================
Pure routing function for LangGraph's add_conditional_edges.

This function inspects the current SOCAgentState after IoC extraction
and decides which tool nodes to execute based on the types of IoCs found.

Design principles (Best Practices):
- PURE FUNCTION: no side effects, no I/O, no LLM calls
- BORING LOGIC: reads state fields, returns node names — nothing more
- EXPLICIT: every routing decision is visible and testable
- FAIL-SAFE: always routes to at least one node; never returns empty

Routing rules:
  ┌─────────────────────────────────────────────────────────────────┐
  │ IoC Type              │ Tool Node(s) Invoked                    │
  ├─────────────────────────────────────────────────────────────────┤
  │ IP addresses          │ abuse_ipdb_node                         │
  │ File hashes           │ virustotal_node                         │
  │ CVE IDs               │ cve_lookup_node                         │
  │ Suspicious processes  │ mitre_attack_node + sigma_node          │
  │ Command lines         │ mitre_attack_node + sigma_node          │
  │ No IoCs found         │ mitre_attack_node (fallback)            │
  └─────────────────────────────────────────────────────────────────┘

Multiple node names may be returned — the graph builder uses a fan-out
pattern to route to all relevant nodes.
"""

from __future__ import annotations

import logging
from typing import List

from socpilot.models.graph_state import SOCAgentState
from socpilot.models.ioc_models import ExtractedIoCs

logger = logging.getLogger(__name__)


def route_to_tools(state: SOCAgentState) -> List[str]:
    """
    Determine which tool nodes to execute based on extracted IoCs.

    This function is called by LangGraph's conditional edge mechanism.
    It is a pure routing function — it must not modify state.

    Args:
        state: Current SOCAgentState (after alert_ingest_node has run).

    Returns:
        List of node name strings to route to. At least one node is always returned.

    Example:
        Alert with IP + PowerShell → ["abuse_ipdb_node", "mitre_attack_node", "sigma_node"]
        Alert with hash only → ["virustotal_node"]
        Alert with no IoCs → ["mitre_attack_node"]
    """
    iocs: ExtractedIoCs = state.get("iocs") or ExtractedIoCs()
    target_nodes: List[str] = []

    # ── IP addresses → AbuseIPDB ──────────────────────────────────────────────
    if iocs.has_ips:
        target_nodes.append("abuse_ipdb_node")
        logger.debug("Router: %d IP(s) → abuse_ipdb_node", len(iocs.ip_addresses))

    # ── File hashes → VirusTotal ──────────────────────────────────────────────
    if iocs.has_hashes:
        target_nodes.append("virustotal_node")
        logger.debug("Router: %d hash(es) → virustotal_node", len(iocs.file_hashes))

    # ── CVE IDs → CVE Lookup ──────────────────────────────────────────────────
    if iocs.has_cves:
        target_nodes.append("cve_lookup_node")
        logger.debug("Router: %d CVE(s) → cve_lookup_node", len(iocs.cve_ids))

    # ── Suspicious processes OR command lines → MITRE + Sigma ─────────────────
    if iocs.has_suspicious_processes or iocs.command_lines:
        if "mitre_attack_node" not in target_nodes:
            target_nodes.append("mitre_attack_node")
        if "sigma_node" not in target_nodes:
            target_nodes.append("sigma_node")
        logger.debug(
            "Router: suspicious processes/commands → mitre_attack_node + sigma_node"
        )

    # ── Fallback: always run MITRE if any IoC exists ──────────────────────────
    if not target_nodes or (target_nodes and "mitre_attack_node" not in target_nodes):
        # Even for IP/hash/CVE alerts, MITRE context is valuable
        if not iocs.is_empty:
            if "mitre_attack_node" not in target_nodes:
                target_nodes.append("mitre_attack_node")

    # ── Absolute fallback: no IoCs detected ──────────────────────────────────
    if not target_nodes:
        logger.warning("Router: no IoCs detected — routing to mitre_attack_node as fallback")
        target_nodes = ["mitre_attack_node"]

    # Log the final routing decision
    logger.info(
        "Tool router decision: [%s] → %s",
        iocs.summary(),
        ", ".join(target_nodes),
    )

    return target_nodes
