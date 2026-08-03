"""
SOCPilot AI — LangGraph Builder
=================================
Constructs the StateGraph that orchestrates the entire SOC investigation pipeline.

Workflow:
1. Alert Ingestion (IoC extraction)
2. Parallel fan-out: Memory retrieval AND RAG retrieval
3. Conditional tool routing: fan-out to specific tools based on IoCs
4. Reasoning: synthesise all data into SOCReport
5. Report: write to disk, persist to memory, output to terminal

Uses MemorySaver for short-term thread memory.
"""

from __future__ import annotations

import logging

from langgraph.graph import END, START, StateGraph

from socpilot.memory.short_term import get_checkpointer
from socpilot.models.graph_state import SOCAgentState
from socpilot.nodes.alert_ingest import alert_ingest_node
from socpilot.nodes.memory_node import memory_node
from socpilot.nodes.rag_node import rag_node
from socpilot.nodes.reasoning_node import reasoning_node
from socpilot.nodes.report_node import report_node
from socpilot.nodes.tool_router import route_to_tools
from socpilot.tools.abuse_ipdb import run_abuseipdb_lookup
from socpilot.tools.cve_lookup import run_cve_lookup
from socpilot.tools.mitre_attack import run_mitre_lookup
from socpilot.tools.sigma_rules import run_sigma_lookup
from socpilot.tools.virustotal import run_virustotal_lookup

logger = logging.getLogger(__name__)


def build_soc_graph() -> StateGraph:
    """
    Construct and compile the LangGraph StateGraph for SOCPilot AI.

    Returns:
        A compiled LangGraph instance ready for invocation.
    """
    logger.info("Building SOCPilot AI StateGraph...")
    
    # ── 1. Initialise StateGraph ──────────────────────────────────────────────
    builder = StateGraph(SOCAgentState)

    # ── 2. Add Nodes ──────────────────────────────────────────────────────────
    builder.add_node("alert_ingest_node", alert_ingest_node)
    
    # Enrichment nodes
    builder.add_node("memory_node", memory_node)
    builder.add_node("rag_node", rag_node)
    
    # Tool nodes
    builder.add_node("abuse_ipdb_node", run_abuseipdb_lookup)
    builder.add_node("virustotal_node", run_virustotal_lookup)
    builder.add_node("cve_lookup_node", run_cve_lookup)
    builder.add_node("mitre_attack_node", run_mitre_lookup)
    builder.add_node("sigma_node", run_sigma_lookup)
    
    # Synthesis nodes
    builder.add_node("reasoning_node", reasoning_node)
    builder.add_node("report_node", report_node)

    # ── 3. Define Edges (The Flow) ────────────────────────────────────────────
    # Entry point
    builder.add_edge(START, "alert_ingest_node")
    
    # After ingest, run memory and RAG in parallel
    builder.add_edge("alert_ingest_node", "memory_node")
    builder.add_edge("alert_ingest_node", "rag_node")
    
    # A dummy node to synchronize parallel enrichment before tool routing
    # (LangGraph handles synchronization automatically when all paths converge on a single node.
    # However, because we want conditional routing *after* both Memory and RAG finish,
    # we use a passthrough node to act as the convergence point.)
    def sync_node(state: SOCAgentState) -> dict:
        return {}
    
    builder.add_node("sync_enrichment", sync_node)
    builder.add_edge("memory_node", "sync_enrichment")
    builder.add_edge("rag_node", "sync_enrichment")

    # ── 4. Conditional Tool Routing ───────────────────────────────────────────
    # We use route_to_tools to inspect the state and return a list of tool nodes to run.
    builder.add_conditional_edges(
        "sync_enrichment",
        route_to_tools,
        {
            "abuse_ipdb_node": "abuse_ipdb_node",
            "virustotal_node": "virustotal_node",
            "cve_lookup_node": "cve_lookup_node",
            "mitre_attack_node": "mitre_attack_node",
            "sigma_node": "sigma_node",
        }
    )

    # ── 5. Converge Tools to Reasoning ────────────────────────────────────────
    # All tool nodes flow into the reasoning node.
    # LangGraph waits for all active parallel paths to complete before executing reasoning_node.
    builder.add_edge("abuse_ipdb_node", "reasoning_node")
    builder.add_edge("virustotal_node", "reasoning_node")
    builder.add_edge("cve_lookup_node", "reasoning_node")
    builder.add_edge("mitre_attack_node", "reasoning_node")
    builder.add_edge("sigma_node", "reasoning_node")

    # ── 6. Final Steps ────────────────────────────────────────────────────────
    builder.add_edge("reasoning_node", "report_node")
    builder.add_edge("report_node", END)

    # ── 7. Compile with Checkpointer ──────────────────────────────────────────
    checkpointer = get_checkpointer()
    graph = builder.compile(checkpointer=checkpointer)
    
    logger.info("StateGraph built and compiled successfully.")
    return graph
