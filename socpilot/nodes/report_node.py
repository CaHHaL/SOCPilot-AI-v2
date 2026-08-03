"""
SOCPilot AI — Report Node
===========================
The final node in the LangGraph pipeline.

Responsibilities:
1. Receives the final SOCReport from the reasoning node.
2. Writes the report to disk in two formats:
   - JSON (for machine ingestion / API response)
   - Markdown (rendered via Jinja2 template for human analysts)
3. Persists the incident to long-term memory (ChromaDB) for future context.
4. Outputs a summary to the console using Rich.
"""

from __future__ import annotations

import json
import logging
import os
from datetime import datetime
from pathlib import Path
from typing import Any, Dict

from jinja2 import Environment, FileSystemLoader
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from socpilot.config.settings import settings
from socpilot.memory.long_term import get_long_term_memory
from socpilot.models.graph_state import SOCAgentState
from socpilot.models.report_models import SOCReport

logger = logging.getLogger(__name__)


def _render_markdown(report: SOCReport) -> str:
    """Render the SOCReport using the Jinja2 markdown template."""
    # Setup Jinja environment pointing to our templates directory
    template_dir = Path(__file__).parent.parent / "reports" / "templates"
    
    # Create default template if it doesn't exist
    if not template_dir.exists():
        template_dir.mkdir(parents=True, exist_ok=True)
    
    template_path = template_dir / "report.md.j2"
    if not template_path.exists():
        logger.warning("Markdown template not found, creating a minimal one.")
        template_path.write_text(
            "# SOC Investigation Report: {{ report.report_id }}\n\n"
            "**Severity**: {{ report.severity }} | **Risk Score**: {{ report.risk_score }}\n\n"
            "## Summary\n{{ report.alert_summary }}\n\n"
            "## Analyst Reasoning\n{{ report.analyst_reasoning }}\n\n"
            "## Recommended Actions\n"
            "{% for action in report.recommended_actions %}- {{ action }}\n{% endfor %}\n"
        )

    env = Environment(loader=FileSystemLoader(str(template_dir)), autoescape=False)
    template = env.get_template("report.md.j2")
    
    # Render with the report model as context
    return template.render(report=report)


def _print_rich_summary(report: SOCReport) -> None:
    """Print a beautiful summary of the report to the terminal using Rich."""
    console = Console()
    console.print("\n")
    
    # Color code severity
    sev_color = {
        "CRITICAL": "bold red",
        "HIGH": "red",
        "MEDIUM": "yellow",
        "LOW": "green"
    }.get(report.severity.value, "white")
    
    header = Text()
    header.append(" SOC Investigation Complete \n", style="bold white on blue")
    header.append(f" Report ID: {report.report_id} \n", style="dim")
    header.append(f" Severity:  {report.severity.value} ", style=sev_color)
    header.append(f"| Risk Score: {report.risk_score}/100\n", style="bold")
    
    console.print(Panel(header, title="SOCPilot AI", border_style="blue"))
    
    console.print(f"\n[bold]Summary:[/bold] {report.alert_summary}\n")
    
    # Actions table
    table = Table(title="Recommended Actions", show_header=True, header_style="bold cyan")
    table.add_column("#", style="dim", width=3)
    table.add_column("Action", style="white")
    
    for i, action in enumerate(report.recommended_actions, 1):
        table.add_row(str(i), action)
        
    console.print(table)
    console.print("\n")


async def report_node(state: SOCAgentState) -> Dict[str, Any]:
    """
    LangGraph node: Finalise report, write to disk, and save to memory.

    Args:
        state: Fully populated SOCAgentState containing the final 'report'.

    Returns:
        State update with 'report_file_path' and 'processing_notes'.
    """
    report: SOCReport | None = state.get("report")
    notes = state.get("processing_notes", [])
    
    if not report:
        logger.error("Report node called but no report found in state.")
        notes.append("Report Node: Failed — no report found in state")
        return {"processing_notes": notes}

    # Ensure reports directory exists
    settings.reports_path.mkdir(parents=True, exist_ok=True)
    
    timestamp_str = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    base_filename = f"{report.report_id}_{timestamp_str}"
    
    # ── Write JSON ────────────────────────────────────────────────────────────
    json_path = settings.reports_path / f"{base_filename}.json"
    try:
        # Pydantic v2 model_dump_json handles datetime serialisation automatically
        with open(json_path, "w", encoding="utf-8") as f:
            f.write(report.model_dump_json(indent=2))
        logger.info("JSON report written to %s", json_path)
    except Exception as e:
        logger.error("Failed to write JSON report: %s", e)
        notes.append(f"Report Node: JSON write failed ({type(e).__name__})")
        
    # ── Write Markdown ────────────────────────────────────────────────────────
    md_path = settings.reports_path / f"{base_filename}.md"
    try:
        markdown_content = _render_markdown(report)
        with open(md_path, "w", encoding="utf-8") as f:
            f.write(markdown_content)
        logger.info("Markdown report written to %s", md_path)
    except Exception as e:
        logger.error("Failed to write Markdown report: %s", e)
        notes.append(f"Report Node: Markdown write failed ({type(e).__name__})")

    # ── Persist to Long-Term Memory ───────────────────────────────────────────
    try:
        ltm = get_long_term_memory()
        
        # Flatten IoCs for search
        flattened_iocs = []
        for ioc_list in report.extracted_iocs.values():
            flattened_iocs.extend(ioc_list)
            
        ltm.add_incident(
            summary=report.alert_summary,
            iocs=flattened_iocs,
            report_id=report.report_id,
            severity=report.severity.value,
            metadata={
                "risk_score": report.risk_score,
                "escalated": report.escalation_required,
                "thread_id": report.thread_id,
            }
        )
        logger.info("Incident %s stored in long-term memory", report.report_id)
        notes.append("Report Node: Incident persisted to long-term memory")
    except Exception as e:
        logger.error("Failed to store incident in long-term memory: %s", e)
        notes.append(f"Report Node: Memory storage failed ({type(e).__name__})")

    # ── Terminal Output ───────────────────────────────────────────────────────
    try:
        _print_rich_summary(report)
    except Exception as e:
        logger.warning("Rich terminal output failed: %s", e)

    notes.append(f"Report Node: Completed. Files saved to {settings.reports_path}")
    
    return {
        "report_file_path": str(md_path),
        "processing_notes": notes,
    }
