"""
SOCPilot AI — Reasoning Node
==============================
The intelligence synthesis stage of the SOCPilot pipeline.

This node receives ALL enrichment data from prior nodes and uses a Groq LLM
with structured output to produce a comprehensive SOCReport.

Design choices:
- Uses with_structured_output(SOCReport) for type-safe, schema-validated output
- Falls back to JSON parsing if structured output fails
- Calculates a severity override if LLM's severity/score are inconsistent
- Always produces a report — even partial data yields a useful analysis
"""

from __future__ import annotations

import json
import logging
import uuid
from datetime import datetime
from typing import Any, Dict, List

from langchain_groq import ChatGroq

from socpilot.config.settings import settings
from socpilot.models.graph_state import SOCAgentState
from socpilot.models.ioc_models import ExtractedIoCs
from socpilot.models.report_models import (
    MitreMapping,
    RelatedIncident,
    SOCReport,
    SeverityLevel,
    SigmaRule,
    ThreatIntelFinding,
    Verdict,
)
from socpilot.prompts.reasoning_prompt import build_reasoning_messages

logger = logging.getLogger(__name__)


def _build_llm() -> ChatGroq:
    """Instantiate the Groq LLM for reasoning with higher token budget."""
    return ChatGroq(
        api_key=settings.groq_api_key,
        model=settings.groq_model,
        temperature=0.1,  # Slightly creative for analyst narration
        max_tokens=4096,
    )


def _score_to_severity(score: int) -> SeverityLevel:
    """Convert numeric risk score to SeverityLevel enum."""
    if score >= 80:
        return SeverityLevel.CRITICAL
    elif score >= 60:
        return SeverityLevel.HIGH
    elif score >= 35:
        return SeverityLevel.MEDIUM
    else:
        return SeverityLevel.LOW


def _build_fallback_report(state: SOCAgentState, error_msg: str) -> SOCReport:
    """
    Build a minimal but valid SOCReport when LLM reasoning fails.

    This ensures the pipeline always produces output, even in degraded mode.
    """
    iocs: ExtractedIoCs = state.get("iocs") or ExtractedIoCs()
    thread_id = state.get("thread_id", "default")
    report_id = f"RPT-{datetime.utcnow().strftime('%Y%m%d')}-{uuid.uuid4().hex[:4].upper()}"

    # Calculate a basic risk score from tool results
    risk_score = _calculate_basic_risk_score(state)
    severity = _score_to_severity(risk_score)

    # Build basic threat intel findings from tool results
    ti_findings = _parse_ti_findings_from_state(state)
    mitre_mappings = _parse_mitre_from_state(state)
    sigma_detections = _parse_sigma_from_state(state)
    related = _parse_incidents_from_state(state)

    return SOCReport(
        report_id=report_id,
        thread_id=thread_id,
        alert_summary=(
            f"Security alert received for analysis. IoCs extracted: {iocs.summary()}. "
            f"Note: LLM reasoning was unavailable ({error_msg}). "
            f"This report was generated from structured tool outputs only."
        ),
        extracted_iocs={
            "ip_addresses": iocs.ip_addresses,
            "file_hashes": iocs.file_hashes,
            "domains": iocs.domains,
            "urls": iocs.urls,
            "cve_ids": iocs.cve_ids,
            "process_names": iocs.process_names,
            "usernames": iocs.usernames,
            "hostnames": iocs.hostnames,
            "command_lines": iocs.command_lines,
            "registry_keys": iocs.registry_keys,
        },
        threat_intel_findings=ti_findings,
        mitre_mappings=mitre_mappings,
        sigma_detections=sigma_detections,
        related_incidents=related,
        rag_context_summary="RAG context unavailable in fallback mode.",
        risk_score=risk_score,
        severity=severity,
        confidence_score=0.4,
        analyst_reasoning=(
            f"Automated tool-based analysis only. LLM reasoning failed: {error_msg}. "
            f"Tool results indicate risk score of {risk_score}/100."
        ),
        recommended_actions=[
            "Review the extracted tool results manually.",
            "Verify flagged IoCs against your threat intelligence platform.",
            "Escalate to a senior analyst for manual investigation.",
        ],
        escalation_required=risk_score >= 60,
        false_positive_likelihood="UNKNOWN",
    )


def _calculate_basic_risk_score(state: SOCAgentState) -> int:
    """Calculate a basic risk score from tool results when LLM is unavailable."""
    score = 20  # Base score for any alert

    # Check AbuseIPDB results
    for result in state.get("abuseipdb_results", []):
        raw_score = result.get("raw_risk_score") or 0
        verdict = result.get("verdict", "UNKNOWN")
        if verdict == "MALICIOUS":
            score += 30
        elif verdict == "SUSPICIOUS":
            score += 15
        score += min(20, raw_score // 5)

    # Check VirusTotal results
    for result in state.get("virustotal_results", []):
        verdict = result.get("verdict", "UNKNOWN")
        if verdict == "MALICIOUS":
            score += 40
        elif verdict == "SUSPICIOUS":
            score += 20

    # Check Sigma rules (by severity)
    for rule in state.get("sigma_results", []):
        sev = rule.get("severity", "LOW")
        if sev == "CRITICAL":
            score += 25
        elif sev == "HIGH":
            score += 15
        elif sev == "MEDIUM":
            score += 8

    # Check MITRE mappings
    mitre_count = len(state.get("mitre_results", []))
    score += min(20, mitre_count * 5)

    return min(100, score)


def _parse_ti_findings_from_state(state: SOCAgentState) -> List[ThreatIntelFinding]:
    """Extract ThreatIntelFinding objects from raw tool results."""
    findings = []

    for result in state.get("abuseipdb_results", []) + state.get("virustotal_results", []) + state.get("cve_results", []):
        try:
            findings.append(
                ThreatIntelFinding(
                    source=result.get("source", "Unknown"),
                    ioc=result.get("ioc", ""),
                    ioc_type=result.get("ioc_type", "unknown"),
                    verdict=Verdict(result.get("verdict", "UNKNOWN")),
                    confidence=float(result.get("confidence", 0.0)),
                    details={k: str(v) for k, v in result.get("details", {}).items()},
                    raw_risk_score=result.get("raw_risk_score"),
                )
            )
        except Exception as e:
            logger.warning("Could not parse TI finding: %s", e)

    return findings


def _parse_mitre_from_state(state: SOCAgentState) -> List[MitreMapping]:
    """Extract MitreMapping objects from raw MITRE results."""
    mappings = []
    for result in state.get("mitre_results", []):
        try:
            mappings.append(
                MitreMapping(
                    technique_id=result.get("technique_id", "UNKNOWN"),
                    technique_name=result.get("technique_name", "Unknown Technique"),
                    tactic=result.get("tactic", "Unknown"),
                    sub_technique=result.get("sub_technique"),
                    description=result.get("description", ""),
                    triggered_by=result.get("triggered_by", ""),
                )
            )
        except Exception as e:
            logger.warning("Could not parse MITRE mapping: %s", e)
    return mappings


def _parse_sigma_from_state(state: SOCAgentState) -> List[SigmaRule]:
    """Extract SigmaRule objects from raw Sigma results."""
    rules = []
    for result in state.get("sigma_results", []):
        try:
            rules.append(
                SigmaRule(
                    rule_id=result.get("rule_id", str(uuid.uuid4())),
                    title=result.get("title", "Unknown Rule"),
                    description=result.get("description", ""),
                    severity=SeverityLevel(result.get("severity", "MEDIUM")),
                    detection_logic=result.get("detection_logic", ""),
                    tags=result.get("tags", []),
                    triggered_by=result.get("triggered_by", ""),
                )
            )
        except Exception as e:
            logger.warning("Could not parse Sigma rule: %s", e)
    return rules


def _parse_incidents_from_state(state: SOCAgentState) -> List[RelatedIncident]:
    """Extract RelatedIncident objects from raw memory results."""
    incidents = []
    for result in state.get("prior_incidents", []):
        try:
            incidents.append(
                RelatedIncident(
                    incident_id=result.get("incident_id", "UNKNOWN"),
                    summary=result.get("summary", ""),
                    similarity_score=float(result.get("similarity_score", 0.0)),
                    iocs_overlap=result.get("iocs_overlap", []),
                    resolved=bool(result.get("resolved", False)),
                )
            )
        except Exception as e:
            logger.warning("Could not parse related incident: %s", e)
    return incidents


async def reasoning_node(state: SOCAgentState) -> Dict[str, Any]:
    """
    LangGraph node: Synthesise all evidence into a structured SOC report.

    Uses the Groq LLM with structured output (Pydantic) to produce a
    SOCReport. Falls back to a tool-result-only report if LLM fails.

    Args:
        state: Fully populated SOCAgentState with all enrichment data.

    Returns:
        State update with 'report' and 'processing_notes'.
    """
    logger.info("Reasoning node: synthesising investigation report")
    notes: List[str] = []

    if not settings.has_groq_key:
        logger.warning("No GROQ_API_KEY — generating fallback report from tool results")
        report = _build_fallback_report(state, "No GROQ_API_KEY configured")
        notes.append("Reasoning: fallback mode (no LLM key)")
        return {
            "report": report,
            "processing_notes": state.get("processing_notes", []) + notes,
        }

    # ── Attempt LLM structured output ─────────────────────────────────────────
    try:
        llm = _build_llm()
        structured_llm = llm.with_structured_output(SOCReport)
        messages = build_reasoning_messages(state)

        logger.info("Reasoning: invoking LLM with structured output...")
        report: SOCReport = await structured_llm.ainvoke(messages)

        # Ensure severity is consistent with risk score
        computed_severity = _score_to_severity(report.risk_score)
        if report.severity != computed_severity:
            logger.info(
                "Severity adjusted: %s → %s (based on risk_score=%d)",
                report.severity,
                computed_severity,
                report.risk_score,
            )
            report = report.model_copy(update={"severity": computed_severity})

        # Ensure report_id and thread_id are set
        if not report.report_id or report.report_id == "string":
            new_id = f"RPT-{datetime.utcnow().strftime('%Y%m%d')}-{uuid.uuid4().hex[:4].upper()}"
            report = report.model_copy(update={"report_id": new_id})

        thread_id = state.get("thread_id", "default")
        if report.thread_id != thread_id:
            report = report.model_copy(update={"thread_id": thread_id})

        notes.append(
            f"Reasoning: LLM synthesis complete | risk={report.risk_score} | "
            f"severity={report.severity} | confidence={report.confidence_score:.2f}"
        )
        logger.info(
            "Reasoning complete: risk=%d, severity=%s, confidence=%.2f",
            report.risk_score,
            report.severity,
            report.confidence_score,
        )

    except Exception as e:
        logger.error("LLM structured reasoning failed: %s", e)
        notes.append(f"Reasoning: LLM failed ({type(e).__name__}) — fallback report generated")
        report = _build_fallback_report(state, str(e))

    return {
        "report": report,
        "processing_notes": state.get("processing_notes", []) + notes,
        "errors": state.get("errors", []),
    }
