"""
SOCPilot AI — Alert Ingest Node
=================================
The entry point of the investigation pipeline.

Responsibilities:
1. Validate and store the raw alert text
2. Use an LLM with structured output to extract IoCs
3. Fall back to regex-based extraction if LLM fails or returns invalid data
4. Merge LLM and regex results for maximum coverage
5. Store extracted IoCs and alert metadata in the state

Design: Two-pass extraction (LLM + regex merge) ensures we never miss IoCs
even if the LLM hallucinates or the API fails.
"""

from __future__ import annotations

import json
import logging
import re
from datetime import datetime
from typing import Any, Dict, List, Optional

from langchain_groq import ChatGroq

from socpilot.config.settings import settings
from socpilot.models.graph_state import SOCAgentState
from socpilot.models.ioc_models import AlertMetadata, ExtractedIoCs
from socpilot.prompts.extraction_prompt import RegexExtractor, build_extraction_messages

logger = logging.getLogger(__name__)


def _build_llm() -> ChatGroq:
    """Instantiate the Groq LLM for IoC extraction."""
    return ChatGroq(
        api_key=settings.groq_api_key,
        model=settings.groq_model,
        temperature=0,  # Deterministic extraction
        max_tokens=2048,
    )


def _parse_llm_ioc_response(response_text: str) -> Optional[Dict[str, List[str]]]:
    """
    Parse the LLM's JSON response into an IoC dictionary.

    Handles cases where the LLM wraps JSON in markdown code fences.

    Args:
        response_text: Raw text response from the LLM.

    Returns:
        Dict matching ExtractedIoCs fields, or None if parsing fails.
    """
    text = response_text.strip()

    # Strip markdown code fences if present
    if "```json" in text:
        match = re.search(r"```json\s*(.*?)\s*```", text, re.DOTALL)
        if match:
            text = match.group(1)
    elif "```" in text:
        match = re.search(r"```\s*(.*?)\s*```", text, re.DOTALL)
        if match:
            text = match.group(1)

    # Find the JSON object
    json_match = re.search(r"\{.*\}", text, re.DOTALL)
    if not json_match:
        return None

    try:
        data = json.loads(json_match.group())
        # Validate expected keys exist
        expected_keys = {
            "ip_addresses", "file_hashes", "domains", "urls",
            "cve_ids", "process_names", "email_addresses",
            "registry_keys", "usernames", "hostnames", "command_lines",
        }
        if not any(k in data for k in expected_keys):
            return None
        return data
    except json.JSONDecodeError as e:
        logger.warning("Failed to parse LLM IoC JSON: %s", e)
        return None


def _merge_iocs(llm_data: Optional[Dict], regex_data: Dict) -> ExtractedIoCs:
    """
    Merge LLM-extracted and regex-extracted IoCs into a single ExtractedIoCs.

    Strategy: Union of both sets, preserving order (LLM first, regex fills gaps).

    Args:
        llm_data: IoC dict from LLM, or None if LLM failed.
        regex_data: IoC dict from regex extractor.

    Returns:
        Merged ExtractedIoCs model.
    """
    def merge_lists(llm_list: List[str], regex_list: List[str]) -> List[str]:
        """Combine two lists, deduplicating case-insensitively."""
        seen = set()
        result = []
        for item in (llm_list or []) + (regex_list or []):
            item_lower = item.lower().strip()
            if item_lower and item_lower not in seen:
                seen.add(item_lower)
                result.append(item)
        return result

    base = llm_data or {}

    return ExtractedIoCs(
        ip_addresses=merge_lists(base.get("ip_addresses", []), regex_data.get("ip_addresses", [])),
        file_hashes=merge_lists(base.get("file_hashes", []), regex_data.get("file_hashes", [])),
        domains=merge_lists(base.get("domains", []), regex_data.get("domains", [])),
        urls=merge_lists(base.get("urls", []), regex_data.get("urls", [])),
        cve_ids=merge_lists(base.get("cve_ids", []), regex_data.get("cve_ids", [])),
        process_names=merge_lists(base.get("process_names", []), regex_data.get("process_names", [])),
        email_addresses=merge_lists(base.get("email_addresses", []), regex_data.get("email_addresses", [])),
        registry_keys=merge_lists(base.get("registry_keys", []), regex_data.get("registry_keys", [])),
        usernames=base.get("usernames", []),  # LLM only — regex unreliable for usernames
        hostnames=merge_lists(base.get("hostnames", []), regex_data.get("hostnames", [])),
        command_lines=base.get("command_lines", []),  # LLM only — regex unreliable for full cmdlines
    )


def _infer_alert_metadata(raw_alert: str, iocs: ExtractedIoCs) -> AlertMetadata:
    """
    Heuristically infer alert metadata from the raw text and extracted IoCs.

    Args:
        raw_alert: Original alert text.
        iocs: Extracted IoCs.

    Returns:
        AlertMetadata with best-effort parsed fields.
    """
    # Attempt to identify alert name
    alert_name = None
    name_patterns = [
        r"Alert(?:\s+Name)?[:\s]+(.+?)(?:\n|$)",
        r"Rule[:\s]+(.+?)(?:\n|$)",
        r"Detection[:\s]+(.+?)(?:\n|$)",
        r"Event[:\s]+(.+?)(?:\n|$)",
    ]
    for pattern in name_patterns:
        match = re.search(pattern, raw_alert, re.IGNORECASE)
        if match:
            alert_name = match.group(1).strip()
            break

    # Hostname — prefer IoCs, fall back to regex
    hostname = iocs.hostnames[0] if iocs.hostnames else None
    if not hostname:
        hostname_match = re.search(
            r"(?:Hostname|Host|Computer|Machine)[:\s]+([A-Za-z0-9_\-\.]+)",
            raw_alert,
            re.IGNORECASE,
        )
        if hostname_match:
            hostname = hostname_match.group(1).strip()

    # Detect source system
    source = None
    source_patterns = {
        "SIEM": r"\b(SIEM|Splunk|QRadar|Sentinel|LogRhythm)\b",
        "EDR": r"\b(EDR|CrowdStrike|Carbon Black|SentinelOne|Defender for Endpoint)\b",
        "Firewall": r"\b(Firewall|Palo Alto|Fortinet|Check Point|pfSense)\b",
        "IDS/IPS": r"\b(IDS|IPS|Snort|Suricata|Zeek)\b",
    }
    for src_name, pattern in source_patterns.items():
        if re.search(pattern, raw_alert, re.IGNORECASE):
            source = src_name
            break

    return AlertMetadata(
        raw_alert=raw_alert,
        alert_name=alert_name,
        hostname=hostname,
        source=source,
        ingestion_time=datetime.utcnow(),
    )


async def alert_ingest_node(state: SOCAgentState) -> Dict[str, Any]:
    """
    LangGraph node: Ingest the security alert and extract all IoCs.

    This node is the first step in every investigation. It:
    1. Validates the raw alert is present
    2. Runs regex extraction (always succeeds, deterministic)
    3. Attempts LLM extraction (may fail gracefully)
    4. Merges both results for maximum IoC coverage
    5. Populates state with iocs and alert_metadata

    Args:
        state: Current SOCAgentState (must have 'raw_alert').

    Returns:
        State update dict with 'iocs', 'alert_metadata', and 'processing_notes'.
    """
    raw_alert = state.get("raw_alert", "").strip()
    if not raw_alert:
        logger.error("Alert ingest: no raw_alert in state")
        return {
            "errors": ["No alert text provided"],
            "processing_notes": ["Alert ingest: FAILED — no alert text"],
        }

    logger.info("Alert ingest: processing alert (%d chars)", len(raw_alert))
    notes: List[str] = []
    errors: List[str] = state.get("errors", [])

    # ── Step 1: Regex extraction (deterministic fallback) ─────────────────────
    regex_data = RegexExtractor.extract(raw_alert)
    logger.info("Regex extraction complete")

    # ── Step 2: LLM extraction ────────────────────────────────────────────────
    llm_data: Optional[Dict] = None

    if settings.has_groq_key:
        try:
            llm = _build_llm()
            messages = build_extraction_messages(raw_alert)
            response = await llm.ainvoke(messages)
            response_text = response.content if hasattr(response, "content") else str(response)
            llm_data = _parse_llm_ioc_response(response_text)

            if llm_data:
                notes.append("IoC extraction: LLM + regex (merged)")
                logger.info("LLM extraction succeeded")
            else:
                notes.append("IoC extraction: LLM returned unparseable output — using regex only")
                logger.warning("LLM IoC response unparseable, falling back to regex")

        except Exception as e:
            logger.warning("LLM extraction failed: %s — falling back to regex", e)
            notes.append(f"IoC extraction: LLM failed ({type(e).__name__}) — using regex only")
            errors.append(f"LLM extraction error: {e}")
    else:
        notes.append("IoC extraction: regex only (no GROQ_API_KEY configured)")
        logger.warning("No GROQ_API_KEY — using regex extraction only")

    # ── Step 3: Merge results ─────────────────────────────────────────────────
    iocs = _merge_iocs(llm_data, regex_data)
    logger.info("Merged IoC extraction: %s", iocs.summary())

    # ── Step 4: Infer metadata ────────────────────────────────────────────────
    alert_metadata = _infer_alert_metadata(raw_alert, iocs)

    notes.append(f"Extracted: {iocs.summary()}")

    return {
        "iocs": iocs,
        "alert_metadata": alert_metadata,
        "processing_notes": state.get("processing_notes", []) + notes,
        "errors": errors,
        # Initialise empty result containers
        "abuseipdb_results": [],
        "virustotal_results": [],
        "cve_results": [],
        "mitre_results": [],
        "sigma_results": [],
        "prior_incidents": [],
        "memory_context": "",
        "rag_context": "",
    }
