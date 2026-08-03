"""
SOCPilot AI — SOC Analyst Reasoning Prompt
============================================
The master prompt that drives the LLM reasoning node.

This prompt instructs the LLM to behave as a senior SOC analyst,
synthesise all gathered evidence, and produce a structured investigation report.

Design choices:
- Explicit analyst persona for domain-appropriate language
- Structured evidence sections keep context organised
- Output schema aligned exactly with SOCReport Pydantic model
- Confidence scoring accounts for data availability
"""

from __future__ import annotations

from langchain_core.messages import HumanMessage, SystemMessage

# ── System Prompt: SOC Analyst Persona ───────────────────────────────────────

REASONING_SYSTEM_PROMPT = """You are SOCPilot AI, a senior cybersecurity analyst and threat intelligence expert \
with 15 years of experience in Security Operations Centres (SOC). You specialise in:

- Incident triage and investigation
- Threat intelligence analysis and correlation
- MITRE ATT&CK framework mapping
- Malware behaviour analysis
- Risk assessment and executive reporting
- Incident response planning

Your role is to analyse a security alert by synthesising information from multiple sources:
threat intelligence tool results, cybersecurity knowledge (RAG), historical incidents (memory), \
and your expert knowledge of attack techniques.

You must produce a thorough, professional SOC investigation report.

IMPORTANT INSTRUCTIONS:
1. Be analytical and evidence-based — cite specific IoCs, tool results, and knowledge sources.
2. Do not speculate beyond what the evidence supports.
3. When data is missing or incomplete, acknowledge it and reflect it in a lower confidence score.
4. Risk scores should reflect actual threat severity: \
   0–34=LOW, 35–59=MEDIUM, 60–79=HIGH, 80–100=CRITICAL.
5. Recommended actions must be concrete, ordered by urgency, and actionable.
6. The analyst_reasoning field must explain your complete thought process step by step.
7. Set escalation_required=true if risk_score >= 60 or if critical infrastructure is at risk.
8. false_positive_likelihood: LOW if strong malicious evidence, HIGH if likely benign."""

# ── Human Prompt Template ─────────────────────────────────────────────────────

REASONING_HUMAN_PROMPT = """Please investigate the following security alert and produce a complete SOC investigation report.

═══════════════════════════════════════════════════════════════
SECTION 1: ORIGINAL SECURITY ALERT
═══════════════════════════════════════════════════════════════
{raw_alert}

═══════════════════════════════════════════════════════════════
SECTION 2: EXTRACTED INDICATORS OF COMPROMISE (IoCs)
═══════════════════════════════════════════════════════════════
IP Addresses:    {ip_addresses}
File Hashes:     {file_hashes}
Domains:         {domains}
URLs:            {urls}
CVE IDs:         {cve_ids}
Process Names:   {process_names}
Usernames:       {usernames}
Hostnames:       {hostnames}
Command Lines:   {command_lines}
Registry Keys:   {registry_keys}

═══════════════════════════════════════════════════════════════
SECTION 3: THREAT INTELLIGENCE TOOL RESULTS
═══════════════════════════════════════════════════════════════
AbuseIPDB Results (IP Reputation):
{abuseipdb_results}

VirusTotal Results (File Hash Reputation):
{virustotal_results}

CVE Lookup Results (Vulnerability Intelligence):
{cve_results}

═══════════════════════════════════════════════════════════════
SECTION 4: MITRE ATT&CK MAPPINGS
═══════════════════════════════════════════════════════════════
{mitre_results}

═══════════════════════════════════════════════════════════════
SECTION 5: SIGMA DETECTION RULES MATCHED
═══════════════════════════════════════════════════════════════
{sigma_results}

═══════════════════════════════════════════════════════════════
SECTION 6: CYBERSECURITY KNOWLEDGE (RAG CONTEXT)
═══════════════════════════════════════════════════════════════
{rag_context}

═══════════════════════════════════════════════════════════════
SECTION 7: HISTORICAL INCIDENTS (LONG-TERM MEMORY)
═══════════════════════════════════════════════════════════════
{prior_incidents}

═══════════════════════════════════════════════════════════════
SECTION 8: SESSION CONTEXT (SHORT-TERM MEMORY)
═══════════════════════════════════════════════════════════════
{memory_context}

═══════════════════════════════════════════════════════════════
TASK
═══════════════════════════════════════════════════════════════
Based on ALL the evidence above, produce a comprehensive SOC investigation report.

Your report must include:

1. alert_summary: A concise 2–4 sentence summary of the alert from a SOC perspective.

2. threat_intel_findings: For each IoC queried, a ThreatIntelFinding with:
   - source, ioc, ioc_type, verdict (MALICIOUS/SUSPICIOUS/CLEAN/UNKNOWN)
   - confidence (0.0–1.0), details dict, raw_risk_score (if available)

3. mitre_mappings: For each matched technique, a MitreMapping with:
   - technique_id, technique_name, tactic, description, triggered_by

4. sigma_detections: For each matched rule, a SigmaRule with:
   - rule_id, title, description, severity, detection_logic, tags, triggered_by

5. related_incidents: From historical memory, RelatedIncident entries with:
   - incident_id, summary, similarity_score (0.0–1.0), iocs_overlap, resolved

6. rag_context_summary: A 2–3 sentence summary of the relevant knowledge retrieved.

7. risk_score: Integer 0–100 based on all evidence.

8. severity: LOW/MEDIUM/HIGH/CRITICAL (must match risk_score ranges).

9. confidence_score: Float 0.0–1.0 (how confident you are given available data).

10. analyst_reasoning: Detailed step-by-step reasoning chain connecting all evidence.

11. recommended_actions: Ordered list of concrete response actions.

12. escalation_required: Boolean.

13. false_positive_likelihood: LOW/MEDIUM/HIGH.

Also include:
- report_id: Generate a unique ID in format "RPT-YYYYMMDD-XXXX" (use current UTC date).
- thread_id: "{thread_id}"

Use the exact field names and types from the SOCReport schema."""


def build_reasoning_messages(state: dict) -> list:
    """
    Build the message list for the reasoning LLM call.

    Args:
        state: The current SOCAgentState dict with all enrichment data populated.

    Returns:
        List of LangChain messages ready for structured-output invocation.
    """
    from socpilot.models.ioc_models import ExtractedIoCs
    import json

    iocs: ExtractedIoCs = state.get("iocs") or ExtractedIoCs()

    def fmt_list(lst: list) -> str:
        return ", ".join(lst) if lst else "None identified"

    def fmt_results(results: list) -> str:
        if not results:
            return "No results available (tool not triggered or API unavailable)."
        return json.dumps(results, indent=2, default=str)

    return [
        SystemMessage(content=REASONING_SYSTEM_PROMPT),
        HumanMessage(
            content=REASONING_HUMAN_PROMPT.format(
                raw_alert=state.get("raw_alert", "Not provided"),
                ip_addresses=fmt_list(iocs.ip_addresses),
                file_hashes=fmt_list(iocs.file_hashes),
                domains=fmt_list(iocs.domains),
                urls=fmt_list(iocs.urls),
                cve_ids=fmt_list(iocs.cve_ids),
                process_names=fmt_list(iocs.process_names),
                usernames=fmt_list(iocs.usernames),
                hostnames=fmt_list(iocs.hostnames),
                command_lines=fmt_list(iocs.command_lines),
                registry_keys=fmt_list(iocs.registry_keys),
                abuseipdb_results=fmt_results(state.get("abuseipdb_results", [])),
                virustotal_results=fmt_results(state.get("virustotal_results", [])),
                cve_results=fmt_results(state.get("cve_results", [])),
                mitre_results=fmt_results(state.get("mitre_results", [])),
                sigma_results=fmt_results(state.get("sigma_results", [])),
                rag_context=state.get("rag_context", "No knowledge retrieved."),
                prior_incidents=fmt_results(state.get("prior_incidents", [])),
                memory_context=state.get("memory_context", "No prior session context."),
                thread_id=state.get("thread_id", "default"),
            )
        ),
    ]
