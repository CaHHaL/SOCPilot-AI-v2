"""
SOCPilot AI — SOC Investigation Report Models
===============================================
Pydantic v2 models for the structured report produced after investigation.
All fields are typed; the report is serialisable to both JSON and Markdown.
"""

from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Dict, List, Optional

from pydantic import BaseModel, Field, field_validator


# ── Enumerations ──────────────────────────────────────────────────────────────


class SeverityLevel(str, Enum):
    """Standardised severity tiers aligned with NIST/CVSS conventions."""

    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class Verdict(str, Enum):
    """Verdict for a threat intelligence finding."""

    MALICIOUS = "MALICIOUS"
    SUSPICIOUS = "SUSPICIOUS"
    CLEAN = "CLEAN"
    UNKNOWN = "UNKNOWN"


# ── Sub-models ────────────────────────────────────────────────────────────────


class ThreatIntelFinding(BaseModel):
    """
    A single threat intelligence finding from one external data source.
    Produced by tools such as AbuseIPDB and VirusTotal.
    """

    source: str = Field(description="Name of the intelligence source (e.g., 'AbuseIPDB').")
    ioc: str = Field(description="The specific IoC that was queried.")
    ioc_type: str = Field(description="Type of IoC: ip, hash, domain, url, cve.")
    verdict: Verdict = Field(description="Overall verdict for this IoC.")
    confidence: float = Field(
        ge=0.0,
        le=1.0,
        description="Confidence score of the finding (0.0 – 1.0).",
    )
    details: Dict[str, str] = Field(
        default_factory=dict,
        description="Source-specific key-value details.",
    )
    raw_risk_score: Optional[int] = Field(
        default=None,
        ge=0,
        le=100,
        description="Numeric risk/abuse score from the source (0–100), if provided.",
    )


class MitreMapping(BaseModel):
    """
    A mapping of observed behaviour to a MITRE ATT&CK technique.
    """

    technique_id: str = Field(
        description="MITRE technique identifier (e.g., 'T1059.001').",
        examples=["T1059.001"],
    )
    technique_name: str = Field(
        description="Human-readable technique name.",
        examples=["Command and Scripting Interpreter: PowerShell"],
    )
    tactic: str = Field(
        description="MITRE tactic category.",
        examples=["Execution"],
    )
    sub_technique: Optional[str] = Field(
        default=None,
        description="Sub-technique description if applicable.",
    )
    description: str = Field(description="Brief description of why this technique was matched.")
    triggered_by: str = Field(description="The IoC or observation that triggered this mapping.")


class SigmaRule(BaseModel):
    """
    A Sigma detection rule that matches activity observed in the alert.
    """

    rule_id: str = Field(description="Unique Sigma rule identifier (UUID or slug).")
    title: str = Field(description="Human-readable rule title.")
    description: str = Field(description="What the rule detects.")
    severity: SeverityLevel = Field(description="Rule severity level.")
    detection_logic: str = Field(
        description="Abbreviated detection condition in Sigma-like pseudo-syntax."
    )
    tags: List[str] = Field(
        default_factory=list,
        description="ATT&CK tags and other labels.",
    )
    triggered_by: str = Field(description="The process or IoC that triggered this rule.")


class RelatedIncident(BaseModel):
    """
    A prior SOC incident retrieved from long-term memory (ChromaDB).
    """

    incident_id: str = Field(description="Unique identifier of the historical incident.")
    summary: str = Field(description="Brief summary of the prior incident.")
    similarity_score: float = Field(
        ge=0.0,
        le=1.0,
        description="Semantic similarity score to the current alert.",
    )
    iocs_overlap: List[str] = Field(
        default_factory=list,
        description="IoCs shared between this incident and the current alert.",
    )
    resolved: bool = Field(
        default=False,
        description="Whether the historical incident was resolved.",
    )


# ── Main Report ───────────────────────────────────────────────────────────────


class SOCReport(BaseModel):
    """
    The complete, structured SOC investigation report.

    This is the final output of the SOCPilot AI pipeline. It aggregates
    findings from all enrichment sources: threat intel tools, MITRE ATT&CK,
    Sigma rules, RAG context, and long-term memory.
    """

    # ── Identity ──────────────────────────────────────────────────────────────
    report_id: str = Field(description="Unique report identifier (UUID).")
    investigation_timestamp: datetime = Field(
        default_factory=datetime.utcnow,
        description="UTC timestamp of the investigation.",
    )
    thread_id: str = Field(
        default="default",
        description="Session thread ID for memory continuity.",
    )

    # ── Alert Context ─────────────────────────────────────────────────────────
    alert_summary: str = Field(
        description=(
            "A concise 2–4 sentence summary of the security alert, "
            "written from the perspective of a SOC analyst."
        )
    )
    extracted_iocs: Dict[str, List[str]] = Field(
        description="All IoCs extracted, keyed by type (ip_addresses, file_hashes, etc.).",
    )

    # ── Intelligence Findings ─────────────────────────────────────────────────
    threat_intel_findings: List[ThreatIntelFinding] = Field(
        default_factory=list,
        description="Findings from external threat intelligence tools.",
    )
    mitre_mappings: List[MitreMapping] = Field(
        default_factory=list,
        description="Matched MITRE ATT&CK techniques.",
    )
    sigma_detections: List[SigmaRule] = Field(
        default_factory=list,
        description="Matched Sigma detection rules.",
    )
    related_incidents: List[RelatedIncident] = Field(
        default_factory=list,
        description="Prior SOC incidents retrieved from long-term memory.",
    )

    # ── RAG Context ───────────────────────────────────────────────────────────
    rag_context_summary: str = Field(
        default="",
        description="Summary of cybersecurity knowledge retrieved from the RAG corpus.",
    )

    # ── Risk Assessment ───────────────────────────────────────────────────────
    risk_score: int = Field(
        ge=0,
        le=100,
        description="Composite risk score (0–100). 0=no risk, 100=critical threat.",
    )
    severity: SeverityLevel = Field(
        description="Derived severity classification based on risk score and context.",
    )
    confidence_score: float = Field(
        ge=0.0,
        le=1.0,
        description=(
            "Analyst confidence in the investigation findings (0.0–1.0). "
            "Reflects data completeness and evidence quality."
        ),
    )

    # ── Analyst Output ────────────────────────────────────────────────────────
    analyst_reasoning: str = Field(
        description=(
            "Detailed reasoning chain explaining how the analyst arrived "
            "at the conclusions, connecting IoCs, TTPs, and context."
        )
    )
    recommended_actions: List[str] = Field(
        description=(
            "Ordered list of recommended response actions for the SOC team. "
            "Start with the most urgent actions."
        )
    )
    escalation_required: bool = Field(
        description="Whether this alert should be escalated to a senior analyst or IR team.",
    )
    false_positive_likelihood: str = Field(
        default="UNKNOWN",
        description="Assessment of false-positive probability: LOW, MEDIUM, HIGH.",
    )

    @field_validator("risk_score")
    @classmethod
    def derive_severity_from_score(cls, v: int) -> int:
        """Validate risk score is in valid range."""
        if not 0 <= v <= 100:
            raise ValueError("risk_score must be between 0 and 100")
        return v

    @property
    def severity_from_score(self) -> SeverityLevel:
        """Compute severity purely from the numeric risk score."""
        if self.risk_score >= 80:
            return SeverityLevel.CRITICAL
        elif self.risk_score >= 60:
            return SeverityLevel.HIGH
        elif self.risk_score >= 35:
            return SeverityLevel.MEDIUM
        else:
            return SeverityLevel.LOW
