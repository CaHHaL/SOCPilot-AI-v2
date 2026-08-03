"""SOCPilot AI — Pydantic models for IoC extraction and alert metadata."""

from __future__ import annotations

from datetime import datetime
from typing import List, Optional

from pydantic import BaseModel, Field


class ExtractedIoCs(BaseModel):
    """
    All Indicators of Compromise extracted from a security alert.

    Each field is a list to support multiple values of the same type
    within a single alert. Empty lists indicate absence of that IoC type.
    """

    ip_addresses: List[str] = Field(
        default_factory=list,
        description="IPv4 or IPv6 addresses found in the alert.",
        examples=[["185.120.33.8", "10.0.0.5"]],
    )
    file_hashes: List[str] = Field(
        default_factory=list,
        description="MD5, SHA1, or SHA256 file hashes found in the alert.",
        examples=[["44d88612fea8a8f36de82e1278abb02f"]],
    )
    domains: List[str] = Field(
        default_factory=list,
        description="Fully-qualified domain names found in the alert.",
        examples=[["evil.example.com"]],
    )
    urls: List[str] = Field(
        default_factory=list,
        description="Full URLs found in the alert.",
        examples=[["http://malware.xyz/dropper.exe"]],
    )
    cve_ids: List[str] = Field(
        default_factory=list,
        description="CVE identifiers found in the alert (e.g., CVE-2021-44228).",
        examples=[["CVE-2021-44228"]],
    )
    process_names: List[str] = Field(
        default_factory=list,
        description="Suspicious process names observed in the alert.",
        examples=[["powershell.exe", "rundll32.exe"]],
    )
    email_addresses: List[str] = Field(
        default_factory=list,
        description="Email addresses found in the alert.",
        examples=[["attacker@evil.com"]],
    )
    registry_keys: List[str] = Field(
        default_factory=list,
        description="Windows registry keys found in the alert.",
        examples=[["HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"]],
    )
    usernames: List[str] = Field(
        default_factory=list,
        description="Usernames or account names mentioned in the alert.",
        examples=[["john", "DOMAIN\\jdoe"]],
    )
    hostnames: List[str] = Field(
        default_factory=list,
        description="Hostnames or machine names found in the alert.",
        examples=[["HR-PC-21", "DC-01"]],
    )
    command_lines: List[str] = Field(
        default_factory=list,
        description="Full command-line strings observed in the alert.",
        examples=[["powershell -enc SQBmAC..."]],
    )

    @property
    def has_ips(self) -> bool:
        return len(self.ip_addresses) > 0

    @property
    def has_hashes(self) -> bool:
        return len(self.file_hashes) > 0

    @property
    def has_cves(self) -> bool:
        return len(self.cve_ids) > 0

    @property
    def has_suspicious_processes(self) -> bool:
        """True if any process name matches known-suspicious executables."""
        suspicious = {
            "powershell.exe",
            "powershell",
            "cmd.exe",
            "rundll32.exe",
            "rundll32",
            "wmic.exe",
            "wmic",
            "mshta.exe",
            "mshta",
            "certutil.exe",
            "certutil",
            "regsvr32.exe",
            "regsvr32",
            "bitsadmin.exe",
            "bitsadmin",
            "cscript.exe",
            "wscript.exe",
            "msiexec.exe",
            "schtasks.exe",
        }
        return any(p.lower() in suspicious for p in self.process_names)

    @property
    def is_empty(self) -> bool:
        """True if no IoCs were extracted at all."""
        return not any(
            [
                self.ip_addresses,
                self.file_hashes,
                self.domains,
                self.urls,
                self.cve_ids,
                self.process_names,
                self.email_addresses,
                self.registry_keys,
                self.usernames,
                self.hostnames,
                self.command_lines,
            ]
        )

    def summary(self) -> str:
        """Human-readable one-liner summary of extracted IoCs."""
        parts = []
        if self.ip_addresses:
            parts.append(f"{len(self.ip_addresses)} IP(s)")
        if self.file_hashes:
            parts.append(f"{len(self.file_hashes)} hash(es)")
        if self.domains:
            parts.append(f"{len(self.domains)} domain(s)")
        if self.cve_ids:
            parts.append(f"{len(self.cve_ids)} CVE(s)")
        if self.process_names:
            parts.append(f"{len(self.process_names)} process(es)")
        if self.usernames:
            parts.append(f"{len(self.usernames)} username(s)")
        if self.hostnames:
            parts.append(f"{len(self.hostnames)} hostname(s)")
        return ", ".join(parts) if parts else "no IoCs detected"


class AlertMetadata(BaseModel):
    """Metadata associated with the ingested security alert."""

    raw_alert: str = Field(description="The original, unmodified alert text.")
    source: Optional[str] = Field(
        default=None,
        description="Alert source system (e.g., 'SIEM', 'EDR', 'Firewall').",
    )
    alert_name: Optional[str] = Field(
        default=None,
        description="Alert rule name or title if identifiable.",
    )
    hostname: Optional[str] = Field(
        default=None,
        description="Primary affected hostname.",
    )
    ingestion_time: datetime = Field(
        default_factory=datetime.utcnow,
        description="UTC timestamp when SOCPilot received this alert.",
    )
