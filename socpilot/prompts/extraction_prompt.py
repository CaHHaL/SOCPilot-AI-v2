"""
SOCPilot AI — IoC Extraction Prompts
======================================
Prompt templates used by the alert ingestion node to extract structured
Indicators of Compromise from free-text security alerts.

Design rationale:
- System prompt defines the extraction task precisely
- Human prompt injects the raw alert text
- Output is constrained to JSON matching ExtractedIoCs schema
- Regex patterns provide a deterministic fallback
"""

from __future__ import annotations

import re
from typing import List, Tuple

from langchain_core.messages import HumanMessage, SystemMessage

# ── System Prompt ─────────────────────────────────────────────────────────────

EXTRACTION_SYSTEM_PROMPT = """You are an expert cybersecurity analyst and SIEM engineer specialised in \
Indicator of Compromise (IoC) extraction from security alerts.

Your task is to extract ALL indicators from the provided security alert and return them in \
structured JSON format. Be thorough — extract every indicator present.

Extract the following IoC types:
- ip_addresses: Any IPv4 or IPv6 addresses (e.g., 185.120.33.8, 10.0.0.1)
- file_hashes: MD5 (32 hex chars), SHA1 (40 hex chars), SHA256 (64 hex chars)
- domains: Fully-qualified domain names (e.g., evil.example.com)
- urls: Complete URLs (e.g., http://malware.xyz/payload.exe)
- cve_ids: CVE identifiers (e.g., CVE-2021-44228)
- process_names: Executable names (e.g., powershell.exe, rundll32.exe, cmd.exe)
- email_addresses: Email addresses found in the alert
- registry_keys: Windows registry paths (e.g., HKCU\\Software\\...)
- usernames: Usernames, account names, or login names
- hostnames: Computer names, server names, hostnames
- command_lines: Full command-line strings observed

Rules:
1. Only extract IoCs explicitly present in the alert text — do not infer or guess.
2. If no IoCs of a type are present, return an empty list for that field.
3. Return ONLY valid JSON. No markdown, no explanation, no code fences.
4. Normalise process names to lowercase with the .exe extension if missing.
5. For IP addresses, include both source and destination if both are present.

Return this exact JSON structure:
{
  "ip_addresses": [],
  "file_hashes": [],
  "domains": [],
  "urls": [],
  "cve_ids": [],
  "process_names": [],
  "email_addresses": [],
  "registry_keys": [],
  "usernames": [],
  "hostnames": [],
  "command_lines": []
}"""


EXTRACTION_HUMAN_PROMPT = """Extract all Indicators of Compromise from the following security alert:

--- ALERT START ---
{alert_text}
--- ALERT END ---

Return only the JSON object with extracted IoCs. No other text."""


def build_extraction_messages(alert_text: str) -> List:
    """
    Build the message list for the IoC extraction LLM call.

    Args:
        alert_text: The raw security alert text.

    Returns:
        List of LangChain messages ready for chat model invocation.
    """
    return [
        SystemMessage(content=EXTRACTION_SYSTEM_PROMPT),
        HumanMessage(
            content=EXTRACTION_HUMAN_PROMPT.format(alert_text=alert_text)
        ),
    ]


# ── Regex Fallback Patterns ───────────────────────────────────────────────────
# Used when LLM extraction fails or as a validation layer.

class RegexExtractor:
    """
    Deterministic regex-based IoC extractor.

    Used as a fallback when the LLM is unavailable and as an optional
    validation/enrichment layer on top of LLM extractions.
    """

    # IPv4 addresses (with basic validation to exclude non-IPs like version numbers)
    IP_V4 = re.compile(
        r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}"
        r"(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b"
    )

    # MD5, SHA1, SHA256 hashes
    MD5 = re.compile(r"\b[0-9a-fA-F]{32}\b")
    SHA1 = re.compile(r"\b[0-9a-fA-F]{40}\b")
    SHA256 = re.compile(r"\b[0-9a-fA-F]{64}\b")

    # Domains (basic, avoids matching IP addresses)
    DOMAIN = re.compile(
        r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)"
        r"+[a-zA-Z]{2,}\b"
    )

    # URLs
    URL = re.compile(
        r"https?://[^\s\"'<>]+"
        r"|ftp://[^\s\"'<>]+"
    )

    # CVE identifiers
    CVE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE)

    # Suspicious process names (common LOLBins and shells)
    SUSPICIOUS_PROCESSES = re.compile(
        r"\b(powershell(?:\.exe)?|cmd(?:\.exe)?|rundll32(?:\.exe)?|"
        r"wmic(?:\.exe)?|mshta(?:\.exe)?|certutil(?:\.exe)?|"
        r"regsvr32(?:\.exe)?|bitsadmin(?:\.exe)?|cscript(?:\.exe)?|"
        r"wscript(?:\.exe)?|msiexec(?:\.exe)?|schtasks(?:\.exe)?|"
        r"net(?:\.exe)?|sc(?:\.exe)?|reg(?:\.exe)?)\b",
        re.IGNORECASE,
    )

    # Email addresses
    EMAIL = re.compile(r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Z|a-z]{2,}\b")

    # Registry keys
    REGISTRY = re.compile(
        r"\b(HKEY_LOCAL_MACHINE|HKLM|HKEY_CURRENT_USER|HKCU|"
        r"HKEY_CLASSES_ROOT|HKCR|HKEY_USERS|HKU)"
        r"\\[^\s\"'<>]+",
        re.IGNORECASE,
    )

    # Hostnames (simple heuristic: uppercase or hyphenated names that look like machines)
    HOSTNAME = re.compile(r"\b[A-Z]{2,}[-][A-Z]{2,}[-]\d+\b|\b[A-Z]+-PC-\d+\b|\bDC-\d+\b")

    @classmethod
    def extract(cls, text: str) -> dict:
        """
        Run all regex patterns against the alert text and return extracted IoCs.

        Args:
            text: The security alert text.

        Returns:
            Dict with the same keys as ExtractedIoCs.
        """
        # Extract hashes — longer matches take priority
        sha256 = list(set(cls.SHA256.findall(text)))
        remaining = cls.SHA256.sub("", text)
        sha1 = list(set(cls.SHA1.findall(remaining)))
        remaining = cls.SHA1.sub("", remaining)
        md5 = list(set(cls.MD5.findall(remaining)))

        all_hashes = sha256 + sha1 + md5

        # Extract IPs
        ips = list(set(cls.IP_V4.findall(text)))
        # Filter out IPs that look like version numbers (e.g., 1.0.0.0)
        ips = [ip for ip in ips if not all(int(o) <= 1 for o in ip.split("."))]

        # Extract domains (filter out things that look like version numbers)
        domains_raw = cls.DOMAIN.findall(text)
        # Remove IPs and known non-domains
        domains = [
            d for d in set(domains_raw)
            if not cls.IP_V4.match(d) and "." in d and len(d) > 4
        ]

        # Extract processes and normalise
        processes_raw = cls.SUSPICIOUS_PROCESSES.findall(text)
        processes = []
        for p in processes_raw:
            p_lower = p.lower()
            if not p_lower.endswith(".exe"):
                p_lower += ".exe"
            if p_lower not in processes:
                processes.append(p_lower)

        return {
            "ip_addresses": ips,
            "file_hashes": all_hashes,
            "domains": domains,
            "urls": list(set(cls.URL.findall(text))),
            "cve_ids": [c.upper() for c in set(cls.CVE.findall(text))],
            "process_names": processes,
            "email_addresses": list(set(cls.EMAIL.findall(text))),
            "registry_keys": list(set(cls.REGISTRY.findall(text))),
            "usernames": [],  # Regex alone is unreliable for usernames
            "hostnames": list(set(cls.HOSTNAME.findall(text))),
            "command_lines": [],  # Regex alone is unreliable for full command lines
        }
