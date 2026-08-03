"""
SOCPilot AI — Sigma Rules Tool Node
=====================================
Provides offline Sigma detection rule matching for observed IoCs.
No external API required — rules are embedded directly.

Sigma is the standard for writing SIEM detection rules. This module
contains a curated set of high-value Sigma rules for common attack
patterns, mapped to suspicious process names and command-line patterns.
"""

from __future__ import annotations

import logging
import uuid
from typing import Any, Dict, List

logger = logging.getLogger(__name__)


# ── Embedded Sigma Rule Library ───────────────────────────────────────────────
# Each rule is keyed by the process/pattern that triggers it.

SIGMA_RULES: List[Dict[str, Any]] = [
    # ── PowerShell Rules ──────────────────────────────────────────────────────
    {
        "rule_id": "8f23cfb5-4b60-4629-9d54-66b07ed53b5f",
        "title": "Suspicious PowerShell Encoded Command Execution",
        "description": (
            "Detects execution of PowerShell with -EncodedCommand or -enc argument, "
            "which is commonly used by attackers to obfuscate malicious scripts."
        ),
        "severity": "HIGH",
        "tags": ["attack.execution", "attack.t1059.001", "attack.defense_evasion", "attack.t1027"],
        "detection_logic": (
            "process.name = 'powershell.exe' AND "
            "(process.args contains '-enc' OR process.args contains '-EncodedCommand' "
            "OR process.args contains '-e ') AND process.args contains_any ['JAB', 'SQBm', 'SQBF']"
        ),
        "triggers": ["powershell.exe", "powershell"],
        "command_triggers": ["-enc", "-encodedcommand"],
    },
    {
        "rule_id": "a7205ce7-1df4-4f6b-9b73-06a2c0b87741",
        "title": "PowerShell Download Cradle Detected",
        "description": (
            "Detects PowerShell downloading content from the internet using common "
            "download cradle patterns (WebClient, Invoke-WebRequest, IEX)."
        ),
        "severity": "HIGH",
        "tags": ["attack.command_and_control", "attack.t1105", "attack.execution", "attack.t1059.001"],
        "detection_logic": (
            "process.name = 'powershell.exe' AND process.args contains_any "
            "['DownloadString', 'DownloadFile', 'Invoke-WebRequest', 'iwr', 'WebClient', 'curl']"
        ),
        "triggers": ["powershell.exe", "powershell"],
        "command_triggers": ["downloadstring", "downloadfile", "invoke-webrequest"],
    },
    {
        "rule_id": "f3a5e7c1-9b2d-4e8f-a1c6-3d7f8e9a2b5c",
        "title": "PowerShell Execution Policy Bypass",
        "description": (
            "Detects PowerShell invoked with execution policy bypass flags, commonly "
            "used to run unsigned scripts without user awareness."
        ),
        "severity": "MEDIUM",
        "tags": ["attack.defense_evasion", "attack.t1059.001"],
        "detection_logic": (
            "process.name = 'powershell.exe' AND process.args contains_any "
            "['-ExecutionPolicy Bypass', '-ep bypass', '-noprofile', '-noninteractive', '-windowstyle hidden']"
        ),
        "triggers": ["powershell.exe", "powershell"],
        "command_triggers": ["executionpolicy bypass", "-ep bypass", "windowstyle hidden"],
    },
    # ── LOLBin Rules ──────────────────────────────────────────────────────────
    {
        "rule_id": "b9c4d2e8-3f7a-4d1e-8c5f-9a6b7e2d3f1a",
        "title": "Mshta Executing Remote HTA File",
        "description": (
            "Detects mshta.exe executing an HTML Application file from a remote URL, "
            "which is a common technique for delivering malware droppers."
        ),
        "severity": "HIGH",
        "tags": ["attack.defense_evasion", "attack.t1218.005", "attack.execution"],
        "detection_logic": (
            "process.name = 'mshta.exe' AND process.args matches_regex 'https?://'"
        ),
        "triggers": ["mshta.exe"],
        "command_triggers": [],
    },
    {
        "rule_id": "c1d5e3f9-4a8b-5e2d-9f6c-0b7c8a1d4e2f",
        "title": "Certutil Downloading File from URL",
        "description": (
            "Detects certutil.exe being used to download files from the internet, "
            "a common living-off-the-land technique for tool delivery."
        ),
        "severity": "HIGH",
        "tags": ["attack.command_and_control", "attack.t1105", "attack.defense_evasion"],
        "detection_logic": (
            "process.name = 'certutil.exe' AND process.args contains '-urlcache'"
        ),
        "triggers": ["certutil.exe"],
        "command_triggers": ["urlcache"],
    },
    {
        "rule_id": "d2e6f4a0-5b9c-6f3e-0a7d-1c8d9b2e5f3a",
        "title": "Certutil Base64 Decode Operation",
        "description": (
            "Detects certutil.exe used to decode Base64-encoded files, "
            "often used to unpack obfuscated payloads on the target system."
        ),
        "severity": "MEDIUM",
        "tags": ["attack.defense_evasion", "attack.t1140"],
        "detection_logic": (
            "process.name = 'certutil.exe' AND process.args contains '-decode'"
        ),
        "triggers": ["certutil.exe"],
        "command_triggers": ["-decode"],
    },
    {
        "rule_id": "e3f7a5b1-6c0d-7a4f-1b8e-2d9e0c3f6a4b",
        "title": "Rundll32 Executing Remote Script",
        "description": (
            "Detects rundll32.exe executing JavaScript or VBScript inline, "
            "or loading content from a remote URL (Squiblydoo-like pattern)."
        ),
        "severity": "HIGH",
        "tags": ["attack.defense_evasion", "attack.t1218.011"],
        "detection_logic": (
            "process.name = 'rundll32.exe' AND "
            "(process.args contains 'javascript:' OR process.args contains 'vbscript:' "
            "OR process.args matches_regex 'https?://')"
        ),
        "triggers": ["rundll32.exe"],
        "command_triggers": ["javascript:", "vbscript:"],
    },
    {
        "rule_id": "f4a8b6c2-7d1e-8b5a-2c9f-3e0f1d4a7b5c",
        "title": "WMI Remote Process Creation",
        "description": (
            "Detects wmic.exe used to create processes on remote systems, "
            "a common lateral movement technique."
        ),
        "severity": "HIGH",
        "tags": ["attack.execution", "attack.t1047", "attack.lateral_movement"],
        "detection_logic": (
            "process.name = 'wmic.exe' AND process.args contains 'process call create'"
        ),
        "triggers": ["wmic.exe"],
        "command_triggers": ["process call create"],
    },
    {
        "rule_id": "a5b9c7d3-8e2f-9c6b-3d0a-4f1a2e5b8c6d",
        "title": "Regsvr32 Remote Script Execution (Squiblydoo)",
        "description": (
            "Detects the Squiblydoo attack: regsvr32.exe used with /i: parameter "
            "to load and execute a remote COM scriptlet, bypassing AppLocker."
        ),
        "severity": "CRITICAL",
        "tags": ["attack.defense_evasion", "attack.t1218.010"],
        "detection_logic": (
            "process.name = 'regsvr32.exe' AND process.args contains '/i:' "
            "AND process.args matches_regex 'https?://'"
        ),
        "triggers": ["regsvr32.exe"],
        "command_triggers": [],
    },
    {
        "rule_id": "b6c0d8e4-9f3a-0d7c-4e1b-5a2b3f6c9d7e",
        "title": "BITS Job Used for File Download",
        "description": (
            "Detects bitsadmin.exe creating a BITS job to download content "
            "from an external URL, used for stealthy file downloads."
        ),
        "severity": "MEDIUM",
        "tags": ["attack.defense_evasion", "attack.t1197", "attack.persistence"],
        "detection_logic": (
            "process.name = 'bitsadmin.exe' AND process.args contains '/transfer'"
        ),
        "triggers": ["bitsadmin.exe"],
        "command_triggers": ["/transfer"],
    },
    # ── Persistence Rules ─────────────────────────────────────────────────────
    {
        "rule_id": "c7d1e9f5-0a4b-1e8d-5f2c-6b3c4a7d0e8f",
        "title": "Scheduled Task Created via Schtasks",
        "description": (
            "Detects creation of a scheduled task using schtasks.exe, "
            "a common persistence mechanism."
        ),
        "severity": "MEDIUM",
        "tags": ["attack.persistence", "attack.t1053.005"],
        "detection_logic": (
            "process.name = 'schtasks.exe' AND process.args contains '/create'"
        ),
        "triggers": ["schtasks.exe"],
        "command_triggers": ["/create"],
    },
    # ── Credential Access ─────────────────────────────────────────────────────
    {
        "rule_id": "d8e2f0a6-1b5c-2f9e-6a3d-7c4d5b8e1f9a",
        "title": "Mimikatz Credential Dumping Detected",
        "description": (
            "Detects Mimikatz credential dumping commands in command-line arguments. "
            "sekurlsa::logonpasswords dumps credentials from LSASS memory."
        ),
        "severity": "CRITICAL",
        "tags": ["attack.credential_access", "attack.t1003.001"],
        "detection_logic": (
            "process.args contains_any ['sekurlsa', 'lsadump', 'mimikatz', 'kerberos::golden']"
        ),
        "triggers": [],
        "command_triggers": ["sekurlsa", "lsadump", "kerberos::golden"],
    },
]


async def run_sigma_lookup(state: dict) -> dict:
    """
    LangGraph node: Match observed IoCs against embedded Sigma detection rules.

    Examines:
    - state["iocs"].process_names → trigger Sigma rules for those processes
    - state["iocs"].command_lines → trigger rules for command-line patterns

    Returns:
        State update dict with "sigma_results" key populated.
    """
    from socpilot.models.ioc_models import ExtractedIoCs

    iocs: ExtractedIoCs = state.get("iocs") or ExtractedIoCs()
    matched_rules: List[Dict[str, Any]] = []
    matched_rule_ids: set = set()

    # Build a set of triggered process names (lowercase)
    triggered_processes = {p.lower() for p in iocs.process_names}

    # Build a combined command-line string for pattern matching
    combined_commands = " ".join(iocs.command_lines).lower()

    for rule in SIGMA_RULES:
        rule_id = rule["rule_id"]
        if rule_id in matched_rule_ids:
            continue

        triggered = False
        trigger_reason = ""

        # Check process name triggers
        for trigger in rule.get("triggers", []):
            if trigger.lower() in triggered_processes:
                triggered = True
                trigger_reason = trigger
                break

        # Check command-line pattern triggers
        if not triggered:
            for cmd_trigger in rule.get("command_triggers", []):
                if cmd_trigger.lower() in combined_commands:
                    triggered = True
                    trigger_reason = f"command pattern: '{cmd_trigger}'"
                    break

        if triggered:
            matched_rule_ids.add(rule_id)
            matched_rules.append(
                {
                    "rule_id": rule["rule_id"],
                    "title": rule["title"],
                    "description": rule["description"],
                    "severity": rule["severity"],
                    "detection_logic": rule["detection_logic"],
                    "tags": rule["tags"],
                    "triggered_by": trigger_reason,
                    "source": "Sigma (embedded)",
                }
            )
            logger.info(
                "Sigma rule matched: '%s' [%s] triggered by: %s",
                rule["title"],
                rule["severity"],
                trigger_reason,
            )

    if not matched_rules:
        logger.info("No Sigma rules matched for current IoCs")

    notes = [f"Sigma: {len(matched_rules)} rule(s) matched"]
    existing_notes = state.get("processing_notes", [])

    return {
        "sigma_results": matched_rules,
        "processing_notes": existing_notes + notes,
    }
