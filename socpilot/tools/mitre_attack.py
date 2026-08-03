"""
SOCPilot AI — MITRE ATT&CK Tool Node
=======================================
Provides offline MITRE ATT&CK technique lookups for observed IoCs.
No external API required — technique data is embedded directly.

Mapping logic:
- Suspicious process names → specific techniques
- Command-line patterns → specific techniques
- Registry keys, domains → relevant techniques
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List

logger = logging.getLogger(__name__)

# ── Embedded MITRE ATT&CK Knowledge Base ─────────────────────────────────────
# Maps lowercase process name (or pattern) → technique(s)

PROCESS_TO_TECHNIQUES: Dict[str, List[Dict[str, str]]] = {
    "powershell.exe": [
        {
            "technique_id": "T1059.001",
            "technique_name": "Command and Scripting Interpreter: PowerShell",
            "tactic": "Execution",
            "sub_technique": "PowerShell",
            "description": (
                "Adversaries abuse PowerShell for execution, discovery, lateral movement, "
                "and data exfiltration. Encoded commands (-enc/-EncodedCommand) and download "
                "cradles (IEX + WebClient) are common evasion techniques."
            ),
        },
        {
            "technique_id": "T1027",
            "technique_name": "Obfuscated Files or Information",
            "tactic": "Defense Evasion",
            "sub_technique": "Base64 encoded commands",
            "description": (
                "PowerShell -enc (EncodedCommand) is used to obfuscate malicious commands "
                "in Base64 to evade string-based detection rules."
            ),
        },
    ],
    "powershell": [
        {
            "technique_id": "T1059.001",
            "technique_name": "Command and Scripting Interpreter: PowerShell",
            "tactic": "Execution",
            "sub_technique": None,
            "description": "PowerShell interpreter used for malicious execution.",
        },
    ],
    "rundll32.exe": [
        {
            "technique_id": "T1218.011",
            "technique_name": "System Binary Proxy Execution: Rundll32",
            "tactic": "Defense Evasion",
            "sub_technique": "Rundll32",
            "description": (
                "Rundll32.exe is used to execute malicious DLLs or scripts while bypassing "
                "application whitelisting. Common patterns include JavaScript and VBScript execution."
            ),
        },
    ],
    "mshta.exe": [
        {
            "technique_id": "T1218.005",
            "technique_name": "System Binary Proxy Execution: Mshta",
            "tactic": "Defense Evasion",
            "sub_technique": "Mshta",
            "description": (
                "Mshta.exe executes HTA files and scripts, commonly used to deliver RATs and "
                "malware downloaders. Often spawned from phishing emails or macro documents."
            ),
        },
    ],
    "wmic.exe": [
        {
            "technique_id": "T1047",
            "technique_name": "Windows Management Instrumentation",
            "tactic": "Execution",
            "sub_technique": None,
            "description": (
                "WMI is used for remote code execution, discovery, and persistence. "
                "'wmic process call create' executes arbitrary commands. "
                "Remote wmic calls indicate lateral movement attempts."
            ),
        },
    ],
    "certutil.exe": [
        {
            "technique_id": "T1105",
            "technique_name": "Ingress Tool Transfer",
            "tactic": "Command and Control",
            "sub_technique": None,
            "description": (
                "Certutil.exe is abused to download files from remote URLs "
                "(-urlcache -split -f) and decode Base64-encoded payloads (-decode)."
            ),
        },
        {
            "technique_id": "T1140",
            "technique_name": "Deobfuscate/Decode Files or Information",
            "tactic": "Defense Evasion",
            "sub_technique": None,
            "description": (
                "Certutil's decode functionality is used to deobfuscate payloads "
                "that were encoded to evade AV detection."
            ),
        },
    ],
    "regsvr32.exe": [
        {
            "technique_id": "T1218.010",
            "technique_name": "System Binary Proxy Execution: Regsvr32",
            "tactic": "Defense Evasion",
            "sub_technique": "Squiblydoo",
            "description": (
                "Regsvr32.exe (Squiblydoo attack) loads remote COM scriptlets to execute "
                "arbitrary code while bypassing AppLocker. Uses /i:URL argument pattern."
            ),
        },
    ],
    "bitsadmin.exe": [
        {
            "technique_id": "T1197",
            "technique_name": "BITS Jobs",
            "tactic": "Defense Evasion",
            "sub_technique": None,
            "description": (
                "BITS (Background Intelligent Transfer Service) is abused to download "
                "malicious files and achieve persistence. BITS jobs survive system reboots."
            ),
        },
    ],
    "cscript.exe": [
        {
            "technique_id": "T1059.005",
            "technique_name": "Command and Scripting Interpreter: Visual Basic",
            "tactic": "Execution",
            "sub_technique": "VBScript via cscript",
            "description": (
                "Cscript.exe executes VBScript files (.vbs). Adversaries use it to run "
                "malicious scripts that download payloads or establish persistence."
            ),
        },
    ],
    "wscript.exe": [
        {
            "technique_id": "T1059.005",
            "technique_name": "Command and Scripting Interpreter: Visual Basic",
            "tactic": "Execution",
            "sub_technique": "VBScript via wscript",
            "description": (
                "Wscript.exe executes VBScript (.vbs) and JScript (.js) files. "
                "Commonly used to execute phishing attachment payloads."
            ),
        },
    ],
    "cmd.exe": [
        {
            "technique_id": "T1059.003",
            "technique_name": "Command and Scripting Interpreter: Windows Command Shell",
            "tactic": "Execution",
            "sub_technique": None,
            "description": (
                "cmd.exe is used for command execution, piping commands, and spawning "
                "child processes. Suspicious when spawned from non-interactive parents."
            ),
        },
    ],
    "msiexec.exe": [
        {
            "technique_id": "T1218.007",
            "technique_name": "System Binary Proxy Execution: Msiexec",
            "tactic": "Defense Evasion",
            "sub_technique": None,
            "description": (
                "Msiexec.exe can execute remote .msi packages. Adversaries use it to "
                "bypass application whitelisting and deliver malicious installers."
            ),
        },
    ],
    "schtasks.exe": [
        {
            "technique_id": "T1053.005",
            "technique_name": "Scheduled Task/Job: Scheduled Task",
            "tactic": "Persistence",
            "sub_technique": "Scheduled Task",
            "description": (
                "Schtasks.exe creates scheduled tasks for persistence or privilege escalation. "
                "Commonly used to execute payloads at logon or on a recurring schedule."
            ),
        },
    ],
}

# Additional technique context for command-line patterns
COMMAND_LINE_TECHNIQUES: List[Dict[str, Any]] = [
    {
        "pattern": "-enc",
        "technique_id": "T1027",
        "technique_name": "Obfuscated Files or Information",
        "tactic": "Defense Evasion",
        "description": "Base64-encoded PowerShell command detected (-enc/-EncodedCommand).",
    },
    {
        "pattern": "-encodedcommand",
        "technique_id": "T1027",
        "technique_name": "Obfuscated Files or Information",
        "tactic": "Defense Evasion",
        "description": "Base64-encoded PowerShell command detected (-EncodedCommand).",
    },
    {
        "pattern": "invoke-expression",
        "technique_id": "T1059.001",
        "technique_name": "PowerShell IEX download cradle",
        "tactic": "Execution",
        "description": "PowerShell IEX download cradle pattern — downloads and executes remote code.",
    },
    {
        "pattern": "downloadstring",
        "technique_id": "T1105",
        "technique_name": "Ingress Tool Transfer",
        "tactic": "Command and Control",
        "description": "WebClient.DownloadString() used to download content from attacker infrastructure.",
    },
    {
        "pattern": "urlcache",
        "technique_id": "T1105",
        "technique_name": "Ingress Tool Transfer",
        "tactic": "Command and Control",
        "description": "Certutil -urlcache used to download files from a URL.",
    },
    {
        "pattern": "vssadmin delete shadows",
        "technique_id": "T1490",
        "technique_name": "Inhibit System Recovery",
        "tactic": "Impact",
        "description": "Volume shadow copies deleted to prevent system recovery (ransomware indicator).",
    },
    {
        "pattern": "sekurlsa",
        "technique_id": "T1003.001",
        "technique_name": "OS Credential Dumping: LSASS Memory",
        "tactic": "Credential Access",
        "description": "Mimikatz sekurlsa module detected — LSASS credential dumping attempted.",
    },
    {
        "pattern": "net user /add",
        "technique_id": "T1136.001",
        "technique_name": "Create Account: Local Account",
        "tactic": "Persistence",
        "description": "New local user account creation detected — possible backdoor account.",
    },
    {
        "pattern": "reg add",
        "technique_id": "T1547.001",
        "technique_name": "Boot or Logon Autostart Execution: Registry Run Keys",
        "tactic": "Persistence",
        "description": "Registry modification to add autostart entry for persistence.",
    },
]


async def run_mitre_lookup(state: dict) -> dict:
    """
    LangGraph node: Map observed IoCs to MITRE ATT&CK techniques.

    Examines:
    - state["iocs"].process_names → process-to-technique mappings
    - state["iocs"].command_lines → command-line pattern matching

    Returns:
        State update dict with "mitre_results" key populated.
    """
    from socpilot.models.ioc_models import ExtractedIoCs

    iocs: ExtractedIoCs = state.get("iocs") or ExtractedIoCs()
    results: List[Dict[str, Any]] = []
    seen_technique_ids: set = set()

    # ── Process name matching ─────────────────────────────────────────────────
    for process in iocs.process_names:
        process_lower = process.lower()
        techniques = PROCESS_TO_TECHNIQUES.get(process_lower, [])

        for technique in techniques:
            tid = technique["technique_id"]
            if tid not in seen_technique_ids:
                seen_technique_ids.add(tid)
                results.append(
                    {
                        **technique,
                        "triggered_by": process,
                        "source": "MITRE ATT&CK (embedded)",
                    }
                )
                logger.info(
                    "MITRE matched: %s → %s (%s)",
                    process,
                    tid,
                    technique["technique_name"],
                )

    # ── Command-line pattern matching ─────────────────────────────────────────
    all_commands = " ".join(iocs.command_lines).lower()
    for pattern_entry in COMMAND_LINE_TECHNIQUES:
        pattern = pattern_entry["pattern"].lower()
        if pattern in all_commands:
            tid = pattern_entry["technique_id"]
            if tid not in seen_technique_ids:
                seen_technique_ids.add(tid)
                results.append(
                    {
                        "technique_id": pattern_entry["technique_id"],
                        "technique_name": pattern_entry["technique_name"],
                        "tactic": pattern_entry["tactic"],
                        "sub_technique": None,
                        "description": pattern_entry["description"],
                        "triggered_by": f"command pattern: '{pattern_entry['pattern']}'",
                        "source": "MITRE ATT&CK (command pattern match)",
                    }
                )
                logger.info("MITRE command match: '%s' → %s", pattern, tid)

    if not results:
        logger.info("No MITRE mappings found for current IoCs")

    notes = [f"MITRE ATT&CK: {len(results)} technique(s) mapped"]
    existing_notes = state.get("processing_notes", [])

    return {
        "mitre_results": results,
        "processing_notes": existing_notes + notes,
    }
