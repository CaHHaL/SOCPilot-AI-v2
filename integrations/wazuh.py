"""
SOCPilot AI — Wazuh SIEM Adapter
==================================
Normalizes Wazuh alert JSON payloads into SOCPilot alert text.

Wazuh sends alerts in a well-defined JSON structure via its Custom Integration
feature. This adapter extracts the most relevant fields and formats them into
the human-readable text that SOCPilot's alert_ingest_node expects.

Wazuh alert JSON structure (simplified):
{
  "timestamp": "2024-01-15T10:23:45.123+0000",
  "rule": {
    "id": "100002",
    "level": 10,
    "description": "Suspicious PowerShell execution",
    "groups": ["windows", "powershell"],
    "mitre": {
      "technique": ["T1059.001"]
    }
  },
  "agent": {
    "id": "001",
    "name": "HR-PC-21",
    "ip": "192.168.1.50"
  },
  "manager": {"name": "wazuh-manager"},
  "id": "1705314225.12345",
  "full_log": "Jan 15 10:23:45 WinEvtLog: Security...",
  "syscheck": {
    "path": "C:\\Windows\\Temp\\evil.exe",
    "sha256_after": "44d88612fea8a8f36de82e1278abb02f...",
    "md5_after": "44d88612fea8a8f36de82e1278abb02f"
  },
  "data": {
    "srcip": "185.220.101.34",
    "dstip": "10.0.0.1",
    "win": {
      "eventdata": {
        "commandLine": "powershell -enc SQBmAC...",
        "user": "john"
      },
      "system": {
        "computer": "HR-PC-21",
        "eventID": "4688"
      }
    },
    "protocol": "tcp",
    "srcport": "45123"
  }
}
"""

from __future__ import annotations

import logging
from typing import Any, Dict

from integrations.base import BaseSIEMAdapter

logger = logging.getLogger(__name__)


class WazuhAdapter(BaseSIEMAdapter):
    """
    Adapter for Wazuh SIEM alert JSON payloads.

    Extracts all relevant fields from Wazuh's alert structure and produces
    a rich, human-readable alert text suitable for SOCPilot investigation.
    """

    def normalize(self, raw_payload: dict) -> str:
        """
        Convert a Wazuh alert JSON payload to SOCPilot alert text.

        Args:
            raw_payload: Parsed Wazuh alert JSON dictionary.

        Returns:
            Formatted alert string with all available IoC context.
        """
        lines: list[str] = []

        # ── Header ────────────────────────────────────────────────────────────
        lines.append("=== WAZUH SIEM ALERT ===")

        # Timestamp
        timestamp = raw_payload.get("timestamp", "Unknown")
        lines.append(f"Timestamp: {timestamp}")

        # ── Rule Information ──────────────────────────────────────────────────
        rule: Dict[str, Any] = raw_payload.get("rule", {})
        rule_id = rule.get("id", "N/A")
        rule_level = rule.get("level", "N/A")
        rule_desc = rule.get("description", "No description")
        rule_groups = ", ".join(rule.get("groups", []))

        lines.append(f"\nAlert Name: {rule_desc}")
        lines.append(f"Rule ID: {rule_id}")
        lines.append(f"Severity Level: {rule_level}/15")
        if rule_groups:
            lines.append(f"Rule Groups: {rule_groups}")

        # MITRE ATT&CK techniques from rule metadata
        mitre = rule.get("mitre", {})
        techniques = mitre.get("technique", [])
        if techniques:
            lines.append(f"MITRE ATT&CK Techniques: {', '.join(techniques)}")

        # ── Agent (Endpoint) Information ──────────────────────────────────────
        agent: Dict[str, Any] = raw_payload.get("agent", {})
        agent_name = agent.get("name", "Unknown")
        agent_ip = agent.get("ip", None)

        lines.append(f"\nHostname: {agent_name}")
        if agent_ip and agent_ip not in ("127.0.0.1", "any"):
            lines.append(f"Agent IP: {agent_ip}")

        # Manager
        manager_name = raw_payload.get("manager", {}).get("name", None)
        if manager_name:
            lines.append(f"Wazuh Manager: {manager_name}")

        # ── Network / Data Fields ─────────────────────────────────────────────
        data: Dict[str, Any] = raw_payload.get("data", {})

        src_ip = data.get("srcip", None)
        dst_ip = data.get("dstip", None)
        src_port = data.get("srcport", None)
        dst_port = data.get("dstport", None)
        protocol = data.get("protocol", None)

        if src_ip:
            lines.append(f"\nSource IP: {src_ip}")
        if src_port:
            lines.append(f"Source Port: {src_port}")
        if dst_ip:
            lines.append(f"Destination IP: {dst_ip}")
        if dst_port:
            lines.append(f"Destination Port: {dst_port}")
        if protocol:
            lines.append(f"Protocol: {protocol}")

        # ── Windows Event Data ────────────────────────────────────────────────
        win_data: Dict[str, Any] = data.get("win", {})
        event_data: Dict[str, Any] = win_data.get("eventdata", {})
        win_system: Dict[str, Any] = win_data.get("system", {})

        user = event_data.get("user", data.get("dstuser", data.get("srcuser", None)))
        command_line = event_data.get("commandLine", event_data.get("command", None))
        process_name = event_data.get("image", event_data.get("parentImage", None))
        event_id = win_system.get("eventID", data.get("id", None))
        win_computer = win_system.get("computer", None)

        if user:
            lines.append(f"\nUser: {user}")
        if win_computer and win_computer != agent_name:
            lines.append(f"Computer: {win_computer}")
        if event_id:
            lines.append(f"Event ID: {event_id}")
        if process_name:
            lines.append(f"Process: {process_name}")
        if command_line:
            lines.append(f"Command Line: {command_line}")

        # ── File Integrity Monitoring (Syscheck) ──────────────────────────────
        syscheck: Dict[str, Any] = raw_payload.get("syscheck", {})
        file_path = syscheck.get("path", None)
        sha256 = syscheck.get("sha256_after", syscheck.get("sha256_before", None))
        md5 = syscheck.get("md5_after", syscheck.get("md5_before", None))
        sha1 = syscheck.get("sha1_after", syscheck.get("sha1_before", None))

        if file_path:
            lines.append(f"\nFile Path: {file_path}")
        if sha256:
            lines.append(f"SHA256: {sha256}")
        if sha1:
            lines.append(f"SHA1: {sha1}")
        if md5:
            lines.append(f"MD5: {md5}")

        # ── Vulnerability Data ────────────────────────────────────────────────
        vulnerability: Dict[str, Any] = raw_payload.get("vulnerability", {})
        cve_id = vulnerability.get("cve", None)
        cve_severity = vulnerability.get("severity", None)
        package_name = vulnerability.get("package", {}).get("name", None)
        package_version = vulnerability.get("package", {}).get("version", None)

        if cve_id:
            lines.append(f"\nCVE: {cve_id}")
        if cve_severity:
            lines.append(f"CVE Severity: {cve_severity}")
        if package_name:
            lines.append(f"Vulnerable Package: {package_name} {package_version or ''}".strip())

        # ── Network Traffic (Zeek/Suricata integration) ───────────────────────
        # Some Wazuh rules decode Suricata/Zeek fields
        suricata_alert = data.get("alert", {})
        suricata_sig = suricata_alert.get("signature", None)
        suricata_category = suricata_alert.get("category", None)
        if suricata_sig:
            lines.append(f"\nIDS Signature: {suricata_sig}")
        if suricata_category:
            lines.append(f"IDS Category: {suricata_category}")

        # ── URL / Domain Fields ───────────────────────────────────────────────
        url = data.get("url", data.get("http", {}).get("url", None))
        domain = data.get("domain", data.get("dns", {}).get("question", {}).get("name", None))
        if url:
            lines.append(f"\nURL: {url}")
        if domain:
            lines.append(f"Domain: {domain}")

        # ── Raw Log Line ──────────────────────────────────────────────────────
        full_log = raw_payload.get("full_log", None)
        if full_log:
            lines.append(f"\nRaw Log:\n{full_log}")

        # ── Alert ID for traceability ─────────────────────────────────────────
        alert_id = raw_payload.get("id", raw_payload.get("_id", None))
        if alert_id:
            lines.append(f"\nWazuh Alert ID: {alert_id}")

        alert_text = "\n".join(lines)
        logger.debug("WazuhAdapter normalized alert:\n%s", alert_text)
        return alert_text

    def get_severity_level(self, raw_payload: dict) -> int:
        """
        Return the Wazuh rule level (1–15) from the payload.

        Wazuh levels:
          1–3   : Informational / low-risk
          4–7   : Low / medium
          8–11  : High
          12–15 : Critical
        """
        try:
            return int(raw_payload.get("rule", {}).get("level", 0))
        except (TypeError, ValueError):
            return 0
