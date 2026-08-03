"""
SOCPilot AI — Base SIEM Adapter
=================================
Abstract interface that every SIEM adapter must implement.

Design contract:
  - Each adapter receives the raw JSON payload sent by its SIEM.
  - It must return a human-readable alert text string.
  - The alert text is passed directly into the SOCPilot investigation pipeline
    (alert_ingest_node), so it should contain as much context as possible:
    hostnames, IPs, hashes, rule names, timestamps, severity, raw log lines, etc.

To add a new SIEM (e.g. Splunk):
  1. Create integrations/splunk.py
  2. Subclass BaseSIEMAdapter
  3. Override normalize()
  4. Register it in integrations/registry.py
"""

from __future__ import annotations

from abc import ABC, abstractmethod


class BaseSIEMAdapter(ABC):
    """
    Abstract base class for all SIEM adapters.

    Each concrete subclass handles one SIEM's alert JSON format and
    converts it to a plain-text alert string understood by SOCPilot.
    """

    @abstractmethod
    def normalize(self, raw_payload: dict) -> str:
        """
        Convert a SIEM-specific JSON payload to SOCPilot alert text.

        Args:
            raw_payload: The raw dictionary parsed from the SIEM's JSON body.

        Returns:
            A human-readable alert string ready for SOCPilot investigation.
            Should include: alert name, severity, hostname, source IPs,
            usernames, process names, hashes, and any available raw log line.

        Raises:
            ValueError: If the payload is missing required fields or
                        cannot be meaningfully normalized.
        """
        ...

    def get_severity_level(self, raw_payload: dict) -> int:
        """
        Extract a numeric severity level from the payload.

        Used by the server to filter low-severity alerts before investigation.
        Subclasses should override this to return the SIEM's native severity.

        Returns:
            Integer severity. Convention:
              - Wazuh: 1–15  (returned as-is)
              - Override in each adapter to normalise to this scale if needed.
            Default: 0 (always pass the filter if not overridden).
        """
        return 0
