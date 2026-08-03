"""
SOCPilot AI — SIEM Adapter Registry
=====================================
Central lookup table mapping SIEM name strings to their adapter classes.

To add a new SIEM integration:
  1. Create integrations/<siem_name>.py with a class inheriting BaseSIEMAdapter
  2. Import it here and add an entry to SIEM_REGISTRY
  3. That's it — no other files need to change.

Supported SIEMs:
  - wazuh  →  WazuhAdapter
"""

from __future__ import annotations

from typing import Dict, Type

from integrations.base import BaseSIEMAdapter
from integrations.wazuh import WazuhAdapter

# ── Registry ──────────────────────────────────────────────────────────────────
# Keys are the URL path segment used in POST /webhook/{siem_name}
# Values are the adapter class (not an instance — instantiated per request)

SIEM_REGISTRY: Dict[str, Type[BaseSIEMAdapter]] = {
    "wazuh": WazuhAdapter,
    # Future SIEMs — add here:
    # "splunk":   SplunkAdapter,
    # "sentinel": SentinelAdapter,
    # "elastic":  ElasticAdapter,
    # "qradar":   QRadarAdapter,
}


def get_adapter(siem_name: str) -> BaseSIEMAdapter:
    """
    Instantiate and return the adapter for a given SIEM name.

    Args:
        siem_name: Lowercase SIEM identifier (e.g. "wazuh").

    Returns:
        An instance of the matching BaseSIEMAdapter subclass.

    Raises:
        KeyError: If the SIEM name is not registered.
    """
    adapter_class = SIEM_REGISTRY[siem_name.lower()]
    return adapter_class()


def list_supported_siems() -> list[str]:
    """Return a sorted list of all registered SIEM names."""
    return sorted(SIEM_REGISTRY.keys())
