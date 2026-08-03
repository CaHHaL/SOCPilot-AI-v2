"""
SOCPilot AI — AbuseIPDB Tool Node
===================================
Queries the AbuseIPDB API for IP address reputation scores.

API: https://www.abuseipdb.com/api
Endpoint: GET /api/v2/check
Authentication: API-Key header

Graceful degradation:
- If no API key is configured, returns a structured mock result with a warning.
- If the API call fails, returns an error result (does not raise exceptions).
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List

import requests

from socpilot.config.settings import settings

logger = logging.getLogger(__name__)

ABUSEIPDB_BASE_URL = "https://api.abuseipdb.com/api/v2"
REQUEST_TIMEOUT = 10  # seconds


def _check_ip(ip_address: str) -> Dict[str, Any]:
    """
    Query AbuseIPDB for a single IP address reputation.

    Args:
        ip_address: The IPv4 or IPv6 address to check.

    Returns:
        Normalised result dict with verdict and details.
    """
    if not settings.has_abuseipdb_key:
        logger.warning("AbuseIPDB API key not configured — returning mock result for %s", ip_address)
        return {
            "ioc": ip_address,
            "ioc_type": "ip",
            "source": "AbuseIPDB",
            "verdict": "UNKNOWN",
            "confidence": 0.0,
            "raw_risk_score": None,
            "details": {
                "note": "API key not configured. Set ABUSEIPDB_API_KEY in .env for live results.",
                "ip_address": ip_address,
            },
            "error": None,
        }

    try:
        response = requests.get(
            f"{ABUSEIPDB_BASE_URL}/check",
            headers={
                "Key": settings.abuseipdb_api_key,
                "Accept": "application/json",
            },
            params={
                "ipAddress": ip_address,
                "maxAgeInDays": 90,
                "verbose": "",
            },
            timeout=REQUEST_TIMEOUT,
        )
        response.raise_for_status()
        data = response.json().get("data", {})

        abuse_score = int(data.get("abuseConfidenceScore", 0))
        total_reports = int(data.get("totalReports", 0))
        country = data.get("countryCode", "UNKNOWN")
        isp = data.get("isp", "UNKNOWN")
        usage_type = data.get("usageType", "UNKNOWN")
        domain = data.get("domain", "")
        is_tor = bool(data.get("isTor", False))
        is_whitelisted = bool(data.get("isWhitelisted", False))

        # Determine verdict from abuse score
        if abuse_score >= 75 or total_reports >= 10:
            verdict = "MALICIOUS"
        elif abuse_score >= 25 or total_reports >= 3:
            verdict = "SUSPICIOUS"
        elif is_whitelisted:
            verdict = "CLEAN"
        else:
            verdict = "UNKNOWN"

        confidence = min(1.0, abuse_score / 100.0)

        return {
            "ioc": ip_address,
            "ioc_type": "ip",
            "source": "AbuseIPDB",
            "verdict": verdict,
            "confidence": confidence,
            "raw_risk_score": abuse_score,
            "details": {
                "abuse_confidence_score": str(abuse_score),
                "total_reports": str(total_reports),
                "country": country,
                "isp": isp,
                "usage_type": usage_type,
                "domain": domain,
                "is_tor": str(is_tor),
                "is_whitelisted": str(is_whitelisted),
            },
            "error": None,
        }

    except requests.exceptions.Timeout:
        logger.error("AbuseIPDB timeout for IP: %s", ip_address)
        return _error_result(ip_address, "API request timed out")
    except requests.exceptions.HTTPError as e:
        logger.error("AbuseIPDB HTTP error for IP %s: %s", ip_address, e)
        return _error_result(ip_address, f"HTTP error: {e.response.status_code}")
    except requests.exceptions.RequestException as e:
        logger.error("AbuseIPDB request failed for IP %s: %s", ip_address, e)
        return _error_result(ip_address, str(e))


def _error_result(ip_address: str, error_msg: str) -> Dict[str, Any]:
    return {
        "ioc": ip_address,
        "ioc_type": "ip",
        "source": "AbuseIPDB",
        "verdict": "UNKNOWN",
        "confidence": 0.0,
        "raw_risk_score": None,
        "details": {"ip_address": ip_address},
        "error": error_msg,
    }


async def run_abuseipdb_lookup(state: dict) -> dict:
    """
    LangGraph node: Query AbuseIPDB for all IP addresses in the alert.

    Processes each IP address found in state["iocs"].ip_addresses.
    Results are collected into a list and stored in state["abuseipdb_results"].

    Args:
        state: Current SOCAgentState.

    Returns:
        State update dict with "abuseipdb_results" and "processing_notes" keys.
    """
    from socpilot.models.ioc_models import ExtractedIoCs

    iocs: ExtractedIoCs = state.get("iocs") or ExtractedIoCs()
    results: List[Dict[str, Any]] = []
    errors: List[str] = []

    for ip in iocs.ip_addresses:
        # Skip private/reserved IP ranges (RFC 1918, loopback)
        if _is_private_ip(ip):
            logger.info("Skipping private IP: %s", ip)
            results.append(
                {
                    "ioc": ip,
                    "ioc_type": "ip",
                    "source": "AbuseIPDB",
                    "verdict": "CLEAN",
                    "confidence": 0.9,
                    "raw_risk_score": 0,
                    "details": {"note": "Private/internal IP address — not queried."},
                    "error": None,
                }
            )
            continue

        result = _check_ip(ip)
        results.append(result)

        if result.get("error"):
            errors.append(f"AbuseIPDB error for {ip}: {result['error']}")

        logger.info(
            "AbuseIPDB: %s → verdict=%s, score=%s",
            ip,
            result["verdict"],
            result.get("raw_risk_score"),
        )

    notes = [f"AbuseIPDB: checked {len(iocs.ip_addresses)} IP address(es)"]
    existing_notes = state.get("processing_notes", [])
    existing_errors = state.get("errors", [])

    return {
        "abuseipdb_results": results,
        "processing_notes": existing_notes + notes,
        "errors": existing_errors + errors,
    }


def _is_private_ip(ip: str) -> bool:
    """Check if an IP address is in a private/reserved range."""
    import ipaddress
    try:
        addr = ipaddress.ip_address(ip)
        return addr.is_private or addr.is_loopback or addr.is_link_local
    except ValueError:
        return False
