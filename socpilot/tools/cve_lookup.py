"""
SOCPilot AI — CVE Lookup Tool Node
=====================================
Queries the NVD NIST API v2.0 for CVE vulnerability details.

API: https://services.nvd.nist.gov/rest/json/cves/2.0
Authentication: Optional API key (higher rate limit with key).
Rate limit: 5 req/30s without key, 50 req/30s with key.

Graceful degradation if no API key or network unavailable.
"""

from __future__ import annotations

import logging
import time
from typing import Any, Dict, List

import requests

from socpilot.config.settings import settings

logger = logging.getLogger(__name__)

NVD_BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
REQUEST_TIMEOUT = 15  # seconds
RATE_LIMIT_DELAY = 6  # seconds between requests without API key


def _lookup_cve(cve_id: str) -> Dict[str, Any]:
    """
    Query NVD NIST for details on a specific CVE.

    Args:
        cve_id: CVE identifier string (e.g., "CVE-2021-44228").

    Returns:
        Normalised result dict with CVSS score and vulnerability details.
    """
    headers = {"Accept": "application/json"}
    if settings.has_nvd_key:
        headers["apiKey"] = settings.nvd_api_key

    try:
        response = requests.get(
            NVD_BASE_URL,
            headers=headers,
            params={"cveId": cve_id.upper()},
            timeout=REQUEST_TIMEOUT,
        )
        response.raise_for_status()
        data = response.json()

        vulnerabilities = data.get("vulnerabilities", [])
        if not vulnerabilities:
            return {
                "ioc": cve_id,
                "ioc_type": "cve",
                "source": "NVD NIST",
                "verdict": "UNKNOWN",
                "confidence": 0.5,
                "raw_risk_score": None,
                "details": {"note": f"CVE {cve_id} not found in NVD database."},
                "error": None,
            }

        cve_data = vulnerabilities[0].get("cve", {})

        # Extract CVSS score (prefer CVSS v3.1, fall back to v3.0, then v2)
        cvss_score = None
        cvss_vector = ""
        cvss_severity = "UNKNOWN"
        metrics = cve_data.get("metrics", {})

        for cvss_version in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
            metric_list = metrics.get(cvss_version, [])
            if metric_list:
                primary = metric_list[0].get("cvssData", {})
                cvss_score = primary.get("baseScore")
                cvss_vector = primary.get("vectorString", "")
                cvss_severity = primary.get("baseSeverity", "UNKNOWN")
                break

        # Extract description
        descriptions = cve_data.get("descriptions", [])
        description = next(
            (d["value"] for d in descriptions if d.get("lang") == "en"),
            "No description available.",
        )

        # Extract affected CPEs (products)
        configurations = cve_data.get("configurations", [])
        affected_products = []
        for config in configurations[:1]:  # Limit to first config
            for node in config.get("nodes", [])[:3]:
                for cpe_match in node.get("cpeMatch", [])[:3]:
                    cpe = cpe_match.get("criteria", "")
                    if cpe:
                        # Extract vendor/product from CPE URI
                        parts = cpe.split(":")
                        if len(parts) >= 5:
                            affected_products.append(f"{parts[3]}/{parts[4]}")

        # Extract references
        refs = cve_data.get("references", [])[:3]
        ref_urls = [r.get("url", "") for r in refs if r.get("url")]

        # Determine verdict from CVSS score
        if cvss_score is not None:
            if cvss_score >= 9.0:
                verdict = "MALICIOUS"
            elif cvss_score >= 7.0:
                verdict = "SUSPICIOUS"
            elif cvss_score >= 4.0:
                verdict = "SUSPICIOUS"
            else:
                verdict = "CLEAN"
        else:
            verdict = "UNKNOWN"

        raw_risk_score = int(cvss_score * 10) if cvss_score is not None else None

        return {
            "ioc": cve_id,
            "ioc_type": "cve",
            "source": "NVD NIST",
            "verdict": verdict,
            "confidence": 0.95,  # NVD is authoritative
            "raw_risk_score": raw_risk_score,
            "details": {
                "cvss_score": str(cvss_score) if cvss_score else "Not available",
                "cvss_severity": cvss_severity,
                "cvss_vector": cvss_vector or "Not available",
                "description": description[:500] + "..." if len(description) > 500 else description,
                "affected_products": ", ".join(affected_products) if affected_products else "See NVD",
                "references": " | ".join(ref_urls) if ref_urls else "See NVD",
            },
            "error": None,
        }

    except requests.exceptions.Timeout:
        logger.error("NVD timeout for CVE: %s", cve_id)
        return _error_result(cve_id, "API request timed out")
    except requests.exceptions.HTTPError as e:
        logger.error("NVD HTTP error for CVE %s: %s", cve_id, e)
        return _error_result(cve_id, f"HTTP error: {e.response.status_code}")
    except requests.exceptions.RequestException as e:
        logger.error("NVD request failed for CVE %s: %s", cve_id, e)
        return _error_result(cve_id, str(e))


def _error_result(cve_id: str, error_msg: str) -> Dict[str, Any]:
    return {
        "ioc": cve_id,
        "ioc_type": "cve",
        "source": "NVD NIST",
        "verdict": "UNKNOWN",
        "confidence": 0.0,
        "raw_risk_score": None,
        "details": {"cve_id": cve_id},
        "error": error_msg,
    }


async def run_cve_lookup(state: dict) -> dict:
    """
    LangGraph node: Query NVD NIST for all CVE IDs in the alert.

    Applies rate limiting between requests to respect NVD API limits.
    Results are stored in state["cve_results"].

    Args:
        state: Current SOCAgentState.

    Returns:
        State update dict with "cve_results" and "processing_notes" keys.
    """
    from socpilot.models.ioc_models import ExtractedIoCs

    iocs: ExtractedIoCs = state.get("iocs") or ExtractedIoCs()
    results: List[Dict[str, Any]] = []
    errors: List[str] = []

    for i, cve_id in enumerate(iocs.cve_ids):
        # Apply rate limiting (NVD is strict about this)
        if i > 0 and not settings.has_nvd_key:
            time.sleep(RATE_LIMIT_DELAY)

        result = _lookup_cve(cve_id)
        results.append(result)

        if result.get("error"):
            errors.append(f"NVD error for {cve_id}: {result['error']}")

        score = result.get("details", {}).get("cvss_score", "N/A")
        logger.info(
            "CVE Lookup: %s → verdict=%s, cvss=%s",
            cve_id,
            result["verdict"],
            score,
        )

    notes = [f"CVE Lookup: checked {len(iocs.cve_ids)} CVE(s)"]
    existing_notes = state.get("processing_notes", [])
    existing_errors = state.get("errors", [])

    return {
        "cve_results": results,
        "processing_notes": existing_notes + notes,
        "errors": existing_errors + errors,
    }
