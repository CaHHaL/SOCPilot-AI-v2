"""
SOCPilot AI — VirusTotal Tool Node
====================================
Queries the VirusTotal API v3 for file hash reputation.

API: https://www.virustotal.com/api/v3
Endpoint: GET /files/{hash}
Authentication: x-apikey header

Supports MD5, SHA1, and SHA256 hashes.
Graceful degradation if no API key is configured.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List

import requests

from socpilot.config.settings import settings

logger = logging.getLogger(__name__)

VIRUSTOTAL_BASE_URL = "https://www.virustotal.com/api/v3"
REQUEST_TIMEOUT = 15  # seconds — VT can be slow


def _check_hash(file_hash: str) -> Dict[str, Any]:
    """
    Query VirusTotal for a single file hash.

    Args:
        file_hash: MD5, SHA1, or SHA256 hash string.

    Returns:
        Normalised result dict with verdict and engine details.
    """
    if not settings.has_virustotal_key:
        logger.warning("VirusTotal API key not configured — returning mock result for %s", file_hash[:16])
        return {
            "ioc": file_hash,
            "ioc_type": "hash",
            "source": "VirusTotal",
            "verdict": "UNKNOWN",
            "confidence": 0.0,
            "raw_risk_score": None,
            "details": {
                "note": "API key not configured. Set VIRUSTOTAL_API_KEY in .env for live results.",
                "hash": file_hash,
            },
            "error": None,
        }

    try:
        response = requests.get(
            f"{VIRUSTOTAL_BASE_URL}/files/{file_hash}",
            headers={
                "x-apikey": settings.virustotal_api_key,
                "Accept": "application/json",
            },
            timeout=REQUEST_TIMEOUT,
        )

        if response.status_code == 404:
            return {
                "ioc": file_hash,
                "ioc_type": "hash",
                "source": "VirusTotal",
                "verdict": "UNKNOWN",
                "confidence": 0.1,
                "raw_risk_score": None,
                "details": {
                    "note": "File hash not found in VirusTotal database.",
                    "hash": file_hash,
                },
                "error": None,
            }

        response.raise_for_status()
        data = response.json().get("data", {}).get("attributes", {})

        stats = data.get("last_analysis_stats", {})
        malicious = int(stats.get("malicious", 0))
        suspicious = int(stats.get("suspicious", 0))
        harmless = int(stats.get("harmless", 0))
        undetected = int(stats.get("undetected", 0))
        total = malicious + suspicious + harmless + undetected

        file_type = data.get("type_description", data.get("magic", "Unknown"))
        file_names = data.get("names", [])[:5]  # Limit to 5 names
        file_size = data.get("size", 0)
        first_seen = str(data.get("first_submission_date", "Unknown"))
        last_seen = str(data.get("last_analysis_date", "Unknown"))
        popular_threat = data.get("popular_threat_classification", {})
        threat_label = popular_threat.get("suggested_threat_label", "")

        # Calculate verdict
        detection_ratio = malicious / total if total > 0 else 0
        if malicious >= 5 or detection_ratio >= 0.1:
            verdict = "MALICIOUS"
        elif suspicious >= 2 or (malicious >= 1 and total > 10):
            verdict = "SUSPICIOUS"
        elif malicious == 0 and harmless > 5:
            verdict = "CLEAN"
        else:
            verdict = "UNKNOWN"

        # Risk score: percentage of engines that flagged it
        raw_risk_score = int(detection_ratio * 100) if total > 0 else None
        confidence = min(1.0, detection_ratio) if verdict == "MALICIOUS" else (
            0.7 if verdict == "SUSPICIOUS" else (0.9 if verdict == "CLEAN" else 0.3)
        )

        return {
            "ioc": file_hash,
            "ioc_type": "hash",
            "source": "VirusTotal",
            "verdict": verdict,
            "confidence": confidence,
            "raw_risk_score": raw_risk_score,
            "details": {
                "malicious_engines": str(malicious),
                "suspicious_engines": str(suspicious),
                "harmless_engines": str(harmless),
                "total_engines": str(total),
                "detection_ratio": f"{malicious}/{total}" if total else "0/0",
                "file_type": file_type,
                "known_names": ", ".join(file_names) if file_names else "Unknown",
                "file_size_bytes": str(file_size),
                "first_seen": first_seen,
                "last_seen": last_seen,
                "threat_label": threat_label or "Unknown",
            },
            "error": None,
        }

    except requests.exceptions.Timeout:
        logger.error("VirusTotal timeout for hash: %s", file_hash[:16])
        return _error_result(file_hash, "API request timed out")
    except requests.exceptions.HTTPError as e:
        logger.error("VirusTotal HTTP error for hash %s: %s", file_hash[:16], e)
        return _error_result(file_hash, f"HTTP error: {e.response.status_code}")
    except requests.exceptions.RequestException as e:
        logger.error("VirusTotal request failed for hash %s: %s", file_hash[:16], e)
        return _error_result(file_hash, str(e))


def _error_result(file_hash: str, error_msg: str) -> Dict[str, Any]:
    return {
        "ioc": file_hash,
        "ioc_type": "hash",
        "source": "VirusTotal",
        "verdict": "UNKNOWN",
        "confidence": 0.0,
        "raw_risk_score": None,
        "details": {"hash": file_hash},
        "error": error_msg,
    }


async def run_virustotal_lookup(state: dict) -> dict:
    """
    LangGraph node: Query VirusTotal for all file hashes in the alert.

    Processes each hash found in state["iocs"].file_hashes.
    Results are stored in state["virustotal_results"].

    Args:
        state: Current SOCAgentState.

    Returns:
        State update dict with "virustotal_results" and "processing_notes" keys.
    """
    from socpilot.models.ioc_models import ExtractedIoCs

    iocs: ExtractedIoCs = state.get("iocs") or ExtractedIoCs()
    results: List[Dict[str, Any]] = []
    errors: List[str] = []

    for file_hash in iocs.file_hashes:
        result = _check_hash(file_hash)
        results.append(result)

        if result.get("error"):
            errors.append(f"VirusTotal error for {file_hash[:16]}...: {result['error']}")

        logger.info(
            "VirusTotal: %s → verdict=%s",
            file_hash[:16] + "...",
            result["verdict"],
        )

    notes = [f"VirusTotal: checked {len(iocs.file_hashes)} hash(es)"]
    existing_notes = state.get("processing_notes", [])
    existing_errors = state.get("errors", [])

    return {
        "virustotal_results": results,
        "processing_notes": existing_notes + notes,
        "errors": existing_errors + errors,
    }
