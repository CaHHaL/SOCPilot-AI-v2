"""
SOCPilot AI — Dashboard API Server
====================================
Lightweight FastAPI server that reads reports/ and serves them to the
frontend dashboard. Completely independent from siem_server.py.

Port: 8080 (SIEM server runs on 8000)

Usage:
  python dashboard/start_dashboard.py
  OR directly:
  uvicorn dashboard.api_server:app --host 0.0.0.0 --port 8080
"""

from __future__ import annotations

import asyncio
import json
import os
import re
import threading
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, AsyncGenerator, Dict, Generator, List, Optional

import uvicorn
from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles

# ── Paths ──────────────────────────────────────────────────────────────────────
BASE_DIR = Path(__file__).parent.parent          # SOC_Agent_V2/
REPORTS_DIR = BASE_DIR / "reports"
STATIC_DIR = Path(__file__).parent / "static"

# ── SSE Subscriber Registry ────────────────────────────────────────────────────
_sse_subscribers: List[asyncio.Queue] = []
_sse_lock = threading.Lock()


def _broadcast_new_report(report_data: Dict[str, Any]) -> None:
    """Thread-safe broadcast of a new-report event to all SSE subscribers."""
    with _sse_lock:
        dead = []
        for q in _sse_subscribers:
            try:
                q.put_nowait(report_data)
            except asyncio.QueueFull:
                dead.append(q)
        for q in dead:
            _sse_subscribers.remove(q)


# ── File Watcher ───────────────────────────────────────────────────────────────
def _start_file_watcher() -> None:
    """Watch reports/ for new JSON files using polling (no extra deps)."""

    known_files: set = set(REPORTS_DIR.glob("*.json"))

    def _poll() -> None:
        nonlocal known_files
        while True:
            try:
                current = set(REPORTS_DIR.glob("*.json"))
                new_files = current - known_files
                for f in sorted(new_files, key=lambda p: p.stat().st_mtime):
                    try:
                        data = json.loads(f.read_text(encoding="utf-8"))
                        data["_filename"] = f.name
                        _broadcast_new_report(data)
                    except Exception:
                        pass
                known_files = current
            except Exception:
                pass
            import time
            time.sleep(3)

    t = threading.Thread(target=_poll, daemon=True)
    t.start()


# ── Report Helpers ─────────────────────────────────────────────────────────────
def _load_report(path: Path) -> Optional[Dict[str, Any]]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        data["_filename"] = path.name
        # Check if matching .md exists
        md_path = path.with_suffix(".md")
        data["_has_markdown"] = md_path.exists()
        return data
    except Exception:
        return None


def _report_summary(data: Dict[str, Any]) -> Dict[str, Any]:
    """Return a lightweight summary dict for the report list."""
    iocs = data.get("extracted_iocs", {})
    total_iocs = sum(
        len(v) for v in iocs.values() if isinstance(v, list)
    )
    return {
        "report_id": data.get("report_id", "UNKNOWN"),
        "filename": data.get("_filename", ""),
        "investigation_timestamp": data.get("investigation_timestamp", ""),
        "thread_id": data.get("thread_id", ""),
        "severity": data.get("severity", "UNKNOWN"),
        "risk_score": data.get("risk_score", 0),
        "confidence_score": data.get("confidence_score", 0),
        "escalation_required": data.get("escalation_required", False),
        "false_positive_likelihood": data.get("false_positive_likelihood", "UNKNOWN"),
        "alert_summary": data.get("alert_summary", "")[:200],
        "ioc_count": total_iocs,
        "mitre_count": len(data.get("mitre_mappings", [])),
        "sigma_count": len(data.get("sigma_detections", [])),
        "threat_intel_count": len(data.get("threat_intel_findings", [])),
        "has_markdown": data.get("_has_markdown", False),
    }


def _get_all_reports() -> List[Dict[str, Any]]:
    reports = []
    for path in sorted(REPORTS_DIR.glob("*.json"), key=lambda p: p.stat().st_mtime, reverse=True):
        data = _load_report(path)
        if data:
            reports.append(_report_summary(data))
    return reports


def _compute_stats(reports_full: List[Dict[str, Any]]) -> Dict[str, Any]:
    severity_counts: Dict[str, int] = defaultdict(int)
    total_risk = 0
    escalation_count = 0
    mitre_techniques: Dict[str, int] = defaultdict(int)
    mitre_tactics: Dict[str, int] = defaultdict(int)
    verdict_counts: Dict[str, int] = defaultdict(int)
    daily_counts: Dict[str, Dict[str, int]] = defaultdict(lambda: defaultdict(int))
    fp_counts: Dict[str, int] = defaultdict(int)

    for r in reports_full:
        sev = r.get("severity", "UNKNOWN")
        severity_counts[sev] += 1
        total_risk += r.get("risk_score", 0)
        if r.get("escalation_required"):
            escalation_count += 1
        fp_counts[r.get("false_positive_likelihood", "UNKNOWN")] += 1

        # Timestamp -> day bucket
        ts_str = r.get("investigation_timestamp", "")
        try:
            if ts_str:
                # Handle various formats
                ts_str_clean = re.sub(r'\+\d{4}$', 'Z', ts_str)
                ts = datetime.fromisoformat(ts_str_clean.replace('Z', '+00:00'))
                day = ts.strftime("%Y-%m-%d")
                daily_counts[day][sev] += 1
        except Exception:
            pass

        for m in r.get("mitre_mappings", []):
            tid = m.get("technique_id", "")
            tname = m.get("technique_name", tid)
            tactic = m.get("tactic", "Unknown")
            if tid:
                mitre_techniques[f"{tid}: {tname}"] += 1
                mitre_tactics[tactic] += 1

        for t in r.get("threat_intel_findings", []):
            v = t.get("verdict", "UNKNOWN")
            verdict_counts[v] += 1

    n = len(reports_full)
    return {
        "total_reports": n,
        "severity_counts": dict(severity_counts),
        "avg_risk_score": round(total_risk / n, 1) if n else 0,
        "escalation_count": escalation_count,
        "mitre_top_techniques": sorted(mitre_techniques.items(), key=lambda x: -x[1])[:10],
        "mitre_top_tactics": sorted(mitre_tactics.items(), key=lambda x: -x[1])[:10],
        "verdict_counts": dict(verdict_counts),
        "daily_severity": {
            day: dict(sev_map)
            for day, sev_map in sorted(daily_counts.items())
        },
        "false_positive_likelihood": dict(fp_counts),
    }


# ── FastAPI App ────────────────────────────────────────────────────────────────
app = FastAPI(
    title="SOCPilot Dashboard API",
    description="Read-only API for the SOCPilot AI dashboard.",
    version="1.0.0",
    docs_url="/api/docs",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["GET"],
    allow_headers=["*"],
)


# ── API Routes ─────────────────────────────────────────────────────────────────

@app.get("/api/reports")
async def list_reports() -> JSONResponse:
    """Return lightweight metadata for all reports, newest first."""
    return JSONResponse({"reports": _get_all_reports()})


@app.get("/api/reports/{filename}")
async def get_report(filename: str) -> JSONResponse:
    """Return full JSON for a single report."""
    # Ensure filename is safe (no path traversal)
    if ".." in filename or "/" in filename or "\\" in filename:
        raise HTTPException(status_code=400, detail="Invalid filename")
    # Accept with or without .json extension
    if not filename.endswith(".json"):
        filename = filename + ".json"
    path = REPORTS_DIR / filename
    if not path.exists():
        raise HTTPException(status_code=404, detail=f"Report '{filename}' not found")
    data = _load_report(path)
    if not data:
        raise HTTPException(status_code=500, detail="Failed to parse report")
    return JSONResponse(data)


@app.get("/api/reports/{filename}/markdown")
async def get_report_markdown(filename: str) -> JSONResponse:
    """Return the markdown content for a report (if available)."""
    if ".." in filename or "/" in filename or "\\" in filename:
        raise HTTPException(status_code=400, detail="Invalid filename")
    base = filename.replace(".json", "").replace(".md", "")
    md_path = REPORTS_DIR / f"{base}.md"
    if not md_path.exists():
        raise HTTPException(status_code=404, detail="Markdown report not found")
    content = md_path.read_text(encoding="utf-8")
    return JSONResponse({"markdown": content, "filename": md_path.name})


@app.get("/api/stats")
async def get_stats() -> JSONResponse:
    """Return aggregated statistics across all reports."""
    all_paths = sorted(REPORTS_DIR.glob("*.json"), key=lambda p: p.stat().st_mtime, reverse=True)
    full_reports = []
    for path in all_paths:
        data = _load_report(path)
        if data:
            full_reports.append(data)
    stats = _compute_stats(full_reports)
    return JSONResponse(stats)


@app.get("/api/stream")
async def sse_stream(request: Request) -> StreamingResponse:
    """Server-Sent Events endpoint for live report notifications."""
    queue: asyncio.Queue = asyncio.Queue(maxsize=50)
    with _sse_lock:
        _sse_subscribers.append(queue)

    async def event_generator() -> AsyncGenerator[str, None]:
        # Send connection heartbeat
        yield "event: connected\ndata: {\"status\": \"connected\"}\n\n"
        try:
            while True:
                if await request.is_disconnected():
                    break
                try:
                    # Wait for a new report event (with timeout for heartbeat)
                    report_data = await asyncio.wait_for(queue.get(), timeout=20)
                    summary = _report_summary(report_data)
                    payload = json.dumps(summary)
                    yield f"event: new_report\ndata: {payload}\n\n"
                except asyncio.TimeoutError:
                    # Heartbeat ping to keep connection alive
                    yield "event: ping\ndata: {}\n\n"
        finally:
            with _sse_lock:
                if queue in _sse_subscribers:
                    _sse_subscribers.remove(queue)

    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
        },
    )


@app.get("/api/health")
async def health() -> JSONResponse:
    report_count = len(list(REPORTS_DIR.glob("*.json")))
    return JSONResponse({
        "status": "ok",
        "service": "SOCPilot Dashboard API",
        "reports_dir": str(REPORTS_DIR),
        "report_count": report_count,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    })


# ── Static Files + SPA Fallback ────────────────────────────────────────────────
app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")


@app.get("/{full_path:path}")
async def spa_fallback(full_path: str) -> FileResponse:
    """Serve index.html for all non-API routes (client-side routing)."""
    return FileResponse(str(STATIC_DIR / "index.html"))


@app.get("/")
async def index() -> FileResponse:
    return FileResponse(str(STATIC_DIR / "index.html"))


# ── Startup ────────────────────────────────────────────────────────────────────
@app.on_event("startup")
async def startup_event():
    _start_file_watcher()


# ── Entry point ────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8080, log_level="info")
