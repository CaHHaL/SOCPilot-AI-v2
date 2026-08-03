"""
SOCPilot AI — SIEM Integration Server
=======================================
A lightweight FastAPI webhook server that receives alerts from any registered
SIEM and forwards them into the SOCPilot investigation pipeline.

Usage:
  uvicorn siem_server:app --host 0.0.0.0 --port 8000

Endpoints:
  GET  /health                  — Server health check
  GET  /siems                   — List supported SIEM integrations
  POST /webhook/{siem_name}     — Receive SIEM alert payload (e.g. /webhook/wazuh)

Authentication (optional):
  If WAZUH_WEBHOOK_TOKEN is set in .env, all /webhook/* requests must include:
    Authorization: Bearer <token>

The investigation runs in a background thread so the webhook returns immediately
(Wazuh / SIEM integrations typically have short HTTP timeouts).
"""

from __future__ import annotations

import asyncio
import logging
import secrets
import uuid
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from typing import Any, Dict

import uvicorn
from fastapi import BackgroundTasks, Depends, FastAPI, HTTPException, Request, status
from fastapi.responses import JSONResponse

from integrations.registry import get_adapter, list_supported_siems
from socpilot.config.settings import settings

# ── Logging ────────────────────────────────────────────────────────────────────
logging.basicConfig(
    level=getattr(logging, settings.log_level),
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    datefmt="%H:%M:%S",
)
logging.getLogger("httpx").setLevel(logging.WARNING)
logging.getLogger("chromadb").setLevel(logging.WARNING)
logging.getLogger("sentence_transformers").setLevel(logging.WARNING)

logger = logging.getLogger("siem_server")


# ── Lifespan (startup/shutdown) ────────────────────────────────────────────────
@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("SOCPilot SIEM Integration Server starting...")
    logger.info("Supported SIEMs: %s", list_supported_siems())
    logger.info(
        "Min alert level filter: %d (Wazuh scale 1-15)",
        settings.wazuh_min_alert_level,
    )
    auth_status = "ENABLED" if settings.wazuh_webhook_token else "DISABLED (no token set)"
    logger.info("Webhook authentication: %s", auth_status)
    yield
    logger.info("SOCPilot SIEM Integration Server shutting down.")


# ── FastAPI App ────────────────────────────────────────────────────────────────
app = FastAPI(
    title="SOCPilot AI — SIEM Integration Service",
    description=(
        "Receives security alerts from SIEM platforms and automatically "
        "triggers SOCPilot AI investigations."
    ),
    version="1.0.0",
    lifespan=lifespan,
)


# ── Authentication Dependency ──────────────────────────────────────────────────
async def verify_token(request: Request) -> None:
    """
    Validate the Bearer token if WAZUH_WEBHOOK_TOKEN is configured.

    If no token is configured in settings, all requests pass through.
    Uses secrets.compare_digest to prevent timing attacks.
    """
    expected_token = settings.wazuh_webhook_token
    if not expected_token:
        # Authentication not configured — allow all requests
        return

    auth_header = request.headers.get("Authorization", "")
    if not auth_header.startswith("Bearer "):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing or invalid Authorization header. Expected: Bearer <token>",
            headers={"WWW-Authenticate": "Bearer"},
        )

    provided_token = auth_header[len("Bearer "):]
    if not secrets.compare_digest(provided_token, expected_token):
        logger.warning(
            "Webhook auth failure from %s",
            request.client.host if request.client else "unknown",
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid webhook token.",
            headers={"WWW-Authenticate": "Bearer"},
        )


# ── Background Investigation Runner ───────────────────────────────────────────
def _run_investigation_sync(alert_text: str, thread_id: str) -> None:
    """
    Run the SOCPilot investigation pipeline synchronously in a background thread.

    We build a new event loop because this function is called from a FastAPI
    BackgroundTask (which runs in a thread pool outside the async event loop).
    """
    from socpilot.graph.builder import build_soc_graph
    from socpilot.memory.short_term import build_config

    logger.info("Background investigation started — thread_id: %s", thread_id)

    async def _run():
        graph = build_soc_graph()
        config = build_config(thread_id)
        initial_state = {
            "raw_alert": alert_text,
            "thread_id": thread_id,
            "errors": [],
            "processing_notes": [],
        }
        async for output in graph.astream(initial_state, config=config):
            for node_name, state_update in output.items():
                if node_name == "sync_enrichment":
                    continue
                logger.info("[%s] Node complete: %s", thread_id, node_name)
                for err in state_update.get("errors", []):
                    logger.error("[%s] Error in %s: %s", thread_id, node_name, err)

        logger.info("Investigation complete — thread_id: %s", thread_id)

    loop = asyncio.new_event_loop()
    try:
        loop.run_until_complete(_run())
    except Exception as exc:
        logger.exception("Investigation failed for thread_id %s: %s", thread_id, exc)
    finally:
        loop.close()


# ── Routes ─────────────────────────────────────────────────────────────────────

@app.get("/health", tags=["System"])
async def health_check() -> Dict[str, Any]:
    """
    Health check endpoint.

    Returns server status and supported SIEM list.
    """
    return {
        "status": "ok",
        "service": "SOCPilot SIEM Integration Server",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "supported_siems": list_supported_siems(),
    }


@app.get("/siems", tags=["System"])
async def list_siems() -> Dict[str, Any]:
    """List all registered SIEM integrations."""
    return {
        "supported_siems": list_supported_siems(),
        "webhook_template": "POST /webhook/{siem_name}",
    }


@app.post(
    "/webhook/{siem_name}",
    tags=["Webhooks"],
    status_code=status.HTTP_202_ACCEPTED,
    dependencies=[Depends(verify_token)],
)
async def receive_alert(
    siem_name: str,
    request: Request,
    background_tasks: BackgroundTasks,
) -> JSONResponse:
    """
    Receive a SIEM alert payload and trigger a SOCPilot investigation.

    - Validates the SIEM name against the registry
    - Parses the JSON payload
    - Applies the minimum severity filter (WAZUH_MIN_ALERT_LEVEL)
    - Normalizes the payload to alert text via the adapter
    - Starts the investigation in a background thread (non-blocking)
    - Returns 202 Accepted immediately

    Authentication: Bearer token required if WAZUH_WEBHOOK_TOKEN is configured.
    """
    # ── 1. Validate SIEM name ─────────────────────────────────────────────────
    siem_name_lower = siem_name.lower()
    try:
        adapter = get_adapter(siem_name_lower)
    except KeyError:
        supported = list_supported_siems()
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"SIEM '{siem_name}' is not supported. Supported: {supported}",
        )

    # ── 2. Parse JSON body ────────────────────────────────────────────────────
    try:
        payload: Dict[str, Any] = await request.json()
    except Exception:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Request body must be valid JSON.",
        )

    if not isinstance(payload, dict):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Payload must be a JSON object.",
        )

    # ── 3. Severity filter ────────────────────────────────────────────────────
    severity_level = adapter.get_severity_level(payload)
    min_level = settings.wazuh_min_alert_level

    if severity_level < min_level:
        logger.debug(
            "Alert dropped — level %d below minimum %d (SIEM: %s)",
            severity_level,
            min_level,
            siem_name_lower,
        )
        return JSONResponse(
            status_code=status.HTTP_200_OK,
            content={
                "status": "skipped",
                "reason": f"Alert level {severity_level} is below minimum threshold {min_level}",
            },
        )

    # ── 4. Normalize payload → alert text ────────────────────────────────────
    try:
        alert_text = adapter.normalize(payload)
    except Exception as exc:
        logger.error("Adapter normalization failed for SIEM '%s': %s", siem_name_lower, exc)
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"Failed to normalize {siem_name} payload: {exc}",
        )

    if not alert_text.strip():
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Normalized alert text is empty.",
        )

    # ── 5. Generate thread ID and dispatch investigation ──────────────────────
    thread_id = f"{siem_name_lower}-{uuid.uuid4().hex[:8]}"

    logger.info(
        "Dispatching investigation — SIEM: %s | level: %d | thread: %s",
        siem_name_lower,
        severity_level,
        thread_id,
    )

    # Run in a background task — returns 202 immediately so SIEM doesn't timeout
    background_tasks.add_task(_run_investigation_sync, alert_text, thread_id)

    return JSONResponse(
        status_code=status.HTTP_202_ACCEPTED,
        content={
            "status": "accepted",
            "thread_id": thread_id,
            "siem": siem_name_lower,
            "severity_level": severity_level,
            "message": "Investigation started. Report will be saved to the reports/ directory.",
        },
    )


# ── Entry point ────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    uvicorn.run(
        "siem_server:app",
        host=settings.siem_server_host,
        port=settings.siem_server_port,
        reload=False,
        log_level=settings.log_level.lower(),
    )

