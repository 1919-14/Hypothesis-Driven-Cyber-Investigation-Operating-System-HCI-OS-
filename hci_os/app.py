"""
app.py
HCI-OS FastAPI Application — Unified API Server

Endpoints:
  POST  /ingest                       Run a raw event through the investigation loop
  POST  /emergency-stop               SD-8: Freeze all autonomous operations
  POST  /emergency-stop/release       SD-8: Release freeze (requires valid approver)
  GET   /emergency-stop/status        SD-8: Current kill-switch status
  GET   /sd/chain-status              SD-7: Verify self-defense log chain integrity
  GET   /health                       System health (watchdog + SD chain + circuit breakers)

SD-8 Release Authorization (Gap #3):
  Valid approvers: CISO, sysadmin, admin, security_lead
  Unauthorized approvers receive HTTP 403.

Run with:
  uvicorn app:app --host 0.0.0.0 --port 8000 --reload
"""

from __future__ import annotations

import logging
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional

# Ensure hci_os package root is on sys.path
_ROOT = Path(__file__).resolve().parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from fastapi import FastAPI, HTTPException, Query
from fastapi.responses import JSONResponse
from pydantic import BaseModel

from agents import a11_watchdog, a12_audit
from agents.self_defense import (
    VALID_APPROVERS,
    freeze_autonomy,
    get_circuit_status,
    is_autonomy_frozen,
    release_autonomy,
)
from pipeline.investigation_loop import run_investigation

logger = logging.getLogger("HCI_OS_App")
logging.basicConfig(level=logging.INFO)

app = FastAPI(
    title="HCI-OS — Hypothesis-Driven Cyber Investigation OS",
    description=(
        "India's critical-infrastructure cyber investigation platform. "
        "Powered by a 13-agent AI pipeline with 8 self-defense layers."
    ),
    version="1.0.0",
)


# =============================================================================
# REQUEST / RESPONSE MODELS
# =============================================================================

class IngestRequest(BaseModel):
    raw_event: Dict[str, Any]
    asset_id:  str = ""
    source:    str = ""


class EmergencyStopRequest(BaseModel):
    reason: str = "emergency-stop triggered via API"


# =============================================================================
# INGEST ENDPOINT
# =============================================================================

@app.post("/ingest", summary="Run a raw telemetry event through the investigation pipeline")
async def ingest(req: IngestRequest) -> JSONResponse:
    """
    POST /ingest
    Passes a raw event through the full A1 → A2 → … → A12 pipeline
    with all SD layers active.
    """
    try:
        result = run_investigation(
            raw_event=req.raw_event,
            asset_id=req.asset_id,
            source=req.source,
        )
        return JSONResponse(content=result)
    except Exception as exc:
        logger.error("/ingest error: %s", exc)
        raise HTTPException(status_code=500, detail=str(exc))


# =============================================================================
# SD-8 KILL SWITCH ENDPOINTS
# =============================================================================

@app.post(
    "/emergency-stop",
    summary="SD-8: Freeze all autonomous HCI-OS operations immediately",
)
async def emergency_stop(req: EmergencyStopRequest) -> JSONResponse:
    """
    POST /emergency-stop
    Activates the kill switch.  AUTONOMY_FROZEN is set to True.
    A7 (SOAR), A10 (Active Hunt), and A13 (Federation) are immediately halted.

    The freeze persists until manually released via POST /emergency-stop/release
    with a valid approver.  It does NOT auto-release after 300 s (fail-safe).
    """
    result = freeze_autonomy(reason=req.reason)
    # Log to SD-7 forensic chain
    try:
        a12_audit.log_rejection(
            agent_id="SD-8",
            violation_type="kill_switch_activated",
            reason=req.reason,
            input_data={"endpoint": "/emergency-stop"},
        )
    except Exception:
        pass
    return JSONResponse(content=result, status_code=200)


@app.post(
    "/emergency-stop/release",
    summary="SD-8: Release autonomous freeze (requires authorized approver)",
)
async def emergency_stop_release(
    approver: str = Query(..., description=f"Authorized approver. Valid values: {sorted(VALID_APPROVERS)}"),
    notes: str = Query("", description="Optional release notes"),
) -> JSONResponse:
    """
    POST /emergency-stop/release?approver=CISO

    Releases the kill switch.  Gap #3: only VALID_APPROVERS are accepted.
    Returns HTTP 403 if approver is not in the authorized list.
    """
    try:
        result = release_autonomy(approver=approver, notes=notes)
        # Log release to SD-7 forensic chain
        try:
            a12_audit.log_rejection(
                agent_id="SD-8",
                violation_type="kill_switch_released",
                reason=f"Released by approver={approver}. Notes: {notes}",
                input_data={"approver": approver, "endpoint": "/emergency-stop/release"},
            )
        except Exception:
            pass
        return JSONResponse(content=result, status_code=200)
    except PermissionError as exc:
        logger.warning("/emergency-stop/release rejected: %s", exc)
        # Log failed release attempt
        try:
            a12_audit.log_rejection(
                agent_id="SD-8",
                violation_type="kill_switch_release_unauthorized",
                reason=str(exc),
                input_data={"approver": approver},
            )
        except Exception:
            pass
        raise HTTPException(status_code=403, detail=str(exc))


@app.get("/emergency-stop/status", summary="SD-8: Current kill-switch state")
async def emergency_stop_status() -> JSONResponse:
    return JSONResponse(content={
        "frozen":      is_autonomy_frozen(),
        "valid_approvers": sorted(VALID_APPROVERS),
        "timestamp":   datetime.now(timezone.utc).isoformat() + "Z",
    })


# =============================================================================
# SD-7 CHAIN STATUS
# =============================================================================

@app.get("/sd/chain-status", summary="SD-7: Verify self-defense rejection log chain integrity")
async def sd_chain_status() -> JSONResponse:
    """
    GET /sd/chain-status
    Runs verify_sd_chain() and returns the integrity result.
    Useful for health dashboards and SOC monitoring.
    """
    result = a12_audit.verify_sd_chain()
    status_code = 200 if result["valid"] else 500
    return JSONResponse(content=result, status_code=status_code)


# =============================================================================
# HEALTH CHECK
# =============================================================================

@app.get("/health", summary="System health: watchdog, SD chain, circuit breakers")
async def health() -> JSONResponse:
    watchdog_health  = a11_watchdog.health_check()
    sd_chain_health  = a12_audit.verify_sd_chain()
    circuit_statuses = get_circuit_status()

    any_circuit_open = any(
        s.get("open_until") is not None for s in circuit_statuses.values()
    )

    overall_healthy = (
        watchdog_health["healthy"]
        and sd_chain_health["valid"]
        and not any_circuit_open
        and not is_autonomy_frozen()
    )

    return JSONResponse(
        content={
            "healthy": overall_healthy,
            "autonomy_frozen": is_autonomy_frozen(),
            "watchdog": watchdog_health,
            "sd_chain": sd_chain_health,
            "circuit_breakers": circuit_statuses,
            "timestamp": datetime.now(timezone.utc).isoformat() + "Z",
        },
        status_code=200 if overall_healthy else 503,
    )


# =============================================================================
# GNN VISUALIZATION — GAT + TGN + GraphSAGE (Gap #4 Cytoscape schema)
# =============================================================================

@app.get("/gnn/visualization", summary="A5: GNN Ensemble visualization (Cytoscape + TGN timeline + GraphSAGE PCA)")
async def gnn_visualization(hypothesis_id: str = "") -> JSONResponse:
    """
    GET /gnn/visualization?hypothesis_id=H-2026-0031
    Returns all three GNN outputs for the dashboard:
      - cytoscape:  Cytoscape.js-compatible graph with attention + fused scores
      - tgn_timeline: per-node memory norms over time
      - sage_pca:   GraphSAGE embeddings projected to 2D
    """
    try:
        from agents.a5_gnn import _get_ensemble
        ens = _get_ensemble()
        preds = ens.predict()
        cyto  = ens.export_cytoscape(preds["fused_scores"], preds["attention"])
        tline = ens.export_tgn_timeline(preds["memory_states"])
        pca   = ens.export_sage_embeddings_pca(preds["embeddings"])
        return JSONResponse(content={
            "cytoscape": cyto,
            "tgn_timeline": tline,
            "sage_pca": pca,
            "perf": preds.get("perf", {}),
        })
    except Exception as exc:
        logger.error("/gnn/visualization error: %s", exc)
        raise HTTPException(status_code=500, detail=str(exc))

# Legacy alias kept for backward compat
@app.get("/gat/topology", include_in_schema=False)
async def gat_topology_legacy() -> JSONResponse:
    return await gnn_visualization()


# =============================================================================
# DIGITAL TWIN SIMULATION (Gap #6)
# =============================================================================

class SimulateRequest(BaseModel):
    start_node: str = "CBSE-WebSvr-01"
    target_node: str = "CrownJewel-ExamDB"
    attacker_ip: str = "185.23.147.82"
    feed_pipeline: bool = False  # Set to False by default for quick demo


@app.post("/digital-twin/simulate", summary="A14: Simulate APT attack through the infrastructure graph")
async def digital_twin_simulate(req: SimulateRequest) -> JSONResponse:
    """
    POST /digital-twin/simulate
    Runs a simulated APT attack from start_node to target_node.
    If feed_pipeline=true, each hop is fed through the real investigation pipeline.
    """
    try:
        from agents.digital_twin import DigitalTwin
        twin = DigitalTwin()
        result = twin.simulate_attack(
            start_node=req.start_node,
            target_node=req.target_node,
            attacker_ip=req.attacker_ip,
            feed_pipeline=req.feed_pipeline,
        )
        return JSONResponse(content=result)
    except Exception as exc:
        logger.error("/digital-twin/simulate error: %s", exc)
        raise HTTPException(status_code=500, detail=str(exc))


@app.get("/digital-twin/graph", summary="A14: Get Digital Twin graph for Cytoscape.js rendering")
async def digital_twin_graph() -> JSONResponse:
    """
    GET /digital-twin/graph
    Returns the Digital Twin's infrastructure graph in Cytoscape.js format.
    """
    try:
        from agents.digital_twin import DigitalTwin
        twin = DigitalTwin()
        return JSONResponse(content=twin.get_cytoscape_elements())
    except Exception as exc:
        logger.error("/digital-twin/graph error: %s", exc)
        raise HTTPException(status_code=500, detail=str(exc))


# =============================================================================
# ROOT
# =============================================================================

@app.get("/", include_in_schema=False)
async def root() -> JSONResponse:
    return JSONResponse(content={
        "service": "HCI-OS",
        "version": "1.1.0",
        "docs":    "/docs",
        "health":  "/health",
        "endpoints": {
            "ingest": "/ingest",
            "gat_topology": "/gat/topology",
            "digital_twin_simulate": "/digital-twin/simulate",
            "digital_twin_graph": "/digital-twin/graph",
            "emergency_stop": "/emergency-stop",
            "sd_chain_status": "/sd/chain-status",
        },
    })
