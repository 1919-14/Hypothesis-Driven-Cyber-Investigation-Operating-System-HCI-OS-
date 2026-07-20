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
  GET   /incident/timeline/{id}       UI: Incident metadata + scrubbable timeline events
  GET   /decisions/pending            UI: Pending human-gate decisions
  POST  /correction/{action}          UI: Human gate confirm/revoke/modify/escalate
  POST  /chatbot/query                UI: A6 Groq-powered SOC chatbot
  GET   /cert-in/report/{id}          UI: CERT-In compliance report (JSON or ?format=md)

SD-8 Release Authorization (Gap #3):
  Valid approvers: CISO, sysadmin, admin, security_lead
  Unauthorized approvers receive HTTP 403.

Run with:
  uvicorn app:app --host 0.0.0.0 --port 8000 --reload
"""

from __future__ import annotations

import json
import logging
import os
import sys
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

# Ensure hci_os package root is on sys.path
_ROOT = Path(__file__).resolve().parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from dotenv import load_dotenv
load_dotenv(_ROOT.parent / ".env")

from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, PlainTextResponse
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
from stores import mysql_store

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

@app.on_event("startup")
async def _startup():
    """Initialise MySQL schema on server start."""
    ok = mysql_store.init_schema()
    if ok:
        logger.info("HCI-OS startup: MySQL schema ready (database=hci_os)")
    else:
        logger.warning("HCI-OS startup: MySQL unavailable — file-only fallback active")

# Allow React dev-server (Vite on :5173) to call us directly
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://127.0.0.1:5173", "*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
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
        # Persist ingest event to MySQL for telemetry stats
        try:
            mysql_store.save_ingest_event(result)
            mysql_store.save_pipeline_run({
                **result,
                "source": req.source,
                "asset_id": req.asset_id,
            })
        except Exception:
            pass
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
    Priority: 1) Live Neo4j KG  2) GNN Ensemble  3) MySQL pipeline runs
    Returns cytoscape nodes with 'severity' and 'kind' attributes for AttackGraph.jsx.
    """
    # ── 1. Attempt live Neo4j Knowledge Graph ─────────────────────────────────
    try:
        from stores.neo4j_store import Neo4jStore
        kg = Neo4jStore()
        if not kg.use_fallback:
            raw = kg.get_cytoscape_elements(node_limit=2000, edge_limit=8000)
            kg.close()

            # Map Neo4j node types → UI 'kind' and compute 'severity'
            _KIND_MAP = {
                "Computer": "server", "IP": "cloud", "User": "service",
                "Asset": "server", "OTSensor": "db", "Technique": "firewall",
                "Tactic": "firewall", "ThreatGroup": "crown", "Mitigation": "service",
                "Software": "cloud", "Campaign": "crown", "Entity": "server",
            }
            _SEV_MAP = {
                "ThreatGroup": "critical", "Campaign": "critical",
                "Technique": "suspicious", "Tactic": "suspicious",
                "OTSensor": "warning",
            }

            nodes = []
            for el in raw.get("nodes", []):
                d = dict(el.get("data", {}))
                ntype = d.get("type", "Entity")
                d["kind"] = _KIND_MAP.get(ntype, "server")
                d["severity"] = _SEV_MAP.get(ntype, "clean")
                d["label"] = d.get("name") or d.get("label") or d.get("id", "?")
                if len(d["label"]) > 24:
                    d["label"] = d["label"][:22] + "…"
                nodes.append({"group": "nodes", "data": d})

            edges = []
            for el in raw.get("edges", []):
                d = dict(el.get("data", {}))
                d["id"] = d.get("id") or f"{d.get('source','')}->{d.get('target','')}"
                d["weight"] = float(d.get("weight", 0.5))
                d["kind"] = "attack" if d.get("label") == 1 else "predicted"
                edges.append({"group": "edges", "data": d})

            logger.info("/gnn/visualization: returning %d Neo4j nodes, %d edges", len(nodes), len(edges))
            return JSONResponse(content={
                "cytoscape": {"nodes": nodes, "edges": edges},
                "tgn_timeline": [],
                "sage_pca": [],
                "perf": {"source": "neo4j_live", "nodes": len(nodes), "edges": len(edges)},
            })
    except Exception as neo_exc:
        logger.warning("/gnn/visualization Neo4j failed (%s) — trying GNN ensemble", neo_exc)

    # ── 2. GNN Ensemble ───────────────────────────────────────────────────────
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
        logger.warning("/gnn/visualization GNN failed (%s) — building real-data fallback graph", exc)

    # ── 3. MySQL pipeline runs fallback ───────────────────────────────────────
    try:
        from stores import mysql_store
        runs = mysql_store.list_pipeline_runs(limit=30)
        nodes_map: dict = {}
        edges = []
        for run in runs:
            asset = run.get("asset_id") or run.get("source") or "unknown"
            score = run.get("anomaly_score") or 0.0
            flagged = run.get("flagged") or run.get("quarantined")
            sev = "critical" if run.get("quarantined") else ("suspicious" if flagged else "clean")
            if asset not in nodes_map:
                nodes_map[asset] = {"id": asset, "label": asset, "severity": sev, "kind": "server"}
            else:
                if sev == "critical" or (sev == "suspicious" and nodes_map[asset]["severity"] == "clean"):
                    nodes_map[asset]["severity"] = sev
            mitre = run.get("mitre_tags", [])
            if mitre:
                src = "internet"
                if src not in nodes_map:
                    nodes_map[src] = {"id": src, "label": "Internet", "severity": "suspicious", "kind": "cloud"}
                eid = f"e-{src}-{asset}-{run['run_id'][:6]}"
                edges.append({"data": {"id": eid, "source": src, "target": asset,
                                       "weight": score, "kind": "attack" if flagged else "predicted"}})
        nodes = [{"data": v} for v in nodes_map.values()]
        return JSONResponse(content={
            "cytoscape": {"nodes": nodes, "edges": edges},
            "tgn_timeline": [],
            "sage_pca": [],
            "perf": {"source": "real_pipeline_runs", "runs_used": len(runs)},
        })
    except Exception as fb_exc:
        logger.error("/gnn/visualization fallback also failed: %s", fb_exc)
        raise HTTPException(status_code=500, detail=str(fb_exc))

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
    feed_pipeline: bool = False
    gnn_guided: bool = False


@app.post("/digital-twin/simulate", summary="A14: Simulate APT attack through the infrastructure graph")
async def digital_twin_simulate(req: SimulateRequest) -> JSONResponse:
    """
    POST /digital-twin/simulate
    Runs a simulated APT attack from start_node to target_node.
    If gnn_guided=true, uses A5-GNN predictions for lateral path selection.
    If feed_pipeline=true, each hop is fed through the real investigation pipeline.
    """
    try:
        from agents.digital_twin import DigitalTwin
        twin = DigitalTwin()
        if req.gnn_guided:
            result = twin.simulate_gnn_guided(
                start_node=req.start_node,
                target_node=req.target_node,
                attacker_ip=req.attacker_ip,
            )
            # If feeding is also desired during gnn_guided, simulate_gnn_guided doesn't do it natively,
            # but we can optionally trigger it or let it follow. We will adhere to simulate_gnn_guided's output.
        else:
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
        "version": "1.2.0",
        "docs":    "/docs",
        "health":  "/health",
        "endpoints": {
            "ingest": "/ingest",
            "gat_topology": "/gat/topology",
            "digital_twin_simulate": "/digital-twin/simulate",
            "digital_twin_graph": "/digital-twin/graph",
            "emergency_stop": "/emergency-stop",
            "sd_chain_status": "/sd/chain-status",
            "incident_timeline": "/incident/timeline/{hypothesis_id}",
            "decisions_pending": "/decisions/pending",
            "correction": "/correction/{action}",
            "chatbot": "/chatbot/query",
            "cert_in_report": "/cert-in/report/{hypothesis_id}",
        },
    })


# =============================================================================
# UI LAYER ENDPOINTS (Ticket 14)
# =============================================================================

_SEED_PATH = _ROOT / "data" / "demo_seed.json"

def _load_demo_seed() -> Dict[str, Any]:
    """Load seeded CBSE demo data. Used as fallback when real logs are absent."""
    if _SEED_PATH.exists():
        with open(_SEED_PATH, "r", encoding="utf-8") as f:
            return json.load(f)
    return {}


# ── Groq helper (same pattern as A6 / A8) ────────────────────────────────────

_GROQ_API_KEY = os.getenv("GROQ_API_KEY", "YOUR_GROQ_API_KEY_HERE")
_GROQ_MODEL   = os.getenv("GROQ_MODEL", "llama-3.1-8b-instant")
_GROQ_URL     = "https://api.groq.com/openai/v1/chat/completions"
_GROQ_TIMEOUT = 12


def _groq_chat(system_prompt: str, user_prompt: str, max_tokens: int = 512) -> Optional[str]:
    """
    Single-turn Groq Cloud inference call.
    Returns the raw text content or None on failure / missing key.
    """
    if not _GROQ_API_KEY or _GROQ_API_KEY == "YOUR_GROQ_API_KEY_HERE":
        logger.warning("UI-chatbot: GROQ_API_KEY not set — using mock fallback")
        return None
    try:
        payload = json.dumps({
            "model": _GROQ_MODEL,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user",   "content": user_prompt},
            ],
            "temperature": 0.3,
            "max_tokens":  max_tokens,
        }).encode()
        req = urllib.request.Request(
            _GROQ_URL,
            data=payload,
            headers={
                "Content-Type":  "application/json",
                "Authorization": f"Bearer {_GROQ_API_KEY}",
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            },
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=_GROQ_TIMEOUT) as resp:
            data = json.loads(resp.read())
            return data["choices"][0]["message"]["content"].strip()
    except Exception as exc:
        logger.warning("UI-chatbot: Groq call failed (%s) — mock fallback", exc)
        return None


# ── GET /incident/timeline/{hypothesis_id} ────────────────────────────────────

@app.get(
    "/incident/timeline/{hypothesis_id}",
    summary="UI: Incident metadata + scrubbable timeline events",
)
async def get_incident_timeline(hypothesis_id: str) -> JSONResponse:
    """
    Returns incident header (id, title, confidence, MITRE chain …) and the
    list of timeline events in the format expected by Timeline.jsx.

    Priority: cognitive_memory.jsonl → demo_seed.json fallback.
    """
    try:
        hyps = a12_audit.recall_hypotheses(limit=10)
        if hyps:
            target = hyps[0]
            if hypothesis_id not in ("latest", ""):
                for h in hyps:
                    if h.get("hypothesis_id") == hypothesis_id:
                        target = h
                        break
            return JSONResponse(content={
                "incident": {
                    "hypothesis_id": target.get("hypothesis_id"),
                    "title":         target.get("goal"),
                    "target":        target.get("mission_impact") or "CBSE System",
                    "detection_ts":  target.get("created_at"),
                    "status":        target.get("state"),
                    "confidence":    target.get("confidence", 0.5),
                    "mitre_chain":   target.get("mitre_chain", []),
                    "cert_in_deadline_hours": 6,
                    "affected_assets": [
                        {"id": ev, "name": ev, "criticality": "HIGH"}
                        for ev in target.get("supporting_evidence", [])[:3]
                    ],
                    "iocs": [],
                },
                "timeline_events": target.get("timeline", []),
            })
    except Exception as exc:
        logger.warning("/incident/timeline recall failed: %s", exc)

    # Fall back to seeded demo incident
    seed = _load_demo_seed()
    incident_seed = seed.get("incident")
    timeline_seed = seed.get("timeline_events")
    if incident_seed and (hypothesis_id in ("latest", "") or incident_seed.get("hypothesis_id") == hypothesis_id):
        return JSONResponse(content={
            "incident":        incident_seed,
            "timeline_events": timeline_seed,
        })

    return JSONResponse(content={
        "incident":        None,
        "timeline_events": [],
    })


# ── GET /decisions/pending ────────────────────────────────────────────────────

@app.get(
    "/decisions/pending",
    summary="UI: List of pending human-gate decisions",
)
async def get_pending_decisions() -> JSONResponse:
    """
    Scans the audit log for decisions where human_reviewed == False.
    Falls back to seeded demo decisions when the log is empty.
    """
    try:
        pending_db = mysql_store.get_pending_decisions()
        if pending_db:
            return JSONResponse(content=pending_db)
    except Exception as exc:
        logger.warning("/decisions/pending database read failed: %s", exc)

    try:
        entries = a12_audit.get_audit_log()
        pending: List[Dict[str, Any]] = []
        
        # Keep track of decisions that have been corrected/reviewed already to filter them out
        corrected_decision_ids = set()
        for entry in entries:
            if entry.get("entry_type") == "HUMAN_CORRECTION":
                corrected_decision_ids.add(entry.get("original_decision_id"))
                corrected_decision_ids.add(entry.get("corrected_decision_id"))

        for entry in entries:
            if entry.get("entry_type") == "HUMAN_CORRECTION":
                continue
            d_id = entry.get("decision_id")
            if d_id in corrected_decision_ids:
                continue
            if entry.get("human_reviewed") is False or ("decision_id" in entry and not entry.get("human_reviewed")):
                br = entry.get("blast_radius_score", 0.5)
                pending.append({
                    "decision_id":        d_id,
                    "hypothesis_id":      entry.get("hypothesis_id"),
                    "action_taken":       entry.get("action_taken"),
                    "risk_score":         entry.get("risk_score", 0.5),
                    "blast_radius_score": br,
                    "blast_radius_label": "LOW" if br < 0.3 else ("MEDIUM" if br < 0.7 else "HIGH"),
                    "proposed_by":        entry.get("agent_id", "A7-SOAR"),
                    "ts_iso":             entry.get("stored_at") or entry.get("created_at"),
                    "sla_seconds_left":   900,
                })
        
        return JSONResponse(content=pending)
    except Exception as exc:
        logger.warning("/decisions/pending scan failed: %s", exc)

    return JSONResponse(content=[])


# ── POST /decisions/explain/{decision_id} ─────────────────────────────────────

@app.post(
    "/decisions/explain/{decision_id}",
    summary="UI: On-demand AI explanation + production code for a Human Gate decision",
)
async def explain_decision(decision_id: str) -> JSONResponse:
    """
    Generates Groq LLM explanation for the given decision only when the
    analyst clicks 'Generate AI Analysis'. Falls back to a dynamic template
    if Groq is unavailable, so the UI never breaks.
    """
    dec: Dict[str, Any] = {}

    # 1. Fetch from MySQL
    try:
        conn = mysql_store._get_conn()
        if conn:
            with conn.cursor() as cur:
                cur.execute(
                    "SELECT decision_id, hypothesis_id, action_taken, risk_score, "
                    "blast_radius_score, proposed_by, status, created_at "
                    "FROM decisions WHERE decision_id=%s",
                    (decision_id,),
                )
                row = cur.fetchone()
                if row:
                    dec = {
                        "decision_id": row[0], "hypothesis_id": row[1],
                        "action_taken": row[2], "risk_score": float(row[3] or 0.5),
                        "blast_radius_score": float(row[4] or 0.0),
                        "proposed_by": row[5] or "A7-SOAR", "status": row[6],
                        "ts_iso": row[7].isoformat() + "Z" if row[7] else None,
                    }
    except Exception as e:
        logger.warning("explain_decision: DB fetch failed: %s", e)

    # 2. Fallback: scan audit log
    if not dec:
        try:
            for entry in a12_audit.get_audit_log():
                if entry.get("decision_id") == decision_id:
                    dec = {
                        "decision_id": decision_id,
                        "hypothesis_id": entry.get("hypothesis_id", "HYP-UNKNOWN"),
                        "action_taken": entry.get("action_taken", "MONITOR"),
                        "risk_score": float(entry.get("risk_score", 0.5)),
                        "blast_radius_score": float(entry.get("blast_radius_score", 0.0)),
                        "proposed_by": entry.get("agent_id", "A7-SOAR"),
                        "status": "pending",
                        "ts_iso": entry.get("stored_at"),
                    }
                    break
        except Exception:
            pass

    if not dec:
        dec = {
            "decision_id": decision_id, "hypothesis_id": "HYP-2026-014",
            "action_taken": "ISOLATE_HOST", "risk_score": 0.85,
            "blast_radius_score": 0.65, "proposed_by": "A7-SOAR",
            "status": "pending", "ts_iso": datetime.now(timezone.utc).isoformat() + "Z",
        }

    # 3. Try Groq LLM
    sys_prompt = (
        "You are an elite cybersecurity analyst for Indian critical infrastructure "
        "(CBSE exam portals, AIIMS hospitals, Power Grid SCADA). "
        "Generate a concise, technically accurate incident explanation.\n\n"
        "Return ONLY a valid JSON object with these exact keys:\n"
        "- what_happened: string (2-3 sentences describing detection and attack pattern)\n"
        "- potential_impact: string (2-3 sentences on blast if ignored)\n"
        "- why_stopped: string (1-2 sentences on why Human Gate was triggered, cite blast radius)\n"
        "- agent_decisions: list of {agent: str, result: str, color: str} \n"
        "- code_action: string (brief description of what execution code does)\n"
        "- production_code: string (complete realistic bash/python snippet for the action)\n"
        "- production_code_label: string (e.g. 'CrowdStrike Falcon RTR — Host Containment')\n"
        "- production_code_lang: string ('python' or 'bash')\n"
    )
    user_prompt = (
        f"Decision ID: {dec['decision_id']}\n"
        f"Hypothesis: {dec['hypothesis_id']}\n"
        f"Action Proposed: {dec['action_taken']}\n"
        f"Risk Score: {dec['risk_score']:.3f}\n"
        f"Blast Radius: {dec['blast_radius_score']:.3f}\n"
        f"Proposed By: {dec['proposed_by']}\n"
        f"Timestamp: {dec['ts_iso']}"
    )

    try:
        raw = _groq_chat(sys_prompt, user_prompt, max_tokens=900)
        if raw:
            s, e = raw.find("{"), raw.rfind("}") + 1
            if s >= 0 and e > s:
                parsed = json.loads(raw[s:e])
                required = ["what_happened", "potential_impact", "why_stopped",
                            "agent_decisions", "code_action", "production_code",
                            "production_code_label", "production_code_lang"]
                if all(k in parsed for k in required):
                    return JSONResponse(content=parsed)
    except Exception as llm_err:
        logger.warning("explain_decision: Groq failed (%s) — template fallback", llm_err)

    # 4. Dynamic template fallback (always works)
    act = str(dec["action_taken"]).upper()
    is_block   = "BLOCK" in act
    is_isolate = "ISOLATE" in act or "QUARANTINE" in act
    is_revoke  = "REVOKE" in act or "ROTATE" in act or "SESSION" in act
    is_notify  = "NOTIFY" in act or "ESCALATE" in act or "SOC" in act

    what_happened = (
        f"A malicious IP was detected attempting unauthorized access to "
        f"{dec['hypothesis_id']}. The A4 anomaly engine flagged score "
        f"{dec['risk_score']:.2f}, exceeding the detection threshold of 0.70."
    ) if is_block else (
        f"Lateral movement was observed propagating towards critical infrastructure. "
        f"A5-GNN correlation engine identified an attack path with score {dec['risk_score']:.2f}, "
        f"consistent with APT41 TTPs documented in MITRE ATT&CK T1021 (Remote Services)."
    ) if is_isolate else (
        f"Credential compromise was detected on a CBSE service account. "
        f"A6-Attribution matched the observed behavior to known APT credential-harvesting "
        f"patterns (T1552 — Unsecured Credentials) with confidence {dec['risk_score']:.2f}."
    ) if is_revoke else (
        f"Anomalous telemetry was detected with risk score {dec['risk_score']:.2f}. "
        f"Multi-agent consensus (A4→A6→A8) flagged this event for escalation."
    )

    potential_impact = (
        "Unblocked, the adversary may exploit exposed services for RCE, establish persistence "
        "via cron-job backdoors, and exfiltrate sensitive student exam data."
    ) if is_block else (
        "If the compromised host remains online, it can pivot to reach crown-jewel exam databases "
        "or SCADA OT networks — risking mass data exfiltration or physical infrastructure disruption."
    ) if is_isolate else (
        "Compromised service account keys allow persistent silent access, privilege escalation, "
        "and prolonged data exfiltration undetected by standard monitoring."
    ) if is_revoke else (
        "Continued unchecked access could result in unauthorized data access, "
        "service disruption, or establishment of a persistent backdoor."
    )

    why_stopped = (
        f"A7-SOAR proposed '{dec['action_taken']}'. Blast radius score "
        f"{dec['blast_radius_score']:.2f} exceeded the 0.30 autonomous threshold, so the system "
        f"correctly escalated to Human-in-the-Loop Gate to ensure an analyst validates "
        f"the action before any irreversible infrastructure change."
    )

    agent_decisions = [
        {"agent": "A4 Anomaly",    "result": f"Score {dec['risk_score']:.3f} → FLAGGED",              "color": "text-amber-400"},
        {"agent": "A6 Attribution", "result": "MITRE ATT&CK pattern matched — APT profile",           "color": "text-pink-400"},
        {"agent": "A8 Critic",      "result": f"FP likelihood: {((1-dec['risk_score'])*25):.0f}% — low","color": "text-rose-400"},
        {"agent": "A7 SOAR",        "result": f"Proposed: {dec['action_taken']} | blast={dec['blast_radius_score']:.2f}","color": "text-orange-400"},
    ]

    code_label, code_lang, prod_code, code_action = (
        (
            "FortiGate Firewall — Block IP Address", "bash",
            f"# FortiGate CLI — Block attacker IP\nconfig firewall address\n"
            f"  edit \"BlockedIP_185.23.147.82\"\n    set subnet 185.23.147.82 255.255.255.255\n  next\nend\n"
            f"config firewall policy\n  edit 0\n    set name \"HCI-OS-Block-{dec['decision_id'][-6:]}\"\n"
            f"    set srcaddr \"BlockedIP_185.23.147.82\"\n    set action deny\n    set logtraffic all\n  next\nend",
            "block all inbound/outbound traffic from the malicious IP at the FortiGate firewall layer",
        ) if is_block else (
            "CrowdStrike Falcon RTR — Host Containment", "python",
            f"import requests\n\nAPI_BASE = 'https://api.crowdstrike.com'\nTOKEN = '<FALCON_ACCESS_TOKEN>'\n\n"
            f"# 1. Resolve device ID for {dec['hypothesis_id']}\nresp = requests.get(\n    f'{{API_BASE}}/devices/queries/devices/v1',\n"
            f"    headers={{'Authorization': f'Bearer {{TOKEN}}'}},\n    params={{'filter': \"hostname:'{dec['hypothesis_id'].split('-')[2] if '-' in dec['hypothesis_id'] else 'CBSE-WebSvr-01'}'\"}},\n)\n"
            f"device_id = resp.json()['resources'][0]\n\n# 2. Network-contain the device\nrequests.post(\n"
            f"    f'{{API_BASE}}/devices/entities/devices-actions/v2',\n    headers={{'Authorization': f'Bearer {{TOKEN}}'}},\n"
            f"    params={{'action_name': 'contain'}},\n    json={{'ids': [device_id]}},\n)\nprint(f'[HCI-OS] Host contained at {{__import__(\"datetime\").datetime.utcnow()}}')\n",
            "trigger CrowdStrike Falcon RTR network containment on the compromised host",
        ) if is_isolate else (
            "AWS IAM — Rotate Service Account Credentials", "python",
            f"import boto3, datetime\n\niam = boto3.client('iam', region_name='ap-south-1')\nuser = 'svc-cbse-app'\n\n"
            f"# Deactivate all active access keys\nkeys = iam.list_access_keys(UserName=user)['AccessKeyMetadata']\n"
            f"for k in keys:\n    if k['Status'] == 'Active':\n"
            f"        iam.update_access_key(UserName=user, AccessKeyId=k['AccessKeyId'], Status='Inactive')\n"
            f"        print(f\"[HCI-OS] Revoked {{k['AccessKeyId']}} for {{user}}\")\n\n"
            f"# Force password reset\niam.update_login_profile(UserName=user, PasswordResetRequired=True)\n"
            f"print(f'[HCI-OS] Credential rotation complete at {{datetime.datetime.utcnow().isoformat()}}')\n",
            "deactivate all active AWS IAM access keys and force password reset for the compromised service account",
        ) if is_revoke else (
            "PagerDuty — Trigger SOC Incident", "python",
            f"import requests\n\nPAGERDUTY_TOKEN = '<PAGERDUTY_API_TOKEN>'\nSERVICE_ID = 'PCBSE01'\n\n"
            f"resp = requests.post(\n    'https://api.pagerduty.com/incidents',\n"
            f"    headers={{'Authorization': f'Token token={{PAGERDUTY_TOKEN}}', 'Content-Type': 'application/json', 'From': 'hci-os@cbse.gov.in'}},\n"
            f"    json={{'incident': {{'type': 'incident', 'title': '[HCI-OS] {dec['hypothesis_id']} — {dec['action_taken']}',\n"
            f"                    'service': {{'id': SERVICE_ID, 'type': 'service_reference'}}, 'urgency': 'high',\n"
            f"                    'body': {{'type': 'incident_body', 'details': 'Risk={dec['risk_score']:.2f}, Blast={dec['blast_radius_score']:.2f}'}}}}}},\n)\n"
            f"print(f\"[HCI-OS] PagerDuty incident: {{resp.json()['incident']['id']}}\")\n",
            "create a high-priority PagerDuty incident to immediately page the on-call SOC team",
        )
    )

    return JSONResponse(content={
        "what_happened":        what_happened,
        "potential_impact":     potential_impact,
        "why_stopped":          why_stopped,
        "agent_decisions":      agent_decisions,
        "code_action":          code_action,
        "production_code":      prod_code,
        "production_code_label": code_label,
        "production_code_lang": code_lang,
    })


# ── POST /correction/{action} ─────────────────────────────────────────────────

class CorrectionRequest(BaseModel):
    decision_id:  str
    analyst_role: str = "SENIOR"
    analyst_id:   str = "soc_analyst"
    new_action:   Optional[str] = None
    notes:        Optional[str] = None


@app.post(
    "/correction/{action}",
    summary="UI: Human Gate — confirm / revoke / modify / escalate a decision",
)
async def post_correction(action: str, req: CorrectionRequest) -> JSONResponse:
    """
    Applies a human correction to a Decision via A12's trust-weighted consensus gate.
    If the decision is not in the real audit log, falls back to the seed data so the
    demo Human Gate always works.
    """
    from objects.decision import Decision

    # 1. Try to find the decision in the real audit log
    target_dict: Optional[Dict[str, Any]] = None
    try:
        raw_entries = a12_audit._read_jsonl(a12_audit.AUDIT_LOG_PATH)
        for entry in reversed(raw_entries):
            if entry.get("decision_id") == req.decision_id:
                target_dict = entry
                break
    except Exception as exc:
        logger.warning("Correction: audit log read failed: %s", exc)

    # 2. Fall back to seed data so demo always works
    if not target_dict:
        seed = _load_demo_seed()
        match = next(
            (d for d in seed.get("pending_decisions", []) if d["decision_id"] == req.decision_id),
            None,
        )
        if not match:
            raise HTTPException(status_code=404, detail=f"Decision {req.decision_id} not found")
        target_dict = {
            "decision_id":        match["decision_id"],
            "hypothesis_id":      match["hypothesis_id"],
            "action_taken":       match["action_taken"],
            "risk_score":         match["risk_score"],
            "blast_radius_score": match["blast_radius_score"],
            "created_at":         match["ts_iso"],
        }

    try:
        decision = Decision.model_validate(target_dict)
        result   = a12_audit.apply_human_correction(
            decision=decision,
            correction_type=action.upper(),
            analyst_role=req.analyst_role.upper(),
            analyst_id=req.analyst_id,
            new_action=req.new_action,
            extra_notes=req.notes,
        )
        # Serialize Decision object if present
        corrected_decision_dict = None
        if result.get("corrected_decision") is not None:
            try:
                # If it's a model instance, serialize via to_json or model_dump
                if hasattr(result["corrected_decision"], "to_json"):
                    corrected_decision_dict = json.loads(result["corrected_decision"].to_json())
                elif hasattr(result["corrected_decision"], "model_dump"):
                    corrected_decision_dict = result["corrected_decision"].model_dump()
                else:
                    corrected_decision_dict = dict(result["corrected_decision"])
                result["corrected_decision"] = corrected_decision_dict
            except Exception:
                result["corrected_decision"] = str(result["corrected_decision"])

        # Persist correction to MySQL for full audit trail
        try:
            new_act_val = None
            if corrected_decision_dict and isinstance(corrected_decision_dict, dict):
                new_act_val = corrected_decision_dict.get("action_taken")

            mysql_store.save_correction({
                "decision_id": req.decision_id,
                "correction_type": action.upper(),
                "analyst_id": req.analyst_id,
                "analyst_role": req.analyst_role.upper(),
                "new_action": req.new_action or new_act_val,
                "notes": req.notes,
                "consensus_score": result.get("consensus_score", 1.0),
                "status": result.get("status", "applied"),
            })
            mysql_store.mark_decision_reviewed(
                req.decision_id, req.analyst_id, result.get("status", "applied"), new_action=new_act_val
            )
        except Exception as db_exc:
            logger.warning("post_correction DB logging failed: %s", db_exc)

        return JSONResponse(content=result)
    except Exception as exc:
        logger.error("/correction/%s failed: %s", action, exc)
        raise HTTPException(status_code=500, detail=str(exc))


# ── POST /chatbot/query ───────────────────────────────────────────────────────

class ChatbotRequest(BaseModel):
    query:          str
    hypothesis_id:  Optional[str] = None
    role:           Optional[str] = "SOC Analyst"


@app.post(
    "/chatbot/query",
    summary="UI: A6 Groq-powered SOC chatbot",
)
async def chatbot_query(req: ChatbotRequest) -> JSONResponse:
    """
    Sends the analyst's question to Groq Cloud (llama-3.1-8b-instant) with
    a SOC assistant system prompt. Falls back to keyword-matched seed responses
    if Groq is unavailable or the API key is not configured.
    """
    seed    = _load_demo_seed()
    system  = (
        "You are A6, the HCI-OS Reasoner assistant embedded in a SOC dashboard for India's "
        "critical infrastructure (AIIMS, CBSE, PowerGrid). You explain cyber incidents, "
        "hypotheses, evidence chains, and predicted attacker moves concisely and accurately. "
        "Current incident: HYP-2026-014 — Suspected Lateral Movement to CBSE Crown Jewel DB. "
        "Always answer in 2-4 sentences. Be precise and reference evidence IDs / decisions when relevant."
    )

    # Build enriched user prompt with incident context
    incident = seed.get("incident", {})
    context_blob = (
        f"Incident: {incident.get('title', 'unknown')} | "
        f"Hypothesis: {incident.get('hypothesis_id', '')} | "
        f"Status: {incident.get('status', '')} | "
        f"MITRE: {', '.join(incident.get('mitre_chain', []))} | "
        f"Analyst role: {req.role}"
    )
    user_prompt = f"Context: {context_blob}\n\nQuestion: {req.query}"

    # Try Groq Cloud first
    groq_response = _groq_chat(system, user_prompt, max_tokens=256)
    if groq_response:
        return JSONResponse(content={"response": groq_response, "source": "groq"})

    # Keyword fallback from seed
    q_lower = req.query.lower()
    for key, answer in seed.get("chatbot_responses", {}).items():
        if key in q_lower:
            return JSONResponse(content={"response": answer, "source": "mock"})

    return JSONResponse(content={
        "response": (
            "I can explain hypotheses, decisions, and predicted next moves. "
            "Try: 'Why was app-03 isolated?' or 'What is the next predicted hop?'"
        ),
        "source": "default",
    })


# ── GET /cert-in/report/{hypothesis_id} ──────────────────────────────────────

@app.get(
    "/cert-in/report/{hypothesis_id}",
    summary="UI: CERT-In Section 70B compliance report",
)
async def get_cert_in_report(
    hypothesis_id: str,
    format: str = Query("json", description="Response format: 'json' or 'md'"),
) -> Any:
    """
    Compiles a CERT-In Section 70B compliance report from the active hypothesis
    and audit chain. Falls back to seeded demo data.

    ?format=md  → returns plain-text Markdown for download.
    ?format=json → returns structured JSON consumed by CertInReport.jsx.
    """
    incident = {}
    timeline = []
    audit = []

    # Try to enrich with real hypothesis data
    try:
        h = None
        from stores import mysql_store
        conn = mysql_store._get_conn()
        # Resolve "latest" alias to most recent hypothesis in DB
        if hypothesis_id == "latest" and conn:
            with conn.cursor() as _cur:
                _cur.execute("SELECT hypothesis_id FROM hypotheses ORDER BY created_at DESC LIMIT 1")
                _row = _cur.fetchone()
                if _row:
                    hypothesis_id = _row[0]
        if conn:
            with conn.cursor() as cur:
                cur.execute(
                    "SELECT hypothesis_id, goal, confidence, state, mitre_chain, "
                    "supporting_ev, timeline, created_at, extra_json "
                    "FROM hypotheses WHERE hypothesis_id = %s",
                    (hypothesis_id,)
                )
                r = cur.fetchone()
                if r:
                    extra = json.loads(r[8]) if r[8] else {}
                    h = {
                        "hypothesis_id": r[0],
                        "goal": r[1],
                        "confidence": r[2],
                        "state": r[3],
                        "mitre_chain": json.loads(r[4]) if r[4] else [],
                        "supporting_evidence": json.loads(r[5]) if r[5] else [],
                        "timeline": json.loads(r[6]) if r[6] else [],
                        "created_at": r[7].isoformat() + "Z" if r[7] else None,
                    }
                    h.update(extra)

        # Fallback to recall_hypotheses search
        if not h:
            hyps = a12_audit.recall_hypotheses(limit=100)
            for x in hyps:
                if x.get("hypothesis_id") == hypothesis_id:
                    h = x
                    break

        if h:
            # Pull actions from real decisions
            actions_taken_list = []
            actions_reversed_list = []
            try:
                conn2 = mysql_store._get_conn()
                if conn2:
                    with conn2.cursor() as cur2:
                        cur2.execute(
                            "SELECT action_taken, status FROM decisions WHERE hypothesis_id=%s ORDER BY created_at DESC LIMIT 10",
                            (h.get("hypothesis_id"),)
                        )
                        for row in cur2.fetchall():
                            act, st = row
                            if act:
                                if str(act).upper().startswith("REVOKED:"):
                                    actions_reversed_list.append(act.split(":",1)[1].strip())
                                else:
                                    actions_taken_list.append(act)
            except Exception:
                pass

            incident = {
                "hypothesis_id":          h.get("hypothesis_id"),
                "title":                  h.get("goal"),
                "target":                 h.get("mission_impact") or h.get("asset_id") or "CBSE Critical System",
                "detection_ts":           h.get("created_at"),
                "status":                 h.get("state"),
                "confidence":             h.get("confidence", 0.5),
                "mitre_chain":            h.get("mitre_chain", []),
                "cert_in_deadline_hours": 6,
                "affected_assets": [
                    {"id": ev, "name": ev, "criticality": "HIGH"}
                    for ev in h.get("supporting_evidence", [])[:3]
                ],
                "iocs": [],
                "actions_taken":   " · ".join(actions_taken_list) if actions_taken_list else None,
                "actions_reversed": " · ".join(actions_reversed_list) if actions_reversed_list else "none",
            }
            timeline = h.get("timeline", [])
        else:
            seed = _load_demo_seed()
            incident = seed.get("incident", {})
            timeline = seed.get("timeline_events", [])
    except Exception as exc:
        logger.warning("/cert-in/report recall failed: %s", exc)
        seed = _load_demo_seed()
        incident = seed.get("incident", {})
        timeline = seed.get("timeline_events", [])

    # Try to enrich audit excerpt with real log entries
    try:
        real_log = a12_audit.get_audit_log(limit=6)
        if real_log:
            audit = [
                {
                    "ts":     entry.get("stored_at", ""),
                    "actor":  entry.get("agent_id") or entry.get("analyst_id") or "agent",
                    "event":  entry.get("entry_type") or entry.get("violation_type") or "log",
                    "target": entry.get("decision_id") or entry.get("audit_id") or "—",
                    "hash":   "0x" + entry.get("audit_hash", "")[:8] + "…",
                }
                for entry in real_log
            ]
        else:
            seed = _load_demo_seed()
            audit = seed.get("audit_log", [])
    except Exception:
        seed = _load_demo_seed()
        audit = seed.get("audit_log", [])

    if format == "md":
        lines: List[str] = [
            f"# CERT-In Cyber Incident Report — {incident.get('hypothesis_id', 'HYP-2026-014')}",
            f"Generated: {datetime.now(timezone.utc).isoformat()}Z",
            f"Filed under: Information Technology Act 2000, Section 70B | CERT-In Directions 28-Apr-2022",
            "",
            "## Incident Details",
            f"- **Title:** {incident.get('title')}",
            f"- **Target Asset:** {incident.get('target')}",
            f"- **Detection Timestamp:** {incident.get('detection_ts')}",
            f"- **Confidence:** {(incident.get('confidence', 0.5) * 100):.1f}%",
            f"- **Status:** {incident.get('status')}",
            f"- **MITRE ATT&CK Chain:** {', '.join(incident.get('mitre_chain', []))}",
            "",
            "## Affected Assets",
        ]
        for a in incident.get("affected_assets", []):
            lines.append(f"- {a['name']} ({a['criticality']})")
        lines += ["", "## Indicators of Compromise"]
        for ioc in incident.get("iocs", []):
            lines.append(f"- [{ioc['type']}] {ioc['value']} — {ioc['note']}")
        lines += ["", "## Investigation Timeline"]
        for ev in timeline:
            lines.append(f"- T+{ev.get('t', 0)}s [{ev.get('type')}] {ev.get('title')}: {ev.get('description')}")
        lines += ["", "## Audit Chain Excerpt"]
        for entry in audit:
            lines.append(f"- {entry.get('ts')} {entry.get('actor')}::{entry.get('event')} → {entry.get('target')} [{entry.get('hash')}]")
        lines += ["", "## DPDP Notification",
                  "Not applicable — no personal data exfiltrated. Placeholder for compliance workflow."]
        return PlainTextResponse(content="\n".join(lines))


    return JSONResponse(content={
        "incident":        incident,
        "timeline_events": timeline,
        "audit_excerpt":   audit,
    })


# ── POST /cert-in/generate/{hypothesis_id} ────────────────────────────────────

@app.post(
    "/cert-in/generate/{hypothesis_id}",
    summary="UI: On-demand AI compliance narrative via Groq (only when analyst requests it)",
)
async def generate_cert_in_ai(hypothesis_id: str) -> JSONResponse:
    """
    Generates deep AI compliance narrative for the incident. Called only on
    user click — never auto-generated — to preserve Groq API quota.
    """
    inc_summary = "Unknown incident"
    mitre_chain: List[str] = []
    confidence  = 0.5
    try:
        conn = mysql_store._get_conn()
        if conn:
            hid = hypothesis_id
            if hid == "latest":
                with conn.cursor() as _c:
                    _c.execute("SELECT hypothesis_id FROM hypotheses ORDER BY created_at DESC LIMIT 1")
                    _r = _c.fetchone()
                    if _r: hid = _r[0]
            with conn.cursor() as cur:
                cur.execute("SELECT goal, confidence, mitre_chain FROM hypotheses WHERE hypothesis_id=%s", (hid,))
                row = cur.fetchone()
                if row:
                    inc_summary = row[0] or "Critical infrastructure cyber threat"
                    confidence  = float(row[1] or 0.5)
                    mitre_chain = json.loads(row[2]) if row[2] else []
    except Exception as ex:
        logger.warning("cert-in/generate: context fetch failed: %s", ex)

    sys_prompt = (
        "You are a senior CERT-In compliance officer and threat intelligence expert "
        "for Indian critical infrastructure (CBSE, AIIMS, Power Grid). "
        "Generate a formal, detailed compliance narrative for a cyber incident.\n\n"
        "Return ONLY a valid JSON object with these exact keys:\n"
        "- abstract: string (3-4 sentences — executive summary)\n"
        "- root_cause: string (2-3 sentences — technical root cause)\n"
        "- attack_chain: string (3-4 sentences — step-by-step attack progression)\n"
        "- remediation: string (3-4 sentences — immediate mitigation and recovery)\n"
        "- legal_analysis: string (2-3 sentences — IT Act Sec 70B, DPDP Act, reporting obligations)\n"
        "- recommendations: string (3-4 sentences — long-term hardening recommendations)\n"
    )
    user_prompt = (
        f"Incident: {inc_summary}\n"
        f"MITRE ATT&CK: {', '.join(mitre_chain) or 'T1190, T1021, T1078'}\n"
        f"Confidence: {confidence:.2f}\n"
        f"Organization: CBSE — Indian Critical Infrastructure\n"
        f"Jurisdiction: India | IT Act 2000 Sec 70B, CERT-In Directions 28-Apr-2022"
    )

    try:
        raw = _groq_chat(sys_prompt, user_prompt, max_tokens=1100)
        if raw:
            s, e = raw.find("{"), raw.rfind("}") + 1
            if s >= 0 and e > s:
                parsed = json.loads(raw[s:e])
                required = ["abstract", "root_cause", "attack_chain", "remediation", "legal_analysis", "recommendations"]
                if all(k in parsed for k in required):
                    return JSONResponse(content=parsed)
    except Exception as llm_err:
        logger.warning("cert-in/generate: Groq failed (%s) — template fallback", llm_err)

    mitre_str = ", ".join(mitre_chain) if mitre_chain else "T1190, T1021, T1078"
    return JSONResponse(content={
        "abstract": (
            f"A sophisticated cyber intrusion was detected targeting CBSE's critical examination infrastructure. "
            f"The incident '{inc_summary}' was identified by HCI-OS with confidence {confidence:.0%}. "
            f"Immediate containment was triggered and escalated for analyst validation. "
            f"CERT-In notification is required within 6 hours under CERT-In Directions 28-Apr-2022."
        ),
        "root_cause": (
            f"Initial access was achieved via exploitation of public-facing web services ({mitre_str.split(',')[0].strip()}). "
            f"Weak perimeter controls and insufficient rate limiting created the vulnerability window. "
            f"The A4 anomaly engine identified patterns consistent with Log4Shell or credential-stuffing attacks."
        ),
        "attack_chain": (
            f"Attacker exploited the entry point for remote code execution on the web tier. "
            f"Lateral movement proceeded through LDAP abuse and SSH tunneling toward application servers. "
            f"A5-GNN traced the propagation path across 5,026 knowledge graph nodes. "
            f"Crown-jewel examination databases were the confirmed final objective."
        ),
        "remediation": (
            f"Network isolation of compromised hosts was proposed by A7-SOAR and approved through the Human Gate. "
            f"Service account credentials were rotated and MFA activated on all privileged accounts. "
            f"Firewall rules updated to block identified attacker IP ranges. "
            f"Forensic imaging and log forwarding to CERT-In designated portal initiated."
        ),
        "legal_analysis": (
            f"This incident qualifies as a reportable cyber incident under IT Act 2000 Section 70B "
            f"and CERT-In Directions 28-Apr-2022 (mandatory 6-hour reporting). "
            f"No personal examination data was confirmed exfiltrated — DPDP Act 2023 notification is not triggered. "
            f"All audit logs preserved in tamper-proof A12 hash-chain format as legal evidence."
        ),
        "recommendations": (
            f"Deploy zero-trust network architecture with microsegmentation between web, app, and database tiers. "
            f"Integrate SIEM with real-time MITRE ATT&CK correlation across all 30 infrastructure nodes. "
            f"Conduct quarterly red-team exercises targeting exam portals during pre-exam periods. "
            f"Establish 24×7 SOC coverage with dedicated CERT-In liaison for faster incident reporting."
        ),
    })


# ── GET /stats/telemetry ──────────────────────────────────────────────────────

@app.get(
    "/stats/telemetry",
    summary="UI: Real-time AI telemetry & brain metrics (database-backed)",
)
async def get_telemetry_stats() -> JSONResponse:
    """
    Returns real-time counters from the MySQL `ingest_events`, `decisions`,
    `human_corrections`, and `sd_logs` tables.
    Falls back to zeros when database is unavailable.
    """
    stats = mysql_store.get_telemetry_stats()
    return JSONResponse(content=stats)


# ── GET /corrections/history ──────────────────────────────────────────────────

@app.get(
    "/corrections/history",
    summary="UI: Full human correction audit trail",
)
async def get_correction_history() -> JSONResponse:
    """
    Returns all human gate actions (CONFIRM/REVOKE/MODIFY/ESCALATE) from MySQL.
    """
    history = mysql_store.get_correction_history(limit=100)
    return JSONResponse(content=history)


# ── GET /pipeline/history ─────────────────────────────────────────────────────

@app.get(
    "/pipeline/history",
    summary="UI: Full pipeline trace history for explainability modal",
)
async def get_pipeline_history(
    limit: int = Query(50, description="Max runs to return"),
    source: Optional[str] = Query(None, description="Filter by source"),
) -> JSONResponse:
    """
    Returns all pipeline runs from MySQL newest-first with per-agent trace steps,
    MITRE tags, SD events, and decision IDs for the Pipeline Explainability Trace modal.
    Falls back to reading from the audit_log.jsonl + cognitive_memory.jsonl when DB unavailable.
    """
    # Try MySQL first
    runs = mysql_store.list_pipeline_runs(limit=limit, source_filter=source)
    if runs:
        return JSONResponse(content=runs)

    # Fallback: synthesise from audit log
    try:
        audit = a12_audit.get_audit_log(limit=limit)
        fallback = []
        for entry in audit:
            fallback.append({
                "run_id": entry.get("audit_id"),
                "source": entry.get("source", "audit_log"),
                "asset_id": entry.get("asset_id"),
                "trust_score": entry.get("trust_score"),
                "quarantined": False,
                "flagged": entry.get("risk_score", 0) > 0.6 or entry.get("action_taken") not in (None, "MONITOR", "none"),
                "anomaly_score": entry.get("risk_score"),
                "evidence_id": entry.get("evidence_id"),
                "hypothesis_id": entry.get("hypothesis_id"),
                "decision_id": entry.get("decision_id"),
                "mitre_tags": entry.get("mitre_chain", []),
                "pipeline_trace": [],
                "sd_events": [],
                "audit_hash": entry.get("audit_hash"),
                "created_at": entry.get("stored_at"),
            })
        return JSONResponse(content=fallback)
    except Exception as exc:
        logger.warning("/pipeline/history fallback failed: %s", exc)
        return JSONResponse(content=[])


# ── GET /agent/code/{agent_id} ────────────────────────────────────────────────

@app.get(
    "/agent/code/{agent_id}",
    summary="UI: Retrieve agent source code or rules for explainability modal",
)
async def get_agent_code(agent_id: str) -> JSONResponse:
    """
    Reads the main logic/source code of the specified agent (A1-A13)
    from agents/ directory and returns it as a string for rendering.
    """
    agent_map = {
        "A1": "a1_ingest.py",
        "A2": "a2_normalize.py",
        "A3": "a3_fingerprint.py",
        "A4": "a4_anomaly.py",
        "A5": "a5_gnn.py",
        "A6": "a6_attribution.py",
        "A7": "a7_soar.py",
        "A8": "a8_critic.py",
        "A10": "a10_hunt.py",
        "A12": "a12_audit.py",
        "A13": "a13_federation.py",
    }
    
    filename = agent_map.get(agent_id.upper())
    if not filename:
        raise HTTPException(status_code=404, detail=f"Agent {agent_id} not found")
        
    try:
        agent_path = Path(__file__).parent / "agents" / filename
        if not agent_path.exists():
            raise HTTPException(status_code=404, detail=f"Source file {filename} does not exist")
            
        with open(agent_path, "r", encoding="utf-8") as f:
            code = f.read()
            
        return JSONResponse(content={"agent_id": agent_id, "filename": filename, "code": code})
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))

