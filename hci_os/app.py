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

    seed = _load_demo_seed()
    return JSONResponse(content={
        "incident":        seed.get("incident", {}),
        "timeline_events": seed.get("timeline_events", []),
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
        entries = a12_audit.get_audit_log()
        pending: List[Dict[str, Any]] = []
        for entry in entries:
            if entry.get("entry_type") == "HUMAN_CORRECTION":
                continue
            if entry.get("human_reviewed") is False or ("decision_id" in entry and not entry.get("human_reviewed")):
                br = entry.get("blast_radius_score", 0.5)
                pending.append({
                    "decision_id":        entry.get("decision_id"),
                    "hypothesis_id":      entry.get("hypothesis_id"),
                    "action_taken":       entry.get("action_taken"),
                    "risk_score":         entry.get("risk_score", 0.5),
                    "blast_radius_score": br,
                    "blast_radius_label": "LOW" if br < 0.3 else ("MEDIUM" if br < 0.7 else "HIGH"),
                    "proposed_by":        entry.get("agent_id", "A7-SOAR"),
                    "ts_iso":             entry.get("stored_at") or entry.get("created_at"),
                    "sla_seconds_left":   900,
                })
        if pending:
            return JSONResponse(content=pending)
    except Exception as exc:
        logger.warning("/decisions/pending scan failed: %s", exc)

    seed = _load_demo_seed()
    return JSONResponse(content=seed.get("pending_decisions", []))


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
        if result.get("corrected_decision") is not None:
            try:
                result["corrected_decision"] = json.loads(result["corrected_decision"].to_json())
            except Exception:
                result["corrected_decision"] = str(result["corrected_decision"])
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
    seed     = _load_demo_seed()
    incident = seed.get("incident", {})
    timeline = seed.get("timeline_events", [])
    audit    = seed.get("audit_log", [])

    # Try to enrich with real hypothesis data
    try:
        hyps = a12_audit.recall_hypotheses(limit=1)
        if hyps:
            h = hyps[0]
            incident = {
                "hypothesis_id":          h.get("hypothesis_id"),
                "title":                  h.get("goal"),
                "target":                 h.get("mission_impact") or "CBSE Grade-12 Result DB",
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
            }
            timeline = h.get("timeline", timeline)
    except Exception as exc:
        logger.warning("/cert-in/report recall failed: %s", exc)

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
    except Exception:
        pass

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
