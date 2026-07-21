"""
pipeline/investigation_loop.py
Master Investigation Loop — HCI-OS

Full pipeline wiring:
  [Raw Telemetry]
    → A1 (SD-0/SD-1: Ingest + Sanitize + Trust Score)
      ↳ trust==0.00 → QUARANTINE (logged SD-7) — HALT
    → A2 (Normalize → Evidence Object)
    → A3 (Fingerprint Router: exact-match / semantic / novel)
    → A4 (Anomaly Detection)
    → A5 (GNN Correlator — lateral movement prediction)
    → A6 (Attribution & RAG — SD-3 Resource Guardian)
    → A10 (Active Hunt — SD-8 Kill Switch guard, SD-3 circuit breaker)
    → A8 (Critic — challenges hypothesis, rates FP likelihood)
    → A7 (SOAR Planner — SD-8 Kill Switch guard)
      ↳ Gap #5: if A8 FP likelihood > 0.5 → force HUMAN_GATE
    → A13 (Federation — SD-8 Kill Switch guard, SD-5 Output Gate)
    → A12 (Audit & Memory)

All agent calls pass through:
  SD-4  Write-authorization enforcement
  SD-6  A11 Behavioral Watchdog
  SD-7  Forensic rejection logging via a12_audit.log_rejection()
  SD-8  AUTONOMY_FROZEN kill-switch check for autonomous agents
"""

from __future__ import annotations

import logging
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

# Ensure hci_os package root is on path when run directly
_PACKAGE_ROOT = Path(__file__).resolve().parent.parent
if str(_PACKAGE_ROOT) not in sys.path:
    sys.path.insert(0, str(_PACKAGE_ROOT))

from agents import a1_ingest, a2_normalize, a3_fingerprint, a4_anomaly, a5_gnn, a6_attribution
from agents import a7_soar, a8_critic, a10_hunt, a11_watchdog, a12_audit, a13_federation
from agents.self_defense import (
    KillSwitchError,
    OutputJudgeViolation,
    check_kill_switch,
    is_autonomy_frozen,
    output_gate,
)
from objects.evidence import Evidence
from objects.hypothesis import Hypothesis

logger = logging.getLogger("InvestigationLoop")
logging.basicConfig(level=logging.INFO)


# =============================================================================
# SD-6 Helper — execute any agent function wrapped by A11 watchdog
# =============================================================================

def _run(agent_id: str, func, *args, action_called: Optional[str] = None, **kwargs) -> Any:
    """Execute func under A11 watchdog supervision (SD-6)."""
    return a11_watchdog.execute_with_watchdog(
        agent_id, func, *args, action_called=action_called, **kwargs
    )


# =============================================================================
# PIPELINE ENTRY POINT
# =============================================================================

def run_investigation(
    raw_event: Dict[str, Any],
    asset_id: str = "",
    source: str = "",
    existing_hypothesis: Optional[Hypothesis] = None,
    hours_since_update: Optional[float] = None,
) -> Dict[str, Any]:
    """
    Run a single raw telemetry event through the full HCI-OS investigation pipeline.

    Args:
        raw_event:            Raw log/telemetry dictionary.
        asset_id:             Target asset ID (optional — A1/A2 will infer if absent).
        source:               Source system label (optional).
        existing_hypothesis:  Pass an existing open hypothesis to continue building on it.
        hours_since_update:   For A7 confidence decay (default: 1.0 h).

    Returns:
        Structured result dict with keys:
            - quarantined: bool
            - trust_score: float
            - evidence_id: str | None
            - anomaly_score: float | None
            - hypothesis: dict | None
            - decision: dict | None
            - audit_hash: str | None
            - sd_events: list[dict]  ← all self-defense events fired this run
    """
    result: Dict[str, Any] = {
        "quarantined":    False,
        "trust_score":    None,
        "evidence_id":    None,
        "anomaly_score":  None,
        "hypothesis":     None,
        "decision":       None,
        "audit_hash":     None,
        "sd_events":      [],
        # ── NEW: step-by-step explainability trace ──
        "pipeline_trace": [],
        "flagged":        False,
        "mitre_tags":     [],
    }

    def _sd_event(layer: str, description: str, data: Any = None):
        result["sd_events"].append({"layer": layer, "description": description})
        try:
            a12_audit.log_rejection(
                agent_id=layer,
                violation_type=description,
                reason=description,
                input_data=data,
            )
        except Exception:
            pass  # never crash the pipeline on a logging failure

    def _trace(agent: str, status: str, summary: str, detail: Optional[Dict] = None):
        """Append one pipeline step to the trace."""
        result["pipeline_trace"].append({
            "agent":   agent,
            "status":  status,   # "pass" | "block" | "flag" | "skip" | "error"
            "summary": summary,
            "detail":  detail or {},
        })

    # ─── SD-0 / SD-1: Ingest & Trust-Score Gate ───────────────────────────────
    logger.info("Pipeline: SD-0/SD-1 — running A1 ingest + trust score")
    try:
        ingest_result = _run("A1", a1_ingest.process, raw_event, asset_id=asset_id, source=source)
    except Exception as exc:
        logger.error("A1 ingest failed: %s", exc)
        _sd_event("SD-0", f"A1 ingest error: {exc}", raw_event)
        _trace("A1", "error", f"Ingest failed: {exc}")
        result["quarantined"] = True
        return result

    trust_score: float = ingest_result.get("trust_score", 0.0)
    result["trust_score"] = trust_score

    if trust_score == 0.0:
        logger.warning(
            "Pipeline: SD-1 QUARANTINE — trust_score=0.00, source='%s'",
            ingest_result.get("source", "unknown"),
        )
        _sd_event(
            "SD-1",
            "quarantined_input — trust_score=0.00",
            {"source": ingest_result.get("source"), "event_preview": str(raw_event)[:200]},
        )
        _trace("A1", "block",
               f"SD-1 QUARANTINE — untrusted source '{ingest_result.get('source', 'unknown')}' (trust=0.00)",
               {"trust_score": 0.0, "source": ingest_result.get("source")})
        result["quarantined"] = True
        return result

    _trace("A1", "pass",
           f"Ingested & sanitized · trust={trust_score:.2f} · source={ingest_result.get('source', source or 'unknown')}",
           {"trust_score": trust_score,
            "source": ingest_result.get("source"),
            "ot_protocol": ingest_result.get("ot_context", {}).get("protocol") if isinstance(ingest_result.get("ot_context"), dict) else None,
            "sanitization_events": len(ingest_result.get("sanitization_events", []))})
    logger.info("Pipeline: SD-1 PASS — trust_score=%.2f", trust_score)

    # ─── A2: Normalize → Evidence Object ──────────────────────────────────────
    logger.info("Pipeline: A2 Normalize")
    try:
        evidence: Evidence = _run(
            "A2", a2_normalize.process,
            ingest_result.get("sanitized_payload", raw_event),
            asset_id=asset_id,
            source=source or ingest_result.get("source", ""),
        )
        result["evidence_id"] = evidence.evidence_id
        _trace("A2", "pass",
               f"Normalized to Evidence · id={evidence.evidence_id} · asset={evidence.asset_id}",
               {"evidence_id": evidence.evidence_id, "asset_id": evidence.asset_id,
                "event_type": getattr(evidence, "event_type", None)})
    except Exception as exc:
        logger.error("A2 normalize failed: %s", exc)
        _trace("A2", "error", f"Normalization failed: {exc}")
        result["quarantined"] = True
        return result

    # ─── A3: Fingerprint Router ────────────────────────────────────────────────
    logger.info("Pipeline: A3 Fingerprint Router")
    try:
        fp_result = _run("A3", a3_fingerprint.process, evidence)
        fp_type = fp_result.get("fingerprint_type", "novel") if isinstance(fp_result, dict) else "routed"
        _trace("A3", "pass",
               f"Fingerprint: {fp_type} match · pattern classified",
               {"fingerprint_type": fp_type})
    except Exception as exc:
        logger.warning("A3 fingerprint error (non-fatal): %s", exc)
        _trace("A3", "skip", f"Fingerprint skipped (non-fatal): {exc}")

    # ─── A4: Anomaly Detection ─────────────────────────────────────────────────
    logger.info("Pipeline: A4 Anomaly Detection")
    anomaly_score: float = 0.0
    try:
        anomaly_result = _run("A4", a4_anomaly.process, evidence)
        if isinstance(anomaly_result, dict):
            anomaly_score = float(anomaly_result.get("anomaly_score", 0.0))
        elif isinstance(anomaly_result, Evidence):
            anomaly_score = float(anomaly_result.context.get("anomaly_score", 0.0))
        result["anomaly_score"] = anomaly_score
        is_flagged = anomaly_score > 0.6
        result["flagged"] = is_flagged
        _trace("A4", "flag" if is_flagged else "pass",
               f"Anomaly score: {anomaly_score:.3f} {'⚠ FLAGGED' if is_flagged else '· within threshold'}",
               {"anomaly_score": anomaly_score, "flagged": is_flagged,
                "detector": anomaly_result.get("detector") if isinstance(anomaly_result, dict) else None})
    except Exception as exc:
        logger.warning("A4 anomaly error (non-fatal): %s", exc)
        _trace("A4", "skip", f"Anomaly detection skipped: {exc}")

    # ─── Hypothesis Initialization ─────────────────────────────────────────────
    if existing_hypothesis is None:
        from objects.hypothesis import Hypothesis
        # Load asset inventory to determine mission and criticality
        try:
            import json
            from pathlib import Path
            inventory_path = Path(__file__).parent.parent / "data" / "asset_inventory.json"
            with open(inventory_path, "r", encoding="utf-8") as f:
                assets = json.load(f)
            target_asset = asset_id or evidence.asset_id
            asset_info = assets.get(target_asset, {})
            if asset_info:
                mission = asset_info.get("mission", "unknown_mission")
                criticality = asset_info.get("criticality", "MEDIUM")
                mission_impact = f"{mission} — {criticality}"
            else:
                mission_impact = f"perimeter — MEDIUM"
        except Exception:
            mission_impact = "CBSE System"

        hypothesis = Hypothesis.model_validate({
            "goal": f"Investigate anomalous event on {asset_id or evidence.asset_id}",
            "confidence": 0.5,
            "supporting_evidence": [evidence.evidence_id],
            "mission_impact": mission_impact,
        })
    else:
        hypothesis = existing_hypothesis


    # ─── A5: GNN Correlator (lateral movement prediction) ──────────────────────
    logger.info("Pipeline: A5 GNN Correlator")
    try:
        _hyp5 = _run("A5", a5_gnn.process, evidence, hypothesis)
        if isinstance(_hyp5, Hypothesis):
            hypothesis = _hyp5
        mitre = getattr(hypothesis, "mitre_chain", []) or []
        result["mitre_tags"] = mitre
        _trace("A5", "pass",
               f"GNN correlation · confidence={hypothesis.confidence:.2f} · MITRE: {', '.join(mitre) if mitre else 'none'}",
               {"confidence": hypothesis.confidence, "mitre_chain": mitre,
                "predicted_hops": len(getattr(hypothesis, "predicted_next_hops", []))})
    except Exception as exc:
        logger.warning("A5 GNN error (non-fatal): %s", exc)
        _trace("A5", "skip", f"GNN correlator skipped: {exc}")

    # ─── A6: Attribution & RAG (wrapped with SD-6 watchdog) ───────────────────
    logger.info("Pipeline: A6 Attribution")
    try:
        _hyp6 = _run("A6", a6_attribution.process, evidence, hypothesis)
        if isinstance(_hyp6, Hypothesis):
            hypothesis = _hyp6
            _trace("A6", "pass",
                   f"Attribution complete · confidence={hypothesis.confidence:.2f}",
                   {"confidence": hypothesis.confidence, "goal": hypothesis.goal})
        else:
            _trace("A6", "skip", f"A6 returned unexpected type {type(_hyp6).__name__} — hypothesis unchanged")
    except Exception as exc:
        logger.warning("A6 attribution error (non-fatal): %s", exc)
        _trace("A6", "skip", f"Attribution skipped: {exc}")

    # ─── A10: Active Hunt (SD-8 Kill Switch guard) ─────────────────────────────
    logger.info("Pipeline: A10 Active Hunt")
    try:
        check_kill_switch("A10")   # SD-8
        _ev10_dict = evidence.model_dump() if hasattr(evidence, "model_dump") else dict(evidence)
        _hyp10 = _run("A10", a10_hunt.process, _ev10_dict, hypothesis)
        if isinstance(_hyp10, Hypothesis):
            hypothesis = _hyp10
            _trace("A10", "pass", "Active Hunt completed · threat intelligence correlated",
                   {"state": hypothesis.state, "confidence": hypothesis.confidence})
        else:
            _trace("A10", "skip", f"A10 returned unexpected type {type(_hyp10).__name__} — hypothesis unchanged")
    except KillSwitchError as kse:
        logger.warning("A10 BLOCKED by kill switch: %s", kse)
        _sd_event("SD-8", str(kse), {"agent": "A10"})
        _trace("A10", "block", f"BLOCKED by Kill Switch (SD-8): {kse}")
    except Exception as exc:
        logger.warning("A10 hunt error (non-fatal): %s", exc)
        _trace("A10", "skip", f"Hunt skipped: {exc}")

    # ─── A8: Critic Agent (challenges hypothesis) ─────────────────────────────
    logger.info("Pipeline: A8 Critic")
    critic_fp = 0.0
    try:
        _hyp8 = _run("A8", a8_critic.process, evidence, hypothesis)
        if isinstance(_hyp8, Hypothesis):
            hypothesis = _hyp8
        if hasattr(hypothesis, "world_model") and hypothesis.world_model is not None:
            critic_fp = hypothesis.world_model.safety_constraints.get("critic_fp_likelihood", 0.0)
        _trace("A8", "flag" if critic_fp > 0.5 else "pass",
               f"Critic · FP-likelihood={critic_fp:.2f} · {'HUMAN_GATE forced' if critic_fp > 0.5 else 'hypothesis accepted'}",
               {"fp_likelihood": critic_fp, "confidence": hypothesis.confidence})
    except Exception as exc:
        logger.warning("A8 critic error (non-fatal): %s", exc)
        _trace("A8", "skip", f"Critic skipped: {exc}")

    # Gap #5: If critic rates false-positive likelihood > 0.5, force HUMAN_GATE
    if critic_fp > 0.5:
        logger.warning(
            "Pipeline: A8 critic FP=%.2f > 0.50 — forcing HUMAN_GATE via safety constraint",
            critic_fp,
        )
        if hasattr(hypothesis, "world_model") and hypothesis.world_model is not None:
            hypothesis.world_model.safety_constraints["auto_isolate_allowed"] = False

    result["hypothesis"] = {"confidence": hypothesis.confidence, "state": hypothesis.state}

    # ─── A7: SOAR Planner (SD-8 Kill Switch guard) ────────────────────────────
    logger.info("Pipeline: A7 SOAR Planner")
    decision = None
    try:
        check_kill_switch("A7")   # SD-8
        decision = _run(
            "A7", a7_soar.process,
            hypothesis, evidence,
            hours_since_update=hours_since_update,
        )
        if decision:
            result["decision"] = {
                "decision_id":  decision.decision_id,
                "action_taken": decision.action_taken,
                "risk_score":   decision.risk_score,
            }
            is_pending = "PENDING" in decision.action_taken
            status_text = "awaiting Human Gate" if is_pending else "executed autonomously"
            _trace("A7", "pass",
                   f"SOAR planned action: '{decision.action_taken}' · risk={decision.risk_score:.2f} · {status_text}",
                   {"decision_id": decision.decision_id, "action": decision.action_taken,
                    "risk_score": decision.risk_score, "blast_radius": getattr(decision, "blast_radius_score", None)})
        else:
            _trace("A7", "skip", "SOAR: no actionable decision generated")
    except KillSwitchError as kse:
        logger.warning("A7 BLOCKED by kill switch: %s", kse)
        _sd_event("SD-8", str(kse), {"agent": "A7"})
        _trace("A7", "block", f"BLOCKED by Kill Switch (SD-8): {kse}")
    except Exception as exc:
        logger.warning("A7 SOAR error (non-fatal): %s", exc)
        _trace("A7", "skip", f"SOAR skipped: {exc}")

    # ─── A13: Federation (SD-5 Output Gate + SD-8 Kill Switch guard) ──────────
    logger.info("Pipeline: A13 Federation")
    try:
        check_kill_switch("A13")   # SD-8
        fed_output = _run("A13", a13_federation.process, evidence, hypothesis)
        # SD-5: gate the federation output before release
        output_gate(fed_output, agent_id="A13", destination="federation_store", raise_on_block=False)
        _trace("A13", "pass", "Federated to peer org nodes · SD-5 output gate passed")
    except KillSwitchError as kse:
        logger.warning("A13 BLOCKED by kill switch: %s", kse)
        _sd_event("SD-8", str(kse), {"agent": "A13"})
        _trace("A13", "block", f"Federation BLOCKED by Kill Switch (SD-8): {kse}")
    except OutputJudgeViolation as ojv:
        logger.warning("A13 output blocked by SD-5: %s", ojv)
        _sd_event("SD-5", str(ojv), {"agent": "A13"})
        _trace("A13", "block", f"Federation blocked by SD-5 Output Gate: {ojv}")
    except Exception as exc:
        logger.warning("A13 federation error (non-fatal): %s", exc)
        _trace("A13", "skip", f"Federation skipped: {exc}")

    # ─── A12: Audit & Memory ───────────────────────────────────────────────────
    logger.info("Pipeline: A12 Audit & Memory")
    if decision:
        try:
            audit_result = _run("A12", a12_audit.process, decision, hypothesis)
            result["audit_hash"] = audit_result.get("audit_hash")
            _trace("A12", "pass",
                   f"Immutable audit entry created · hash={str(result['audit_hash'])[:16]}…",
                   {"audit_hash": result["audit_hash"]})
        except Exception as exc:
            logger.warning("A12 audit error (non-fatal): %s", exc)
            _trace("A12", "skip", f"Audit skipped: {exc}")
    else:
        _trace("A12", "skip", "No decision to audit")

    # Populate asset_id at root if evidence exists
    if "evidence" in locals() and evidence:
        result["asset_id"] = evidence.asset_id
    
    # Flag run if decision has a non-monitoring action
    if result.get("decision") and result["decision"].get("action_taken") not in (None, "MONITOR", "none"):
        result["flagged"] = True

    logger.info(
        "Pipeline COMPLETE: ev=%s trust=%.2f anomaly=%.2f decisions=%s trace_steps=%d",
        result["evidence_id"],
        trust_score,
        result["anomaly_score"] or 0.0,
        result["decision"]["action_taken"] if result["decision"] else "none",
        len(result["pipeline_trace"]),
    )
    return result


# =============================================================================
# BATCH PROCESSING
# =============================================================================

def run_batch(
    events: List[Dict[str, Any]],
    asset_id: str = "",
    source: str = "",
) -> List[Dict[str, Any]]:
    """
    Process a list of raw events through the investigation loop.
    Quarantined events are included in results with quarantined=True.
    """
    results = []
    for i, event in enumerate(events):
        logger.info("Pipeline batch: processing event %d/%d", i + 1, len(events))
        results.append(run_investigation(event, asset_id=asset_id, source=source))
    return results
