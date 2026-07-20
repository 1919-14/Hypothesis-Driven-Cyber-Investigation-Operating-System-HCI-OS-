"""
agents/a8_critic.py
A8: Critic / Skeptic Agent (Layer 7, LLM-3) — HCI-OS

REAL second LLM call that challenges hypotheses with counter-evidence.
Uses the same Groq API / Llama 3.x 8B as A6, but with a DIFFERENT
system prompt — a skeptical security analyst perspective.

Output: counter_evidence list, false_positive_likelihood (0-1), reasoning.

Gap Fixes:
  #5  Critic → A7 integration: sets hypothesis.false_positive_likelihood.
      investigation_loop forces HUMAN_GATE if FP > 0.5.
  #8  Explicit mock responses for all mission types (exam_portal,
      power_management, patient_records, default).
"""

from __future__ import annotations

import json
import logging
import os
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from dotenv import load_dotenv

logger = logging.getLogger("A8_Critic")
logging.basicConfig(level=logging.INFO)

load_dotenv()

GROQ_API_KEY = os.getenv("GROQ_API_KEY", "YOUR_GROQ_API_KEY_HERE")
GROQ_MODEL = os.getenv("GROQ_MODEL", "llama-3.1-8b-instant")
GROQ_URL = "https://api.groq.com/openai/v1/chat/completions"
GROQ_TIMEOUT = 12


# ── System Prompt ──────────────────────────────────────────────────────────────

CRITIC_SYSTEM_PROMPT = (
    "You are a skeptical security analyst for Indian critical infrastructure "
    "(CBSE, AIIMS, Power Grid). Your job is to CHALLENGE the hypothesis — "
    "find reasons it could be a false positive.\n\n"
    "Check these counter-evidence types:\n"
    "1. whitelist: Is the source IP or asset whitelisted?\n"
    "2. known_scanner: Is this a known vulnerability scanner (Nessus, Qualys, Shodan)?\n"
    "3. valid_certificate: Does the connection have a valid TLS certificate?\n"
    "4. redteam_window: Is this during a scheduled red-team exercise?\n"
    "5. maintenance_window: Is this during scheduled maintenance?\n\n"
    "Output ONLY valid JSON with keys:\n"
    "- counter_evidence: list of {type: str, found: bool, detail: str}\n"
    "- false_positive_likelihood: float 0.0-1.0\n"
    "- reasoning: string explaining your analysis\n"
    "- recommended_action: 'proceed' | 'human_review' | 'dismiss'"
)


# ── Mock Responses (Gap #8) ───────────────────────────────────────────────────

_MOCKS: Dict[str, Dict[str, Any]] = {
    "exam_portal": {
        "counter_evidence": [
            {"type": "whitelist", "found": False, "detail": "Source IP 185.23.147.82 is NOT in CBSE whitelist"},
            {"type": "known_scanner", "found": False, "detail": "IP not in known scanner databases"},
            {"type": "valid_certificate", "found": False, "detail": "No valid TLS cert on the connection"},
            {"type": "redteam_window", "found": False, "detail": "No red-team exercise currently scheduled"},
            {"type": "maintenance_window", "found": False, "detail": "Outside maintenance window"},
        ],
        "false_positive_likelihood": 0.08,
        "reasoning": (
            "No counter-evidence found. Source IP is foreign, targets exam portal "
            "during off-hours, and uses Log4Shell payload patterns consistent with "
            "APT41. Hypothesis is highly plausible."
        ),
        "recommended_action": "proceed",
    },
    "power_management": {
        "counter_evidence": [
            {"type": "whitelist", "found": False, "detail": "Source not whitelisted for OT/SCADA access"},
            {"type": "known_scanner", "found": False, "detail": "Not a known security scanner"},
            {"type": "valid_certificate", "found": False, "detail": "No TLS on Modbus/DNP3 connections"},
            {"type": "redteam_window", "found": False, "detail": "No red-team exercise scheduled"},
            {"type": "maintenance_window", "found": True, "detail": "Possible overlap with grid maintenance window"},
        ],
        "false_positive_likelihood": 0.22,
        "reasoning": (
            "Slight overlap with scheduled grid maintenance window raises FP likelihood "
            "slightly. However, the attack pattern (lateral movement via IEC-104) is "
            "inconsistent with standard maintenance operations. Recommend proceeding "
            "with caution."
        ),
        "recommended_action": "proceed",
    },
    "patient_records": {
        "counter_evidence": [
            {"type": "whitelist", "found": False, "detail": "Source not in AIIMS trusted list"},
            {"type": "known_scanner", "found": False, "detail": "Not a known scanner"},
            {"type": "valid_certificate", "found": True, "detail": "Valid internal CA certificate found"},
            {"type": "redteam_window", "found": False, "detail": "No red-team exercise scheduled"},
            {"type": "maintenance_window", "found": False, "detail": "Outside maintenance window"},
        ],
        "false_positive_likelihood": 0.35,
        "reasoning": (
            "Valid internal CA certificate is present, which could indicate a "
            "legitimate internal service. However, the access pattern to patient "
            "records from an unusual source raises concerns. Recommend human review."
        ),
        "recommended_action": "human_review",
    },
    "default": {
        "counter_evidence": [
            {"type": "whitelist", "found": False, "detail": "Source not whitelisted"},
            {"type": "known_scanner", "found": False, "detail": "Not a known scanner"},
            {"type": "valid_certificate", "found": False, "detail": "No valid certificate"},
            {"type": "redteam_window", "found": False, "detail": "No red-team exercise scheduled"},
            {"type": "maintenance_window", "found": False, "detail": "Outside maintenance window"},
        ],
        "false_positive_likelihood": 0.12,
        "reasoning": "No strong counter-evidence found. Hypothesis is plausible.",
        "recommended_action": "proceed",
    },
}


# ── LLM Call ──────────────────────────────────────────────────────────────────

def _build_user_prompt(hypothesis: Any, evidence: Any) -> str:
    """Build the user prompt from hypothesis and evidence."""
    # Extract fields flexibly (Pydantic model or dict)
    if hasattr(hypothesis, "goal"):
        goal = hypothesis.goal
        conf = hypothesis.confidence
        chain = hypothesis.mitre_chain
        supporting = hypothesis.supporting_evidence
    elif isinstance(hypothesis, dict):
        goal = hypothesis.get("goal", "Unknown")
        conf = hypothesis.get("confidence", 0.5)
        chain = hypothesis.get("mitre_chain", [])
        supporting = hypothesis.get("supporting_evidence", [])
    else:
        goal, conf, chain, supporting = "Unknown", 0.5, [], []

    if hasattr(evidence, "normalized"):
        ev_data = {
            "asset_id": evidence.asset_id,
            "source": evidence.source,
            "normalized": dict(list(evidence.normalized.items())[:6]) if evidence.normalized else {},
            "criticality": evidence.context.get("criticality", "MEDIUM"),
            "mission": evidence.context.get("mission", ""),
        }
    elif isinstance(evidence, dict):
        ev_data = evidence
    else:
        ev_data = {}

    return (
        f"Hypothesis: {goal}\n"
        f"Confidence: {conf}\n"
        f"MITRE Chain: {chain}\n"
        f"Supporting Evidence: {len(supporting)} items\n"
        f"Evidence Details:\n{json.dumps(ev_data, indent=2, default=str)}"
    )


def _call_llm(hypothesis: Any, evidence: Any) -> Dict[str, Any]:
    """Call Groq API for critic analysis. Falls back to mock if unavailable."""
    if not GROQ_API_KEY or GROQ_API_KEY == "YOUR_GROQ_API_KEY_HERE":
        logger.warning("A8: Groq API Key not configured — using mock response")
        return _get_mock_response(hypothesis, evidence)

    user_prompt = _build_user_prompt(hypothesis, evidence)

    try:
        import urllib.request

        payload = json.dumps({
            "model": GROQ_MODEL,
            "messages": [
                {"role": "system", "content": CRITIC_SYSTEM_PROMPT},
                {"role": "user", "content": user_prompt},
            ],
            "temperature": 0.1,
            "max_tokens": 512,
            "response_format": {"type": "json_object"},
        }).encode()

        req = urllib.request.Request(
            GROQ_URL,
            data=payload,
            headers={
                "Content-Type": "application/json",
                "Authorization": f"Bearer {GROQ_API_KEY}",
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            },
            method="POST",
        )

        with urllib.request.urlopen(req, timeout=GROQ_TIMEOUT) as resp:
            res = json.loads(resp.read())
            raw = res["choices"][0]["message"]["content"]

        # Parse JSON from response
        s, e = raw.find("{"), raw.rfind("}") + 1
        if s >= 0 and e > s:
            parsed = json.loads(raw[s:e])
            if "false_positive_likelihood" in parsed:
                # Clamp to [0, 1]
                parsed["false_positive_likelihood"] = max(
                    0.0, min(1.0, float(parsed["false_positive_likelihood"]))
                )
                return parsed

    except Exception as exc:
        logger.warning("A8: Groq LLM call failed (%s) — mock fallback", exc)

    return _get_mock_response(hypothesis, evidence)


def _get_mock_response(hypothesis: Any, evidence: Any) -> Dict[str, Any]:
    """Gap #8: Return explicit mock response based on mission type."""
    mission = ""
    if hasattr(evidence, "context"):
        mission = evidence.context.get("mission", "")
    elif isinstance(evidence, dict):
        mission = evidence.get("context", {}).get("mission", "")
        if not mission:
            mission = evidence.get("mission", "")

    for key in _MOCKS:
        if key != "default" and key in mission:
            return dict(_MOCKS[key])

    return dict(_MOCKS["default"])


# ── Main Entry Point ──────────────────────────────────────────────────────────

def process(
    evidence: Any,
    hypothesis: Any,
) -> Any:
    """
    A8 Critic Agent — challenge the hypothesis with counter-evidence.

    Steps:
      1. Call Groq LLM with skeptical system prompt (or mock fallback).
      2. Parse counter-evidence, false_positive_likelihood, reasoning.
      3. Update hypothesis.contradicting_evidence with critic findings.
      4. Set hypothesis false_positive_likelihood for A7 integration (Gap #5).
      5. Add timeline event.

    Returns:
        Updated hypothesis.
    """
    start = time.perf_counter()

    # 1. LLM call
    result = _call_llm(hypothesis, evidence)

    fp_likelihood = float(result.get("false_positive_likelihood", 0.12))
    reasoning = result.get("reasoning", "")
    counter_evidence = result.get("counter_evidence", [])
    recommended_action = result.get("recommended_action", "proceed")

    # 2. Update hypothesis
    if hasattr(hypothesis, "contradicting_evidence"):
        # Add critic reasoning to contradicting evidence
        for ce in counter_evidence:
            if ce.get("found"):
                hypothesis.contradicting_evidence.append(
                    f"A8 Critic: {ce['type']} — {ce.get('detail', '')}"
                )
        hypothesis.contradicting_evidence.append(
            f"A8 Critic verdict: FP likelihood={fp_likelihood:.2f} | {reasoning[:200]}"
        )

    # Gap #5: Store false_positive_likelihood in hypothesis context for A7
    if hasattr(hypothesis, "world_model") and hypothesis.world_model is not None:
        hypothesis.world_model.safety_constraints["critic_fp_likelihood"] = fp_likelihood
    elif hasattr(hypothesis, "context") and isinstance(hypothesis.context, dict):
        hypothesis.context["critic_fp_likelihood"] = fp_likelihood

    # 3. Timeline event
    if hasattr(hypothesis, "add_timeline_event"):
        hypothesis.add_timeline_event(
            time_str=datetime.now(timezone.utc).strftime("%H:%M:%S"),
            event=(
                f"A8 Critic: FP={fp_likelihood:.0%} | "
                f"{len([c for c in counter_evidence if c.get('found')])} counter-evidence found | "
                f"Action: {recommended_action}"
            ),
            event_type="critic_review",
        )

    ms = (time.perf_counter() - start) * 1000
    logger.info(
        "A8: FP=%.2f | action=%s | counter_ev=%d | %.1fms",
        fp_likelihood, recommended_action, len(counter_evidence), ms,
    )

    return hypothesis
