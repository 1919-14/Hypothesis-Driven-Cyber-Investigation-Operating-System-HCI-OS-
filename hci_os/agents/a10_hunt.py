"""
agents/a10_hunt.py
A10: Active Hunt Agent (Layer 5.5) — HCI-OS

Actively hunts corroborating evidence when anomaly_score > 0.7
and no open hypothesis covers the asset.

Gap Fixes:
  Gap 1  Structured mock responses   — MOCK_VT_RESPONSE / MOCK_SHODAN_RESPONSE defined
  Gap 2  Empty entity handling        — skip + logger.warning if no entities extracted
  Gap 3  60-second cooling window     — circuit breaker explicitly set to 60s
  Gap 4  Linear boost formula         — boost = 0.05 + 0.10 * hunt_score → [0.05, 0.15]
  Gap 5  Structured logging           — logger.info/warning/error at all decision points

Pipeline position: A4/A6 (anomaly + attribution) → [A10] → Hypothesis.supporting_evidence
"""

from __future__ import annotations

import base64
import hashlib
import json
import logging
import os
import re
import time
import uuid
from collections import deque
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import requests

from objects.evidence import Evidence
from objects.hypothesis import Hypothesis

# ── Logging ───────────────────────────────────────────────────────────────────
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("A10_Hunt")

# ── Paths ─────────────────────────────────────────────────────────────────────
_AGENT_DIR = Path(__file__).parent
_DATA_DIR  = _AGENT_DIR.parent / "data"
_HUNT_CACHE_PATH = _DATA_DIR / "hunt_cache.json"

# ── API Config ────────────────────────────────────────────────────────────────
VT_API_KEY:     Optional[str] = os.environ.get("VT_API_KEY")
SHODAN_API_KEY: Optional[str] = os.environ.get("SHODAN_API_KEY")

VT_BASE_URL     = "https://www.virustotal.com/api/v3"
SHODAN_BASE_URL = "https://api.shodan.io"

HUNT_TIMEOUT_SECS = 10
HUNT_MAX_RETRIES  = 3
HUNT_BACKOFF_BASE = 1     # seconds; exponential: 1s, 2s, 4s

# ── Thresholds ────────────────────────────────────────────────────────────────
ANOMALY_SCORE_THRESHOLD   = 0.7
VT_MAX_REQ_PER_MINUTE     = 4
VT_RATE_WINDOW_SECS       = 60

# ── Circuit Breaker ───────────────────────────────────────────────────────────
CB_MAX_FAILURES    = 3
CB_COOLING_SECS    = 60   # Gap #3 — explicitly 60 seconds

# ── Cache ─────────────────────────────────────────────────────────────────────
CACHE_TTL_HOURS = 24

# ── Confidence Boost Formula ──────────────────────────────────────────────────
# Gap #4 — linear: boost = BOOST_BASE + BOOST_SLOPE * hunt_score
# hunt_score=0.0 → boost=0.05  |  hunt_score=1.0 → boost=0.15
BOOST_BASE  = 0.05
BOOST_SLOPE = 0.10

# ── Mock Responses (Gap #1) ───────────────────────────────────────────────────
MOCK_VT_RESPONSE: Dict[str, Any] = {
    "data": {
        "attributes": {
            "last_analysis_stats": {
                "malicious":  0,
                "suspicious": 0,
                "undetected": 72,
                "harmless":   18,
            }
        }
    },
    "_mock": True,
}

MOCK_SHODAN_RESPONSE: Dict[str, Any] = {
    "ip_str": "0.0.0.0",
    "ports":  [],
    "vulns":  {},
    "tags":   [],
    "_mock":  True,
}


# =============================================================================
# ENTITY EXTRACTION
# =============================================================================

# (entity_type, compiled_pattern, priority — lower = hunted first)
_ENTITY_PATTERNS: List[Tuple[str, re.Pattern, int]] = [
    ("hash",   re.compile(r"\b([a-fA-F0-9]{64}|[a-fA-F0-9]{40}|[a-fA-F0-9]{32})\b"), 1),
    ("ip",     re.compile(r"\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b"),               2),
    ("domain", re.compile(r"\b([a-zA-Z0-9-]{2,63}\.[a-zA-Z]{2,6})\b"),                 3),
    ("url",    re.compile(r"(https?://[^\s\"'<>]+)"),                                   4),
]

_PRIVATE_IP = re.compile(
    r"^(10\.|172\.(1[6-9]|2\d|3[01])\.|192\.168\.|127\.|0\.0\.0\.0)"
)


def _flatten_values(data: Any) -> List[str]:
    """Recursively collect all scalar values from nested dicts/lists."""
    out: List[str] = []
    if isinstance(data, dict):
        for v in data.values():
            out.extend(_flatten_values(v))
    elif isinstance(data, list):
        for item in data:
            out.extend(_flatten_values(item))
    elif data is not None:
        out.append(str(data))
    return out


def extract_entities(evidence_data: Dict[str, Any]) -> List[Dict[str, str]]:
    """
    Extract huntable entities from Evidence data dict.
    Returns [{type, value}] sorted by priority (hash first).
    Private IPs are excluded. Deduplication by value.
    """
    text = " ".join(_flatten_values(evidence_data))
    seen: Dict[str, Dict[str, Any]] = {}

    for etype, pattern, priority in _ENTITY_PATTERNS:
        for m in pattern.finditer(text):
            val = m.group(1)
            if etype == "ip" and _PRIVATE_IP.match(val):
                continue
            if etype == "domain" and len(val) < 5:
                continue
            if val not in seen or seen[val]["priority"] > priority:
                seen[val] = {"type": etype, "value": val, "priority": priority}

    entities = sorted(seen.values(), key=lambda e: e["priority"])
    logger.info("A10: extracted %d entities", len(entities))
    return [{"type": e["type"], "value": e["value"]} for e in entities]


# =============================================================================
# RATE LIMITER
# =============================================================================

class RateLimiter:
    """Sliding-window rate limiter (thread-safe via GIL for single-process use)."""

    def __init__(self, max_requests: int, window_seconds: float):
        self.max_requests   = max_requests
        self.window_seconds = window_seconds
        self._timestamps: deque = deque()

    def wait_if_needed(self) -> None:
        now = time.monotonic()
        while self._timestamps and self._timestamps[0] < now - self.window_seconds:
            self._timestamps.popleft()
        if len(self._timestamps) >= self.max_requests:
            sleep_secs = self.window_seconds - (now - self._timestamps[0])
            if sleep_secs > 0:
                logger.info("A10: rate limit — sleeping %.2fs", sleep_secs)
                time.sleep(sleep_secs)
        self._timestamps.append(time.monotonic())


_vt_rate_limiter = RateLimiter(VT_MAX_REQ_PER_MINUTE, VT_RATE_WINDOW_SECS)


# =============================================================================
# CIRCUIT BREAKER  (Gap #3 — 60s cooling window)
# =============================================================================

class CircuitBreaker:
    def __init__(self, max_failures: int = CB_MAX_FAILURES, cooling_secs: float = CB_COOLING_SECS):
        self.max_failures = max_failures
        self.cooling_secs = cooling_secs
        self._failures:    int = 0
        self._open_since:  Optional[float] = None

    @property
    def is_open(self) -> bool:
        if self._open_since is None:
            return False
        if time.monotonic() - self._open_since >= self.cooling_secs:
            logger.info("A10: circuit breaker RESET after %.0fs cooling", self.cooling_secs)
            self._failures   = 0
            self._open_since = None
            return False
        return True

    def record_success(self) -> None:
        self._failures   = 0
        self._open_since = None

    def record_failure(self) -> None:
        self._failures += 1
        if self._failures >= self.max_failures and self._open_since is None:
            self._open_since = time.monotonic()
            logger.warning(
                "A10: circuit breaker OPEN (%d failures, cooling=%ds)",
                self._failures, int(self.cooling_secs),
            )


_circuit_breaker = CircuitBreaker()


# =============================================================================
# HUNT CACHE
# =============================================================================

def _cache_key(etype: str, value: str) -> str:
    return hashlib.sha256(f"{etype}::{value}".encode()).hexdigest()[:32]


def _load_cache() -> Dict[str, Any]:
    if not _HUNT_CACHE_PATH.exists():
        return {}
    try:
        with open(_HUNT_CACHE_PATH, "r", encoding="utf-8") as fh:
            return json.load(fh)
    except (json.JSONDecodeError, OSError) as exc:
        logger.warning("A10: cache read error (%s) — fresh start", exc)
        return {}


def _save_cache(cache: Dict[str, Any]) -> None:
    try:
        _DATA_DIR.mkdir(parents=True, exist_ok=True)
        with open(_HUNT_CACHE_PATH, "w", encoding="utf-8") as fh:
            json.dump(cache, fh, indent=2, default=str)
    except OSError as exc:
        logger.warning("A10: cache write error (%s)", exc)


def get_cached_result(etype: str, value: str) -> Optional[Dict[str, Any]]:
    cache = _load_cache()
    entry = cache.get(_cache_key(etype, value))
    if not entry:
        return None
    cached_at = datetime.fromisoformat(entry["cached_at"])
    age_h = (datetime.now(timezone.utc) - cached_at).total_seconds() / 3600.0
    if age_h > CACHE_TTL_HOURS:
        logger.info("A10: cache EXPIRED for %s:%s (%.1fh)", etype, value, age_h)
        return None
    logger.info("A10: cache HIT for %s:%s (%.1fh old)", etype, value, age_h)
    return entry["result"]


def set_cached_result(etype: str, value: str, result: Dict[str, Any]) -> None:
    cache = _load_cache()
    cache[_cache_key(etype, value)] = {
        "entity_type": etype,
        "entity_value": value,
        "cached_at": datetime.now(timezone.utc).isoformat(),
        "result": result,
    }
    _save_cache(cache)


# =============================================================================
# HTTP CLIENT
# =============================================================================

def _hunt_with_retry(url: str, headers: Optional[Dict[str, str]] = None) -> Dict[str, Any]:
    """GET with timeout + exponential backoff. Records to circuit breaker."""
    if _circuit_breaker.is_open:
        logger.warning("A10: circuit OPEN — skipping %s", url)
        return {"error": "circuit_breaker_open"}

    for attempt in range(HUNT_MAX_RETRIES):
        try:
            resp = requests.get(url, headers=headers or {}, timeout=HUNT_TIMEOUT_SECS)
            if resp.status_code == 200:
                _circuit_breaker.record_success()
                return resp.json()
            elif resp.status_code == 429:
                logger.warning("A10: HTTP 429 rate limited — attempt %d", attempt + 1)
            else:
                logger.warning("A10: HTTP %d from remote — attempt %d", resp.status_code, attempt + 1)
        except (requests.Timeout, requests.ConnectionError) as exc:
            logger.warning("A10: request error (%s) attempt %d/%d", exc, attempt + 1, HUNT_MAX_RETRIES)
        time.sleep(HUNT_BACKOFF_BASE * (2 ** attempt))

    _circuit_breaker.record_failure()
    logger.error("A10: all %d retries failed for %s", HUNT_MAX_RETRIES, url)
    return {"error": f"failed_after_{HUNT_MAX_RETRIES}_retries"}


# =============================================================================
# VIRUSTOTAL CLIENT
# =============================================================================

def _vt_url(etype: str, value: str) -> Optional[str]:
    if etype == "ip":
        return f"{VT_BASE_URL}/ip_addresses/{value}"
    if etype == "domain":
        return f"{VT_BASE_URL}/domains/{value}"
    if etype == "hash":
        return f"{VT_BASE_URL}/files/{value}"
    if etype == "url":
        encoded = base64.urlsafe_b64encode(value.encode()).rstrip(b"=").decode()
        return f"{VT_BASE_URL}/urls/{encoded}"
    return None


def _parse_vt_stats(resp: Dict[str, Any]) -> Tuple[Dict[str, int], float]:
    """Extract analysis stats and compute hunt_score."""
    if "error" in resp:
        return {}, 0.0
    try:
        stats: Dict[str, int] = (
            resp.get("data", {})
                .get("attributes", {})
                .get("last_analysis_stats", {})
        )
        mal  = stats.get("malicious",  0)
        sus  = stats.get("suspicious", 0)
        und  = stats.get("undetected", 0)
        har  = stats.get("harmless",   0)
        total = mal + sus + und + har
        score = (mal + sus) / total if total > 0 else 0.0
        return stats, round(score, 4)
    except Exception as exc:
        logger.warning("A10: VT stats parse error (%s)", exc)
        return {}, 0.0


def query_virustotal(etype: str, value: str) -> Tuple[Dict[str, Any], float]:
    """
    Query VirusTotal. Falls back to MOCK_VT_RESPONSE (Gap #1) if key absent.
    Returns (raw_response, hunt_score).
    """
    if not VT_API_KEY:
        logger.warning("A10: VT_API_KEY missing — using mock for %s:%s", etype, value)
        stats, score = _parse_vt_stats(MOCK_VT_RESPONSE)
        return {**MOCK_VT_RESPONSE, "entity_type": etype, "entity_value": value}, score

    url = _vt_url(etype, value)
    if not url:
        logger.warning("A10: no VT endpoint for entity type '%s'", etype)
        return {"error": "unsupported_entity_type"}, 0.0

    _vt_rate_limiter.wait_if_needed()
    logger.info("A10: querying VT %s:%s", etype, value)
    raw = _hunt_with_retry(url, headers={"x-apikey": VT_API_KEY})
    stats, score = _parse_vt_stats(raw)
    logger.info("A10: VT hunt_score=%.4f stats=%s for %s", score, stats, value)
    return raw, score


# =============================================================================
# SHODAN CLIENT
# =============================================================================

def query_shodan(ip: str) -> Dict[str, Any]:
    """
    Query Shodan for an IP. Falls back to MOCK_SHODAN_RESPONSE (Gap #1) if key absent.
    Roadmap: domain ASN and certificate lookups.
    """
    if not SHODAN_API_KEY:
        logger.warning(
            "A10: SHODAN_API_KEY missing — stubbing for %s "
            "[ROADMAP: add SHODAN_API_KEY to .env for live service enrichment]", ip,
        )
        return MOCK_SHODAN_RESPONSE

    url = f"{SHODAN_BASE_URL}/shodan/host/{ip}?key={SHODAN_API_KEY}"
    logger.info("A10: querying Shodan IP %s", ip)
    return _hunt_with_retry(url)


def _parse_shodan(raw: Dict[str, Any]) -> Dict[str, Any]:
    if "error" in raw:
        return {"shodan_available": False, "error": raw["error"]}
    return {
        "shodan_available": True,
        "ports":    raw.get("ports", []),
        "vulns":    list(raw.get("vulns", {}).keys()),
        "tags":     raw.get("tags", []),
        "is_c2":    "c2" in [t.lower() for t in raw.get("tags", [])],
        "has_vulns": bool(raw.get("vulns")),
        "_mock":    raw.get("_mock", False),
    }


# =============================================================================
# CONFIDENCE BOOST  (Gap #4)
# =============================================================================

def compute_confidence_boost(hunt_score: float) -> float:
    """
    Linear formula: boost = 0.05 + 0.10 * hunt_score
    Range: [0.05 … 0.15]
    """
    return round(BOOST_BASE + BOOST_SLOPE * max(0.0, min(1.0, hunt_score)), 4)


def boost_hypothesis_confidence(hyp: Hypothesis, hunt_score: float, evidence_id: str) -> None:
    """Apply confidence boost and attach new evidence ID. Clamps to [0.0, 1.0]."""
    boost = compute_confidence_boost(hunt_score)
    old   = hyp.confidence
    hyp.confidence = round(min(1.0, hyp.confidence + boost), 4)
    hyp.supporting_evidence.append(evidence_id)
    logger.info(
        "A10: hypothesis %s confidence %.4f → %.4f (boost=+%.4f, hunt_score=%.4f)",
        hyp.hypothesis_id, old, hyp.confidence, boost, hunt_score,
    )


# =============================================================================
# HUNT EVIDENCE BUILDER
# =============================================================================

def _fingerprint(payload: Dict[str, Any]) -> str:
    return hashlib.sha256(
        json.dumps(payload, sort_keys=True, default=str).encode()
    ).hexdigest()


def build_hunt_evidence(
    etype: str,
    value: str,
    vt_stats: Dict[str, int],
    hunt_score: float,
    shodan_data: Optional[Dict[str, Any]],
    asset_id: str,
    criticality: str = "HIGH",
) -> Evidence:
    """Construct a new Evidence object from hunt results."""
    eid = f"EV-HUNT-{uuid.uuid4().hex[:8].upper()}"
    normalized: Dict[str, Any] = {
        "entity_type":      etype,
        "entity_value":     value,
        "virustotal_stats": vt_stats,
        "hunt_score":       hunt_score,
    }
    if shodan_data:
        normalized["shodan"] = shodan_data

    ev = Evidence.model_validate({
        "evidence_id":         eid,
        "timestamp":           datetime.now(timezone.utc),
        "source":              "active_hunt_virustotal",
        "asset_id":            asset_id,
        "normalized":          normalized,
        "content_fingerprint": _fingerprint(normalized),
        "behavior_embedding":  [0.0],
        "context":             {"criticality": criticality, "hunt_type": "virustotal", "hunt_score": hunt_score},
        "confidence":          round(hunt_score, 4),
        "uncertainty":         round(max(0.0, 1.0 - hunt_score), 4),
        "provenance":          "A10_active_hunt",
    })
    logger.info("A10: created hunt Evidence %s (entity=%s:%s, score=%.4f)", eid, etype, value, hunt_score)
    return ev


# =============================================================================
# TRIGGER CHECK
# =============================================================================

def _get_anomaly_score(evidence_data: Dict[str, Any]) -> float:
    """Read anomaly_score from context or fall back to top-level confidence."""
    ctx_score = evidence_data.get("context", {}).get("anomaly_score")
    if ctx_score is not None:
        return float(ctx_score)
    return float(evidence_data.get("confidence", 0.0))


def _open_hypothesis_matches(asset_id: str, open_hypotheses: Optional[List[Hypothesis]]) -> bool:
    """True if any ACTIVE_INVESTIGATION hypothesis covers this asset."""
    if not open_hypotheses:
        return False
    for hyp in open_hypotheses:
        if hyp.state == "ACTIVE_INVESTIGATION" and asset_id.lower() in hyp.goal.lower():
            return True
    return False


def should_trigger(
    evidence_data: Dict[str, Any],
    open_hypotheses: Optional[List[Hypothesis]] = None,
) -> Tuple[bool, str]:
    """Returns (fire, reason)."""
    score    = _get_anomaly_score(evidence_data)
    asset_id = evidence_data.get("asset_id", "")

    if score <= ANOMALY_SCORE_THRESHOLD:
        reason = f"anomaly_score={score:.4f} ≤ threshold={ANOMALY_SCORE_THRESHOLD}"
        logger.info("A10: trigger SKIP — %s", reason)
        return False, reason

    if _open_hypothesis_matches(asset_id, open_hypotheses):
        reason = f"open hypothesis already covers asset_id='{asset_id}'"
        logger.info("A10: trigger SKIP — %s", reason)
        return False, reason

    reason = f"anomaly_score={score:.4f} > {ANOMALY_SCORE_THRESHOLD}, no open hypothesis"
    logger.info("A10: trigger FIRE — %s", reason)
    return True, reason


# =============================================================================
# MAIN ENTRY POINT
# =============================================================================

def process(
    evidence_data: Dict[str, Any],
    hypothesis: Optional[Hypothesis] = None,
    open_hypotheses: Optional[List[Hypothesis]] = None,
) -> Dict[str, Any]:
    """
    A10 pipeline function.

    Args:
        evidence_data:    Evidence dict from A4/A6.
        hypothesis:       Active Hypothesis to update (optional).
        open_hypotheses:  Open hypotheses for duplicate-trigger guard.

    Returns dict with:
        triggered, reason, hunt_results, hunt_evidences, hypothesis_updated
    """
    triggered, reason = should_trigger(evidence_data, open_hypotheses)
    if not triggered:
        return {
            "triggered": False, "reason": reason,
            "hunt_results": [], "hunt_evidences": [], "hypothesis_updated": False,
        }

    asset_id    = str(evidence_data.get("asset_id", "UNKNOWN"))
    criticality = evidence_data.get("context", {}).get("criticality", "HIGH")

    # ── Entity extraction ─────────────────────────────────────────────────────
    entities = extract_entities(evidence_data)

    # Gap #2 — skip with structured log if nothing to hunt
    if not entities:
        logger.warning("A10: no huntable entities in evidence for asset=%s — hunt skipped", asset_id)
        return {
            "triggered": True, "reason": "no huntable entities",
            "hunt_results": [], "hunt_evidences": [], "hypothesis_updated": False,
        }

    hunt_results:   List[Dict[str, Any]] = []
    hunt_evidences: List[Evidence]       = []
    hypothesis_updated                   = False

    for entity in entities:
        etype = entity["type"]
        value = entity["value"]

        logger.info("A10: hunting %s:%s for asset=%s", etype, value, asset_id)

        # ── Cache lookup ──────────────────────────────────────────────────────
        cached = get_cached_result(etype, value)
        if cached:
            vt_stats   = cached.get("vt_stats", {})
            hunt_score = cached.get("hunt_score", 0.0)
            shodan_data = cached.get("shodan_data")
        else:
            # ── VirusTotal ────────────────────────────────────────────────────
            vt_raw, hunt_score = query_virustotal(etype, value)
            vt_stats, _        = _parse_vt_stats(vt_raw)

            # ── Shodan (IPs only) ─────────────────────────────────────────────
            shodan_data = None
            if etype == "ip":
                shodan_raw  = query_shodan(value)
                shodan_data = _parse_shodan(shodan_raw)
                # Additional boost if Shodan confirms C2 or vulnerabilities
                if shodan_data.get("is_c2") or shodan_data.get("has_vulns"):
                    hunt_score = min(1.0, hunt_score + 0.05)
                    logger.info("A10: Shodan C2/vuln confirmed — boosted hunt_score to %.4f", hunt_score)

            # ── Write to cache ────────────────────────────────────────────────
            set_cached_result(etype, value, {
                "vt_stats":   vt_stats,
                "hunt_score": hunt_score,
                "shodan_data": shodan_data,
            })

        # ── Build hunt Evidence ───────────────────────────────────────────────
        hunt_ev = build_hunt_evidence(etype, value, vt_stats, hunt_score, shodan_data, asset_id, criticality)
        hunt_evidences.append(hunt_ev)

        # ── Update Hypothesis ─────────────────────────────────────────────────
        if hypothesis is not None:
            boost_hypothesis_confidence(hypothesis, hunt_score, hunt_ev.evidence_id)
            hypothesis_updated = True

        hunt_results.append({
            "entity_type":  etype,
            "entity_value": value,
            "hunt_score":   hunt_score,
            "vt_stats":     vt_stats,
            "shodan_data":  shodan_data,
            "evidence_id":  hunt_ev.evidence_id,
        })

    logger.info(
        "A10: hunt complete — asset=%s entities=%d evidences=%d hypothesis_updated=%s",
        asset_id, len(entities), len(hunt_evidences), hypothesis_updated,
    )

    return {
        "triggered":          True,
        "reason":             reason,
        "hunt_results":       hunt_results,
        "hunt_evidences":     [ev.model_dump() for ev in hunt_evidences],
        "hypothesis_updated": hypothesis_updated,
    }


# =============================================================================
# SMOKE TEST
# =============================================================================
if __name__ == "__main__":
    import sys
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

    print("\n=== A10 Smoke Test ===\n")

    ev_data = {
        "asset_id":   "CBSE-WebSvr-01",
        "confidence": 0.85,
        "context":    {"criticality": "HIGH"},
        "normalized": {
            "src_ip": "185.23.147.82",
            "hash":   "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
        },
    }

    result = process(ev_data)
    print("triggered:", result["triggered"])
    print("entities hunted:", len(result["hunt_results"]))
    print("evidences created:", len(result["hunt_evidences"]))
    print("\nSmoke test done.")
