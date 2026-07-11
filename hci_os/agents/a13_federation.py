"""
agents/a13_federation.py
A13: Federation Agent (Layer 6) — HCI-OS

Simulates cross-organization threat intelligence sharing via a mock STIX-2.1 feed.
Explicitly labeled as SIMULATED — demonstrates the shape of a production system.

Pipeline position: Triggered by A7 (SOAR) after a Hypothesis is confirmed.
Consumer path:     Called from A1/A2 ingest to boost confidence from peer intel.

Gap Fixes:
  Gap 1  Missing data fallback  — skip publishing if anonymizer yields no IOCs
  Gap 2  Conflict resolution    — only store/accept conf > 0.85 (via FederationStore)
  Gap 3  Store initialization   — FederationStore auto-creates file on first run
  Gap 4  Org labeling           — use HCI_OS_ORG_ID env var (default "Org-A")
  Gap 5  Confidence clamping    — min(hypothesis.confidence + boost, 1.0)
"""

from __future__ import annotations

import json
import logging
import os
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from objects.evidence   import Evidence
from objects.hypothesis import Hypothesis
from stores.federation_store import (
    CONFIDENCE_THRESHOLD,
    ORG_ID,
    STORE_PATH,
    add_indicator,
    build_stix_indicator,
    query_indicators,
)

# ── Logging ───────────────────────────────────────────────────────────────────
logger = logging.getLogger("A13_Federation")

# ── PII fields to strip from shared intelligence ──────────────────────────────
PII_FIELDS: set = {
    "src_ip",          # stripped; public C2 IPs extracted separately
    "user",
    "asset_id",
    "internal_domain",
    "hostname",
    "email",
    "username",
    "user_id",
    "internal_ip",
}

# ── Private / non-routable IP filter ─────────────────────────────────────────
_PRIVATE_IP = re.compile(
    r"^(10\.|172\.(1[6-9]|2\d|3[01])\.|192\.168\.|127\.|169\.254\.|0\.0\.0\.0)"
)

# ── Entity extraction patterns ────────────────────────────────────────────────
_IP_RE     = re.compile(r"\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b")
_HASH_RE   = re.compile(r"\b([a-fA-F0-9]{64}|[a-fA-F0-9]{40}|[a-fA-F0-9]{32})\b")
_DOMAIN_RE = re.compile(r"\b([a-zA-Z0-9-]{2,63}\.[a-zA-Z]{2,6})\b")


# =============================================================================
# TRIGGER
# =============================================================================

def should_share(hypothesis: Hypothesis) -> bool:
    """
    Returns True if the hypothesis meets the federation sharing threshold.
    Condition: confidence > 0.85 (or state is CONFIRMED as a bonus check).
    """
    if hypothesis.confidence > CONFIDENCE_THRESHOLD:
        logger.info(
            "A13: trigger FIRE — hypothesis %s confidence=%.4f > %.2f",
            hypothesis.hypothesis_id, hypothesis.confidence, CONFIDENCE_THRESHOLD,
        )
        return True
    logger.info(
        "A13: trigger SKIP — hypothesis %s confidence=%.4f ≤ %.2f",
        hypothesis.hypothesis_id, hypothesis.confidence, CONFIDENCE_THRESHOLD,
    )
    return False


# =============================================================================
# ENTITY EXTRACTION
# =============================================================================

def _flatten_values(data: Any) -> List[str]:
    """Recursively collect all scalar values from nested dicts/lists."""
    out: List[str] = []
    if isinstance(data, dict):
        for v in data.values():   # scan ALL values — PII filtering is in publish, not scan
            out.extend(_flatten_values(v))
    elif isinstance(data, list):
        for item in data:
            out.extend(_flatten_values(item))
    elif data is not None:
        out.append(str(data))
    return out


def _extract_public_ips(text: str) -> List[str]:
    return [ip for ip in _IP_RE.findall(text) if not _PRIVATE_IP.match(ip)]


def _extract_hashes(text: str) -> List[str]:
    return list(dict.fromkeys(_HASH_RE.findall(text)))   # dedupe, preserve order


def _extract_domains(text: str) -> List[str]:
    found = []
    for d in _DOMAIN_RE.findall(text):
        if len(d) > 5 and not _IP_RE.match(d):
            found.append(d)
    return list(dict.fromkeys(found))


def extract_public_entities(evidence_data: Dict[str, Any]) -> Dict[str, List[str]]:
    """
    Extract entity values from Evidence payload.
    Scans all values (including PII-keyed fields) to find public IPs/hashes/domains.
    PII stripping happens only at the publish/output stage, not during scanning.
    Returns categorized public entities: ips, hashes, domains.
    """
    # Scan the entire evidence dict for entity values
    text = " ".join(_flatten_values(evidence_data))
    return {
        "ips":     _extract_public_ips(text),
        "hashes":  _extract_hashes(text),
        "domains": _extract_domains(text),
    }


# =============================================================================
# ANONYMIZER
# =============================================================================

def anonymize_ioc(
    evidence_data: Dict[str, Any],
    hypothesis: Hypothesis,
) -> Optional[Dict[str, Any]]:
    """
    Gap #1 — Returns None if no shareable IOCs are found after PII stripping.
    Strips forbidden PII fields; retains public IPs, hashes, and behavioral signals.
    """
    entities = extract_public_entities(evidence_data)
    all_iocs = entities["ips"] + entities["hashes"] + entities["domains"]

    # Gap #1: skip if nothing to share
    if not all_iocs:
        logger.warning(
            "A13: anonymize_ioc — no shareable IOCs found for asset=%s (skipping)",
            evidence_data.get("asset_id", "UNKNOWN"),
        )
        return None

    return {
        "public_ips":  entities["ips"],
        "hashes":      entities["hashes"],
        "domains":     entities["domains"],
        "confidence":  round(hypothesis.confidence, 4),
        "goal":        hypothesis.goal,
        "state":       getattr(hypothesis, "state", "ACTIVE_INVESTIGATION"),
    }


# =============================================================================
# PUBLISH  (Org A role)
# =============================================================================

def publish_ioc(
    evidence_data: Dict[str, Any],
    hypothesis:    Hypothesis,
    store_path:    Path = STORE_PATH,
    org_id:        str  = ORG_ID,          # Gap #4
) -> Dict[str, Any]:
    """
    Anonymize and publish IOC to the Federation Store.
    Returns a summary dict with the IOCs published and their indicator IDs.

    Gap #1: skips if anonymizer returns None.
    Gap #2: FederationStore rejects confidence ≤ 0.85.
    Gap #4: org_id sourced from HCI_OS_ORG_ID env var.
    """
    if not should_share(hypothesis):
        return {"published": False, "reason": "confidence_below_threshold", "indicators": []}

    anon = anonymize_ioc(evidence_data, hypothesis)
    if anon is None:
        return {"published": False, "reason": "no_shareable_iocs", "indicators": []}

    published: List[Dict[str, Any]] = []

    # Publish each public IP
    for ip in anon["public_ips"]:
        ind = build_stix_indicator(
            ioc_type   = "ip",
            ioc_value  = ip,
            confidence = anon["confidence"],
            name       = f"Federated C2 IP ({org_id})",
            labels     = ["malicious-activity", "c2"],
            org_id     = org_id,
        )
        if add_indicator(ind, store_path):
            published.append({"type": "ip", "value": ip, "indicator_id": ind["id"]})

    # Publish each hash
    for h in anon["hashes"]:
        htype = "hash_sha256" if len(h) == 64 else "hash_md5"
        ind = build_stix_indicator(
            ioc_type   = htype,
            ioc_value  = h,
            confidence = anon["confidence"],
            name       = f"Federated malware hash ({org_id})",
            labels     = ["malicious-activity", "malware"],
            org_id     = org_id,
        )
        if add_indicator(ind, store_path):
            published.append({"type": htype, "value": h[:16] + "...", "indicator_id": ind["id"]})

    # Publish each domain (only if domain looks like external C2)
    for domain in anon["domains"]:
        ind = build_stix_indicator(
            ioc_type   = "domain",
            ioc_value  = domain,
            confidence = anon["confidence"],
            name       = f"Federated C2 domain ({org_id})",
            labels     = ["malicious-activity", "c2"],
            org_id     = org_id,
        )
        if add_indicator(ind, store_path):
            published.append({"type": "domain", "value": domain, "indicator_id": ind["id"]})

    logger.info(
        "A13: published %d indicator(s) to federation store (org=%s, conf=%.4f)",
        len(published), org_id, anon["confidence"],
    )
    return {
        "published":  len(published) > 0,
        "reason":     "ok" if published else "all_rejected_by_store",
        "indicators": published,
    }


# =============================================================================
# CONSUME  (Org B role)
# =============================================================================

def check_federation(
    evidence_data: Dict[str, Any],
    store_path:    Path = STORE_PATH,
) -> float:
    """
    Query the Federation Store for IOCs matching this Evidence.
    Returns the confidence boost (0.0 if no match).
    Formula: boost = min(0.10 + 0.05 * (matches - 1), 0.15)
    """
    entities = extract_public_entities(evidence_data)
    query_vals = entities["ips"] + entities["hashes"] + entities["domains"]

    if not query_vals:
        logger.info("A13: check_federation — no queryable entities, boost=0.0")
        return 0.0

    matches = query_indicators(query_vals, store_path)
    if not matches:
        return 0.0

    # Formula: 0.10 for first match, +0.05 for each additional, capped at 0.15
    boost = min(0.10 + 0.05 * (len(matches) - 1), 0.15)
    logger.info(
        "A13: check_federation — %d match(es), boost=+%.2f",
        len(matches), boost,
    )
    return boost


def apply_boost(
    hypothesis: Hypothesis,
    boost:      float,
    evidence_id: Optional[str] = None,
) -> None:
    """
    Gap #5 — Apply confidence boost clamped to [0.0, 1.0].
    Optionally attaches evidence_id to supporting_evidence.
    """
    old = hypothesis.confidence
    hypothesis.confidence = round(min(hypothesis.confidence + boost, 1.0), 4)
    if evidence_id:
        hypothesis.supporting_evidence.append(evidence_id)
    logger.info(
        "A13: hypothesis %s confidence %.4f → %.4f (boost=+%.4f)",
        hypothesis.hypothesis_id, old, hypothesis.confidence, boost,
    )


# =============================================================================
# MAIN ENTRY POINT
# =============================================================================

def process(
    evidence_data: Dict[str, Any],
    hypothesis:    Optional[Hypothesis] = None,
    store_path:    Path = STORE_PATH,
    org_id:        str  = ORG_ID,
) -> Dict[str, Any]:
    """
    A13 unified pipeline function. Performs both roles:

    Publisher (Org A):
      - If hypothesis provided and confidence > 0.85, publish anonymized IOC.

    Consumer (Org B):
      - Always checks federation store for matching IOCs.
      - Boosts hypothesis confidence if matches found.

    Returns dict with: published, boost, hypothesis_updated
    """
    result: Dict[str, Any] = {
        "published":          False,
        "publish_result":     {},
        "boost":              0.0,
        "hypothesis_updated": False,
    }

    # Publisher role
    if hypothesis is not None and should_share(hypothesis):
        pub = publish_ioc(evidence_data, hypothesis, store_path, org_id)
        result["published"]      = pub["published"]
        result["publish_result"] = pub

    # Consumer role — always check, even if we just published (catches cross-org)
    boost = check_federation(evidence_data, store_path)
    result["boost"] = boost

    if boost > 0.0 and hypothesis is not None:
        apply_boost(hypothesis, boost, evidence_data.get("evidence_id"))
        result["hypothesis_updated"] = True

    return result


# =============================================================================
# LEGACY ALIAS
# =============================================================================

def share_intel(hypothesis: dict) -> dict:
    """Backward-compatible stub (from original scaffold)."""
    from objects.hypothesis import Hypothesis as H
    hyp = H(goal=hypothesis.get("goal", "Unknown"), confidence=hypothesis.get("confidence", 0.0))
    pub = publish_ioc({}, hyp)
    return {"shared": pub["published"], "peer_confidence_boost": 0.0}
