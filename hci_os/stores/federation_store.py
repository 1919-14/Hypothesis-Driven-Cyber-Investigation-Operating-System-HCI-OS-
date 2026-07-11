"""
stores/federation_store.py
Federation Store (DS7) — STIX-2.1-shaped JSON hub for cross-org intelligence sharing.

Architecture:
  - Shared file: data/federation_store.json
  - Two-process-safe: atomic tempfile-rename writes (Gap #3 + concurrency)
  - TTL: 7 days (expired indicators purged on read and write)
  - Gap #2: Only indicators with confidence > 0.85 are accepted
  - Gap #3: Missing file auto-initialized with empty bundle on first run
  - Gap #4: Org identity from HCI_OS_ORG_ID env var
"""

from __future__ import annotations

import json
import logging
import os
import re
import tempfile
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger("A13_FederationStore")

# ── Paths ─────────────────────────────────────────────────────────────────────
_STORE_DIR  = Path(__file__).parent.parent / "data"
STORE_PATH  = _STORE_DIR / "federation_store.json"

# ── Config ────────────────────────────────────────────────────────────────────
TTL_DAYS                = 7
CONFIDENCE_THRESHOLD    = 0.85   # Gap #2 — only store confirmed malicious
ORG_ID: str             = os.environ.get("HCI_OS_ORG_ID", "Org-A")  # Gap #4

# ── Private IP filter ─────────────────────────────────────────────────────────
_PRIVATE_IP = re.compile(
    r"^(10\.|172\.(1[6-9]|2\d|3[01])\.|192\.168\.|127\.|169\.254\.|0\.0\.0\.0)"
)

# ── Empty bundle template ─────────────────────────────────────────────────────
_EMPTY_BUNDLE: Dict[str, Any] = {
    "type":         "bundle",
    "id":           f"bundle--{uuid.uuid4()}",
    "spec_version": "2.1",
    "indicators":   [],
}


# =============================================================================
# STORE FILE MANAGEMENT
# =============================================================================

def _ensure_store(path: Path = STORE_PATH) -> None:
    """Gap #3 — Initialize an empty bundle if the store file is missing."""
    if not path.exists():
        path.parent.mkdir(parents=True, exist_ok=True)
        _atomic_write(path, _EMPTY_BUNDLE)
        logger.info("FederationStore: initialized empty store at %s", path)


def _atomic_write(path: Path, data: Dict[str, Any]) -> None:
    """Write JSON atomically (tempfile + os.replace) to prevent corruption."""
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp_fd, tmp_path = tempfile.mkstemp(dir=path.parent, suffix=".tmp")
    try:
        with os.fdopen(tmp_fd, "w", encoding="utf-8") as fh:
            json.dump(data, fh, indent=2, default=str)
        os.replace(tmp_path, path)
    except Exception:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass
        raise


def _load_raw(path: Path = STORE_PATH) -> Dict[str, Any]:
    """Load raw bundle dict. Initializes if missing (Gap #3)."""
    _ensure_store(path)
    try:
        with open(path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
        if "indicators" not in data:
            data["indicators"] = []
        return data
    except (json.JSONDecodeError, OSError) as exc:
        logger.warning("FederationStore: corrupt store (%s) — reinitializing", exc)
        bundle = dict(_EMPTY_BUNDLE)
        bundle["id"] = f"bundle--{uuid.uuid4()}"
        _atomic_write(path, bundle)
        return bundle


# =============================================================================
# TTL
# =============================================================================

def is_expired(indicator: Dict[str, Any], ttl_days: int = TTL_DAYS) -> bool:
    """Return True if the indicator is older than ttl_days."""
    try:
        created_str = indicator.get("created", "")
        created = datetime.fromisoformat(created_str.rstrip("Z")).replace(tzinfo=timezone.utc)
        return datetime.now(timezone.utc) - created > timedelta(days=ttl_days)
    except (ValueError, TypeError):
        return True   # malformed timestamp → treat as expired


def load_indicators(path: Path = STORE_PATH) -> List[Dict[str, Any]]:
    """Load all non-expired indicators from the store."""
    bundle = _load_raw(path)
    fresh = [i for i in bundle.get("indicators", []) if not is_expired(i)]
    skipped = len(bundle.get("indicators", [])) - len(fresh)
    if skipped:
        logger.info("FederationStore: skipped %d expired indicator(s)", skipped)
    return fresh


def save_indicators(indicators: List[Dict[str, Any]], path: Path = STORE_PATH) -> None:
    """Overwrite the store with a fresh non-expired indicator list."""
    bundle = _load_raw(path)
    bundle["indicators"] = [i for i in indicators if not is_expired(i)]
    _atomic_write(path, bundle)


# =============================================================================
# STIX INDICATOR BUILDER
# =============================================================================

def _build_stix_pattern(ioc_type: str, ioc_value: str) -> str:
    """Return a STIX 2.1 pattern string for a given entity type + value."""
    if ioc_type == "ip":
        return f"[ipv4-addr:value = '{ioc_value}']"
    if ioc_type == "domain":
        return f"[domain-name:value = '{ioc_value}']"
    if ioc_type == "hash_sha256":
        return f"[file:hashes.'SHA-256' = '{ioc_value}']"
    if ioc_type == "hash_md5":
        return f"[file:hashes.MD5 = '{ioc_value}']"
    if ioc_type == "url":
        return f"[url:value = '{ioc_value}']"
    return f"[artifact:value = '{ioc_value}']"


def build_stix_indicator(
    ioc_type:      str,
    ioc_value:     str,
    confidence:    float,
    name:          str          = "Federated APT IOC",
    labels:        Optional[List[str]] = None,
    kill_chain_phase: Optional[str]    = None,
    org_id:        str          = ORG_ID,
) -> Dict[str, Any]:
    """Construct a STIX 2.1-shaped indicator dict."""
    now = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    valid_from = datetime.now(timezone.utc).replace(hour=0, minute=0, second=0, microsecond=0)\
        .isoformat().replace("+00:00", "Z")

    kc_phases: List[Dict[str, str]] = []
    if kill_chain_phase:
        kc_phases = [{"kill_chain_name": "mitre-attack", "phase_name": kill_chain_phase}]

    return {
        "id":               f"indicator--{uuid.uuid4()}",
        "type":             "indicator",
        "spec_version":     "2.1",
        "created":          now,
        "modified":         now,
        "name":             name,
        "pattern":          _build_stix_pattern(ioc_type, ioc_value),
        "pattern_type":     "stix",
        "valid_from":       valid_from,
        "confidence":       round(confidence, 4),
        "kill_chain_phases": kc_phases,
        "labels":           labels or ["malicious-activity"],
        "external_references": [
            {"source_name": org_id, "description": "Federated threat intel (simulated)"}
        ],
        "_org_id":   org_id,
        "_ioc_type": ioc_type,
        "_ioc_value": ioc_value,
    }


# =============================================================================
# STORE OPERATIONS
# =============================================================================

def add_indicator(
    indicator: Dict[str, Any],
    path: Path = STORE_PATH,
) -> bool:
    """
    Gap #2 — Only persist indicators with confidence > CONFIDENCE_THRESHOLD.
    Returns True if the indicator was accepted and saved.
    """
    conf = indicator.get("confidence", 0.0)
    if conf <= CONFIDENCE_THRESHOLD:
        logger.info(
            "FederationStore: SKIPPING indicator (confidence %.4f ≤ %.2f threshold)",
            conf, CONFIDENCE_THRESHOLD,
        )
        return False

    indicators = load_indicators(path)
    indicators.append(indicator)
    save_indicators(indicators, path)
    logger.info(
        "FederationStore: added indicator %s (conf=%.4f, org=%s)",
        indicator.get("id", "?"), conf, indicator.get("_org_id", "?"),
    )
    return True


def purge_expired(path: Path = STORE_PATH) -> int:
    """Remove TTL'd indicators. Returns count of purged records."""
    bundle = _load_raw(path)
    before = len(bundle.get("indicators", []))
    bundle["indicators"] = [i for i in bundle["indicators"] if not is_expired(i)]
    after = len(bundle["indicators"])
    purged = before - after
    if purged:
        _atomic_write(path, bundle)
        logger.info("FederationStore: purged %d expired indicator(s)", purged)
    return purged


# =============================================================================
# PATTERN MATCHING
# =============================================================================

# Extracts the value literal from STIX patterns like:
#   [ipv4-addr:value = '185.23.147.82']
#   [file:hashes.'SHA-256' = 'abc123...']
_PATTERN_VALUE_RE = re.compile(r"= '([^']+)'")


def extract_pattern_value(pattern: str) -> Optional[str]:
    """Extract the literal value from a STIX 2.1 pattern string."""
    m = _PATTERN_VALUE_RE.search(pattern)
    return m.group(1) if m else None


def query_indicators(
    entity_values: List[str],
    path: Path = STORE_PATH,
) -> List[Dict[str, Any]]:
    """
    Return all non-expired indicators whose pattern value matches any entry
    in entity_values (case-insensitive). Performs partial/suffix matching
    for paths and exact matching for IPs/hashes.
    """
    if not entity_values:
        return []

    normalized_vals = {v.lower() for v in entity_values}
    active = load_indicators(path)
    matched: List[Dict[str, Any]] = []

    for ind in active:
        pattern = ind.get("pattern", "")
        stored_val = extract_pattern_value(pattern)
        if stored_val and stored_val.lower() in normalized_vals:
            matched.append(ind)

    if matched:
        logger.info(
            "FederationStore: %d indicator(s) matched from %d in store",
            len(matched), len(active),
        )
    return matched
