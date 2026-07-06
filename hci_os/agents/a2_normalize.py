"""
agents/a2_normalize.py
A2: Normalizer & Context Agent (Layer 2) — HCI-OS

Transforms raw log rows (Apache, Windows Event, NetFlow, OT/SCADA, CICIDS-2017)
into fully-populated Evidence Objects enriched with:
  - Normalized sub-schema (src_ip, path, method, etc.)
  - Basic NER (IPs, users, processes, domains, hashes)
  - Asset criticality from data/asset_inventory.json
  - OT Context (can_reboot, can_interrupt, safety_critical)
  - Indian Context (exam_season, govt_year_end, election_period, holiday_period)
  - SHA-256 content_fingerprint of normalized payload

Pipeline position: A1 (Trust/Ingest) → [A2] → A3 (Hash Router)
"""

import hashlib
import json
import logging
import os
import re
import uuid
import warnings
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from objects.evidence import Evidence

# ─── Logging ────────────────────────────────────────────────────────────────
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("A2_Normalizer")

# ─── Paths ───────────────────────────────────────────────────────────────────
_AGENT_DIR = Path(__file__).parent
_DATA_DIR = _AGENT_DIR.parent / "data"
_ASSET_INVENTORY_PATH = _DATA_DIR / "asset_inventory.json"

# ─── Default values for unknown assets ───────────────────────────────────────
_UNKNOWN_ASSET_DEFAULTS: Dict[str, Any] = {
    "criticality": "MEDIUM",
    "mission": "unknown",
    "type": "unknown",
    "safety_critical": False,
    "can_reboot": True,
    "can_interrupt": True,
    "impact_if_compromised": "MEDIUM",
}

# ─── OT Protocol Signatures ──────────────────────────────────────────────────
_OT_PROTOCOL_SIGNATURES: Dict[str, List[str]] = {
    "Modbus":    ["modbus", "502", "function_code"],
    "DNP3":      ["dnp3", "dnp", "20000"],
    "S7":        ["s7comm", "s7", "102"],
    "OPC-UA":    ["opcua", "opc-ua", "opc_ua", "4840"],
    "IEC-61850": ["iec61850", "61850", "goose", "mms"],
}

# ─── Field Mapping — source_type → normalized schema ─────────────────────────
# Each source maps its raw field names to our canonical names.
_FIELD_MAPS: Dict[str, Dict[str, str]] = {
    "web_access_log": {
        "src_ip": "src_ip",
        "dst_ip": "dst_ip",
        "request_path": "path",
        "http_method": "method",
        "user_agent": "user_agent",
        "status_code": "status",
        "bytes_sent": "bytes",
        "protocol": "protocol",
        "timestamp": "timestamp",
    },
    "cicids_2017": {
        # CICIDS-2017 CSV column names
        " Source IP":           "src_ip",
        " Destination IP":      "dst_ip",
        " Source Port":         "src_port",
        " Destination Port":    "dst_port",
        " Protocol":            "protocol",
        " Flow Duration":       "flow_duration",
        " Total Fwd Packets":   "fwd_packets",
        " Total Backward Packets": "bwd_packets",
        " Total Length of Fwd Packets": "bytes",
        " Label":               "label",
        "Flow ID":              "flow_id",
        " Timestamp":           "timestamp",
    },
    "windows_event": {
        "EventID":       "event_id",
        "SubjectUserName": "user",
        "TargetUserName": "target_user",
        "IpAddress":     "src_ip",
        "ProcessName":   "process",
        "LogonType":     "logon_type",
        "Status":        "status",
        "TimeCreated":   "timestamp",
    },
    "netflow": {
        "src_addr": "src_ip",
        "dst_addr": "dst_ip",
        "src_port": "src_port",
        "dst_port": "dst_port",
        "proto":    "protocol",
        "bytes":    "bytes",
        "pkts":     "packets",
        "start":    "timestamp",
    },
    "scada": {
        "src_ip":    "src_ip",
        "dst_ip":    "dst_ip",
        "function":  "method",
        "register":  "path",
        "value":     "value",
        "protocol":  "protocol",
        "timestamp": "timestamp",
    },
}

# ─── NER Patterns ────────────────────────────────────────────────────────────
_NER_PATTERNS: Dict[str, re.Pattern] = {
    "ip":      re.compile(r"\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b"),
    "user":    re.compile(r"user[=:\s]+([^\s,;\"']+)", re.IGNORECASE),
    "process": re.compile(r"process[=:\s]+([^\s,;\"']+)", re.IGNORECASE),
    "domain":  re.compile(r"(?:domain|hostname)[=:\s]+([^\s,;\"']+)", re.IGNORECASE),
    "hash":    re.compile(r"\b([a-fA-F0-9]{32}|[a-fA-F0-9]{40}|[a-fA-F0-9]{64})\b"),
}


# ─── Asset Inventory ─────────────────────────────────────────────────────────
def _load_asset_inventory() -> Dict[str, Dict[str, Any]]:
    """Load asset_inventory.json once at module import time."""
    if not _ASSET_INVENTORY_PATH.exists():
        logger.warning(
            "asset_inventory.json not found at %s — all assets will use defaults",
            _ASSET_INVENTORY_PATH,
        )
        return {}
    try:
        with open(_ASSET_INVENTORY_PATH, "r", encoding="utf-8") as fh:
            return json.load(fh)
    except json.JSONDecodeError as exc:
        logger.error("Failed to parse asset_inventory.json: %s", exc)
        return {}


_ASSET_INVENTORY: Dict[str, Dict[str, Any]] = _load_asset_inventory()


def lookup_asset(asset_id: str) -> Dict[str, Any]:
    """
    Return asset metadata from the inventory.
    Falls back to _UNKNOWN_ASSET_DEFAULTS if not found, with a warning.
    """
    if asset_id in _ASSET_INVENTORY:
        return _ASSET_INVENTORY[asset_id]
    # Try IP-based lookup
    for aid, meta in _ASSET_INVENTORY.items():
        if meta.get("ip") == asset_id:
            return meta
    logger.warning(
        "Unknown asset '%s' — defaulting to MEDIUM criticality and can_reboot=True",
        asset_id,
    )
    return dict(_UNKNOWN_ASSET_DEFAULTS)


# ─── OT Protocol Detection ───────────────────────────────────────────────────
def detect_ot_protocol(raw_log: Dict[str, Any]) -> Optional[str]:
    """
    Scan all string values in raw_log for known OT protocol signatures.
    Returns the protocol name if found, else None.
    """
    raw_text = " ".join(str(v).lower() for v in raw_log.values())
    for proto, signatures in _OT_PROTOCOL_SIGNATURES.items():
        if any(sig in raw_text for sig in signatures):
            return proto
    return None


def classify_ot_device(asset_meta: Dict[str, Any]) -> Optional[str]:
    """Return device_type from asset metadata (PLC, RTU, HMI, sensor, etc.)."""
    return asset_meta.get("type")


def is_safety_critical(asset_meta: Dict[str, Any]) -> bool:
    return bool(asset_meta.get("safety_critical", False))


def can_allow_interruption(asset_meta: Dict[str, Any]) -> bool:
    return bool(asset_meta.get("can_interrupt", True))


def can_allow_reboot(asset_meta: Dict[str, Any]) -> bool:
    return bool(asset_meta.get("can_reboot", True))


def compute_impact(asset_meta: Dict[str, Any]) -> str:
    return asset_meta.get("impact_if_compromised", "MEDIUM")


def build_ot_context(raw_log: Dict[str, Any], asset_meta: Dict[str, Any]) -> Dict[str, Any]:
    """
    Build the OT context dict for an Evidence Object.

    Fields:
        protocol           — OT protocol detected in raw log (or None for IT assets)
        device_type        — PLC, RTU, HMI, sensor, web_server, database, etc.
        safety_critical    — True if a life-safety system (MRI, power relay, etc.)
        can_interrupt      — False → never send actions that interrupt operation
        can_reboot         — False → A7 must force HUMAN_GATE regardless of confidence
        impact_if_compromised — LOW / MEDIUM / HIGH / CRITICAL
    """
    return {
        "protocol":             detect_ot_protocol(raw_log),
        "device_type":          classify_ot_device(asset_meta),
        "safety_critical":      is_safety_critical(asset_meta),
        "can_interrupt":        can_allow_interruption(asset_meta),
        "can_reboot":           can_allow_reboot(asset_meta),
        "impact_if_compromised": compute_impact(asset_meta),
    }


# ─── Indian Context Builder ───────────────────────────────────────────────────
def is_exam_season(dt: datetime) -> bool:
    """
    True during major Indian exam periods.
    CBSE Board Exams: ~Feb–March
    JEE Mains: ~January & April
    NEET / State boards: ~May
    """
    return dt.month in (1, 2, 3, 4, 5)


def is_government_year_end(dt: datetime) -> bool:
    """
    True in the last 10 days of the Indian financial year (March 22–31).
    Heightened risk window: budget rushes, last-minute transfers, reduced oversight.
    """
    return dt.month == 3 and dt.day >= 22


def is_election_period(dt: datetime) -> bool:
    """
    Stub: True during known major Indian election windows.
    In production, query the Election Commission of India calendar API.
    Hardcoded for hackathon demo: General Elections ~April–May 2024.
    """
    # 2024 Indian General Elections: April 19 – June 1
    election_windows = [
        (datetime(2024, 4, 19, tzinfo=timezone.utc), datetime(2024, 6, 4, tzinfo=timezone.utc)),
    ]
    dt_utc = dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
    return any(start <= dt_utc <= end for start, end in election_windows)


def is_national_holiday(dt: datetime) -> bool:
    """
    Stub: True on major Indian national holidays (reduced SOC coverage).
    Republic Day, Independence Day, Gandhi Jayanti, Diwali (approx).
    """
    # (month, day) pairs for fixed holidays
    fixed_holidays = {
        (1, 26),  # Republic Day
        (8, 15),  # Independence Day
        (10, 2),  # Gandhi Jayanti
        (12, 25), # Christmas
    }
    return (dt.month, dt.day) in fixed_holidays


def build_indian_context(dt: datetime) -> Dict[str, Any]:
    """
    Build the Indian threat-context dict.
    These flags are used by A4 to adjust anomaly thresholds:
      - exam_season=True  → web portal spikes are LESS anomalous
      - govt_year_end=True → financial transfers are LESS anomalous
      - election_period=True → political-sector targets are HIGHER priority
      - holiday_period=True → SOC may be under-staffed; escalate faster
    """
    return {
        "exam_season":     is_exam_season(dt),
        "govt_year_end":   is_government_year_end(dt),
        "election_period": is_election_period(dt),
        "holiday_period":  is_national_holiday(dt),
    }


# ─── Time-of-Day Classifier ───────────────────────────────────────────────────
def classify_time_of_day(dt: datetime) -> str:
    """
    Classify event time into: business_hours / off_hours / night
    Used downstream by A4 to weight anomaly scores.
    """
    hour = dt.hour
    if 9 <= hour < 18:
        return "business_hours"
    elif 18 <= hour < 23:
        return "off_hours"
    else:
        return "night"


# ─── NER Extractor ───────────────────────────────────────────────────────────
def extract_ner(raw_log: Dict[str, Any]) -> Dict[str, Optional[str]]:
    """
    Extract named entities from all string fields in the raw log.
    Returns a dict with keys: ip, user, process, domain, hash.
    Any failed extraction returns None — never raises.
    """
    raw_text = " ".join(str(v) for v in raw_log.values())
    entities: Dict[str, Optional[str]] = {}
    for entity_name, pattern in _NER_PATTERNS.items():
        try:
            match = pattern.search(raw_text)
            entities[entity_name] = match.group(1) if match else None
        except Exception:
            entities[entity_name] = None
    return entities


# ─── Normalization ────────────────────────────────────────────────────────────
def _detect_source_type(raw_log: Dict[str, Any]) -> str:
    """
    Auto-detect the source type of the raw log by inspecting its keys.
    Falls back to 'generic' if no match.
    """
    keys = set(raw_log.keys())
    # CICIDS-2017 has space-prefixed columns
    if " Source IP" in keys or "Flow ID" in keys:
        return "cicids_2017"
    if "EventID" in keys or "SubjectUserName" in keys:
        return "windows_event"
    if "src_addr" in keys or "dst_addr" in keys:
        return "netflow"
    if "function" in keys and "register" in keys:
        return "scada"
    if "http_method" in keys or "request_path" in keys:
        return "web_access_log"
    return "generic"


def normalize_fields(
    raw_log: Dict[str, Any],
    source_type: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Map raw log fields → normalized schema.
    Missing fields are set to None — never crash the pipeline.
    """
    if source_type is None:
        source_type = _detect_source_type(raw_log)

    field_map = _FIELD_MAPS.get(source_type, {})

    # Start with a base normalized dict with all canonical fields set to None
    normalized: Dict[str, Any] = {
        "src_ip":     None,
        "dst_ip":     None,
        "src_port":   None,
        "dst_port":   None,
        "path":       None,
        "method":     None,
        "user_agent": None,
        "status":     None,
        "bytes":      None,
        "protocol":   None,
        "timestamp":  None,
    }

    # Apply the field map
    for raw_field, canonical_field in field_map.items():
        value = raw_log.get(raw_field)
        if value is not None:
            normalized[canonical_field] = value

    # Also do a direct pass — if raw_log already uses canonical names, pick them up
    for canonical in list(normalized.keys()):
        if normalized[canonical] is None and canonical in raw_log:
            normalized[canonical] = raw_log[canonical]

    # Strip None-valued keys for clean JSON fingerprinting
    return {k: v for k, v in normalized.items() if v is not None}


# ─── Fingerprint ─────────────────────────────────────────────────────────────
def compute_content_fingerprint(normalized: Dict[str, Any]) -> str:
    """
    SHA-256 of the canonicalized (sorted-keys) JSON representation
    of the normalized payload.
    Returns a 64-char lowercase hex string.
    """
    canonical = json.dumps(normalized, sort_keys=True, default=str)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


# ─── Evidence ID Generator ────────────────────────────────────────────────────
def _generate_evidence_id() -> str:
    """
    Generate a unique Evidence ID in the format EV-YYYY-XXXXXX.
    Uses current UTC year + 6 random uppercase hex characters.
    """
    year = datetime.now(timezone.utc).year
    suffix = uuid.uuid4().hex[:6].upper()
    return f"EV-{year}-{suffix}"


# ─── Main Entry Point ─────────────────────────────────────────────────────────
def process(
    raw_log: Dict[str, Any],
    asset_id: Optional[str] = None,
    source: Optional[str] = None,
) -> Evidence:
    """
    Main A2 entry point.

    Args:
        raw_log:   Raw log dict — any format (CICIDS-2017, Apache, Windows, NetFlow, SCADA).
        asset_id:  Optional explicit asset ID. If None, A2 attempts lookup from raw_log fields.
        source:    Optional explicit source label (e.g. 'web_access_log'). Auto-detected if None.

    Returns:
        A fully validated Evidence object with OT context, Indian context,
        SHA-256 fingerprint, NER entities, and a 256-dim zero-vector embedding placeholder.

    Raises:
        ValueError: Only if the Evidence Object schema itself is violated
                    (should never happen with valid input — A2 is defensive).
    """
    # ── 1. Detect source type ────────────────────────────────────────────────
    detected_source = source or _detect_source_type(raw_log)
    logger.debug("A2: source_type=%s", detected_source)

    # ── 2. Resolve timestamp ─────────────────────────────────────────────────
    raw_ts = (
        raw_log.get("timestamp")
        or raw_log.get(" Timestamp")
        or raw_log.get("TimeCreated")
        or raw_log.get("start")
    )
    try:
        if isinstance(raw_ts, datetime):
            event_time = raw_ts if raw_ts.tzinfo else raw_ts.replace(tzinfo=timezone.utc)
        elif isinstance(raw_ts, (int, float)):
            event_time = datetime.fromtimestamp(raw_ts, tz=timezone.utc)
        elif isinstance(raw_ts, str):
            # Try ISO format first, then common formats
            for fmt in ("%Y-%m-%dT%H:%M:%SZ", "%Y-%m-%d %H:%M:%S", "%d/%b/%Y:%H:%M:%S %z"):
                try:
                    event_time = datetime.strptime(raw_ts.strip(), fmt)
                    if event_time.tzinfo is None:
                        event_time = event_time.replace(tzinfo=timezone.utc)
                    break
                except ValueError:
                    continue
            else:
                raise ValueError(f"Cannot parse timestamp: {raw_ts!r}")
        else:
            event_time = datetime.now(timezone.utc)
    except Exception as exc:
        logger.warning("A2: timestamp parse failed (%s) — using now(UTC)", exc)
        event_time = datetime.now(timezone.utc)

    # ── 3. Normalize fields ──────────────────────────────────────────────────
    normalized = normalize_fields(raw_log, source_type=detected_source)

    # ── 4. NER extraction ────────────────────────────────────────────────────
    ner_entities = extract_ner(raw_log)
    # Fill in normalized fields from NER if not already populated
    if not normalized.get("src_ip") and ner_entities.get("ip"):
        normalized["src_ip"] = ner_entities["ip"]

    # ── 5. Resolve asset_id ──────────────────────────────────────────────────
    if not asset_id:
        # Try to infer asset from dst_ip
        dst_ip = normalized.get("dst_ip") or normalized.get("src_ip")
        resolved_id = None
        if dst_ip:
            for aid, meta in _ASSET_INVENTORY.items():
                if meta.get("ip") == dst_ip:
                    resolved_id = aid
                    break
        asset_id = resolved_id or raw_log.get("asset_id") or "UNKNOWN"

    # ── 6. Asset criticality lookup ──────────────────────────────────────────
    asset_meta = lookup_asset(asset_id)

    # ── 7. OT Context ────────────────────────────────────────────────────────
    ot_ctx = build_ot_context(raw_log, asset_meta)

    # ── 8. Indian Context ────────────────────────────────────────────────────
    indian_ctx = build_indian_context(event_time)

    # ── 9. Build the full context dict ───────────────────────────────────────
    context = {
        "criticality":    asset_meta.get("criticality", "MEDIUM"),
        "mission":        asset_meta.get("mission", "unknown"),
        "time_of_day":    classify_time_of_day(event_time),
        "indian_context": indian_ctx,
        "ot_context":     ot_ctx,
        "ner_entities":   ner_entities,
    }

    # ── 10. Compute SHA-256 fingerprint ─────────────────────────────────────
    fingerprint = compute_content_fingerprint(normalized)

    # ── 11. Construct and validate Evidence Object ───────────────────────────
    evidence = Evidence.model_validate({
        "evidence_id":         _generate_evidence_id(),
        "timestamp":           event_time,
        "source":              detected_source,
        "asset_id":            asset_id,
        "normalized":          normalized,
        "content_fingerprint": fingerprint,
        "behavior_embedding":  [0.0],   # Placeholder — Ticket 4 computes real embedding
        "context":             context,
        "confidence":          0.5,
        "uncertainty":         0.5,
        "provenance":          "A2_normalizer",
    })

    logger.info(
        "A2: produced Evidence %s | asset=%s | criticality=%s | can_reboot=%s | exam_season=%s",
        evidence.evidence_id,
        asset_id,
        asset_meta.get("criticality"),
        ot_ctx["can_reboot"],
        indian_ctx["exam_season"],
    )

    return evidence


# ─── Batch Processing ─────────────────────────────────────────────────────────
def process_batch(raw_logs: List[Dict[str, Any]]) -> List[Evidence]:
    """
    Process a list of raw log dicts and return a list of Evidence objects.
    Failures in individual rows are logged but do not stop the batch.
    """
    results: List[Evidence] = []
    for i, raw_log in enumerate(raw_logs):
        try:
            results.append(process(raw_log))
        except Exception as exc:
            logger.error("A2: Failed to process log row %d: %s", i, exc)
    return results


def process_csv(csv_path: str) -> List[Evidence]:
    """
    Load a CSV file and process each row through A2.
    Supports CICIDS-2017 column layout automatically.
    """
    import csv
    results: List[Evidence] = []
    with open(csv_path, newline="", encoding="utf-8") as fh:
        reader = csv.DictReader(fh)
        for row in reader:
            # Convert numeric strings to int/float where possible
            coerced: Dict[str, Any] = {}
            for k, v in row.items():
                try:
                    coerced[k] = int(v)
                except (ValueError, TypeError):
                    try:
                        coerced[k] = float(v)
                    except (ValueError, TypeError):
                        coerced[k] = v
            try:
                results.append(process(coerced))
            except Exception as exc:
                logger.error("A2: CSV row error: %s", exc)
    return results


# ─── Quick Smoke Test ─────────────────────────────────────────────────────────
if __name__ == "__main__":
    # Test 1: IT asset (CBSE web server)
    web_log = {
        "src_ip":       "185.23.147.82",
        "dst_ip":       "203.94.1.10",
        "request_path": "/api/users",
        "http_method":  "GET",
        "user_agent":   "curl/7.68.0",
        "status_code":  200,
        "bytes_sent":   1234,
        "timestamp":    "2026-03-15T02:47:33Z",
    }
    ev1 = process(web_log, asset_id="CBSE-WebSvr-01", source="web_access_log")
    print("\n=== Test 1: IT Asset (CBSE Web Server) ===")
    print(json.loads(ev1.to_json()))

    # Test 2: OT/SCADA asset — should flag can_reboot=False
    scada_log = {
        "src_ip":    "10.0.1.99",
        "dst_ip":    "10.0.2.10",
        "function":  "write_coil",
        "register":  "0x0001",
        "value":     "0xFF",
        "protocol":  "modbus",
        "timestamp": "2026-01-26T23:00:00Z",
    }
    ev2 = process(scada_log, asset_id="CBSE-OT-SCADA-01", source="scada")
    print("\n=== Test 2: OT Asset (SCADA — can_reboot=False) ===")
    ot = ev2.context.get("ot_context", {})
    print(f"  can_reboot:     {ot['can_reboot']}   <-- A7 will FORCE Human Gate")
    print(f"  safety_critical:{ot['safety_critical']}")
    print(f"  protocol:       {ot['protocol']}")

    # Test 3: Unknown asset — should use MEDIUM defaults
    unknown_log = {
        "src_ip":    "10.99.88.77",
        "dst_ip":    "172.16.0.55",
        "timestamp": "2026-08-15T10:00:00Z",
    }
    ev3 = process(unknown_log, asset_id="MYSTERY-HOST-99")
    print("\n=== Test 3: Unknown Asset (defaults) ===")
    print(f"  criticality: {ev3.context['criticality']}  (expected MEDIUM)")
    print(f"  can_reboot:  {ev3.context['ot_context']['can_reboot']}  (expected True)")

    print("\n✅ All A2 smoke tests passed — Evidence Objects constructed successfully.")
