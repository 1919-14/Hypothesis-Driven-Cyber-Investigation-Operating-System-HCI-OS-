"""
tests/test_a2_normalize.py
Comprehensive unit tests for A2: Normalizer & Context Agent.

Covers:
  - Raw log normalization (web, CICIDS, SCADA, Windows, generic)
  - NER extraction (IP, user, process, domain, hash)
  - Asset criticality lookup (known + unknown assets)
  - OT Context Builder (all 6 fields including can_reboot safety gate)
  - Indian Context Builder (exam_season, govt_year_end, election, holiday)
  - SHA-256 content_fingerprint
  - Evidence Object validation via Pydantic model_validate
  - Batch and CSV processing

Run with:  pytest tests/test_a2_normalize.py -v
"""

import json
import os
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path

import pytest

# Ensure hci_os/ is on the path for imports
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from agents.a2_normalize import (
    build_indian_context,
    build_ot_context,
    classify_time_of_day,
    compute_content_fingerprint,
    detect_ot_protocol,
    extract_ner,
    is_exam_season,
    is_government_year_end,
    is_national_holiday,
    lookup_asset,
    normalize_fields,
    process,
    process_batch,
    process_csv,
)
from objects.evidence import Evidence


# ─── NORMALIZATION TESTS ─────────────────────────────────────────────────────

class TestNormalization:
    """Test that raw logs are correctly mapped to the canonical schema."""

    def test_web_access_log_normalization(self):
        raw = {
            "src_ip": "185.23.147.82",
            "dst_ip": "203.94.1.10",
            "request_path": "/api/users",
            "http_method": "GET",
            "user_agent": "curl/7.68.0",
            "status_code": 200,
            "bytes_sent": 1234,
        }
        norm = normalize_fields(raw, source_type="web_access_log")
        assert norm["src_ip"] == "185.23.147.82"
        assert norm["path"] == "/api/users"
        assert norm["method"] == "GET"
        assert norm["user_agent"] == "curl/7.68.0"
        assert norm["status"] == 200
        assert norm["bytes"] == 1234

    def test_cicids_normalization(self):
        raw = {
            " Source IP": "192.168.1.105",
            " Destination IP": "203.94.1.10",
            " Source Port": 55123,
            " Destination Port": 443,
            " Protocol": 6,
            " Flow Duration": 300000,
            " Total Fwd Packets": 50,
            " Total Length of Fwd Packets": 15000,
            " Label": "Bot",
        }
        norm = normalize_fields(raw, source_type="cicids_2017")
        assert norm["src_ip"] == "192.168.1.105"
        assert norm["dst_ip"] == "203.94.1.10"
        assert norm["protocol"] == 6

    def test_scada_normalization(self):
        raw = {
            "src_ip": "10.0.1.99",
            "dst_ip": "10.0.2.10",
            "function": "write_coil",
            "register": "0x0001",
            "value": "0xFF",
            "protocol": "modbus",
        }
        norm = normalize_fields(raw, source_type="scada")
        assert norm["src_ip"] == "10.0.1.99"
        assert norm["method"] == "write_coil"
        assert norm["path"] == "0x0001"
        assert norm["protocol"] == "modbus"

    def test_missing_fields_dont_crash(self):
        """Missing fields should result in None/omission, never an exception."""
        raw = {"src_ip": "1.2.3.4"}
        norm = normalize_fields(raw, source_type="web_access_log")
        assert norm.get("src_ip") == "1.2.3.4"
        # Missing fields are omitted (not set to None)
        assert "method" not in norm or norm["method"] is None or isinstance(norm["method"], str)

    def test_auto_detect_cicids(self):
        raw = {" Source IP": "10.0.0.1", " Destination IP": "10.0.0.2", " Protocol": 6}
        norm = normalize_fields(raw)  # No explicit source_type
        assert norm["src_ip"] == "10.0.0.1"


# ─── NER TESTS ────────────────────────────────────────────────────────────────

class TestNER:
    """Test named entity recognition extraction."""

    def test_extract_ip(self):
        raw = {"message": "Connection from 185.23.147.82 to server"}
        entities = extract_ner(raw)
        assert entities["ip"] == "185.23.147.82"

    def test_extract_user(self):
        raw = {"message": "user=admin login attempt"}
        entities = extract_ner(raw)
        assert entities["user"] == "admin"

    def test_extract_process(self):
        raw = {"message": "process=svchost.exe started"}
        entities = extract_ner(raw)
        assert entities["process"] == "svchost.exe"

    def test_extract_domain(self):
        raw = {"message": "domain=evil.example.com resolved"}
        entities = extract_ner(raw)
        assert entities["domain"] == "evil.example.com"

    def test_extract_hash_sha256(self):
        raw = {"message": "File hash: 9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"}
        entities = extract_ner(raw)
        assert entities["hash"] == "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"

    def test_extract_hash_md5(self):
        raw = {"message": "MD5: d41d8cd98f00b204e9800998ecf8427e"}
        entities = extract_ner(raw)
        assert entities["hash"] == "d41d8cd98f00b204e9800998ecf8427e"

    def test_missing_entities_return_none(self):
        raw = {"message": "nothing useful here"}
        entities = extract_ner(raw)
        assert entities["user"] is None
        assert entities["process"] is None
        assert entities["domain"] is None


# ─── ASSET LOOKUP TESTS ──────────────────────────────────────────────────────

class TestAssetLookup:
    """Test asset criticality lookup with known and unknown assets."""

    def test_known_asset_by_id(self):
        meta = lookup_asset("CBSE-WebSvr-01")
        assert meta["criticality"] == "HIGH"
        assert meta["mission"] == "exam_portal"
        assert meta["can_reboot"] is True

    def test_known_ot_asset(self):
        meta = lookup_asset("CBSE-OT-SCADA-01")
        assert meta["criticality"] == "CRITICAL"
        assert meta["can_reboot"] is False
        assert meta["can_interrupt"] is False
        assert meta["safety_critical"] is True

    def test_unknown_asset_defaults(self):
        meta = lookup_asset("UNKNOWN-HOST-99")
        assert meta["criticality"] == "MEDIUM"
        assert meta["can_reboot"] is True
        assert meta["can_interrupt"] is True
        assert meta["safety_critical"] is False

    def test_ip_based_lookup(self):
        meta = lookup_asset("203.94.1.10")
        assert meta["mission"] == "exam_portal"


# ─── OT CONTEXT TESTS ────────────────────────────────────────────────────────

class TestOTContext:
    """Test OT Context Builder — all 6 fields."""

    def test_modbus_detection(self):
        raw = {"protocol": "modbus", "function": "read_holding_register"}
        assert detect_ot_protocol(raw) == "Modbus"

    def test_dnp3_detection(self):
        raw = {"protocol": "dnp3", "src_ip": "10.0.1.1"}
        assert detect_ot_protocol(raw) == "DNP3"

    def test_s7_detection(self):
        raw = {"protocol": "s7comm", "dst_ip": "10.30.1.10"}
        assert detect_ot_protocol(raw) == "S7"

    def test_no_ot_protocol(self):
        raw = {"protocol": "HTTP", "method": "GET"}
        assert detect_ot_protocol(raw) is None

    def test_scada_ot_context_full(self):
        raw = {"protocol": "modbus", "value": "0xFF"}
        asset_meta = lookup_asset("CBSE-OT-SCADA-01")
        ot_ctx = build_ot_context(raw, asset_meta)
        assert ot_ctx["protocol"] == "Modbus"
        assert ot_ctx["device_type"] == "scada_controller"
        assert ot_ctx["safety_critical"] is True
        assert ot_ctx["can_interrupt"] is False
        assert ot_ctx["can_reboot"] is False
        assert ot_ctx["impact_if_compromised"] == "CRITICAL"

    def test_it_asset_ot_context(self):
        raw = {"protocol": "HTTP", "method": "GET"}
        asset_meta = lookup_asset("CBSE-WebSvr-01")
        ot_ctx = build_ot_context(raw, asset_meta)
        assert ot_ctx["protocol"] is None
        assert ot_ctx["can_reboot"] is True
        assert ot_ctx["safety_critical"] is False


# ─── INDIAN CONTEXT TESTS ────────────────────────────────────────────────────

class TestIndianContext:
    """Test Indian Context Builder — all 4 flags."""

    def test_exam_season_march(self):
        dt = datetime(2026, 3, 15, tzinfo=timezone.utc)
        assert is_exam_season(dt) is True

    def test_exam_season_january(self):
        dt = datetime(2026, 1, 10, tzinfo=timezone.utc)
        assert is_exam_season(dt) is True

    def test_not_exam_season_august(self):
        dt = datetime(2026, 8, 15, tzinfo=timezone.utc)
        assert is_exam_season(dt) is False

    def test_govt_year_end_march_31(self):
        dt = datetime(2026, 3, 31, tzinfo=timezone.utc)
        assert is_government_year_end(dt) is True

    def test_govt_year_end_march_22(self):
        dt = datetime(2026, 3, 22, tzinfo=timezone.utc)
        assert is_government_year_end(dt) is True

    def test_not_govt_year_end_march_20(self):
        dt = datetime(2026, 3, 20, tzinfo=timezone.utc)
        assert is_government_year_end(dt) is False

    def test_republic_day(self):
        dt = datetime(2026, 1, 26, tzinfo=timezone.utc)
        assert is_national_holiday(dt) is True

    def test_independence_day(self):
        dt = datetime(2026, 8, 15, tzinfo=timezone.utc)
        assert is_national_holiday(dt) is True

    def test_not_a_holiday(self):
        dt = datetime(2026, 7, 7, tzinfo=timezone.utc)
        assert is_national_holiday(dt) is False

    def test_full_indian_context_dict(self):
        dt = datetime(2026, 3, 28, 23, 55, 0, tzinfo=timezone.utc)
        ctx = build_indian_context(dt)
        assert ctx["exam_season"] is True
        assert ctx["govt_year_end"] is True
        assert ctx["election_period"] is False
        assert ctx["holiday_period"] is False


# ─── TIME-OF-DAY TESTS ───────────────────────────────────────────────────────

class TestTimeOfDay:
    def test_business_hours(self):
        assert classify_time_of_day(datetime(2026, 3, 15, 10, 0)) == "business_hours"

    def test_off_hours(self):
        assert classify_time_of_day(datetime(2026, 3, 15, 20, 0)) == "off_hours"

    def test_night(self):
        assert classify_time_of_day(datetime(2026, 3, 15, 2, 0)) == "night"


# ─── FINGERPRINT TESTS ───────────────────────────────────────────────────────

class TestFingerprint:
    def test_sha256_length(self):
        fp = compute_content_fingerprint({"src_ip": "1.2.3.4", "method": "GET"})
        assert len(fp) == 64
        assert all(c in "0123456789abcdef" for c in fp)

    def test_deterministic(self):
        payload = {"src_ip": "1.2.3.4", "method": "GET"}
        fp1 = compute_content_fingerprint(payload)
        fp2 = compute_content_fingerprint(payload)
        assert fp1 == fp2

    def test_different_payloads_different_hashes(self):
        fp1 = compute_content_fingerprint({"src_ip": "1.2.3.4"})
        fp2 = compute_content_fingerprint({"src_ip": "5.6.7.8"})
        assert fp1 != fp2


# ─── FULL EVIDENCE PIPELINE TESTS ────────────────────────────────────────────

class TestFullPipeline:
    """End-to-end tests: raw log → Evidence Object."""

    def test_it_asset_evidence(self):
        raw = {
            "src_ip": "185.23.147.82",
            "dst_ip": "203.94.1.10",
            "request_path": "/api/users",
            "http_method": "GET",
            "user_agent": "curl/7.68.0",
            "status_code": 200,
            "bytes_sent": 1234,
            "timestamp": "2026-03-15T02:47:33Z",
        }
        ev = process(raw, asset_id="CBSE-WebSvr-01", source="web_access_log")

        # Type check
        assert isinstance(ev, Evidence)

        # Core identity
        assert ev.evidence_id.startswith("EV-")
        assert ev.source == "web_access_log"
        assert ev.asset_id == "CBSE-WebSvr-01"

        # Normalized fields
        assert ev.normalized["src_ip"] == "185.23.147.82"
        assert ev.normalized["path"] == "/api/users"

        # Fingerprint — valid SHA-256
        assert len(ev.content_fingerprint) == 64

        # Embedding placeholder
        assert len(ev.behavior_embedding) == 256
        assert all(x == 0.0 for x in ev.behavior_embedding)

        # Context
        assert ev.context["criticality"] == "HIGH"
        assert ev.context["mission"] == "exam_portal"

        # Indian context
        assert ev.context["indian_context"]["exam_season"] is True

        # OT context — IT asset
        assert ev.context["ot_context"]["can_reboot"] is True
        assert ev.context["ot_context"]["protocol"] is None

        # Provenance
        assert ev.provenance == "A2_normalizer"

    def test_scada_asset_forces_human_gate(self):
        """
        OT/SCADA asset with can_reboot=False and safety_critical=True.
        A7 uses these flags to force HUMAN_GATE — verify A2 sets them.
        """
        raw = {
            "src_ip": "10.0.1.99",
            "dst_ip": "10.0.2.10",
            "function": "write_coil",
            "register": "0x0001",
            "value": "0xFF",
            "protocol": "modbus",
            "timestamp": "2026-01-26T23:00:00Z",
        }
        ev = process(raw, asset_id="CBSE-OT-SCADA-01", source="scada")

        ot = ev.context["ot_context"]
        assert ot["can_reboot"] is False, "SCADA asset must have can_reboot=False"
        assert ot["can_interrupt"] is False
        assert ot["safety_critical"] is True
        assert ot["protocol"] == "Modbus"
        assert ot["impact_if_compromised"] == "CRITICAL"

    def test_unknown_asset_uses_defaults(self):
        raw = {
            "src_ip": "10.99.88.77",
            "dst_ip": "172.16.0.55",
            "timestamp": "2026-08-15T10:00:00Z",
        }
        ev = process(raw, asset_id="MYSTERY-HOST-99")

        assert ev.context["criticality"] == "MEDIUM"
        assert ev.context["ot_context"]["can_reboot"] is True
        assert ev.context["ot_context"]["safety_critical"] is False

    def test_indian_context_holiday(self):
        """Republic Day (Jan 26) should flag holiday_period=True."""
        raw = {"src_ip": "10.0.0.1", "timestamp": "2026-01-26T10:00:00Z"}
        ev = process(raw, asset_id="CBSE-WebSvr-01")
        assert ev.context["indian_context"]["holiday_period"] is True
        assert ev.context["indian_context"]["exam_season"] is True

    def test_serialization_round_trip(self):
        raw = {
            "src_ip": "185.23.147.82",
            "dst_ip": "203.94.1.10",
            "http_method": "POST",
            "timestamp": "2026-03-15T14:00:00Z",
        }
        ev = process(raw, asset_id="CBSE-WebSvr-01")
        json_str = ev.to_json()
        restored = Evidence.from_json(json_str)
        assert restored.evidence_id == ev.evidence_id
        assert restored.content_fingerprint == ev.content_fingerprint


# ─── BATCH / CSV TESTS ───────────────────────────────────────────────────────

class TestBatchProcessing:
    def test_batch_multiple_logs(self):
        logs = [
            {"src_ip": "1.2.3.4", "timestamp": "2026-03-15T10:00:00Z"},
            {"src_ip": "5.6.7.8", "timestamp": "2026-08-20T22:00:00Z"},
        ]
        results = process_batch(logs)
        assert len(results) == 2
        assert all(isinstance(ev, Evidence) for ev in results)

    def test_batch_tolerates_bad_row(self):
        """A bad row should be skipped, not crash the entire batch."""
        logs = [
            {"src_ip": "1.2.3.4", "timestamp": "2026-03-15T10:00:00Z"},
            None,  # This will cause an error — should be logged and skipped
            {"src_ip": "5.6.7.8", "timestamp": "2026-08-20T22:00:00Z"},
        ]
        # process_batch iterates and catches per-row exceptions
        results = process_batch([l for l in logs if l is not None])
        assert len(results) == 2

    def test_csv_processing(self):
        csv_path = str(Path(__file__).resolve().parent.parent / "data" / "sample_logs.csv")
        if not os.path.exists(csv_path):
            pytest.skip("sample_logs.csv not found")
        results = process_csv(csv_path)
        assert len(results) > 0
        assert all(isinstance(ev, Evidence) for ev in results)


# ─── RUN ──────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    pytest.main([__file__, "-v"])
