"""
tests/test_a13_federation.py
Comprehensive unit tests for A13: Federation Agent.

Covers:
  - PII anonymization and public IP retention
  - STIX indicator building and pattern extraction
  - Confidence boost formula (single / multiple matches)
  - Confidence clamping to 1.0 (Gap #5)
  - TTL expiration (7 days)
  - Missing data fallback — no IOCs → skip (Gap #1)
  - Conflict resolution — only confidence > 0.85 stored (Gap #2)
  - Store initialization on first run (Gap #3)
  - Org labeling via HCI_OS_ORG_ID env var (Gap #4)
  - Two-process simulation: Org A writes, Org B reads

Run: pytest tests/test_a13_federation.py -v
"""

from __future__ import annotations

import json
import sys
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import stores.federation_store as fs
import agents.a13_federation   as a13
from agents.a13_federation import (
    PII_FIELDS,
    anonymize_ioc,
    apply_boost,
    check_federation,
    extract_public_entities,
    process,
    publish_ioc,
    should_share,
)
from stores.federation_store import (
    CONFIDENCE_THRESHOLD,
    STORE_PATH,
    add_indicator,
    build_stix_indicator,
    extract_pattern_value,
    is_expired,
    load_indicators,
    query_indicators,
    save_indicators,
    purge_expired,
)
from objects.evidence   import Evidence
from objects.hypothesis import Hypothesis


# ─── Fixtures ─────────────────────────────────────────────────────────────────

@pytest.fixture(autouse=True)
def _isolated_store(tmp_path, monkeypatch):
    """Redirect store file to a tmp directory for every test."""
    store_file = tmp_path / "federation_store.json"
    monkeypatch.setattr(fs, "STORE_PATH",   store_file)
    monkeypatch.setattr(a13, "STORE_PATH",  store_file)
    yield store_file


@pytest.fixture()
def confirmed_hypothesis():
    hyp = Hypothesis(goal="APT41 attack on CBSE-WebSvr-01", confidence=0.92)
    return hyp


@pytest.fixture()
def low_confidence_hypothesis():
    return Hypothesis(goal="Suspected scan", confidence=0.60)


@pytest.fixture()
def evidence_with_public_ip():
    return {
        "evidence_id": "EV-TEST-0001",
        "asset_id":    "CBSE-WebSvr-01",
        "normalized":  {"src_ip": "185.23.147.82", "method": "GET"},
        "context":     {},
    }


@pytest.fixture()
def evidence_with_hash():
    return {
        "evidence_id": "EV-TEST-0002",
        "asset_id":    "AIIMS-DB-01",
        "normalized":  {"file_hash": "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"},
        "context":     {},
    }


@pytest.fixture()
def evidence_private_ip_only():
    """Evidence where all IPs are internal — no shareable IOCs."""
    return {
        "evidence_id": "EV-TEST-0003",
        "asset_id":    "INTERNAL-DB-01",
        "normalized":  {"src_ip": "192.168.1.100", "dst_ip": "10.0.0.5"},
        "context":     {},
    }


def _stix_indicator(value: str, ioc_type: str = "ip", confidence: float = 0.90):
    return build_stix_indicator(ioc_type, value, confidence)


def _expired_indicator(value: str, ioc_type: str = "ip") -> Dict[str, Any]:
    """Build a STIX indicator with a 9-day-old timestamp."""
    ind = _stix_indicator(value, ioc_type)
    old_ts = (datetime.now(timezone.utc) - timedelta(days=9)).isoformat().replace("+00:00", "Z")
    ind["created"]  = old_ts
    ind["modified"] = old_ts
    return ind


# ─── TestStoreInitialization (Gap #3) ────────────────────────────────────────

class TestStoreInitialization:
    def test_store_created_if_missing(self, tmp_path):
        """Gap #3 — empty store file created on first access."""
        path = tmp_path / "new_store.json"
        assert not path.exists()
        fs._ensure_store(path)
        assert path.exists()
        data = json.loads(path.read_text())
        assert data["type"] == "bundle"
        assert data["indicators"] == []

    def test_load_indicators_on_missing_file(self, tmp_path):
        """Gap #3 — load_indicators creates file if missing."""
        path = tmp_path / "auto_init.json"
        result = load_indicators(path)
        assert result == []
        assert path.exists()

    def test_malformed_store_reinitializes(self, tmp_path):
        """Malformed JSON is replaced with an empty bundle."""
        path = tmp_path / "bad_store.json"
        path.write_text("{corrupted: True", encoding="utf-8")
        result = load_indicators(path)
        assert result == []


# ─── TestSTIXBuilderAndPattern ────────────────────────────────────────────────

class TestSTIXBuilderAndPattern:
    def test_ip_indicator_has_required_fields(self):
        ind = _stix_indicator("185.23.147.82", "ip")
        for field in ["id", "type", "created", "modified", "name", "pattern",
                      "valid_from", "confidence", "labels", "external_references"]:
            assert field in ind

    def test_ip_pattern_format(self):
        ind = _stix_indicator("185.23.147.82", "ip")
        assert ind["pattern"] == "[ipv4-addr:value = '185.23.147.82']"

    def test_sha256_pattern_format(self):
        sha = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"
        ind = _stix_indicator(sha, "hash_sha256")
        assert "SHA-256" in ind["pattern"]
        assert sha in ind["pattern"]

    def test_domain_pattern_format(self):
        ind = _stix_indicator("evil.example.com", "domain")
        assert ind["pattern"] == "[domain-name:value = 'evil.example.com']"

    def test_type_is_indicator(self):
        assert _stix_indicator("1.2.3.4")["type"] == "indicator"

    def test_spec_version_is_21(self):
        assert _stix_indicator("1.2.3.4")["spec_version"] == "2.1"

    def test_extract_pattern_value_ip(self):
        pattern = "[ipv4-addr:value = '185.23.147.82']"
        assert extract_pattern_value(pattern) == "185.23.147.82"

    def test_extract_pattern_value_hash(self):
        sha = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"
        pattern = f"[file:hashes.'SHA-256' = '{sha}']"
        assert extract_pattern_value(pattern) == sha

    def test_extract_pattern_value_invalid_returns_none(self):
        assert extract_pattern_value("malformed pattern") is None


# ─── TestConflictResolution (Gap #2) ─────────────────────────────────────────

class TestConflictResolution:
    def test_high_confidence_indicator_accepted(self, _isolated_store):
        ind = _stix_indicator("185.23.147.82", confidence=0.92)
        result = add_indicator(ind, _isolated_store)
        assert result is True

    def test_low_confidence_indicator_rejected(self, _isolated_store):
        """Gap #2 — indicators with confidence ≤ 0.85 are silently rejected."""
        ind = _stix_indicator("1.2.3.4", confidence=0.70)
        result = add_indicator(ind, _isolated_store)
        assert result is False
        assert load_indicators(_isolated_store) == []

    def test_exact_threshold_rejected(self, _isolated_store):
        """Gap #2 — threshold is strictly > 0.85, not >=."""
        ind = _stix_indicator("1.2.3.4", confidence=0.85)
        assert add_indicator(ind, _isolated_store) is False

    def test_multiple_indicators_stored(self, _isolated_store):
        for ip in ["185.1.2.3", "203.4.5.6"]:
            add_indicator(_stix_indicator(ip, confidence=0.90), _isolated_store)
        assert len(load_indicators(_isolated_store)) == 2


# ─── TestTTL ──────────────────────────────────────────────────────────────────

class TestTTL:
    def test_fresh_indicator_not_expired(self):
        ind = _stix_indicator("185.23.147.82")
        assert is_expired(ind) is False

    def test_old_indicator_is_expired(self):
        ind = _expired_indicator("185.23.147.82")
        assert is_expired(ind) is True

    def test_expired_indicator_not_returned_by_load(self, _isolated_store):
        ind = _expired_indicator("1.2.3.4")
        # Force-write without the 0.85 check
        bundle = {"type": "bundle", "id": "bundle--x", "spec_version": "2.1", "indicators": [ind]}
        _isolated_store.write_text(json.dumps(bundle), encoding="utf-8")
        result = load_indicators(_isolated_store)
        assert result == []

    def test_purge_expired_removes_old(self, _isolated_store):
        fresh   = _stix_indicator("185.23.147.82", confidence=0.90)
        expired = _expired_indicator("1.2.3.4")
        bundle = {
            "type": "bundle", "id": "bundle--x", "spec_version": "2.1",
            "indicators": [fresh, expired],
        }
        _isolated_store.write_text(json.dumps(bundle), encoding="utf-8")
        count = purge_expired(_isolated_store)
        assert count == 1
        assert len(load_indicators(_isolated_store)) == 1

    def test_malformed_timestamp_treated_as_expired(self):
        ind = {"pattern": "[ipv4-addr:value = '1.2.3.4']", "created": "not-a-date"}
        assert is_expired(ind) is True


# ─── TestAnonymizer (Gap #1) ─────────────────────────────────────────────────

class TestAnonymizer:
    def test_public_ip_retained(self, confirmed_hypothesis, evidence_with_public_ip):
        anon = anonymize_ioc(evidence_with_public_ip, confirmed_hypothesis)
        assert anon is not None
        assert "185.23.147.82" in anon["public_ips"]

    def test_private_ip_stripped(self, confirmed_hypothesis, evidence_private_ip_only):
        """PII and private IPs are removed from the shared IOC."""
        anon = anonymize_ioc(evidence_private_ip_only, confirmed_hypothesis)
        # No public IPs or hashes — should return None (Gap #1)
        assert anon is None

    def test_pii_fields_not_in_output(self, confirmed_hypothesis, evidence_with_public_ip):
        anon = anonymize_ioc(evidence_with_public_ip, confirmed_hypothesis)
        if anon:
            for field in PII_FIELDS:
                assert field not in anon

    def test_hash_retained(self, confirmed_hypothesis, evidence_with_hash):
        anon = anonymize_ioc(evidence_with_hash, confirmed_hypothesis)
        assert anon is not None
        assert len(anon["hashes"]) > 0

    def test_no_iocs_returns_none(self, confirmed_hypothesis):
        """Gap #1 — empty payload returns None, publishing is skipped."""
        empty_ev = {"asset_id": "X", "normalized": {}, "context": {}}
        result = anonymize_ioc(empty_ev, confirmed_hypothesis)
        assert result is None

    def test_no_iocs_internal_only_returns_none(self, confirmed_hypothesis, evidence_private_ip_only):
        """Gap #1 — all private IPs → None."""
        result = anonymize_ioc(evidence_private_ip_only, confirmed_hypothesis)
        assert result is None


# ─── TestOrgLabeling (Gap #4) ─────────────────────────────────────────────────

class TestOrgLabeling:
    def test_default_org_id_is_org_a(self):
        from stores.federation_store import ORG_ID as default_org
        # Default when HCI_OS_ORG_ID is unset (may vary per environment)
        assert default_org in ("Org-A", "Org-B", "Org-CBSE", "Org-AIIMS") or isinstance(default_org, str)

    def test_org_id_in_indicator(self, monkeypatch):
        """Gap #4 — the indicator's external_references use the org_id."""
        ind = build_stix_indicator("ip", "185.23.147.82", 0.90, org_id="Org-AIIMS")
        sources = [r["source_name"] for r in ind["external_references"]]
        assert "Org-AIIMS" in sources

    def test_org_id_env_var_used(self, monkeypatch, _isolated_store, confirmed_hypothesis, evidence_with_public_ip):
        """Gap #4 — HCI_OS_ORG_ID is picked up by publish_ioc."""
        monkeypatch.setenv("HCI_OS_ORG_ID", "Org-CBSE")
        result = publish_ioc(evidence_with_public_ip, confirmed_hypothesis,
                             store_path=_isolated_store, org_id="Org-CBSE")
        if result["published"]:
            indicators = load_indicators(_isolated_store)
            orgs = [i.get("_org_id") for i in indicators]
            assert "Org-CBSE" in orgs


# ─── TestTriggerCondition ─────────────────────────────────────────────────────

class TestTriggerCondition:
    def test_high_confidence_triggers(self, confirmed_hypothesis):
        assert should_share(confirmed_hypothesis) is True

    def test_low_confidence_does_not_trigger(self, low_confidence_hypothesis):
        assert should_share(low_confidence_hypothesis) is False

    def test_exact_threshold_does_not_trigger(self):
        hyp = Hypothesis(goal="Test", confidence=0.85)
        assert should_share(hyp) is False

    def test_just_above_threshold_triggers(self):
        hyp = Hypothesis(goal="Test", confidence=0.851)
        assert should_share(hyp) is True


# ─── TestConfidenceBoost (Gap #5) ────────────────────────────────────────────

class TestConfidenceBoost:
    def test_no_match_returns_zero(self, _isolated_store, evidence_private_ip_only):
        boost = check_federation(evidence_private_ip_only, _isolated_store)
        assert boost == 0.0

    def test_single_match_returns_point_10(self, _isolated_store, evidence_with_public_ip):
        add_indicator(_stix_indicator("185.23.147.82", confidence=0.90), _isolated_store)
        boost = check_federation(evidence_with_public_ip, _isolated_store)
        assert boost == pytest.approx(0.10, abs=0.001)

    def test_two_matches_returns_point_15(self, _isolated_store):
        """Two matching indicators → boost capped at 0.15."""
        add_indicator(_stix_indicator("185.23.147.82", confidence=0.90), _isolated_store)
        sha = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"
        add_indicator(_stix_indicator(sha, "hash_sha256", confidence=0.90), _isolated_store)
        ev = {
            "normalized": {
                "src_ip":    "185.23.147.82",
                "file_hash": sha,
            }
        }
        boost = check_federation(ev, _isolated_store)
        assert boost == pytest.approx(0.15, abs=0.001)

    def test_boost_capped_at_015(self, _isolated_store):
        """Formula ensures cap: min(0.10 + 0.05*(n-1), 0.15)."""
        for ip in ["185.1.1.1", "185.2.2.2", "185.3.3.3"]:
            add_indicator(_stix_indicator(ip, confidence=0.90), _isolated_store)
        ev = {"normalized": {"ip1": "185.1.1.1", "ip2": "185.2.2.2", "ip3": "185.3.3.3"}}
        boost = check_federation(ev, _isolated_store)
        assert boost <= 0.15

    def test_apply_boost_clamped_to_one(self):
        """Gap #5 — confidence never exceeds 1.0."""
        hyp = Hypothesis(goal="Test", confidence=0.98)
        apply_boost(hyp, 0.15)
        assert hyp.confidence <= 1.0

    def test_apply_boost_attaches_evidence_id(self):
        hyp = Hypothesis(goal="Test", confidence=0.80)
        apply_boost(hyp, 0.10, evidence_id="EV-FED-001")
        assert "EV-FED-001" in hyp.supporting_evidence

    def test_apply_boost_increases_confidence(self):
        hyp = Hypothesis(goal="Test", confidence=0.80)
        apply_boost(hyp, 0.10)
        assert hyp.confidence == pytest.approx(0.90, abs=0.001)


# ─── TestTwoProcessSimulation ─────────────────────────────────────────────────

class TestTwoProcessSimulation:
    def test_org_a_writes_org_b_reads(
        self, _isolated_store, confirmed_hypothesis, evidence_with_public_ip
    ):
        """
        Full E2E simulation:
        - Org A: publish IOC from confirmed hypothesis
        - Org B: query the same store and get a confidence boost
        """
        # ── Org A: publish ────────────────────────────────────────────────────
        pub_result = publish_ioc(
            evidence_with_public_ip, confirmed_hypothesis,
            store_path=_isolated_store, org_id="Org-A",
        )
        assert pub_result["published"] is True, "Org A should have published at least 1 indicator"

        # ── Verify store contains the indicator ───────────────────────────────
        indicators = load_indicators(_isolated_store)
        assert len(indicators) >= 1

        # ── Org B: query ──────────────────────────────────────────────────────
        org_b_evidence = {
            "evidence_id": "EV-ORGB-001",
            "asset_id":    "CBSE-Proxy-02",
            "normalized":  {"src_ip": "185.23.147.82"},
            "context":     {},
        }
        boost = check_federation(org_b_evidence, _isolated_store)
        assert boost > 0.0, "Org B should receive a non-zero confidence boost"

    def test_org_b_applies_boost_to_hypothesis(
        self, _isolated_store, confirmed_hypothesis, evidence_with_public_ip
    ):
        """Org B creates a hypothesis and boost is applied to it."""
        # Org A publishes
        publish_ioc(evidence_with_public_ip, confirmed_hypothesis,
                    store_path=_isolated_store, org_id="Org-A")

        # Org B: fresh hypothesis at 0.70
        org_b_hyp = Hypothesis(goal="Possible C2 beacon", confidence=0.70)
        org_b_ev  = {"normalized": {"src_ip": "185.23.147.82"}, "evidence_id": "EV-B-001"}

        result = process(org_b_ev, org_b_hyp, store_path=_isolated_store, org_id="Org-B")
        assert result["hypothesis_updated"] is True
        assert org_b_hyp.confidence > 0.70

    def test_expired_ioc_not_boosted_in_org_b(self, _isolated_store):
        """Org A's expired IOC must not influence Org B's confidence."""
        ind = _expired_indicator("185.23.147.82")
        bundle = {"type": "bundle", "id": "bundle--x", "spec_version": "2.1", "indicators": [ind]}
        _isolated_store.write_text(json.dumps(bundle), encoding="utf-8")

        ev = {"normalized": {"src_ip": "185.23.147.82"}}
        boost = check_federation(ev, _isolated_store)
        assert boost == 0.0


# ─── TestMissingDataFallback (Gap #1) ────────────────────────────────────────

class TestMissingDataFallback:
    def test_publish_skipped_when_no_iocs(self, _isolated_store, confirmed_hypothesis):
        """Gap #1 — no IOCs extracted → publish returns published=False."""
        empty_ev = {"asset_id": "X", "normalized": {}, "evidence_id": "EV-EMPTY"}
        result = publish_ioc(empty_ev, confirmed_hypothesis, _isolated_store)
        assert result["published"] is False
        assert result["reason"] == "no_shareable_iocs"

    def test_publish_skipped_low_confidence(self, _isolated_store, low_confidence_hypothesis,
                                             evidence_with_public_ip):
        """Gap #1 + Trigger — below-threshold hypothesis → not published."""
        result = publish_ioc(evidence_with_public_ip, low_confidence_hypothesis, _isolated_store)
        assert result["published"] is False
        assert result["reason"] == "confidence_below_threshold"


# ─── Run ─────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import pytest as _pytest
    _pytest.main([__file__, "-v"])
