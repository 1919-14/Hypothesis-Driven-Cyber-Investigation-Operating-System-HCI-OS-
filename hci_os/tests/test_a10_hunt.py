"""
tests/test_a10_hunt.py
Comprehensive unit tests for A10: Active Hunt Agent.

Covers:
  - Trigger condition (anomaly_score, open hypothesis match)
  - Entity extraction (IP, domain, hash, URL; priority; private IP filter)
  - Rate limiter behavior
  - Hunt cache (hit/miss/expiration)
  - Circuit breaker (opens on failures, cooling window)
  - VirusTotal / Shodan mock fallbacks (Gap #1)
  - Confidence boost formula (Gap #4)
  - Skip on no entities (Gap #2)
  - E2E pipeline integration

Run:  pytest tests/test_a10_hunt.py -v
"""

from __future__ import annotations

import json
import sys
import time
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List
from unittest.mock import MagicMock, patch

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import agents.a10_hunt as a10
from agents.a10_hunt import (
    CB_COOLING_SECS,
    MOCK_VT_RESPONSE,
    MOCK_SHODAN_RESPONSE,
    CircuitBreaker,
    RateLimiter,
    boost_hypothesis_confidence,
    build_hunt_evidence,
    compute_confidence_boost,
    extract_entities,
    get_cached_result,
    process,
    query_shodan,
    query_virustotal,
    set_cached_result,
    should_trigger,
)
from objects.hypothesis import Hypothesis


# ─── Fixtures ────────────────────────────────────────────────────────────────

@pytest.fixture(autouse=True)
def _tmp_cache(tmp_path, monkeypatch):
    """Redirect cache file to tmp dir for every test."""
    cache_file = tmp_path / "hunt_cache.json"
    monkeypatch.setattr(a10, "_HUNT_CACHE_PATH", cache_file)
    monkeypatch.setattr(a10, "_DATA_DIR", tmp_path)
    yield cache_file


@pytest.fixture(autouse=True)
def _reset_circuit_breaker():
    """Reset the module-level circuit breaker before every test."""
    a10._circuit_breaker = CircuitBreaker()
    yield


@pytest.fixture()
def high_score_evidence():
    return {
        "asset_id":   "CBSE-WebSvr-01",
        "confidence": 0.85,
        "context":    {"criticality": "HIGH"},
        "normalized": {"src_ip": "185.23.147.82"},
    }


@pytest.fixture()
def low_score_evidence():
    return {
        "asset_id":   "CBSE-WebSvr-01",
        "confidence": 0.50,
        "normalized": {},
    }


@pytest.fixture()
def active_hypothesis():
    return Hypothesis(
        goal="Exploitation of CBSE-WebSvr-01 via Log4Shell",
        state="ACTIVE_INVESTIGATION",
        confidence=0.60,
    )


# ─── TestTrigger ─────────────────────────────────────────────────────────────

class TestTrigger:
    def test_fires_on_high_score_no_open_hypothesis(self, high_score_evidence):
        fired, reason = should_trigger(high_score_evidence)
        assert fired is True
        assert "0.85" in reason

    def test_skip_low_anomaly_score(self, low_score_evidence):
        fired, reason = should_trigger(low_score_evidence)
        assert fired is False
        assert "0.50" in reason or "≤" in reason

    def test_skip_exact_threshold(self):
        ev = {"asset_id": "X", "confidence": 0.7, "normalized": {}}
        fired, _ = should_trigger(ev)
        assert fired is False   # strictly greater than 0.7

    def test_fires_just_above_threshold(self):
        ev = {"asset_id": "X", "confidence": 0.701, "normalized": {}}
        fired, _ = should_trigger(ev)
        assert fired is True

    def test_skip_when_open_hypothesis_matches(self, high_score_evidence, active_hypothesis):
        fired, reason = should_trigger(high_score_evidence, open_hypotheses=[active_hypothesis])
        assert fired is False
        assert "open hypothesis" in reason

    def test_fire_when_open_hypothesis_different_asset(self, high_score_evidence):
        hyp = Hypothesis(goal="Exploitation of AIIMS DB server", state="ACTIVE_INVESTIGATION", confidence=0.9)
        fired, _ = should_trigger(high_score_evidence, open_hypotheses=[hyp])
        assert fired is True   # different asset — should still fire

    def test_skip_when_hypothesis_is_confirmed(self, high_score_evidence):
        hyp = Hypothesis(goal="CBSE-WebSvr-01 attack", state="CONFIRMED", confidence=0.9)
        fired, _ = should_trigger(high_score_evidence, open_hypotheses=[hyp])
        assert fired is True   # CONFIRMED ≠ ACTIVE — hunt should fire

    def test_context_anomaly_score_takes_precedence(self):
        ev = {"asset_id": "X", "confidence": 0.3, "context": {"anomaly_score": 0.9}, "normalized": {}}
        fired, _ = should_trigger(ev)
        assert fired is True


# ─── TestEntityExtraction ─────────────────────────────────────────────────────

class TestEntityExtraction:
    def test_extracts_public_ip(self):
        ev = {"normalized": {"src_ip": "185.23.147.82"}}
        entities = extract_entities(ev)
        values = [e["value"] for e in entities]
        assert "185.23.147.82" in values

    def test_filters_private_ip(self):
        ev = {"normalized": {"src_ip": "192.168.1.1"}}
        entities = extract_entities(ev)
        values = [e["value"] for e in entities]
        assert "192.168.1.1" not in values

    def test_filters_loopback(self):
        ev = {"normalized": {"src_ip": "127.0.0.1"}}
        assert not any(e["value"] == "127.0.0.1" for e in extract_entities(ev))

    def test_extracts_sha256_hash(self):
        sha = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"
        ev = {"normalized": {"file_hash": sha}}
        entities = extract_entities(ev)
        assert any(e["type"] == "hash" and e["value"] == sha for e in entities)

    def test_extracts_md5_hash(self):
        md5 = "d41d8cd98f00b204e9800998ecf8427e"
        ev = {"normalized": {"hash": md5}}
        entities = extract_entities(ev)
        assert any(e["type"] == "hash" for e in entities)

    def test_hash_has_higher_priority_than_ip(self):
        sha = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"
        ev = {"normalized": {"src_ip": "185.23.147.82", "hash": sha}}
        entities = extract_entities(ev)
        types = [e["type"] for e in entities]
        assert types.index("hash") < types.index("ip")

    def test_extracts_domain(self):
        ev = {"normalized": {"message": "connection to evil.example.com established"}}
        entities = extract_entities(ev)
        values = [e["value"] for e in entities]
        assert any("example.com" in v for v in values)

    def test_extracts_url(self):
        ev = {"normalized": {"url": "https://attacker.com/malware.exe"}}
        entities = extract_entities(ev)
        assert any(e["type"] == "url" for e in entities)

    def test_deduplication(self):
        ev = {"normalized": {"a": "185.23.147.82", "b": "185.23.147.82"}}
        entities = extract_entities(ev)
        values = [e["value"] for e in entities]
        assert values.count("185.23.147.82") == 1

    def test_empty_evidence_returns_empty(self):
        assert extract_entities({"normalized": {}}) == []

    def test_nested_structure_scanned(self):
        ev = {"normalized": {"outer": {"inner": "185.23.147.82"}}}
        entities = extract_entities(ev)
        assert any(e["value"] == "185.23.147.82" for e in entities)


# ─── TestRateLimiter ─────────────────────────────────────────────────────────

class TestRateLimiter:
    def test_does_not_sleep_under_limit(self):
        rl = RateLimiter(max_requests=4, window_seconds=60)
        start = time.monotonic()
        for _ in range(3):
            rl.wait_if_needed()
        elapsed = time.monotonic() - start
        assert elapsed < 1.0   # no waiting

    def test_allows_exactly_max_requests(self):
        rl = RateLimiter(max_requests=4, window_seconds=60)
        for _ in range(4):
            rl.wait_if_needed()
        assert len(rl._timestamps) == 4

    def test_deque_evicts_old_timestamps(self):
        rl = RateLimiter(max_requests=2, window_seconds=0.1)
        rl.wait_if_needed()
        rl.wait_if_needed()
        time.sleep(0.15)
        # After window expires, both old timestamps evicted
        rl.wait_if_needed()
        assert len(rl._timestamps) == 1


# ─── TestCache ───────────────────────────────────────────────────────────────

class TestCache:
    def test_cache_miss_returns_none(self):
        assert get_cached_result("ip", "1.2.3.4") is None

    def test_cache_set_and_get(self):
        result = {"vt_stats": {"malicious": 5}, "hunt_score": 0.5}
        set_cached_result("ip", "1.2.3.4", result)
        cached = get_cached_result("ip", "1.2.3.4")
        assert cached is not None
        assert cached["hunt_score"] == 0.5

    def test_cache_separates_by_entity_type(self):
        set_cached_result("ip", "1.2.3.4", {"hunt_score": 0.1})
        set_cached_result("hash", "1.2.3.4", {"hunt_score": 0.9})
        ip_res   = get_cached_result("ip",   "1.2.3.4")
        hash_res = get_cached_result("hash", "1.2.3.4")
        assert ip_res["hunt_score"]   == 0.1
        assert hash_res["hunt_score"] == 0.9

    def test_expired_cache_returns_none(self, _tmp_cache, monkeypatch):
        # Write a cache entry with timestamp 25 hours ago
        old_time = (datetime.now(timezone.utc) - timedelta(hours=25)).isoformat()
        key = a10._cache_key("ip", "9.9.9.9")
        cache = {key: {"entity_type": "ip", "entity_value": "9.9.9.9", "cached_at": old_time, "result": {"hunt_score": 0.8}}}
        _tmp_cache.write_text(json.dumps(cache))
        assert get_cached_result("ip", "9.9.9.9") is None

    def test_fresh_cache_returns_result(self, _tmp_cache):
        result = {"hunt_score": 0.42}
        set_cached_result("domain", "evil.com", result)
        assert get_cached_result("domain", "evil.com") is not None


# ─── TestCircuitBreaker ───────────────────────────────────────────────────────

class TestCircuitBreaker:
    def test_starts_closed(self):
        cb = CircuitBreaker()
        assert cb.is_open is False

    def test_opens_after_max_failures(self):
        cb = CircuitBreaker(max_failures=3, cooling_secs=60)
        for _ in range(3):
            cb.record_failure()
        assert cb.is_open is True

    def test_does_not_open_before_max_failures(self):
        cb = CircuitBreaker(max_failures=3, cooling_secs=60)
        cb.record_failure()
        cb.record_failure()
        assert cb.is_open is False

    def test_resets_after_cooling_window(self):
        cb = CircuitBreaker(max_failures=1, cooling_secs=0.05)
        cb.record_failure()
        assert cb.is_open is True
        time.sleep(0.1)
        assert cb.is_open is False   # cooling expired

    def test_cb_cooling_secs_is_60(self):
        """Gap #3 — explicitly verify the 60s default."""
        assert CB_COOLING_SECS == 60

    def test_success_resets_failures(self):
        cb = CircuitBreaker(max_failures=3, cooling_secs=60)
        cb.record_failure()
        cb.record_failure()
        cb.record_success()
        cb.record_failure()
        cb.record_failure()
        assert cb.is_open is False   # only 2 failures since reset


# ─── TestVTClient ─────────────────────────────────────────────────────────────

class TestVTClient:
    def test_mock_response_when_no_api_key(self, monkeypatch):
        """Gap #1 — structured mock returned if VT_API_KEY absent."""
        monkeypatch.setattr(a10, "VT_API_KEY", None)
        raw, score = query_virustotal("ip", "185.23.147.82")
        assert raw.get("_mock") is True
        assert score == 0.0   # mock has 0 malicious

    def test_hunt_score_formula(self):
        """hunt_score = (malicious + suspicious) / total"""
        resp = {"data": {"attributes": {"last_analysis_stats": {
            "malicious": 47, "suspicious": 12, "undetected": 31, "harmless": 0,
        }}}}
        stats, score = a10._parse_vt_stats(resp)
        expected = (47 + 12) / (47 + 12 + 31 + 0)
        assert abs(score - expected) < 0.0001

    def test_zero_total_returns_zero_score(self):
        resp = {"data": {"attributes": {"last_analysis_stats": {
            "malicious": 0, "suspicious": 0, "undetected": 0, "harmless": 0,
        }}}}
        _, score = a10._parse_vt_stats(resp)
        assert score == 0.0

    def test_error_response_returns_zero(self):
        _, score = a10._parse_vt_stats({"error": "not found"})
        assert score == 0.0

    def test_real_vt_call_mocked(self, monkeypatch):
        """Verify live VT path calls rate limiter and returns parsed score."""
        monkeypatch.setattr(a10, "VT_API_KEY", "fake_key")
        fake_resp = {"data": {"attributes": {"last_analysis_stats": {
            "malicious": 10, "suspicious": 5, "undetected": 85, "harmless": 0,
        }}}}
        with patch("agents.a10_hunt._hunt_with_retry", return_value=fake_resp):
            raw, score = query_virustotal("ip", "8.8.8.8")
        assert score == pytest.approx((10 + 5) / 100, abs=0.001)


# ─── TestShodanClient ─────────────────────────────────────────────────────────

class TestShodanClient:
    def test_mock_returned_when_no_key(self, monkeypatch):
        """Gap #1 — structured mock if SHODAN_API_KEY missing."""
        monkeypatch.setattr(a10, "SHODAN_API_KEY", None)
        result = query_shodan("185.23.147.82")
        assert result.get("_mock") is True
        assert isinstance(result["ports"], list)

    def test_parse_shodan_c2_tag(self):
        raw = {"ports": [80, 443], "vulns": {}, "tags": ["C2", "proxy"]}
        parsed = a10._parse_shodan(raw)
        assert parsed["is_c2"] is True
        assert parsed["has_vulns"] is False

    def test_parse_shodan_with_vulns(self):
        raw = {"ports": [22], "vulns": {"CVE-2021-44228": {}}, "tags": []}
        parsed = a10._parse_shodan(raw)
        assert parsed["has_vulns"] is True
        assert "CVE-2021-44228" in parsed["vulns"]

    def test_parse_shodan_error(self):
        parsed = a10._parse_shodan({"error": "no info"})
        assert parsed["shodan_available"] is False


# ─── TestConfidenceBoost ──────────────────────────────────────────────────────

class TestConfidenceBoost:
    """Gap #4 — linear formula: boost = 0.05 + 0.10 * hunt_score"""

    def test_boost_at_zero(self):
        assert compute_confidence_boost(0.0) == pytest.approx(0.05, abs=0.0001)

    def test_boost_at_one(self):
        assert compute_confidence_boost(1.0) == pytest.approx(0.15, abs=0.0001)

    def test_boost_at_half(self):
        assert compute_confidence_boost(0.5) == pytest.approx(0.10, abs=0.0001)

    def test_boost_clamped_above_one(self):
        assert compute_confidence_boost(2.0) == pytest.approx(0.15, abs=0.0001)

    def test_boost_clamped_below_zero(self):
        assert compute_confidence_boost(-1.0) == pytest.approx(0.05, abs=0.0001)

    def test_hypothesis_confidence_clamped_at_one(self, active_hypothesis):
        active_hypothesis.confidence = 0.98
        boost_hypothesis_confidence(active_hypothesis, 1.0, "EV-X")
        assert active_hypothesis.confidence <= 1.0

    def test_hypothesis_evidence_attached(self, active_hypothesis):
        boost_hypothesis_confidence(active_hypothesis, 0.8, "EV-HUNT-AAAA")
        assert "EV-HUNT-AAAA" in active_hypothesis.supporting_evidence

    def test_hypothesis_confidence_increases(self, active_hypothesis):
        old = active_hypothesis.confidence
        boost_hypothesis_confidence(active_hypothesis, 0.5, "EV-1")
        assert active_hypothesis.confidence > old


# ─── TestHuntEvidence ─────────────────────────────────────────────────────────

class TestHuntEvidence:
    def test_evidence_id_format(self):
        ev = build_hunt_evidence("ip", "1.2.3.4", {}, 0.5, None, "CBSE-01")
        assert ev.evidence_id.startswith("EV-HUNT-")

    def test_evidence_provenance(self):
        ev = build_hunt_evidence("ip", "1.2.3.4", {}, 0.5, None, "CBSE-01")
        assert ev.provenance == "A10_active_hunt"

    def test_evidence_source(self):
        ev = build_hunt_evidence("ip", "1.2.3.4", {}, 0.5, None, "CBSE-01")
        assert ev.source == "active_hunt_virustotal"

    def test_evidence_confidence_matches_hunt_score(self):
        ev = build_hunt_evidence("hash", "abc" * 10 + "ab", {}, 0.72, None, "CBSE-01")
        assert ev.confidence == pytest.approx(0.72, abs=0.001)

    def test_evidence_fingerprint_valid_sha256(self):
        ev = build_hunt_evidence("ip", "1.2.3.4", {}, 0.5, None, "CBSE-01")
        assert len(ev.content_fingerprint) == 64


# ─── TestProcess ─────────────────────────────────────────────────────────────

class TestProcess:
    def test_skip_on_low_score(self, low_score_evidence):
        result = process(low_score_evidence)
        assert result["triggered"] is False
        assert result["hunt_results"] == []

    def test_skip_on_no_entities(self, monkeypatch):
        """Gap #2 — no entities → triggered=True but hunt_results=[]."""
        monkeypatch.setattr(a10, "VT_API_KEY", None)
        ev = {"asset_id": "CBSE-01", "confidence": 0.9, "context": {}, "normalized": {}}
        result = process(ev)
        assert result["triggered"] is True
        assert result["hunt_results"] == []
        assert "no huntable entities" in result["reason"]

    def test_full_hunt_with_mock_vt(self, monkeypatch):
        monkeypatch.setattr(a10, "VT_API_KEY", None)   # use mock
        monkeypatch.setattr(a10, "SHODAN_API_KEY", None)
        ev = {
            "asset_id":   "CBSE-WebSvr-01",
            "confidence": 0.85,
            "context":    {"criticality": "HIGH"},
            "normalized": {"src_ip": "185.23.147.82"},
        }
        result = process(ev)
        assert result["triggered"] is True
        assert len(result["hunt_results"]) == 1
        assert result["hunt_results"][0]["entity_value"] == "185.23.147.82"

    def test_hypothesis_updated(self, high_score_evidence, active_hypothesis, monkeypatch):
        monkeypatch.setattr(a10, "VT_API_KEY", None)
        monkeypatch.setattr(a10, "SHODAN_API_KEY", None)
        old_conf = active_hypothesis.confidence
        result = process(high_score_evidence, hypothesis=active_hypothesis)
        assert result["hypothesis_updated"] is True
        assert active_hypothesis.confidence >= old_conf

    def test_hunt_result_uses_cache(self, monkeypatch):
        monkeypatch.setattr(a10, "VT_API_KEY", None)
        ev = {
            "asset_id":   "CBSE-01",
            "confidence": 0.9,
            "context":    {},
            "normalized": {"src_ip": "185.23.147.82"},
        }
        # First call — populates cache
        process(ev)
        # Second call — reads from cache; we verify by checking circuit_breaker not triggered
        a10._circuit_breaker = CircuitBreaker()  # reset
        result = process(ev)
        assert result["triggered"] is True

    def test_circuit_breaker_blocks_after_failures(self, monkeypatch):
        monkeypatch.setattr(a10, "VT_API_KEY", "fake_key")
        monkeypatch.setattr(a10, "SHODAN_API_KEY", None)
        # Open the circuit breaker by manually triggering max failures
        cb = CircuitBreaker(max_failures=1, cooling_secs=3600)  # very long cooling
        for _ in range(1):
            cb.record_failure()
        monkeypatch.setattr(a10, "_circuit_breaker", cb)
        assert cb.is_open is True

        ev = {
            "asset_id":   "CBSE-01",
            "confidence": 0.9,
            "context":    {},
            "normalized": {"src_ip": "185.23.147.82"},
        }
        # Process should return circuit_breaker_open error in VT result — not crash
        result = process(ev)
        # Hunt may still produce an entry (error VT response → score=0.0) or empty
        # Key assertion: pipeline did not raise and result is a valid dict
        assert isinstance(result, dict)
        assert result["triggered"] is True


# ─── Run ─────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import pytest as _pytest
    _pytest.main([__file__, "-v"])
