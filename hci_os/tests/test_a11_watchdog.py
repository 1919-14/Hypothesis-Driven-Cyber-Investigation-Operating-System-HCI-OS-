"""
tests/test_a11_watchdog.py
Comprehensive unit tests for A11: Behavioral Watchdog Agent.

Covers:
  - Profile loading and defaults
  - Output type mismatch detection
  - Pydantic schema validation
  - Rate limit enforcement
  - Forbidden action detection
  - Forbidden path detection (Gap #2)
  - Violation JSONL logging
  - Agent suspension + disk persistence (Gap #3)
  - Watchdog self-protection health check (Gap #1)
  - Pipeline decorator and wrapper

Run: pytest tests/test_a11_watchdog.py -v
"""

from __future__ import annotations

import json
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import agents.a11_watchdog as a11
from agents.a11_watchdog import (
    PROFILES_PATH,
    SUSPENDED_AGENTS,
    SUSPENSIONS_PATH,
    WATCHDOG_LOG_PATH,
    check_behavior,
    check_forbidden_action,
    check_forbidden_paths,
    check_output_type,
    check_rate_limit,
    check_schema,
    execute_with_watchdog,
    get_profile,
    health_check,
    is_suspended,
    suspend_agent,
    unsuspend_agent,
    watchdog_intercept,
)
from objects.evidence   import Evidence
from objects.hypothesis import Hypothesis
from objects.decision   import Decision


# ─── Fixtures ─────────────────────────────────────────────────────────────────

@pytest.fixture(autouse=True)
def _isolated_paths(tmp_path, monkeypatch):
    """Redirect all data files to a tmp directory for every test."""
    monkeypatch.setattr(a11, "_DATA_DIR", tmp_path)
    monkeypatch.setattr(a11, "PROFILES_PATH",     tmp_path / "agent_profiles.json")
    monkeypatch.setattr(a11, "WATCHDOG_LOG_PATH", tmp_path / "watchdog_log.jsonl")
    monkeypatch.setattr(a11, "SUSPENSIONS_PATH",  tmp_path / "watchdog_suspensions.json")
    yield tmp_path


@pytest.fixture(autouse=True)
def _reset_state():
    """Clear in-memory state before every test."""
    a11._profiles.clear()
    a11._call_timestamps.clear()
    SUSPENDED_AGENTS.clear()
    yield
    SUSPENDED_AGENTS.clear()


@pytest.fixture()
def loaded_profiles(tmp_path):
    """Write the real agent_profiles.json to tmp and load it."""
    real_path = Path(__file__).resolve().parent.parent / "data" / "agent_profiles.json"
    content = real_path.read_text(encoding="utf-8") if real_path.exists() else json.dumps([
        {
            "agent_id": "A3",
            "display_name": "Fingerprint",
            "allowed_output_types": ["Evidence", "Decision", "dict"],
            "forbidden_output_types": ["Hypothesis"],
            "max_calls_per_minute": 600,
            "expected_output_schema": "Evidence",
            "forbidden_actions": ["write_to_audit", "execute_playbook"],
            "forbidden_paths": ["data/audit_log.jsonl"],
        },
        {
            "agent_id": "A6",
            "display_name": "Attribution",
            "allowed_output_types": ["Hypothesis", "dict"],
            "forbidden_output_types": ["Decision"],
            "max_calls_per_minute": 60,
            "expected_output_schema": "Hypothesis",
            "forbidden_actions": ["execute_playbook", "write_to_audit"],
            "forbidden_paths": ["data/audit_log.jsonl"],
        },
        {
            "agent_id": "A11",
            "display_name": "Watchdog",
            "allowed_output_types": ["dict"],
            "forbidden_output_types": ["Hypothesis", "Decision"],
            "max_calls_per_minute": 6000,
            "expected_output_schema": "dict",
            "forbidden_actions": [],
            "forbidden_paths": [],
        },
    ])
    (tmp_path / "agent_profiles.json").write_text(content, encoding="utf-8")
    a11._load_profiles()
    return a11._profiles


@pytest.fixture()
def a3_profile():
    return {
        "agent_id": "A3",
        "allowed_output_types": ["Evidence", "Decision", "dict"],
        "forbidden_output_types": ["Hypothesis"],
        "max_calls_per_minute": 600,
        "expected_output_schema": "Evidence",
        "forbidden_actions": ["write_to_audit", "execute_playbook"],
        "forbidden_paths": ["data/audit_log.jsonl"],
    }


@pytest.fixture()
def a6_profile():
    return {
        "agent_id": "A6",
        "allowed_output_types": ["Hypothesis", "dict"],
        "forbidden_output_types": ["Decision"],
        "max_calls_per_minute": 60,
        "expected_output_schema": "Hypothesis",
        "forbidden_actions": ["execute_playbook", "write_to_audit"],
        "forbidden_paths": ["data/audit_log.jsonl", "data/watchdog_log.jsonl"],
    }


def _make_evidence():
    import hashlib
    fp = hashlib.sha256(b"test").hexdigest()
    return Evidence(
        evidence_id="EV-TEST-0001",
        timestamp=datetime.now(timezone.utc),
        source="test",
        asset_id="TEST-01",
        normalized={"key": "val"},
        content_fingerprint=fp,
    )


def _make_hypothesis():
    return Hypothesis(goal="Test hypothesis", confidence=0.5)


def _make_decision():
    return Decision(
        decision_id="DEC-TEST-001",
        hypothesis_id="H-TEST-001",
        action_taken="BLOCK_IP",
        risk_score=0.8,
        blast_radius_score=0.4,
    )


# ─── TestProfileLoading ───────────────────────────────────────────────────────

class TestProfileLoading:
    def test_profiles_loaded_from_json(self, loaded_profiles):
        assert len(loaded_profiles) > 0

    def test_get_profile_returns_correct(self, loaded_profiles):
        p = get_profile("A6")
        assert p is not None
        assert p["agent_id"] == "A6"

    def test_get_profile_unknown_returns_none(self, loaded_profiles):
        assert get_profile("A99") is None

    def test_defaults_written_if_file_missing(self, tmp_path):
        """If agent_profiles.json doesn't exist, defaults are written."""
        assert not (tmp_path / "agent_profiles.json").exists()
        a11._load_profiles()
        assert (tmp_path / "agent_profiles.json").exists()
        assert len(a11._profiles) > 0


# ─── TestOutputTypeCheck ──────────────────────────────────────────────────────

class TestOutputTypeCheck:
    def test_compliant_type_returns_none(self, a3_profile):
        ev = _make_evidence()
        result = check_output_type("A3", ev, a3_profile)
        assert result is None

    def test_forbidden_type_returns_violation(self, a3_profile, tmp_path):
        hyp = _make_hypothesis()
        result = check_output_type("A3", hyp, a3_profile)
        assert result is not None
        assert result["violation_type"] == "output_type_mismatch"
        assert result["actual"] == "Hypothesis"

    def test_dict_output_is_allowed(self, a3_profile):
        result = check_output_type("A3", {"key": "val"}, a3_profile)
        assert result is None

    def test_decision_forbidden_for_a6(self, a6_profile, tmp_path):
        dec = _make_decision()
        result = check_output_type("A6", dec, a6_profile)
        assert result is not None
        assert result["severity"] == "CRITICAL"

    def test_severity_critical_for_decision_hypothesis_mismatch(self, a3_profile, tmp_path):
        hyp = _make_hypothesis()
        result = check_output_type("A3", hyp, a3_profile)
        assert result["severity"] == "CRITICAL"


# ─── TestSchemaValidation ─────────────────────────────────────────────────────

class TestSchemaValidation:
    def test_valid_evidence_passes(self, a3_profile):
        ev = _make_evidence()
        assert check_schema("A3", ev, a3_profile) is None

    def test_valid_evidence_dict_passes(self, a3_profile):
        ev = _make_evidence()
        result = check_schema("A3", ev.model_dump(), a3_profile)
        assert result is None

    def test_invalid_dict_fails_schema(self, a3_profile, tmp_path):
        bad_dict = {"malformed": "data"}
        result = check_schema("A3", bad_dict, a3_profile)
        assert result is not None
        assert result["violation_type"] == "schema_validation_failure"

    def test_dict_schema_skips_validation(self):
        profile = {"expected_output_schema": "dict"}
        result = check_schema("A1", {"anything": True}, profile)
        assert result is None


# ─── TestRateLimiting ─────────────────────────────────────────────────────────

class TestRateLimiting:
    def test_under_limit_is_compliant(self, a6_profile):
        """60 calls/min limit — 5 calls should be fine."""
        for _ in range(5):
            result = check_rate_limit("A6", a6_profile)
        assert result is None

    def test_over_limit_triggers_violation(self, tmp_path):
        """Simulate 62 calls when limit is 60."""
        profile = {"max_calls_per_minute": 3}
        result = None
        for _ in range(4):
            result = check_rate_limit("TEST_AGENT", profile)
        assert result is not None
        assert result["violation_type"] == "rate_limit_exceeded"
        assert result["severity"] == "HIGH"

    def test_old_timestamps_evicted(self):
        """After window expires, counter resets."""
        profile = {"max_calls_per_minute": 2}
        ts_queue = a11._call_timestamps.get("EVICT_AGENT")

        # Manually pre-fill old timestamps
        now = time.monotonic()
        a11._call_timestamps["EVICT_AGENT"] = __import__("collections").deque([now - 65, now - 61])
        # These are outside the 60s window and should be evicted
        result = check_rate_limit("EVICT_AGENT", profile)
        assert result is None   # only 1 new timestamp (under limit of 2)


# ─── TestForbiddenAction ──────────────────────────────────────────────────────

class TestForbiddenAction:
    def test_forbidden_action_is_critical(self, a6_profile, tmp_path):
        result = check_forbidden_action("A6", "execute_playbook", a6_profile)
        assert result is not None
        assert result["violation_type"] == "forbidden_action"
        assert result["severity"] == "CRITICAL"

    def test_case_insensitive_match(self, a6_profile, tmp_path):
        result = check_forbidden_action("A6", "Execute_Playbook", a6_profile)
        assert result is not None

    def test_allowed_action_returns_none(self, a6_profile):
        result = check_forbidden_action("A6", "update_hypothesis", a6_profile)
        assert result is None

    def test_no_forbidden_actions_always_passes(self):
        profile = {"forbidden_actions": []}
        assert check_forbidden_action("A11", "anything", profile) is None


# ─── TestForbiddenPaths (Gap #2) ──────────────────────────────────────────────

class TestForbiddenPaths:
    def test_forbidden_path_triggers_critical(self, a6_profile, tmp_path):
        result = check_forbidden_paths("A6", ["/app/data/audit_log.jsonl"], a6_profile)
        assert result is not None
        assert result["violation_type"] == "forbidden_path_access"
        assert result["severity"] == "CRITICAL"

    def test_allowed_path_returns_none(self, a6_profile):
        result = check_forbidden_paths("A6", ["/app/data/hunt_cache.json"], a6_profile)
        assert result is None

    def test_windows_path_normalized(self, a6_profile, tmp_path):
        result = check_forbidden_paths(
            "A6", [r"C:\app\data\audit_log.jsonl"], a6_profile
        )
        assert result is not None

    def test_empty_paths_returns_none(self, a6_profile):
        assert check_forbidden_paths("A6", [], a6_profile) is None

    def test_no_forbidden_paths_in_profile_passes(self):
        profile = {"forbidden_paths": []}
        result = check_forbidden_paths("A11", ["/data/anything.json"], profile)
        assert result is None

    def test_partial_path_match(self, a6_profile, tmp_path):
        """Path containing 'audit_log.jsonl' anywhere should flag."""
        result = check_forbidden_paths("A6", ["backup/data/audit_log.jsonl"], a6_profile)
        assert result is not None


# ─── TestViolationLogging ─────────────────────────────────────────────────────

class TestViolationLogging:
    def test_violation_written_to_jsonl(self, a3_profile, tmp_path):
        """CRITICAL output mismatch should append a record to watchdog_log.jsonl."""
        log_path = tmp_path / "watchdog_log.jsonl"
        a11.WATCHDOG_LOG_PATH = log_path
        hyp = _make_hypothesis()
        check_output_type("A3", hyp, a3_profile)
        assert log_path.exists()
        records = [json.loads(line) for line in log_path.read_text().splitlines() if line]
        assert len(records) >= 1

    def test_violation_record_has_required_fields(self, a3_profile, tmp_path):
        log_path = tmp_path / "watchdog_log.jsonl"
        a11.WATCHDOG_LOG_PATH = log_path
        hyp = _make_hypothesis()
        check_output_type("A3", hyp, a3_profile)
        record = json.loads(log_path.read_text().splitlines()[0])
        for field in ["agent_id", "violation_type", "expected", "actual", "severity", "recommendation", "timestamp"]:
            assert field in record

    def test_compliant_call_not_logged(self, a3_profile, tmp_path):
        log_path = tmp_path / "watchdog_log.jsonl"
        a11.WATCHDOG_LOG_PATH = log_path
        ev = _make_evidence()
        check_output_type("A3", ev, a3_profile)
        assert not log_path.exists() or log_path.read_text().strip() == ""


# ─── TestSuspension (Gap #3) ─────────────────────────────────────────────────

class TestSuspension:
    def test_suspend_adds_to_registry(self, tmp_path):
        a11.SUSPENSIONS_PATH = tmp_path / "suspensions.json"
        suspend_agent("A6", "test reason")
        assert is_suspended("A6")

    def test_suspension_persisted_to_disk(self, tmp_path):
        """Gap #3 — suspension survives restart by being saved to disk."""
        susp_path = tmp_path / "suspensions.json"
        a11.SUSPENSIONS_PATH = susp_path
        suspend_agent("A6", "critical violation")
        assert susp_path.exists()
        data = json.loads(susp_path.read_text())
        assert "A6" in data["suspended"]

    def test_suspension_restored_on_reload(self, tmp_path):
        """Gap #3 — load_suspensions() restores from disk on restart."""
        susp_path = tmp_path / "suspensions.json"
        a11.SUSPENSIONS_PATH = susp_path
        suspend_agent("A6", "persisted reason")
        a11.SUSPENDED_AGENTS.clear()   # simulate restart
        a11._load_suspensions()
        assert is_suspended("A6")
        assert a11.SUSPENDED_AGENTS["A6"] == "persisted reason"

    def test_unsuspend_removes_from_registry(self, tmp_path):
        a11.SUSPENSIONS_PATH = tmp_path / "suspensions.json"
        suspend_agent("A6", "test")
        unsuspend_agent("A6")
        assert not is_suspended("A6")

    def test_unsuspend_updates_disk(self, tmp_path):
        susp_path = tmp_path / "suspensions.json"
        a11.SUSPENSIONS_PATH = susp_path
        suspend_agent("A6", "test")
        unsuspend_agent("A6")
        data = json.loads(susp_path.read_text())
        assert "A6" not in data["suspended"]

    def test_critical_violation_auto_suspends(self, a6_profile, tmp_path):
        a11.SUSPENSIONS_PATH = tmp_path / "suspensions.json"
        a11.WATCHDOG_LOG_PATH = tmp_path / "watchdog_log.jsonl"
        dec = _make_decision()
        check_output_type("A6", dec, a6_profile)
        assert is_suspended("A6")

    def test_cannot_suspend_a11_self(self, tmp_path):
        """Gap #1 — Watchdog protects itself from self-suspension."""
        a11.SUSPENSIONS_PATH = tmp_path / "suspensions.json"
        suspend_agent("A11", "attempt to disable watchdog")
        assert not is_suspended("A11")


# ─── TestSelfProtection (Gap #1) ─────────────────────────────────────────────

class TestSelfProtection:
    def test_health_check_passes_clean_env(self, tmp_path, loaded_profiles):
        a11.SUSPENSIONS_PATH = tmp_path / "suspensions.json"
        result = health_check()
        assert result["healthy"] is True
        assert result["status"] == "HEALTHY"

    def test_health_check_detects_missing_profiles(self, tmp_path):
        a11.PROFILES_PATH = tmp_path / "missing.json"
        a11._profiles.clear()
        result = health_check()
        assert result["healthy"] is False

    def test_health_check_self_not_suspended(self, tmp_path):
        result = health_check()
        assert result["checks"]["self_not_suspended"] == "OK"

    def test_health_check_returns_required_keys(self, loaded_profiles):
        result = health_check()
        for key in ["healthy", "status", "checks"]:
            assert key in result


# ─── TestCheckBehavior ────────────────────────────────────────────────────────

class TestCheckBehavior:
    def test_compliant_call_returns_clean_report(self, loaded_profiles, tmp_path):
        a11.WATCHDOG_LOG_PATH = tmp_path / "watchdog_log.jsonl"
        ev = _make_evidence()
        report = check_behavior("A3", {"raw": True}, ev)
        assert report["compliant"] is True
        assert report["violations"] == []

    def test_type_mismatch_shows_in_violations(self, loaded_profiles, tmp_path):
        a11.WATCHDOG_LOG_PATH = tmp_path / "watchdog_log.jsonl"
        a11.SUSPENSIONS_PATH  = tmp_path / "suspensions.json"
        hyp = _make_hypothesis()
        report = check_behavior("A3", {"raw": True}, hyp)
        assert report["compliant"] is False
        assert any(v["violation_type"] == "output_type_mismatch" for v in report["violations"])

    def test_forbidden_action_shows_in_violations(self, loaded_profiles, tmp_path):
        a11.WATCHDOG_LOG_PATH = tmp_path / "watchdog_log.jsonl"
        a11.SUSPENSIONS_PATH  = tmp_path / "suspensions.json"
        hyp = _make_hypothesis()
        report = check_behavior("A6", {"raw": True}, hyp, action_called="execute_playbook")
        assert any(v["violation_type"] == "forbidden_action" for v in report["violations"])

    def test_forbidden_path_shows_in_violations(self, loaded_profiles, tmp_path):
        a11.WATCHDOG_LOG_PATH = tmp_path / "watchdog_log.jsonl"
        a11.SUSPENSIONS_PATH  = tmp_path / "suspensions.json"
        hyp = _make_hypothesis()
        report = check_behavior("A6", {}, hyp, paths_accessed=["/data/audit_log.jsonl"])
        assert any(v["violation_type"] == "forbidden_path_access" for v in report["violations"])

    def test_unknown_agent_is_compliant(self, tmp_path):
        report = check_behavior("A99", {}, {"result": True})
        assert report["compliant"] is True


# ─── TestPipelineWrapper ──────────────────────────────────────────────────────

class TestPipelineWrapper:
    def test_execute_with_watchdog_calls_func(self, loaded_profiles, tmp_path):
        a11.WATCHDOG_LOG_PATH = tmp_path / "watchdog_log.jsonl"
        a11.SUSPENSIONS_PATH  = tmp_path / "suspensions.json"
        a11.SUSPENDED_AGENTS.clear()  # ensure A3 is not suspended from prior test
        called = []
        ev = _make_evidence()

        def fake_process(inp):
            called.append(inp)
            return ev

        result = execute_with_watchdog("A3", fake_process, {"raw": True})
        assert called
        assert isinstance(result, Evidence)

    def test_execute_with_watchdog_skips_suspended(self, loaded_profiles, tmp_path):
        a11.SUSPENSIONS_PATH = tmp_path / "suspensions.json"
        suspend_agent("A6", "test suspension")
        called = []

        def fake_process(inp):
            called.append(inp)
            return _make_hypothesis()

        result = execute_with_watchdog("A6", fake_process, {"input": True})
        assert not called   # agent should be skipped
        assert result == {"input": True}   # input returned unchanged

    def test_watchdog_intercept_decorator(self, loaded_profiles, tmp_path):
        a11.WATCHDOG_LOG_PATH = tmp_path / "watchdog_log.jsonl"
        a11.SUSPENSIONS_PATH  = tmp_path / "suspensions.json"
        a11.SUSPENDED_AGENTS.clear()  # ensure A3 is not suspended from prior test
        ev = _make_evidence()

        @watchdog_intercept("A3")
        def fake_process(inp):
            return ev

        result = fake_process({"raw": True})
        assert isinstance(result, Evidence)

    def test_intercept_decorator_blocks_suspended(self, loaded_profiles, tmp_path):
        a11.SUSPENSIONS_PATH = tmp_path / "suspensions.json"
        suspend_agent("A6", "suspended")

        @watchdog_intercept("A6")
        def compromised_process(inp):
            return _make_decision()   # would be forbidden output

        result = compromised_process({"inp": True})
        assert result == {"inp": True}   # fallback: input returned


# ─── Run ─────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import pytest as _pytest
    _pytest.main([__file__, "-v"])
