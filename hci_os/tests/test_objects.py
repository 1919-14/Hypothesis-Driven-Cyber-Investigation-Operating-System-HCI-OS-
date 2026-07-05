"""
tests/test_objects.py
Unit tests for the three core objects.
Run with: pytest tests/test_objects.py -v
"""

import pytest
import json
import math
from datetime import datetime, timedelta
from objects.evidence import Evidence
from objects.hypothesis import Hypothesis, CompetingHypothesis, PredictedMove, WorldModel
from objects.decision import Decision

# ─── EVIDENCE TESTS ──────────────────────────────────────────────────────

def test_evidence_creation():
    """Test that a valid Evidence object can be created."""
    ev = Evidence(
        evidence_id="EV-2026-004471",
        timestamp=datetime.now(),
        source="web_access_log",
        asset_id="CBSE-WebSvr-01",
        normalized={"src_ip": "185.23.147.82", "path": "/api/users", "method": "GET"},
        content_fingerprint="9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
        confidence=0.97,
        uncertainty=0.04
    )
    assert ev.evidence_id == "EV-2026-004471"
    assert 0.0 <= ev.confidence <= 1.0

def test_evidence_validation_fails_on_bad_hash():
    """Test that an invalid SHA-256 hash raises validation error."""
    with pytest.raises(ValueError):
        Evidence(
            evidence_id="EV-2026-004471",
            timestamp=datetime.now(),
            source="web_access_log",
            asset_id="CBSE-WebSvr-01",
            normalized={},
            content_fingerprint="not_a_hex_string"
        )

def test_evidence_serialization():
    """Test to_json and from_json round-trip."""
    original = Evidence(
        evidence_id="EV-2026-004471",
        timestamp=datetime.now(),
        source="web_access_log",
        asset_id="CBSE-WebSvr-01",
        normalized={"src_ip": "185.23.147.82"},
        content_fingerprint="9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
        confidence=0.97
    )
    json_str = original.to_json()
    restored = Evidence.from_json(json_str)
    assert restored.evidence_id == original.evidence_id
    assert restored.confidence == original.confidence

# ─── HYPOTHESIS TESTS ──────────────────────────────────────────────────

def test_hypothesis_creation():
    """Test that a valid Hypothesis object can be created."""
    hyp = Hypothesis(
        goal="Remote Code Execution via Log4Shell",
        state="ACTIVE_INVESTIGATION",
        supporting_evidence=["EV-004471"],
        confidence=0.91,
        uncertainty=0.05,
        competing_hypotheses=[
            CompetingHypothesis(goal="False positive", confidence=0.06)
        ],
        world_model=WorldModel(
            industry="education",
            mission="Examination Records",
            criticality="HIGH",
            safety_constraints={"can_reboot": True, "auto_isolate_allowed": True}
        )
    )
    assert hyp.goal == "Remote Code Execution via Log4Shell"
    assert hyp.confidence == 0.91
    assert hyp.state == "ACTIVE_INVESTIGATION"

def test_hypothesis_confidence_decay():
    """Test confidence_decay() method (R3 #59)."""
    hyp = Hypothesis(
        goal="Test",
        confidence=0.91,
        confidence_decay_rate=0.02
    )
    # After 4 hours
    decayed = hyp.confidence_decay(4.0)
    expected = 0.91 * math.exp(-0.02 * 4)
    assert abs(decayed - expected) < 0.001
    # After 0 hours (no decay)
    decayed = hyp.confidence_decay(0.0)
    assert decayed == 0.91
    # After a very long time (approaches 0)
    decayed = hyp.confidence_decay(1000.0)
    assert decayed < 0.01

def test_hypothesis_primary_hypothesis():
    """Test get_primary_hypothesis() with competing hypotheses."""
    hyp = Hypothesis(
        goal="APT41",
        confidence=0.91,
        competing_hypotheses=[
            CompetingHypothesis(goal="Admin", confidence=0.06),
            CompetingHypothesis(goal="Backup", confidence=0.02)
        ]
    )
    assert hyp.get_primary_hypothesis() == "APT41"
    
    # Add a competing hypothesis with higher confidence
    hyp.competing_hypotheses.append(
        CompetingHypothesis(goal="RedTeam", confidence=0.95)
    )
    assert hyp.get_primary_hypothesis() == "RedTeam"

def test_hypothesis_add_timeline_event():
    """Test timeline event addition."""
    hyp = Hypothesis(goal="Test")
    hyp.add_timeline_event("03:14:22", "HTTP request to /cgi-bin/", "observation")
    assert len(hyp.timeline) == 1
    assert hyp.timeline[0]["event"] == "HTTP request to /cgi-bin/"
    assert hyp.timeline[0]["type"] == "observation"

def test_hypothesis_serialization():
    """Test to_json and from_json round-trip for Hypothesis."""
    original = Hypothesis(
        goal="Test Attack",
        confidence=0.91,
        competing_hypotheses=[
            CompetingHypothesis(goal="False positive", confidence=0.06)
        ]
    )
    json_str = original.to_json()
    restored = Hypothesis.from_json(json_str)
    assert restored.goal == original.goal
    assert restored.confidence == original.confidence

# ─── DECISION TESTS ────────────────────────────────────────────────────

def test_decision_creation():
    """Test that a valid Decision object can be created."""
    dec = Decision(
        decision_id="DEC-2026-000812",
        hypothesis_id="H-2026-0031",
        action_taken="BLOCK_IP + ISOLATE_ENDPOINT",
        risk_score=0.826,
        blast_radius_score=0.73
    )
    assert dec.decision_id == "DEC-2026-000812"
    assert dec.human_reviewed is False
    assert dec.version == 1

def test_decision_hash_compute():
    """Test that compute_hash() returns a 64-char hex string."""
    dec = Decision(
        decision_id="DEC-2026-000812",
        hypothesis_id="H-2026-0031",
        action_taken="BLOCK_IP",
        risk_score=0.826,
        blast_radius_score=0.73
    )
    hash_val = dec.compute_hash()
    assert len(hash_val) == 64
    assert all(c in "0123456789abcdef" for c in hash_val)

def test_decision_chain():
    """Test that chaining decisions works."""
    dec1 = Decision(
        decision_id="DEC-2026-000811",
        hypothesis_id="H-2026-0030",
        action_taken="MONITOR",
        risk_score=0.3,
        blast_radius_score=0.1
    )
    dec2 = Decision(
        decision_id="DEC-2026-000812",
        hypothesis_id="H-2026-0031",
        action_taken="BLOCK_IP",
        risk_score=0.826,
        blast_radius_score=0.73
    )
    # Chain dec2 to dec1
    chained_dec2 = dec2.chain(previous_decision=dec1)
    assert chained_dec2.audit_chain_prev == dec1.compute_hash()
    
    # Chain a new decision without previous (genesis)
    genesis = dec1.chain(previous_decision=None)
    assert genesis.audit_chain_prev is None

def test_decision_correction():
    """Test that a correction creates a versioned decision."""
    dec = Decision(
        decision_id="DEC-2026-000812",
        hypothesis_id="H-2026-0031",
        action_taken="BLOCK_IP + ISOLATE_ENDPOINT",
        risk_score=0.826,
        blast_radius_score=0.73
    )
    correction = dec.create_correction(
        new_action="ALLOW (False Positive)",
        reviewer_id="OFF-KUMAR-03"
    )
    assert correction.decision_id == "DEC-2026-000812-CORR"
    assert correction.action_taken == "ALLOW (False Positive)"
    assert correction.human_reviewed is True
    assert correction.reviewer_id == "OFF-KUMAR-03"
    assert correction.version == 2
    assert correction.supersedes_decision_id == "DEC-2026-000812"

def test_decision_serialization():
    """Test to_json and from_json round-trip for Decision."""
    original = Decision(
        decision_id="DEC-2026-000812",
        hypothesis_id="H-2026-0031",
        action_taken="BLOCK_IP",
        risk_score=0.826,
        blast_radius_score=0.73
    )
    json_str = original.to_json()
    restored = Decision.from_json(json_str)
    assert restored.decision_id == original.decision_id
    assert restored.action_taken == original.action_taken

# ─── RUN ALL TESTS ────────────────────────────────────────────────────

if __name__ == "__main__":
    pytest.main([__file__, "-v"])
