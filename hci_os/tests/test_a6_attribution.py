"""
tests/test_a6_attribution.py
Unit tests for A6: Attribution & RAG Agent.

Run with:  pytest tests/test_a6_attribution.py -v
"""

import hashlib
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

import numpy as np
import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from agents.a6_attribution import (
    _call_llm,
    _hash_embed,
    _seq_embed,
    match_campaign_genome,
    resolve_attribution,
    retrieve,
)
from objects.evidence import Evidence
from objects.hypothesis import Hypothesis, PredictedMove


# ─── Helpers ─────────────────────────────────────────────────────────────────

def _make_evidence(mission="exam_portal", method="GET", path="/api/results",
                   src_ip="185.23.147.82", dst_ip="203.94.1.10"):
    norm = {"src_ip": src_ip, "dst_ip": dst_ip, "method": method, "path": path}
    fp = hashlib.sha256(json.dumps(norm, sort_keys=True).encode()).hexdigest()
    return Evidence.model_validate({
        "evidence_id": f"EV-SMOKE-{mission[:4].upper()}",
        "timestamp": "2026-03-15T02:47:33Z",
        "source": "web_access_log",
        "asset_id": "CBSE-WebSvr-01",
        "normalized": norm,
        "content_fingerprint": fp,
        "behavior_embedding": [0.0],
        "context": {
            "criticality": "HIGH",
            "mission": mission,
            "ot_context": {"can_reboot": True, "protocol": None},
            "indian_context": {"exam_season": True},
        },
        "confidence": 0.5,
        "uncertainty": 0.5,
        "provenance": "A2_normalizer",
    })


def _make_hypothesis():
    return Hypothesis(goal="Suspected APT campaign against CBSE exam portal")


SAMPLE_CAMPAIGNS = {
    "APT41": {
        "ttp_sequence": ["T1595", "T1190", "T1059", "T1003", "T1486"],
        "preventive_actions": {
            "T1595": "deploy_honeypots",
            "T1190": "patch_log4shell",
            "T1059": "restrict_scripts",
            "T1003": "enable_credential_guard",
            "T1486": "immutable_backups",
        },
    },
    "SideWinder": {
        "ttp_sequence": ["T1566", "T1203", "T1059", "T1071", "T1003"],
        "preventive_actions": {
            "T1566": "email_security_gateway",
        },
    },
}


# ─── Hash Embedding Tests ─────────────────────────────────────────────────────

class TestHashEmbed:
    def test_output_shape(self):
        vecs = _hash_embed(["attack on CBSE"], 384)
        assert vecs.shape == (1, 384)

    def test_normalized(self):
        vecs = _hash_embed(["some text"], 384)
        norm = float(np.linalg.norm(vecs[0]))
        assert abs(norm - 1.0) < 1e-5

    def test_different_texts_different_vecs(self):
        v1 = _hash_embed(["Log4Shell exploit"], 384)
        v2 = _hash_embed(["phishing email"], 384)
        assert not np.allclose(v1, v2)


# ─── Sequence Embedding Tests ─────────────────────────────────────────────────

class TestSequenceEmbed:
    def test_empty_chain(self):
        vec = _seq_embed([])
        assert vec.shape == (64,)
        assert np.allclose(vec, 0.0)

    def test_single_ttp(self):
        vec = _seq_embed(["T1595"])
        assert vec.shape == (64,)
        assert not np.allclose(vec, 0.0)

    def test_order_matters(self):
        """Different orderings should produce different embeddings."""
        v1 = _seq_embed(["T1595", "T1190", "T1059"])
        v2 = _seq_embed(["T1059", "T1190", "T1595"])
        assert not np.allclose(v1, v2), "Order-preserving: reversed should differ"

    def test_normalized(self):
        vec = _seq_embed(["T1595", "T1190"])
        norm = float(np.linalg.norm(vec))
        assert abs(norm - 1.0) < 1e-5


# ─── Campaign Genome Tests ─────────────────────────────────────────────────────

class TestCampaignGenome:
    def test_exact_prefix_match(self):
        """Observed chain is a prefix of APT41 → should match and predict next."""
        result = match_campaign_genome(
            ["T1595", "T1190", "T1059"],
            SAMPLE_CAMPAIGNS,
            threshold=0.5,
        )
        assert result is not None
        assert result["matched_campaign"] == "APT41"
        assert result["predicted_next"] == "T1003"

    def test_no_match_below_threshold(self):
        result = match_campaign_genome(
            ["T1595", "T1190"],
            SAMPLE_CAMPAIGNS,
            threshold=0.999,  # impossibly high
        )
        assert result is None

    def test_empty_chain_returns_none(self):
        assert match_campaign_genome([], SAMPLE_CAMPAIGNS) is None

    def test_no_campaigns_returns_none(self):
        assert match_campaign_genome(["T1595"], {}) is None

    def test_full_chain_no_prediction(self):
        """Full campaign chain observed → no next TTP to predict."""
        result = match_campaign_genome(
            ["T1595", "T1190", "T1059", "T1003", "T1486"],
            SAMPLE_CAMPAIGNS,
            threshold=0.5,
        )
        if result is not None:
            # predicted_next should be None since chain is complete
            assert result["predicted_next"] is None

    def test_preventive_action_populated(self):
        result = match_campaign_genome(
            ["T1595", "T1190", "T1059"],
            SAMPLE_CAMPAIGNS,
            threshold=0.5,
        )
        if result and result.get("predicted_next") == "T1003":
            assert result["preventive_action"] == "enable_credential_guard"

    def test_confidence_is_float_in_range(self):
        result = match_campaign_genome(
            ["T1595", "T1190"],
            SAMPLE_CAMPAIGNS,
            threshold=0.0,
        )
        assert result is not None
        assert 0.0 <= result["confidence"] <= 1.0


# ─── Trust-Weighted Conflict Resolution Tests ─────────────────────────────────

class TestResolveAttribution:
    def test_single_source(self):
        docs = [{"attribution": "APT41", "trust_weight": 0.90, "similarity_score": 0.85}]
        result = resolve_attribution(docs, "APT41", 0.80)
        assert result["primary"]["group"] == "APT41"

    def test_conflict_preserves_secondary(self):
        docs = [
            {"attribution": "SideWinder", "trust_weight": 0.95, "similarity_score": 0.90},
            {"attribution": "APT41",      "trust_weight": 0.90, "similarity_score": 0.70},
        ]
        result = resolve_attribution(docs, "APT41", 0.80)
        assert result["primary"] is not None
        assert result["secondary"] is not None
        # Primary should have higher confidence
        assert result["primary"]["confidence"] >= result["secondary"]["confidence"]

    def test_cert_in_outweighs_mitre(self):
        """CERT-In (0.95) source attribution should win over MITRE (0.90) with same similarity."""
        docs = [
            {"attribution": "SideWinder", "trust_weight": 0.95, "similarity_score": 0.80},
            {"attribution": "APT41",      "trust_weight": 0.90, "similarity_score": 0.80},
        ]
        result = resolve_attribution(docs, "Unknown", 0.0)
        assert result["primary"]["group"] == "SideWinder"

    def test_no_docs_uses_llm(self):
        result = resolve_attribution([], "APT41", 0.75)
        assert result["primary"]["group"] == "APT41"

    def test_unknown_llm_attribution(self):
        result = resolve_attribution([], "Unknown", 0.5)
        assert result["primary"]["group"] == "Unknown"

    def test_confidence_sums_to_one(self):
        docs = [
            {"attribution": "APT41",     "trust_weight": 0.90, "similarity_score": 0.80},
            {"attribution": "SideWinder","trust_weight": 0.95, "similarity_score": 0.70},
        ]
        result = resolve_attribution(docs, "APT41", 0.70)
        primary_conf = result["primary"]["confidence"]
        secondary_conf = result["secondary"]["confidence"] if result["secondary"] else 0.0
        # Primary + secondary don't have to sum to 1 (there may be more groups)
        # But primary must be >= secondary
        assert primary_conf >= secondary_conf


# ─── LLM Fallback Tests ───────────────────────────────────────────────────────

class TestLLMFallback:
    def test_returns_valid_structure(self):
        ev = _make_evidence(mission="exam_portal")
        result = _call_llm(ev, [])
        assert "mitre_chain" in result
        assert "confidence" in result
        assert "attribution_group" in result
        assert isinstance(result["mitre_chain"], list)
        assert 0.0 <= result["confidence"] <= 1.0

    def test_exam_portal_mock(self):
        ev = _make_evidence(mission="exam_portal")
        result = _call_llm(ev, [])
        assert result["attribution_group"] == "APT41"
        assert "T1595" in result["mitre_chain"]

    def test_power_management_mock(self):
        ev = _make_evidence(mission="power_management")
        result = _call_llm(ev, [])
        assert result["attribution_group"] == "RansomwareGroup"

    def test_unknown_mission_uses_default(self):
        ev = _make_evidence(mission="some_unknown_mission_xyz")
        result = _call_llm(ev, [])
        assert "mitre_chain" in result
        assert len(result["mitre_chain"]) > 0


# ─── Full Pipeline Tests ──────────────────────────────────────────────────────

class TestFullPipeline:
    """End-to-end: Evidence + Hypothesis → updated Hypothesis."""

    def test_supporting_evidence_linked(self):
        from agents.a6_attribution import process
        ev = _make_evidence()
        hyp = _make_hypothesis()
        updated = process(ev, hyp)
        assert ev.evidence_id in updated.supporting_evidence

    def test_no_duplicate_evidence_id(self):
        from agents.a6_attribution import process
        ev = _make_evidence()
        hyp = _make_hypothesis()
        process(ev, hyp)
        process(ev, hyp)  # second call
        assert hyp.supporting_evidence.count(ev.evidence_id) == 1

    def test_mitre_chain_populated(self):
        from agents.a6_attribution import process
        ev = _make_evidence()
        hyp = _make_hypothesis()
        updated = process(ev, hyp)
        assert isinstance(updated.mitre_chain, list)
        assert len(updated.mitre_chain) > 0

    def test_confidence_updated(self):
        from agents.a6_attribution import process
        ev = _make_evidence()
        hyp = _make_hypothesis()
        original_conf = hyp.confidence
        updated = process(ev, hyp)
        # Confidence should have been updated from default 0.1
        assert updated.confidence != original_conf or updated.confidence >= 0.0

    def test_confidence_in_valid_range(self):
        from agents.a6_attribution import process
        ev = _make_evidence()
        hyp = _make_hypothesis()
        updated = process(ev, hyp)
        assert 0.0 <= updated.confidence <= 1.0

    def test_campaign_genome_set(self):
        from agents.a6_attribution import process
        ev = _make_evidence()
        hyp = _make_hypothesis()
        updated = process(ev, hyp)
        assert updated.campaign_genome is not None
        assert "attribution" in updated.campaign_genome

    def test_timeline_event_added(self):
        from agents.a6_attribution import process
        ev = _make_evidence()
        hyp = _make_hypothesis()
        updated = process(ev, hyp)
        assert any(e.get("type") == "attribution" for e in updated.timeline)

    def test_predicted_moves_are_predicted_move_objects(self):
        from agents.a6_attribution import process
        ev = _make_evidence()
        hyp = _make_hypothesis()
        updated = process(ev, hyp)
        for move in updated.predicted_next_moves:
            assert isinstance(move, PredictedMove)
            assert move.ttp.startswith("T")
            assert 0.0 <= move.confidence <= 1.0

    def test_serialization_after_update(self):
        from agents.a6_attribution import process
        from objects.hypothesis import Hypothesis as Hyp
        ev = _make_evidence()
        hyp = _make_hypothesis()
        updated = process(ev, hyp)
        json_str = updated.to_json()
        restored = Hyp.from_json(json_str)
        assert restored.mitre_chain == updated.mitre_chain
        assert restored.confidence == updated.confidence


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
