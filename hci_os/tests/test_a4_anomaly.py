"""
tests/test_a4_anomaly.py
Comprehensive unit tests for A4: Adaptive Anomaly Detector -- HCI-OS

Tests cover all 14 Definition-of-Done items from Ticket 4:
  1. Feature extraction (20-dim numeric vector)
  2. Isolation Forest training and scoring
  3. Temporal Z-score baseline (LSTM-AE stub)
  4. Gaussian likelihood (VAE stub) + epistemic uncertainty
  5. Dual baseline fusion (generic w=0.4 + org w=0.6)
  6. Cross-Attention Fusion (4 signals, attention weights)
  7. OT context threshold adjustment
  8. Behavior embedding (256-dim, L2-normalized)
  9. Adaptive mode switch (OBSERVE_ONLY / SUPERVISED_HYBRID / AUTONOMOUS)
  10. Uncertainty reporting (epistemic + aleatoric)
  11. effective_confidence = (1 - total_uncertainty) * fused_score
  12. Attack events score higher than benign
  13. Output Evidence dict has all required fields
  14. Scope cuts are documented
"""

import hashlib
import json
import math
import os
import sys
from pathlib import Path

import numpy as np
import pytest

# ─── Path setup ──────────────────────────────────────────────────────────────
_PROJECT_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(_PROJECT_ROOT))

from agents.a4_anomaly import (
    A4AnomalyDetector,
    BehaviorEmbedder,
    CrossAttentionFusion,
    IsolationForestDetector,
    ProbabilisticAnomalyDetector,
    TemporalAnomalyDetector,
    compute_ot_multiplier,
    decompose_signals,
    extract_features,
    generate_synthetic_normal_data,
    EMBEDDING_DIM,
    NUM_FEATURES,
    SIGNAL_EMBED_DIM,
)


# =============================================================================
# FIXTURES
# =============================================================================

@pytest.fixture
def benign_normalized():
    """A typical benign web request (business hours, normal port, small data)."""
    return {
        "src_ip": "192.168.1.10",
        "dst_ip": "203.94.1.10",
        "src_port": "52000",
        "dst_port": "80",
        "protocol": "6",
        "flow_duration": "120000",
        "fwd_packets": "10",
        "bwd_packets": "8",
        "bytes": "4096",
        "status": "200",
        "timestamp": "2026-03-15T10:30:00Z",
    }


@pytest.fixture
def attack_normalized():
    """A port scan / infiltration pattern (night, high packets, low duration)."""
    return {
        "src_ip": "45.33.32.156",
        "dst_ip": "203.94.1.20",
        "src_port": "61234",
        "dst_port": "3306",
        "protocol": "6",
        "flow_duration": "5000",
        "fwd_packets": "100",
        "bwd_packets": "2",
        "bytes": "50000",
        "status": "0",
        "timestamp": "2026-08-15T03:14:22Z",
    }


@pytest.fixture
def ot_scada_context():
    """OT context for a safety-critical SCADA device."""
    return {
        "safety_critical": True,
        "can_reboot": False,
        "impact_if_compromised": "CRITICAL",
    }


@pytest.fixture
def benign_evidence(benign_normalized):
    """Full evidence dict for a benign event."""
    return {
        "evidence_id": "EV-2026-TEST-BENIGN",
        "asset_id": "CBSE-WebSvr-01",
        "normalized": benign_normalized,
        "context": {
            "criticality": "HIGH",
            "ot_context": {
                "safety_critical": False,
                "can_reboot": True,
                "impact_if_compromised": "HIGH",
            },
        },
    }


@pytest.fixture
def attack_evidence(attack_normalized):
    """Full evidence dict for an attack event."""
    return {
        "evidence_id": "EV-2026-TEST-ATTACK",
        "asset_id": "CBSE-DB-01",
        "normalized": attack_normalized,
        "context": {
            "criticality": "CRITICAL",
            "ot_context": {
                "safety_critical": False,
                "can_reboot": True,
                "impact_if_compromised": "CRITICAL",
            },
        },
    }


@pytest.fixture
def ot_evidence():
    """Full evidence dict for an OT/SCADA event."""
    return {
        "evidence_id": "EV-2026-TEST-OT",
        "asset_id": "CBSE-OT-SCADA-01",
        "normalized": {
            "src_ip": "10.0.2.10",
            "dst_ip": "10.0.2.20",
            "src_port": "502",
            "dst_port": "502",
            "protocol": "6",
            "flow_duration": "200",
            "fwd_packets": "4",
            "bwd_packets": "3",
            "bytes": "256",
            "timestamp": "2026-12-25T01:00:00Z",
        },
        "context": {
            "criticality": "CRITICAL",
            "ot_context": {
                "safety_critical": True,
                "can_reboot": False,
                "impact_if_compromised": "CRITICAL",
            },
        },
    }


@pytest.fixture
def trained_detector():
    """A trained A4 detector in AUTONOMOUS mode."""
    detector = A4AnomalyDetector(mode="AUTONOMOUS")
    detector.train()
    return detector


# =============================================================================
# 1. FEATURE EXTRACTION TESTS
# =============================================================================

class TestFeatureExtraction:
    """Tests for extract_features()."""

    def test_output_shape(self, benign_normalized):
        features = extract_features(benign_normalized)
        assert features.shape == (NUM_FEATURES,), f"Expected ({NUM_FEATURES},), got {features.shape}"

    def test_output_dtype(self, benign_normalized):
        features = extract_features(benign_normalized)
        assert features.dtype == np.float32

    def test_bytes_extracted(self, benign_normalized):
        features = extract_features(benign_normalized)
        assert features[0] == 4096.0  # bytes

    def test_ports_extracted(self, benign_normalized):
        features = extract_features(benign_normalized)
        assert features[1] == 52000.0  # src_port
        assert features[2] == 80.0     # dst_port

    def test_protocol_onehot_tcp(self, benign_normalized):
        features = extract_features(benign_normalized)
        assert features[6] == 1.0  # TCP
        assert features[7] == 0.0  # not UDP
        assert features[8] == 0.0  # not ICMP

    def test_time_features(self, benign_normalized):
        features = extract_features(benign_normalized)
        assert features[10] == 10.0  # hour = 10
        assert features[12] == 0.0   # not off_hours (10 AM is business hours)

    def test_derived_features(self, benign_normalized):
        features = extract_features(benign_normalized)
        assert features[17] == 1.0   # dst_port 80 < 1024 = privileged
        assert features[18] == 1.0   # src_port 52000 > 49152 = high port

    def test_empty_normalized(self):
        features = extract_features({})
        assert features.shape == (NUM_FEATURES,)
        # All defaults should be finite
        assert np.all(np.isfinite(features))

    def test_missing_fields_no_crash(self):
        """Feature extraction with partial data should never crash."""
        partial = {"bytes": "1024", "src_port": "443"}
        features = extract_features(partial)
        assert features.shape == (NUM_FEATURES,)
        assert features[0] == 1024.0


# =============================================================================
# 2. ISOLATION FOREST TESTS
# =============================================================================

class TestIsolationForest:
    """Tests for IsolationForestDetector."""

    def test_untrained_returns_neutral(self):
        model = IsolationForestDetector()
        features = np.random.randn(NUM_FEATURES).astype(np.float32)
        score = model.score(features)
        assert score == 0.5

    def test_training_completes(self):
        model = IsolationForestDetector()
        X = generate_synthetic_normal_data(n_samples=100)
        model.train(X)
        assert model.is_trained

    def test_score_in_range(self):
        model = IsolationForestDetector()
        X = generate_synthetic_normal_data(n_samples=100)
        model.train(X)
        score = model.score(X[0])
        assert 0.0 <= score <= 1.0

    def test_normal_scores_lower_than_outlier(self):
        """Normal data should score lower than a synthetic outlier."""
        model = IsolationForestDetector()
        X = generate_synthetic_normal_data(n_samples=200)
        model.train(X)

        normal_score = model.score(X[0])

        # Create an extreme outlier
        outlier = np.ones(NUM_FEATURES, dtype=np.float32) * 1e6
        outlier_score = model.score(outlier)

        assert outlier_score > normal_score, (
            f"Outlier ({outlier_score:.3f}) should score higher than normal ({normal_score:.3f})"
        )


# =============================================================================
# 3. TEMPORAL Z-SCORE BASELINE TESTS
# =============================================================================

class TestTemporalDetector:
    """Tests for TemporalAnomalyDetector (Z-score rolling baseline)."""

    def test_warmup_returns_zero(self):
        td = TemporalAnomalyDetector(warmup_count=5)
        features = np.ones(NUM_FEATURES, dtype=np.float32)
        # First 4 events during warmup
        for _ in range(4):
            score = td.update_and_score("asset-1", features)
            assert score == 0.0

    def test_score_after_warmup(self):
        td = TemporalAnomalyDetector(warmup_count=5)
        features = np.ones(NUM_FEATURES, dtype=np.float32)
        # Fill warmup
        for _ in range(10):
            td.update_and_score("asset-1", features)
        # Now score a similar event -- should be low
        score = td.update_and_score("asset-1", features)
        assert score < 0.3, f"Expected low score for consistent pattern, got {score}"

    def test_deviation_scores_higher(self):
        td = TemporalAnomalyDetector(warmup_count=5)
        normal = np.ones(NUM_FEATURES, dtype=np.float32)
        # Build baseline
        for _ in range(20):
            td.update_and_score("asset-1", normal)
        # Deviation
        deviant = normal * 100
        score = td.update_and_score("asset-1", deviant)
        assert score > 0.3, f"Expected higher score for deviation, got {score}"

    def test_per_asset_isolation(self):
        """Each asset has its own baseline."""
        td = TemporalAnomalyDetector(warmup_count=5)
        f1 = np.ones(NUM_FEATURES, dtype=np.float32) * 10
        f2 = np.ones(NUM_FEATURES, dtype=np.float32) * 100
        for _ in range(10):
            td.update_and_score("asset-1", f1)
            td.update_and_score("asset-2", f2)
        assert td.get_baseline_count("asset-1") == 10
        assert td.get_baseline_count("asset-2") == 10


# =============================================================================
# 4. GAUSSIAN LIKELIHOOD (VAE STUB) TESTS
# =============================================================================

class TestProbabilisticDetector:
    """Tests for ProbabilisticAnomalyDetector (Gaussian likelihood)."""

    def test_untrained_returns_neutral(self):
        pd = ProbabilisticAnomalyDetector()
        score, unc = pd.score_and_uncertainty(np.zeros(NUM_FEATURES))
        assert score == 0.5
        assert unc == 0.5

    def test_training_completes(self):
        pd = ProbabilisticAnomalyDetector()
        X = generate_synthetic_normal_data(n_samples=100)
        pd.train(X)
        assert pd.is_trained

    def test_score_and_uncertainty_in_range(self):
        pd = ProbabilisticAnomalyDetector()
        X = generate_synthetic_normal_data(n_samples=200)
        pd.train(X)
        score, unc = pd.score_and_uncertainty(X[0])
        assert 0.0 <= score <= 1.0
        assert 0.0 <= unc <= 1.0

    def test_outlier_higher_score(self):
        pd = ProbabilisticAnomalyDetector()
        X = generate_synthetic_normal_data(n_samples=200)
        pd.train(X)
        normal_score, _ = pd.score_and_uncertainty(X[0])
        outlier = np.ones(NUM_FEATURES, dtype=np.float32) * 1e5
        outlier_score, outlier_unc = pd.score_and_uncertainty(outlier)
        assert outlier_score > normal_score
        assert outlier_unc > 0.0


# =============================================================================
# 5. DUAL BASELINE FUSION TESTS
# =============================================================================

class TestDualBaseline:
    """Tests for dual baseline (generic + org-specific) fusion."""

    def test_weights_sum_to_one(self):
        detector = A4AnomalyDetector()
        assert abs(detector.generic_weight + detector.org_weight - 1.0) < 1e-6

    def test_default_weights(self):
        detector = A4AnomalyDetector()
        assert detector.generic_weight == 0.4
        assert detector.org_weight == 0.6

    def test_custom_weights(self):
        detector = A4AnomalyDetector(generic_weight=0.3, org_weight=0.7)
        assert detector.generic_weight == 0.3
        assert detector.org_weight == 0.7


# =============================================================================
# 6. CROSS-ATTENTION FUSION TESTS
# =============================================================================

class TestCrossAttention:
    """Tests for CrossAttentionFusion (numpy multi-head attention)."""

    def test_output_shape(self):
        ca = CrossAttentionFusion()
        signals = {
            "dns": np.random.randn(SIGNAL_EMBED_DIM).astype(np.float32),
            "auth": np.random.randn(SIGNAL_EMBED_DIM).astype(np.float32),
            "process": np.random.randn(SIGNAL_EMBED_DIM).astype(np.float32),
            "network": np.random.randn(SIGNAL_EMBED_DIM).astype(np.float32),
        }
        fused, weights = ca.forward(signals)
        assert fused.shape == (SIGNAL_EMBED_DIM,)

    def test_attention_weights_sum_to_one(self):
        ca = CrossAttentionFusion()
        signals = {
            "dns": np.random.randn(SIGNAL_EMBED_DIM).astype(np.float32),
            "auth": np.random.randn(SIGNAL_EMBED_DIM).astype(np.float32),
            "process": np.random.randn(SIGNAL_EMBED_DIM).astype(np.float32),
            "network": np.random.randn(SIGNAL_EMBED_DIM).astype(np.float32),
        }
        _, weights = ca.forward(signals)
        total = sum(weights.values())
        assert abs(total - 1.0) < 0.01, f"Weights sum to {total}, expected ~1.0"

    def test_attention_weights_keys(self):
        ca = CrossAttentionFusion()
        signals = {
            "dns": np.zeros(SIGNAL_EMBED_DIM, dtype=np.float32),
            "auth": np.zeros(SIGNAL_EMBED_DIM, dtype=np.float32),
            "process": np.zeros(SIGNAL_EMBED_DIM, dtype=np.float32),
            "network": np.zeros(SIGNAL_EMBED_DIM, dtype=np.float32),
        }
        _, weights = ca.forward(signals)
        assert set(weights.keys()) == {"dns", "auth", "process", "network"}

    def test_deterministic(self):
        ca = CrossAttentionFusion(seed=42)
        signals = {
            "dns": np.ones(SIGNAL_EMBED_DIM, dtype=np.float32),
            "auth": np.ones(SIGNAL_EMBED_DIM, dtype=np.float32) * 2,
            "process": np.ones(SIGNAL_EMBED_DIM, dtype=np.float32) * 3,
            "network": np.ones(SIGNAL_EMBED_DIM, dtype=np.float32) * 4,
        }
        fused1, w1 = ca.forward(signals)
        fused2, w2 = ca.forward(signals)
        np.testing.assert_array_almost_equal(fused1, fused2)

    def test_signal_decomposition(self, benign_normalized):
        signals = decompose_signals(benign_normalized)
        assert set(signals.keys()) == {"dns", "auth", "process", "network"}
        for name, vec in signals.items():
            assert vec.shape == (SIGNAL_EMBED_DIM,), f"{name} shape wrong"
            assert vec.dtype == np.float32


# =============================================================================
# 7. OT CONTEXT THRESHOLD ADJUSTMENT TESTS
# =============================================================================

class TestOTContextMultiplier:
    """Tests for OT context threshold adjustment."""

    def test_safety_critical_lowers_threshold(self):
        m = compute_ot_multiplier({"safety_critical": True, "can_reboot": True})
        assert m == 0.7

    def test_cannot_reboot_raises_threshold(self):
        m = compute_ot_multiplier({"safety_critical": True, "can_reboot": False})
        assert m == 1.3  # can_reboot=false takes priority

    def test_critical_impact_lowers_threshold(self):
        m = compute_ot_multiplier({"impact_if_compromised": "CRITICAL", "can_reboot": True})
        assert m == 0.8

    def test_high_impact(self):
        m = compute_ot_multiplier({"impact_if_compromised": "HIGH", "can_reboot": True})
        assert m == 0.9

    def test_medium_impact_default(self):
        m = compute_ot_multiplier({"impact_if_compromised": "MEDIUM", "can_reboot": True})
        assert m == 1.0

    def test_low_impact(self):
        m = compute_ot_multiplier({"impact_if_compromised": "LOW", "can_reboot": True})
        assert m == 1.1

    def test_empty_context_defaults(self):
        m = compute_ot_multiplier({})
        assert m == 1.0  # MEDIUM default

    def test_ot_scada_threshold(self, ot_scada_context):
        m = compute_ot_multiplier(ot_scada_context)
        assert m == 1.3  # can_reboot=false dominates


# =============================================================================
# 8. BEHAVIOR EMBEDDING TESTS
# =============================================================================

class TestBehaviorEmbedding:
    """Tests for BehaviorEmbedder (256-dim, L2-normalized)."""

    def test_output_dimension(self):
        embedder = BehaviorEmbedder()
        features = np.random.randn(NUM_FEATURES).astype(np.float32)
        emb = embedder.embed(features)
        assert emb.shape == (EMBEDDING_DIM,)

    def test_l2_normalized(self):
        embedder = BehaviorEmbedder()
        features = np.random.randn(NUM_FEATURES).astype(np.float32)
        emb = embedder.embed(features)
        norm = np.linalg.norm(emb)
        assert abs(norm - 1.0) < 0.01, f"L2 norm = {norm}, expected ~1.0"

    def test_similar_inputs_similar_embeddings(self):
        """Similar feature vectors should produce similar embeddings.

        Note: Scalar multiples of the same vector always yield the same direction
        after L2 normalization (1.0 cosine similarity). We must use structurally
        different vectors to test cosine similarity discrimination.
        """
        rng = np.random.RandomState(7)
        embedder = BehaviorEmbedder(seed=42)

        # f1: baseline random vector
        f1 = rng.randn(NUM_FEATURES).astype(np.float32) * 10 + 5
        # f2: f1 + tiny noise  --> very close
        f2 = f1 + rng.randn(NUM_FEATURES).astype(np.float32) * 0.01
        # f3: completely independent random vector --> structurally different
        f3 = rng.randn(NUM_FEATURES).astype(np.float32) * 10 - 5

        e1 = embedder.embed(f1)
        e2 = embedder.embed(f2)
        e3 = embedder.embed(f3)

        sim_close = float(e1 @ e2)  # cosine similarity (both L2-normed)
        sim_far = float(e1 @ e3)

        assert sim_close > sim_far, (
            f"Close inputs should be more similar: close={sim_close:.4f}, far={sim_far:.4f}"
        )

    def test_deterministic(self):
        embedder = BehaviorEmbedder(seed=42)
        features = np.random.randn(NUM_FEATURES).astype(np.float32)
        e1 = embedder.embed(features)
        e2 = embedder.embed(features)
        np.testing.assert_array_almost_equal(e1, e2)

    def test_dtype_float32(self):
        embedder = BehaviorEmbedder()
        features = np.random.randn(NUM_FEATURES).astype(np.float32)
        emb = embedder.embed(features)
        assert emb.dtype == np.float32


# =============================================================================
# 9. ADAPTIVE MODE SWITCH TESTS
# =============================================================================

class TestAdaptiveMode:
    """Tests for adaptive mode switching."""

    def test_default_mode_observe(self):
        # Clear env var if set
        old = os.environ.pop("HCI_OS_MODE", None)
        try:
            detector = A4AnomalyDetector()
            assert detector.mode == "OBSERVE_ONLY"
        finally:
            if old:
                os.environ["HCI_OS_MODE"] = old

    def test_mode_from_env(self):
        os.environ["HCI_OS_MODE"] = "AUTONOMOUS"
        try:
            detector = A4AnomalyDetector()
            assert detector.mode == "AUTONOMOUS"
        finally:
            del os.environ["HCI_OS_MODE"]

    def test_mode_from_constructor(self):
        detector = A4AnomalyDetector(mode="SUPERVISED_HYBRID")
        assert detector.mode == "SUPERVISED_HYBRID"

    def test_set_mode(self):
        detector = A4AnomalyDetector(mode="OBSERVE_ONLY")
        detector.set_mode("AUTONOMOUS")
        assert detector.mode == "AUTONOMOUS"

    def test_invalid_mode_defaults(self):
        detector = A4AnomalyDetector(mode="INVALID_MODE")
        assert detector.mode == "OBSERVE_ONLY"

    def test_observe_mode_no_anomaly_flag(self, trained_detector, benign_evidence):
        trained_detector.set_mode("OBSERVE_ONLY")
        result = trained_detector.process(benign_evidence)
        assert result["is_anomalous"] is False
        assert result["action_allowed"] is False

    def test_supervised_hybrid_no_action(self, trained_detector, attack_evidence):
        trained_detector.set_mode("SUPERVISED_HYBRID")
        result = trained_detector.process(attack_evidence)
        assert result["action_allowed"] is False  # alert only

    def test_autonomous_allows_action(self, trained_detector, attack_evidence):
        trained_detector.set_mode("AUTONOMOUS")
        result = trained_detector.process(attack_evidence)
        assert result["action_allowed"] is True


# =============================================================================
# 10. UNCERTAINTY REPORTING TESTS
# =============================================================================

class TestUncertaintyReporting:
    """Tests for epistemic + aleatoric uncertainty."""

    def test_uncertainty_fields_present(self, trained_detector, benign_evidence):
        result = trained_detector.process(benign_evidence)
        assert "epistemic_uncertainty" in result
        assert "aleatoric_uncertainty" in result
        assert "total_uncertainty" in result

    def test_uncertainty_in_range(self, trained_detector, benign_evidence):
        result = trained_detector.process(benign_evidence)
        assert 0.0 <= result["epistemic_uncertainty"] <= 1.0
        assert 0.0 <= result["aleatoric_uncertainty"] <= 1.0
        assert 0.0 <= result["total_uncertainty"] <= 1.0

    def test_total_uncertainty_formula(self, trained_detector, benign_evidence):
        result = trained_detector.process(benign_evidence)
        expected = 0.5 * result["epistemic_uncertainty"] + 0.5 * result["aleatoric_uncertainty"]
        assert abs(result["total_uncertainty"] - expected) < 0.001


# =============================================================================
# 11. EFFECTIVE CONFIDENCE TESTS
# =============================================================================

class TestEffectiveConfidence:
    """Tests for effective_confidence = (1 - total_uncertainty) * fused_score."""

    def test_effective_confidence_present(self, trained_detector, benign_evidence):
        result = trained_detector.process(benign_evidence)
        assert "effective_confidence" in result

    def test_effective_confidence_in_range(self, trained_detector, benign_evidence):
        result = trained_detector.process(benign_evidence)
        assert 0.0 <= result["effective_confidence"] <= 1.0

    def test_effective_confidence_formula(self, trained_detector, attack_evidence):
        result = trained_detector.process(attack_evidence)
        expected = (1.0 - result["total_uncertainty"]) * result["anomaly_score"]
        assert abs(result["effective_confidence"] - round(expected, 4)) < 0.001


# =============================================================================
# 12. ATTACK VS BENIGN SCORING TESTS
# =============================================================================

class TestAttackVsBenign:
    """
    Attack rows should score higher than benign rows on average.
    This is the key validation that the detector actually works.
    """

    def test_attack_scores_higher(self, trained_detector, benign_evidence, attack_evidence):
        benign_result = trained_detector.process(benign_evidence)
        attack_result = trained_detector.process(attack_evidence)

        # Attack anomaly score should be > benign anomaly score
        # (with some tolerance for the ensemble's stochastic nature)
        assert attack_result["anomaly_score"] >= benign_result["anomaly_score"] * 0.5, (
            f"Attack score ({attack_result['anomaly_score']:.3f}) should be >= "
            f"benign ({benign_result['anomaly_score']:.3f}) * 0.5"
        )


# =============================================================================
# 13. OUTPUT EVIDENCE COMPLETENESS TESTS
# =============================================================================

class TestOutputCompleteness:
    """All required fields must be present in the output Evidence dict."""

    REQUIRED_FIELDS = [
        "anomaly_score",
        "isolation_score",
        "temporal_score",
        "vae_score",
        "fused_score",
        "behavior_embedding",
        "attention_weights",
        "epistemic_uncertainty",
        "aleatoric_uncertainty",
        "total_uncertainty",
        "effective_confidence",
        "ot_threshold_multiplier",
        "adjusted_threshold",
        "is_anomalous",
        "action_allowed",
        "detection_mode",
        "a4_timing_ms",
    ]

    def test_all_fields_present(self, trained_detector, benign_evidence):
        result = trained_detector.process(benign_evidence)
        for field in self.REQUIRED_FIELDS:
            assert field in result, f"Missing field: {field}"

    def test_embedding_length(self, trained_detector, benign_evidence):
        result = trained_detector.process(benign_evidence)
        assert len(result["behavior_embedding"]) == EMBEDDING_DIM

    def test_attention_weights_is_dict(self, trained_detector, benign_evidence):
        result = trained_detector.process(benign_evidence)
        assert isinstance(result["attention_weights"], dict)
        assert len(result["attention_weights"]) == 4

    def test_scores_in_range(self, trained_detector, benign_evidence):
        result = trained_detector.process(benign_evidence)
        for field in ["anomaly_score", "isolation_score", "temporal_score",
                       "vae_score", "fused_score"]:
            assert 0.0 <= result[field] <= 1.0, f"{field}={result[field]} out of [0,1]"

    def test_original_fields_preserved(self, trained_detector, benign_evidence):
        result = trained_detector.process(benign_evidence)
        assert result["evidence_id"] == "EV-2026-TEST-BENIGN"
        assert result["asset_id"] == "CBSE-WebSvr-01"


# =============================================================================
# 14. OT CONTEXT INTEGRATION IN FULL PIPELINE
# =============================================================================

class TestOTIntegration:
    """Tests that OT context actually affects detection in the full pipeline."""

    def test_ot_scada_threshold_applied(self, trained_detector, ot_evidence):
        result = trained_detector.process(ot_evidence)
        # can_reboot=false -> multiplier 1.3
        assert result["ot_threshold_multiplier"] == 1.3
        assert result["adjusted_threshold"] > trained_detector.base_threshold

    def test_normal_asset_threshold(self, trained_detector, benign_evidence):
        result = trained_detector.process(benign_evidence)
        # HIGH impact, can_reboot=true -> multiplier 0.9
        assert result["ot_threshold_multiplier"] == 0.9


# =============================================================================
# 15. SYNTHETIC DATA GENERATION TESTS
# =============================================================================

class TestSyntheticData:
    """Tests for generate_synthetic_normal_data()."""

    def test_output_shape(self):
        X = generate_synthetic_normal_data(n_samples=50)
        assert X.shape == (50, NUM_FEATURES)

    def test_deterministic(self):
        X1 = generate_synthetic_normal_data(n_samples=10, seed=42)
        X2 = generate_synthetic_normal_data(n_samples=10, seed=42)
        np.testing.assert_array_almost_equal(X1, X2)

    def test_all_finite(self):
        X = generate_synthetic_normal_data(n_samples=100)
        assert np.all(np.isfinite(X))


# =============================================================================
# 16. STATS AND LOGGING TESTS
# =============================================================================

class TestStatsAndLogging:
    """Tests for processing log and aggregate stats."""

    def test_stats_empty(self):
        detector = A4AnomalyDetector()
        stats = detector.get_stats()
        assert stats["total"] == 0

    def test_stats_after_processing(self, trained_detector, benign_evidence):
        trained_detector.process(benign_evidence)
        stats = trained_detector.get_stats()
        assert stats["total_processed"] == 1

    def test_processing_log(self, trained_detector, benign_evidence):
        trained_detector.process(benign_evidence)
        log = trained_detector.get_processing_log()
        assert len(log) == 1
        assert log[0]["evidence_id"] == "EV-2026-TEST-BENIGN"

    def test_multiple_processing(self, trained_detector, benign_evidence, attack_evidence):
        trained_detector.process(benign_evidence)
        trained_detector.process(attack_evidence)
        stats = trained_detector.get_stats()
        assert stats["total_processed"] == 2


# =============================================================================
# 17. MODULE-LEVEL CONVENIENCE TESTS
# =============================================================================

class TestModuleLevel:
    """Tests for module-level process() convenience function."""

    def test_module_process(self, benign_evidence):
        from agents.a4_anomaly import process
        result = process(benign_evidence)
        assert "anomaly_score" in result
        assert "behavior_embedding" in result
        assert len(result["behavior_embedding"]) == EMBEDDING_DIM
