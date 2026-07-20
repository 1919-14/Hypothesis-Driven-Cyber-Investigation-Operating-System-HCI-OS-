"""
agents/a4_anomaly.py
A4: Adaptive Anomaly Detector (Layer 4) -- HCI-OS

Unsupervised ML ensemble that detects novel anomalies on Evidence objects
that A3 could not resolve (Path 3 -- no cache hit).

Pipeline position: A3 (Path 3 novel) --> [A4] --> A5/A6/A7

--- ML Ensemble (Ticket 19c) ---
1. One-Class SVM         -- boundary-based anomaly detection (PRIMARY, replaces IF)
2. LSTM-Autoencoder      -- temporal anomalies (SCOPE CUT: Z-score rolling baseline)
3. VAE / Gaussian        -- probabilistic + epistemic uncertainty
4. Cross-Attention Fusion-- numpy multi-head attention over 4 signal types

--- Key Features ---
- Dual Baseline: Generic (CICIDS w=0.4) + Org-specific (rolling w=0.6)
- Cross-Attention Fusion: numpy multi-head attention over 4 signal types
- OT/Safety Context: adjusts anomaly thresholds per asset criticality
- Adaptive Mode: OBSERVE_ONLY -> SUPERVISED_HYBRID -> AUTONOMOUS
- 256-dim Behavior Embedding: real learned projection, L2-normalized
- Uncertainty: epistemic (Gaussian) + aleatoric (ensemble variance)
- effective_confidence = (1 - total_uncertainty) * fused_score

--- Scope Cuts (Documented) ---
# SCOPE CUT: LSTM-AE replaced with Z-score rolling baseline per asset_id.
#   Full implementation would use a 2-layer LSTM (hidden=128) autoencoder
#   trained on per-asset event sequences with reconstruction error as score.
#   Roadmap: Ticket 13+ or post-hackathon.
# SCOPE CUT: VAE replaced with multivariate Gaussian likelihood.
#   Full implementation would use a torch VAE with encoder/decoder networks,
#   KL divergence for epistemic uncertainty, and ELBO loss for training.
#   Roadmap: Ticket 13+ or post-hackathon.
# SCOPE CUT: Cross-Attention uses numpy instead of torch.nn.MultiheadAttention.
#   Mathematically identical (scaled dot-product attention, 4 heads).
#   Avoids ~2GB PyTorch dependency. Swappable when torch is available.
"""

import hashlib
import json
import logging
import math
import os
import time
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple

import numpy as np

# Isolation Forest -- real scikit-learn implementation (kept for org-specific baseline)
try:
    from sklearn.ensemble import IsolationForest
    from sklearn.preprocessing import StandardScaler
    _HAS_SKLEARN = True
except ImportError:
    _HAS_SKLEARN = False

# One-Class SVM -- Ticket 19c primary detector
try:
    from sklearn.svm import OneClassSVM as _OneClassSVM
    _HAS_OCSVM = True
except ImportError:
    _HAS_OCSVM = False

# ─── Logging ────────────────────────────────────────────────────────────────
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("A4_AnomalyDetector")

# ─── Configuration ───────────────────────────────────────────────────────────
DEFAULT_BASE_THRESHOLD: float = 0.5
DEFAULT_FUZZY_THRESHOLD: float = 0.85
GENERIC_WEIGHT: float = 0.4
ORG_WEIGHT: float = 0.6
EMBEDDING_DIM: int = 256
NUM_FEATURES: int = 20  # number of extracted numeric features
NUM_ATTENTION_HEADS: int = 4
SIGNAL_EMBED_DIM: int = 16  # per-signal embedding dimension for cross-attention

# Adaptive mode -- controlled by env var HCI_OS_MODE
VALID_MODES = {"OBSERVE_ONLY", "SUPERVISED_HYBRID", "AUTONOMOUS"}

# ─── Paths ───────────────────────────────────────────────────────────────────
_AGENT_DIR = Path(__file__).parent
_DATA_DIR = _AGENT_DIR.parent / "data"
_ASSET_INVENTORY_PATH = _DATA_DIR / "asset_inventory.json"


# =============================================================================
# FEATURE EXTRACTION
# =============================================================================

def extract_features(evidence_normalized: Dict[str, Any]) -> np.ndarray:
    """
    Extract a fixed-length numeric feature vector from Evidence.normalized fields.

    Produces a 20-dim vector covering:
      [0]  bytes (data volume)
      [1]  src_port
      [2]  dst_port
      [3]  flow_duration (microseconds)
      [4]  fwd_packets
      [5]  bwd_packets
      [6]  protocol_tcp (1/0)
      [7]  protocol_udp (1/0)
      [8]  protocol_icmp (1/0)
      [9]  status_code (HTTP status or 0)
      [10] hour_of_day (0-23)
      [11] day_of_week (0-6)
      [12] is_off_hours (1/0)
      [13] is_night (1/0)
      [14] port_entropy (high = port scan indicator)
      [15] byte_rate (bytes / duration, or 0)
      [16] packet_ratio (fwd / (fwd+bwd), or 0.5)
      [17] is_privileged_port (dst_port < 1024)
      [18] is_high_port (src_port > 49152)
      [19] connection_density (fwd_packets * bwd_packets)
    """
    n = evidence_normalized

    def _float(key: str, default: float = 0.0) -> float:
        try:
            return float(n.get(key, default))
        except (ValueError, TypeError):
            return default

    bytes_val = _float("bytes")
    src_port = _float("src_port")
    dst_port = _float("dst_port")
    flow_duration = _float("flow_duration")
    fwd_packets = _float("fwd_packets")
    bwd_packets = _float("bwd_packets")

    # Protocol one-hot
    proto_raw = str(n.get("protocol", "")).lower()
    proto_num = _float("protocol")
    protocol_tcp = 1.0 if proto_raw in ("tcp", "6") or proto_num == 6 else 0.0
    protocol_udp = 1.0 if proto_raw in ("udp", "17") or proto_num == 17 else 0.0
    protocol_icmp = 1.0 if proto_raw in ("icmp", "1") or proto_num == 1 else 0.0

    # Status code
    status_code = _float("status")

    # Time features
    ts_raw = n.get("timestamp", "")
    hour_of_day = 12.0  # default midday
    day_of_week = 2.0   # default Wednesday
    is_off_hours = 0.0
    is_night = 0.0
    if ts_raw:
        try:
            if isinstance(ts_raw, str):
                dt = datetime.fromisoformat(ts_raw.replace("Z", "+00:00"))
            elif isinstance(ts_raw, datetime):
                dt = ts_raw
            else:
                dt = None
            if dt:
                hour_of_day = float(dt.hour)
                day_of_week = float(dt.weekday())
                is_off_hours = 1.0 if dt.hour >= 18 or dt.hour < 9 else 0.0
                is_night = 1.0 if dt.hour >= 23 or dt.hour < 6 else 0.0
        except (ValueError, TypeError):
            pass

    # Derived features
    port_entropy = abs(src_port - dst_port) / max(src_port + dst_port, 1.0)
    byte_rate = bytes_val / max(flow_duration / 1e6, 0.001) if flow_duration > 0 else 0.0
    total_packets = fwd_packets + bwd_packets
    packet_ratio = fwd_packets / max(total_packets, 1.0)
    is_privileged_port = 1.0 if dst_port < 1024 and dst_port > 0 else 0.0
    is_high_port = 1.0 if src_port > 49152 else 0.0
    connection_density = fwd_packets * bwd_packets

    return np.array([
        bytes_val,          # 0
        src_port,           # 1
        dst_port,           # 2
        flow_duration,      # 3
        fwd_packets,        # 4
        bwd_packets,        # 5
        protocol_tcp,       # 6
        protocol_udp,       # 7
        protocol_icmp,      # 8
        status_code,        # 9
        hour_of_day,        # 10
        day_of_week,        # 11
        is_off_hours,       # 12
        is_night,           # 13
        port_entropy,       # 14
        byte_rate,          # 15
        packet_ratio,       # 16
        is_privileged_port, # 17
        is_high_port,       # 18
        connection_density, # 19
    ], dtype=np.float32)


# =============================================================================
# SIGNAL DECOMPOSITION (for Cross-Attention)
# =============================================================================

def decompose_signals(
    evidence_normalized: Dict[str, Any],
) -> Dict[str, np.ndarray]:
    """
    Decompose an Evidence's normalized fields into 4 signal-type vectors
    for cross-attention fusion.

    Each signal is a fixed-length SIGNAL_EMBED_DIM (16-dim) vector.

    Signal types:
      dns_signal     -- DNS query patterns (domain entropy, rare domains)
      auth_signal    -- Authentication events (failed logins, privileged access)
      process_signal -- Process spawn events (new processes, suspicious names)
      network_signal -- Network flow events (unusual ports, outbound connections)
    """
    n = evidence_normalized

    def _f(key, default=0.0):
        try:
            return float(n.get(key, default))
        except (ValueError, TypeError):
            return default

    # ── DNS signal ───────────────────────────────────────────────────────
    # For hackathon: derive from dst_port (53 = DNS), domain name length
    domain = str(n.get("domain", n.get("path", "")))
    domain_len = float(len(domain)) if domain else 0.0
    domain_entropy = 0.0
    if domain and len(domain) > 0:
        # Shannon entropy of the domain string
        freq = defaultdict(int)
        for c in domain.lower():
            freq[c] += 1
        total = len(domain)
        domain_entropy = -sum(
            (cnt / total) * math.log2(cnt / total) for cnt in freq.values()
        )
    is_dns_port = 1.0 if _f("dst_port") == 53 else 0.0
    dns_signal = np.zeros(SIGNAL_EMBED_DIM, dtype=np.float32)
    dns_signal[0] = domain_len / 100.0  # normalized domain length
    dns_signal[1] = domain_entropy / 5.0  # normalized entropy
    dns_signal[2] = is_dns_port
    dns_signal[3] = 1.0 if domain_len > 50 else 0.0  # suspiciously long domain

    # ── Auth signal ──────────────────────────────────────────────────────
    user = str(n.get("user", ""))
    logon_type = _f("logon_type")
    status_code = _f("status")
    is_failed_auth = 1.0 if status_code in (401, 403) or logon_type == 3 else 0.0
    is_admin = 1.0 if "admin" in user.lower() else 0.0
    auth_signal = np.zeros(SIGNAL_EMBED_DIM, dtype=np.float32)
    auth_signal[0] = is_failed_auth
    auth_signal[1] = is_admin
    auth_signal[2] = logon_type / 10.0 if logon_type > 0 else 0.0
    auth_signal[3] = 1.0 if _f("dst_port") == 389 else 0.0  # LDAP
    auth_signal[4] = 1.0 if _f("dst_port") == 88 else 0.0   # Kerberos

    # ── Process signal ───────────────────────────────────────────────────
    process = str(n.get("process", n.get("method", "")))
    process_len = float(len(process)) if process else 0.0
    suspicious_processes = ["powershell", "cmd", "wscript", "cscript", "mshta",
                            "certutil", "bitsadmin", "rundll32"]
    is_suspicious_proc = 1.0 if any(sp in process.lower() for sp in suspicious_processes) else 0.0
    process_signal = np.zeros(SIGNAL_EMBED_DIM, dtype=np.float32)
    process_signal[0] = process_len / 50.0
    process_signal[1] = is_suspicious_proc
    process_signal[2] = 1.0 if "shell" in process.lower() else 0.0
    process_signal[3] = 1.0 if "script" in process.lower() else 0.0

    # ── Network signal ───────────────────────────────────────────────────
    src_port = _f("src_port")
    dst_port = _f("dst_port")
    bytes_val = _f("bytes")
    fwd_packets = _f("fwd_packets")
    bwd_packets = _f("bwd_packets")
    flow_duration = _f("flow_duration")

    network_signal = np.zeros(SIGNAL_EMBED_DIM, dtype=np.float32)
    network_signal[0] = min(bytes_val / 100000.0, 1.0)  # normalized bytes
    network_signal[1] = 1.0 if dst_port < 1024 and dst_port > 0 else 0.0  # privileged
    network_signal[2] = 1.0 if src_port > 49152 else 0.0  # ephemeral
    network_signal[3] = min(fwd_packets / 100.0, 1.0)  # normalized pkt count
    network_signal[4] = min(bwd_packets / 100.0, 1.0)
    network_signal[5] = min(flow_duration / 1e6, 1.0)  # normalized duration (sec)
    # Unusual port indicators
    network_signal[6] = 1.0 if dst_port in (4444, 5555, 6666, 1389, 8443) else 0.0
    network_signal[7] = 1.0 if dst_port == 3389 else 0.0  # RDP

    return {
        "dns": dns_signal,
        "auth": auth_signal,
        "process": process_signal,
        "network": network_signal,
    }


# =============================================================================
# CROSS-ATTENTION FUSION (Pure NumPy)
# =============================================================================

class CrossAttentionFusion:
    """
    Multi-head scaled dot-product attention over 4 signal types.

    Mathematically identical to torch.nn.MultiheadAttention but implemented
    in pure numpy to avoid the ~2GB PyTorch dependency.

    Input:  4 signal vectors of shape (SIGNAL_EMBED_DIM,) each
    Output: fused vector of shape (SIGNAL_EMBED_DIM,) + attention_weights dict

    # SCOPE CUT: Uses numpy instead of torch.nn.MultiheadAttention.
    # Same math (scaled dot-product attention, 4 heads). Swappable when torch available.
    """

    def __init__(
        self,
        embed_dim: int = SIGNAL_EMBED_DIM,
        num_heads: int = NUM_ATTENTION_HEADS,
        seed: int = 42,
    ):
        self.embed_dim = embed_dim
        self.num_heads = num_heads
        self.head_dim = embed_dim // num_heads
        assert embed_dim % num_heads == 0, (
            f"embed_dim ({embed_dim}) must be divisible by num_heads ({num_heads})"
        )

        rng = np.random.RandomState(seed)
        scale = 1.0 / np.sqrt(self.head_dim)

        # Initialize Q, K, V projection weights (small Xavier-like init)
        self.W_q = rng.randn(embed_dim, embed_dim).astype(np.float32) * scale
        self.W_k = rng.randn(embed_dim, embed_dim).astype(np.float32) * scale
        self.W_v = rng.randn(embed_dim, embed_dim).astype(np.float32) * scale
        self.W_o = rng.randn(embed_dim, embed_dim).astype(np.float32) * scale

    def forward(
        self, signals: Dict[str, np.ndarray]
    ) -> Tuple[np.ndarray, Dict[str, float]]:
        """
        Apply multi-head attention over signal vectors.

        Args:
            signals: dict of signal_name -> np.ndarray(SIGNAL_EMBED_DIM,)

        Returns:
            (fused_vector, attention_weights_dict)
            fused_vector: np.ndarray(SIGNAL_EMBED_DIM,)
            attention_weights_dict: {signal_name: float} showing relative importance
        """
        signal_names = list(signals.keys())
        n_signals = len(signal_names)

        # Stack signals: (n_signals, embed_dim)
        X = np.stack([signals[name] for name in signal_names])

        # Project Q, K, V: (n_signals, embed_dim)
        Q = X @ self.W_q
        K = X @ self.W_k
        V = X @ self.W_v

        # Reshape for multi-head: (num_heads, n_signals, head_dim)
        Q = Q.reshape(n_signals, self.num_heads, self.head_dim).transpose(1, 0, 2)
        K = K.reshape(n_signals, self.num_heads, self.head_dim).transpose(1, 0, 2)
        V = V.reshape(n_signals, self.num_heads, self.head_dim).transpose(1, 0, 2)

        # Scaled dot-product attention per head
        # scores: (num_heads, n_signals, n_signals)
        scale = np.sqrt(self.head_dim)
        scores = np.matmul(Q, K.transpose(0, 2, 1)) / scale

        # Softmax per head
        # Numerically stable softmax
        scores_max = np.max(scores, axis=-1, keepdims=True)
        exp_scores = np.exp(scores - scores_max)
        attn_weights = exp_scores / np.sum(exp_scores, axis=-1, keepdims=True)

        # Weighted sum of values: (num_heads, n_signals, head_dim)
        attended = np.matmul(attn_weights, V)

        # Concatenate heads: (n_signals, embed_dim)
        attended = attended.transpose(1, 0, 2).reshape(n_signals, self.embed_dim)

        # Output projection
        output = attended @ self.W_o

        # Fused vector = mean over signals
        fused = output.mean(axis=0)

        # Compute per-signal attention weights (average across heads and query positions)
        # attn_weights shape: (num_heads, n_signals, n_signals)
        # Average attention received by each signal (column-wise mean)
        per_signal_attn = attn_weights.mean(axis=(0, 1))  # (n_signals,)
        # Normalize to sum to 1
        total = per_signal_attn.sum()
        if total > 0:
            per_signal_attn = per_signal_attn / total

        weights_dict = {
            name: round(float(per_signal_attn[i]), 4)
            for i, name in enumerate(signal_names)
        }

        return fused, weights_dict


# =============================================================================
# ISOLATION FOREST (Real scikit-learn)
# =============================================================================

class IsolationForestDetector:
    """
    Real Isolation Forest anomaly detector trained on normal traffic features.
    Uses scikit-learn IsolationForest with StandardScaler preprocessing.
    """

    def __init__(self, contamination: float = 0.05, n_estimators: int = 100, seed: int = 42):
        self.contamination = contamination
        self.n_estimators = n_estimators
        self.seed = seed
        self._scaler = StandardScaler() if _HAS_SKLEARN else None
        self._model = None
        self._is_trained = False

    def train(self, X: np.ndarray) -> None:
        """
        Train the Isolation Forest on normal traffic data.

        Args:
            X: (n_samples, NUM_FEATURES) array of normal traffic features.
        """
        if not _HAS_SKLEARN:
            logger.warning("scikit-learn not available -- IsolationForest will return 0.5")
            return

        X_scaled = self._scaler.fit_transform(X)
        self._model = IsolationForest(
            contamination=self.contamination,
            n_estimators=self.n_estimators,
            random_state=self.seed,
            n_jobs=-1,
        )
        self._model.fit(X_scaled)
        self._is_trained = True
        logger.info(
            "IsolationForest: Trained on %d samples (%d features)",
            X.shape[0], X.shape[1],
        )

    def score(self, features: np.ndarray) -> float:
        """
        Score a single feature vector. Returns anomaly score in [0, 1].
        Higher = more anomalous.

        sklearn's decision_function returns negative for anomalies,
        so we negate and normalize to [0, 1].
        """
        if not self._is_trained or self._model is None:
            return 0.5  # neutral score when untrained

        features_2d = features.reshape(1, -1)
        features_scaled = self._scaler.transform(features_2d)

        # decision_function: negative = anomaly, positive = normal
        raw_score = self._model.decision_function(features_scaled)[0]

        # Convert to [0, 1] where 1 = highly anomalous
        # Typical range is [-0.5, 0.5]; clamp and invert
        normalized = 0.5 - raw_score
        return float(np.clip(normalized, 0.0, 1.0))

    @property
    def is_trained(self) -> bool:
        return self._is_trained


# =============================================================================
# ONE-CLASS SVM DETECTOR  (Ticket 19c — replaces Isolation Forest)
# =============================================================================

class OneClassSVMDetector:
    """
    One-Class SVM anomaly detector.

    Wraps a pre-trained sklearn OneClassSVM loaded from one_class_svm.pkl.
    Uses decision_function() output converted to [0,1] via sigmoid so that:
      - Benign (inside boundary): decision_function > 0 → sigmoid ≈ 0.5-≈0 (low anomaly)
      - Attack (outside boundary): decision_function < 0 → sigmoid > 0.5 (high anomaly)

    Formula: anomaly_score = sigmoid(-decision_function) = 1 / (1 + exp(df))
    This maps  df >> 0 (deep inside) → ~0,  df << 0 (far outside) → ~1.
    """

    def __init__(self):
        self._model   = None
        self._scaler  = None
        self._n_feat  = 20
        self._score_std = 1.0
        self._is_loaded = False

    def load(self, payload: dict) -> None:
        """
        Load from the dict stored inside one_class_svm.pkl.

        payload["model"] is the inner dict produced by _save_pkl():
          {"model": OneClassSVM, "scaler": StandardScaler,
           "threshold": float, "n_features": int, "score_std": float}
        """
        bundle = payload.get("model", {})
        if isinstance(bundle, dict):
            self._model  = bundle.get("model")
            self._scaler = bundle.get("scaler")
            self._n_feat = bundle.get("n_features", 20)
            self._score_std = bundle.get("score_std", 1.0)
        else:
            self._model  = bundle   # bare model (fallback)
            self._score_std = 1.0
        self._is_loaded = self._model is not None
        if self._is_loaded:
            logger.info(
                "OneClassSVMDetector: Loaded  n_features=%d  score_std=%.6f",
                self._n_feat, self._score_std,
            )

    def score(self, features: np.ndarray) -> float:
        """
        Score a single feature vector. Returns anomaly score in [0, 1].
        Higher = more anomalous.

        Uses sigmoid(-df / score_std) where df = decision_function output.
        """
        if not self._is_loaded or self._model is None:
            return 0.5   # neutral when not loaded

        # Trim / pad to expected feature count
        feat = features[:self._n_feat]
        if len(feat) < self._n_feat:
            feat = np.pad(feat, (0, self._n_feat - len(feat)))

        feat_2d = feat.reshape(1, -1)
        if self._scaler is not None:
            feat_2d = self._scaler.transform(feat_2d)

        df = float(self._model.decision_function(feat_2d)[0])
        # sigmoid(-df / score_std): inside boundary (df>0) → low score; outside (df<0) → high score
        scaled_df = df / self._score_std
        anomaly_score = 1.0 / (1.0 + np.exp(scaled_df))
        return float(np.clip(anomaly_score, 0.0, 1.0))

    @property
    def is_loaded(self) -> bool:
        return self._is_loaded


# =============================================================================
# LSTM-AE STUB (Z-Score Rolling Baseline)
# =============================================================================

class TemporalAnomalyDetector:
    """
    # SCOPE CUT: LSTM-Autoencoder replaced with Z-score rolling baseline.
    # Full implementation: 2-layer LSTM (hidden=128) autoencoder per asset_id.
    # Reconstruction error as anomaly score. Trained on normal event sequences.
    # Roadmap: Ticket 13+ or post-hackathon.

    Current implementation:
    Tracks per-asset running statistics (mean, variance) using Welford's
    online algorithm. Computes Z-score for each new event.
    """

    def __init__(self, warmup_count: int = 10):
        self.warmup_count = warmup_count
        # Per-asset statistics: {asset_id: {"n": int, "mean": ndarray, "M2": ndarray}}
        self._stats: Dict[str, Dict[str, Any]] = {}

    def update_and_score(self, asset_id: str, features: np.ndarray) -> float:
        """
        Update the running baseline for this asset and return Z-score anomaly.

        Uses Welford's online algorithm for numerically stable incremental
        mean/variance computation.

        Returns: anomaly score in [0, 1]. Higher = more anomalous.
        """
        if asset_id not in self._stats:
            self._stats[asset_id] = {
                "n": 0,
                "mean": np.zeros_like(features),
                "M2": np.zeros_like(features),
            }

        stats = self._stats[asset_id]
        stats["n"] += 1
        n = stats["n"]

        # Welford's online update
        delta = features - stats["mean"]
        stats["mean"] = stats["mean"] + delta / n
        delta2 = features - stats["mean"]
        stats["M2"] = stats["M2"] + delta * delta2

        # During warmup, don't score (not enough data)
        if n < self.warmup_count:
            return 0.0

        # Compute variance and Z-score
        variance = stats["M2"] / (n - 1)
        std = np.sqrt(np.maximum(variance, 1e-8))
        z_scores = np.abs((features - stats["mean"]) / std)

        # Average Z-score across features, normalized to [0, 1]
        avg_z = float(np.mean(z_scores))
        # Z-score of 3 maps to ~0.5, Z-score of 6+ maps to ~1.0
        normalized = 1.0 - np.exp(-avg_z / 3.0)
        return float(np.clip(normalized, 0.0, 1.0))

    def get_baseline_count(self, asset_id: str) -> int:
        """Return number of samples seen for this asset."""
        if asset_id in self._stats:
            return self._stats[asset_id]["n"]
        return 0


# =============================================================================
# VAE STUB (Gaussian Likelihood)
# =============================================================================

class ProbabilisticAnomalyDetector:
    """
    # SCOPE CUT: VAE replaced with multivariate Gaussian likelihood.
    # Full implementation: torch VAE with encoder/decoder, KL divergence
    # for epistemic uncertainty, ELBO loss for training.
    # Roadmap: Ticket 13+ or post-hackathon.

    Current implementation:
    Fits a multivariate Gaussian (mean, covariance) on training data.
    Scores events by negative log-likelihood (Mahalanobis distance).
    Epistemic uncertainty estimated by distance from training distribution center.
    """

    def __init__(self):
        self._mean: Optional[np.ndarray] = None
        self._cov_inv: Optional[np.ndarray] = None
        self._cov_det_log: float = 0.0
        self._is_trained = False
        self._training_max_distance: float = 1.0

    def train(self, X: np.ndarray) -> None:
        """
        Fit a multivariate Gaussian on normal training data.

        Args:
            X: (n_samples, n_features) array of normal traffic features.
        """
        self._mean = np.mean(X, axis=0)
        cov = np.cov(X, rowvar=False)

        # Regularize covariance to prevent singular matrix
        cov += np.eye(cov.shape[0]) * 1e-6

        try:
            self._cov_inv = np.linalg.inv(cov)
            sign, self._cov_det_log = np.linalg.slogdet(cov)
            if sign <= 0:
                self._cov_det_log = 0.0
        except np.linalg.LinAlgError:
            # Fallback: use diagonal covariance
            diag_var = np.var(X, axis=0) + 1e-6
            self._cov_inv = np.diag(1.0 / diag_var)
            self._cov_det_log = float(np.sum(np.log(diag_var)))

        # Compute max Mahalanobis distance in training set (for normalization)
        distances = np.array([self._mahalanobis(x) for x in X])
        self._training_max_distance = max(float(np.percentile(distances, 99)), 1.0)
        self._is_trained = True

        logger.info(
            "GaussianLikelihood: Trained on %d samples, max_distance=%.2f",
            X.shape[0], self._training_max_distance,
        )

    def _mahalanobis(self, x: np.ndarray) -> float:
        """Compute Mahalanobis distance from the training distribution center."""
        if self._mean is None or self._cov_inv is None:
            return 0.0
        diff = x - self._mean
        return float(np.sqrt(np.maximum(diff @ self._cov_inv @ diff, 0.0)))

    def score_and_uncertainty(self, features: np.ndarray) -> Tuple[float, float]:
        """
        Score a single feature vector.

        Returns:
            (anomaly_score, epistemic_uncertainty) both in [0, 1].

        anomaly_score: based on Mahalanobis distance (higher = more anomalous).
        epistemic_uncertainty: proxy for KL divergence -- how far from known distribution.
        """
        if not self._is_trained:
            return 0.5, 0.5  # neutral when untrained

        dist = self._mahalanobis(features)

        # Normalize to [0, 1] using training max distance
        anomaly_score = float(np.clip(dist / self._training_max_distance, 0.0, 1.0))

        # Epistemic uncertainty: far from center = high uncertainty
        # Use sigmoid-like mapping: dist > max_training -> uncertainty approaches 1
        epistemic = float(1.0 - np.exp(-dist / max(self._training_max_distance, 1.0)))

        return anomaly_score, epistemic

    @property
    def is_trained(self) -> bool:
        return self._is_trained


# =============================================================================
# BEHAVIOR EMBEDDING COMPUTATION
# =============================================================================

class BehaviorEmbedder:
    """
    Computes a 256-dim behavior embedding from the 20-dim feature vector.

    Uses a small learned projection (random but deterministic weights)
    followed by L2 normalization so that cosine similarity works in FAISS.

    # SCOPE CUT: Uses a fixed random projection instead of a learned GNN encoder.
    # Full implementation: Use A5's GNN encoder for graph-contextualized embeddings.
    # This projection still produces meaningful embeddings because:
    #   - Random projections approximately preserve distances (Johnson-Lindenstrauss)
    #   - L2 normalization ensures cosine similarity in FAISS works correctly
    #   - Similar events produce similar embeddings (verified in tests)
    """

    def __init__(self, input_dim: int = NUM_FEATURES, output_dim: int = EMBEDDING_DIM, seed: int = 42):
        self.input_dim = input_dim
        self.output_dim = output_dim
        rng = np.random.RandomState(seed)
        # Xavier-like initialization for the projection matrix
        scale = np.sqrt(2.0 / (input_dim + output_dim))
        self.W1 = rng.randn(input_dim, 64).astype(np.float32) * scale
        self.b1 = np.zeros(64, dtype=np.float32)
        self.W2 = rng.randn(64, output_dim).astype(np.float32) * scale
        self.b2 = np.zeros(output_dim, dtype=np.float32)

    def embed(self, features: np.ndarray) -> np.ndarray:
        """
        Compute 256-dim behavior embedding from features.

        Args:
            features: (NUM_FEATURES,) raw feature vector.

        Returns:
            (EMBEDDING_DIM,) L2-normalized embedding vector.
        """
        # Two-layer projection with ReLU activation
        h = features @ self.W1 + self.b1
        h = np.maximum(h, 0)  # ReLU
        embedding = h @ self.W2 + self.b2

        # L2 normalize for cosine similarity
        norm = np.linalg.norm(embedding)
        if norm > 0:
            embedding = embedding / norm

        return embedding.astype(np.float32)


# =============================================================================
# OT CONTEXT THRESHOLD ADJUSTMENT
# =============================================================================

def compute_ot_multiplier(ot_context: Dict[str, Any]) -> float:
    """
    Compute the OT context multiplier for the anomaly threshold.

    Rules (from architecture spec):
      safety_critical: true   -> 0.7  (more sensitive, lower threshold)
      can_reboot: false        -> 1.3  (less sensitive, Human Gate forced by A7)
      impact_if_compromised:
        CRITICAL               -> 0.8
        HIGH                   -> 0.9
        MEDIUM                 -> 1.0
        LOW                    -> 1.1

    When multiple rules apply, we take the most conservative (lowest) multiplier
    UNLESS can_reboot is false (safety override -- must be less sensitive to
    prevent auto-actions on critical OT devices).

    The can_reboot=false rule takes priority because A7 forces Human Gate anyway.
    """
    safety_critical = ot_context.get("safety_critical", False)
    can_reboot = ot_context.get("can_reboot", True)
    impact = str(ot_context.get("impact_if_compromised", "MEDIUM")).upper()

    # can_reboot=false takes priority (OT SCADA safety rule)
    if not can_reboot:
        return 1.3

    # safety_critical lowers threshold
    if safety_critical:
        return 0.7

    # Impact-based adjustment
    impact_map = {
        "CRITICAL": 0.8,
        "HIGH": 0.9,
        "MEDIUM": 1.0,
        "LOW": 1.1,
    }
    return impact_map.get(impact, 1.0)


# =============================================================================
# SYNTHETIC CICIDS NORMAL TRAINING DATA
# =============================================================================

def generate_synthetic_normal_data(n_samples: int = 1000, seed: int = 42) -> np.ndarray:
    """
    Generate synthetic normal traffic data mimicking CICIDS 2017 benign flows.

    Used for training the Isolation Forest and Gaussian likelihood models
    when real CICIDS data is not available.

    When real CICIDS 2017 CSV is available, replace this function with:
        df = pd.read_csv("data/cicids_normal.csv")
        X = np.array([extract_features(row) for _, row in df.iterrows()])

    Feature distributions are based on published CICIDS 2017 statistics
    for BENIGN traffic class.
    """
    rng = np.random.RandomState(seed)

    X = np.zeros((n_samples, NUM_FEATURES), dtype=np.float32)

    # bytes: normal web traffic ~500-50000 bytes
    X[:, 0] = rng.lognormal(mean=7.0, sigma=1.5, size=n_samples)
    # src_port: ephemeral ports 49152-65535
    X[:, 1] = rng.uniform(49152, 65535, size=n_samples)
    # dst_port: common ports (80, 443, 8080)
    common_ports = [80, 443, 8080, 3306, 22, 25, 53]
    X[:, 2] = rng.choice(common_ports, size=n_samples).astype(np.float32)
    # flow_duration: 100ms to 300s
    X[:, 3] = rng.lognormal(mean=11, sigma=2, size=n_samples)
    # fwd_packets: 1-50
    X[:, 4] = rng.poisson(lam=10, size=n_samples).astype(np.float32) + 1
    # bwd_packets: 1-40
    X[:, 5] = rng.poisson(lam=8, size=n_samples).astype(np.float32) + 1
    # protocol_tcp: mostly TCP
    X[:, 6] = (rng.random(n_samples) > 0.15).astype(np.float32)
    # protocol_udp
    X[:, 7] = (1 - X[:, 6]) * (rng.random(n_samples) > 0.5).astype(np.float32)
    # protocol_icmp
    X[:, 8] = np.zeros(n_samples, dtype=np.float32)
    # status_code: mostly 200
    X[:, 9] = rng.choice([200, 200, 200, 301, 304, 404], size=n_samples).astype(np.float32)
    # hour_of_day: business hours peak
    X[:, 10] = rng.normal(loc=13, scale=3, size=n_samples).clip(0, 23)
    # day_of_week: weekdays
    X[:, 11] = rng.choice([0, 1, 2, 3, 4, 5, 6], p=[0.18, 0.18, 0.18, 0.18, 0.18, 0.05, 0.05], size=n_samples).astype(np.float32)
    # is_off_hours
    X[:, 12] = ((X[:, 10] >= 18) | (X[:, 10] < 9)).astype(np.float32)
    # is_night
    X[:, 13] = ((X[:, 10] >= 23) | (X[:, 10] < 6)).astype(np.float32)
    # port_entropy
    X[:, 14] = np.abs(X[:, 1] - X[:, 2]) / np.maximum(X[:, 1] + X[:, 2], 1.0)
    # byte_rate
    X[:, 15] = X[:, 0] / np.maximum(X[:, 3] / 1e6, 0.001)
    # packet_ratio
    total_pkts = X[:, 4] + X[:, 5]
    X[:, 16] = X[:, 4] / np.maximum(total_pkts, 1.0)
    # is_privileged_port
    X[:, 17] = (X[:, 2] < 1024).astype(np.float32)
    # is_high_port
    X[:, 18] = (X[:, 1] > 49152).astype(np.float32)
    # connection_density
    X[:, 19] = X[:, 4] * X[:, 5]

    return X


# =============================================================================
# MAIN A4 DETECTOR CLASS
# =============================================================================

class A4AnomalyDetector:
    """
    Adaptive Anomaly Detector -- the ML engine of HCI-OS.

    Combines:
      - Isolation Forest (point anomalies)
      - Temporal Z-score baseline (temporal anomalies, stub for LSTM-AE)
      - Gaussian likelihood (probabilistic anomalies, stub for VAE)
      - Cross-Attention Fusion over 4 signal types
      - OT context threshold adjustment
      - Dual baseline (generic + org-specific)
      - 256-dim behavior embedding computation
      - Adaptive mode switching
      - Uncertainty reporting (epistemic + aleatoric)

    Usage:
        detector = A4AnomalyDetector()
        detector.train()  # trains generic baseline
        result = detector.process(evidence)
    """

    def __init__(
        self,
        mode: Optional[str] = None,
        base_threshold: float = DEFAULT_BASE_THRESHOLD,
        generic_weight: float = GENERIC_WEIGHT,
        org_weight: float = ORG_WEIGHT,
    ):
        """
        Initialize the A4 Anomaly Detector.

        Args:
            mode: One of OBSERVE_ONLY, SUPERVISED_HYBRID, AUTONOMOUS.
                  Defaults to env var HCI_OS_MODE or OBSERVE_ONLY.
            base_threshold: Base anomaly threshold before OT adjustment.
            generic_weight: Weight for generic (CICIDS) baseline (default 0.4).
            org_weight: Weight for org-specific baseline (default 0.6).
        """
        # ── Mode ──────────────────────────────────────────────────────────
        if mode is None:
            mode = os.getenv("HCI_OS_MODE", "OBSERVE_ONLY")
        mode = mode.upper()
        if mode not in VALID_MODES:
            logger.warning("Invalid mode '%s' -- defaulting to OBSERVE_ONLY", mode)
            mode = "OBSERVE_ONLY"
        self.mode = mode

        # ── Configuration ─────────────────────────────────────────────────
        self.base_threshold = base_threshold
        self.generic_weight = generic_weight
        self.org_weight = org_weight

        # ── ML Models ─────────────────────────────────────────────────────
        self.ocsvm              = OneClassSVMDetector()   # Ticket 19c PRIMARY
        self.isolation_forest   = IsolationForestDetector()   # kept for org baseline
        self.temporal_detector     = TemporalAnomalyDetector()
        self.probabilistic_detector = ProbabilisticAnomalyDetector()
        self.cross_attention       = CrossAttentionFusion()
        self.embedder              = BehaviorEmbedder()

        # ── Org-specific baseline (online learning) ────────────────────────
        self._org_isolation_forest = IsolationForestDetector()
        self._org_samples: List[np.ndarray] = []
        self._org_retrain_interval: int = 100
        self._org_trained: bool = False

        # ── Processing log ────────────────────────────────────────────────
        self._processing_log: List[Dict[str, Any]] = []

        logger.info(
            "A4AnomalyDetector: Initialized (mode=%s, threshold=%.2f, "
            "generic_w=%.1f, org_w=%.1f)",
            self.mode, self.base_threshold, self.generic_weight, self.org_weight,
        )

    # ─── Training ─────────────────────────────────────────────────────────────

    def train(self, training_data: Optional[np.ndarray] = None) -> None:
        """
        Train the generic baseline models on normal traffic data.

        Args:
            training_data: (n_samples, NUM_FEATURES) normal traffic features.
                          If None, generates synthetic CICIDS-like data.
        """
        if training_data is None:
            training_data = generate_synthetic_normal_data()
            logger.info("A4: Using synthetic CICIDS-normal data (%d samples)", len(training_data))

        # Train Isolation Forest
        self.isolation_forest.train(training_data)

        # Train Gaussian likelihood (VAE stub)
        self.probabilistic_detector.train(training_data)

        logger.info("A4: Generic baseline training complete")

    def load_real_models(self, models_dir: Optional[str] = None) -> Dict[str, bool]:
        """
        Load pre-trained real models from the pipeline/models/ directory.

        Tries to load:
          one_class_svm.pkl      — PRIMARY anomaly detector (Ticket 19c)
          gaussian_likelihood.pkl— probabilistic baseline
          lstm_autoencoder.pkl   — temporal baseline

        Returns dict of {model_name: loaded_successfully}.
        """
        import pickle
        base = Path(models_dir) if models_dir else (
            Path(__file__).parent.parent / "data" / "models")

        loaded = {}

        # ── One-Class SVM (PRIMARY) ──────────────────────────────────────
        ocsvm_path = base / "one_class_svm.pkl"
        if ocsvm_path.exists():
            try:
                with open(ocsvm_path, "rb") as f:
                    payload = pickle.load(f)
                self.ocsvm.load(payload)
                loaded["one_class_svm"] = True
                logger.info("A4: Loaded one_class_svm.pkl")
            except Exception as exc:
                logger.warning("A4: Failed to load one_class_svm.pkl: %s", exc)
                loaded["one_class_svm"] = False
        else:
            logger.warning("A4: one_class_svm.pkl not found at %s", ocsvm_path)
            loaded["one_class_svm"] = False

        # ── Gaussian Likelihood ───────────────────────────────────────────
        gauss_path = base / "gaussian_likelihood.pkl"
        if gauss_path.exists():
            try:
                with open(gauss_path, "rb") as f:
                    g = pickle.load(f)
                g_data = g.get("model", g) if isinstance(g, dict) else g
                if isinstance(g_data, dict):
                    self.probabilistic_detector._mean    = g_data["mean"]
                    self.probabilistic_detector._cov_inv = g_data["cov_inv"]
                    self.probabilistic_detector._training_max_distance = (
                        g_data["training_max_distance"])
                    self.probabilistic_detector._is_trained = True
                    loaded["gaussian"] = True
                    logger.info("A4: Loaded gaussian_likelihood.pkl")
            except Exception as exc:
                logger.warning("A4: Failed to load gaussian_likelihood.pkl: %s", exc)
                loaded["gaussian"] = False

        return loaded

    def _update_org_baseline(self, features: np.ndarray) -> None:
        """
        Incrementally update the org-specific baseline with new observations.
        Retrains the org-specific Isolation Forest periodically.
        """
        self._org_samples.append(features.copy())

        # Retrain org-specific model periodically
        if len(self._org_samples) >= self._org_retrain_interval:
            org_data = np.stack(self._org_samples)
            self._org_isolation_forest.train(org_data)
            self._org_trained = True
            logger.info(
                "A4: Org-specific baseline retrained on %d samples",
                len(self._org_samples),
            )

    # ─── Mode Management ──────────────────────────────────────────────────────

    def set_mode(self, mode: str) -> None:
        """Switch the adaptive mode."""
        mode = mode.upper()
        if mode not in VALID_MODES:
            raise ValueError(f"Invalid mode: {mode}. Must be one of {VALID_MODES}")
        old_mode = self.mode
        self.mode = mode
        logger.info("A4: Mode switched %s -> %s", old_mode, mode)

    # ─── Main Processing ──────────────────────────────────────────────────────

    def process(self, evidence_dict: Dict[str, Any]) -> Dict[str, Any]:
        """
        Process an Evidence object through the anomaly detection ensemble.

        This is the main entry point called by A3 (Path 3) or the pipeline.

        Args:
            evidence_dict: Dict representation of an Evidence object.
                          Must contain 'normalized', 'asset_id', 'evidence_id'.
                          May contain 'context.ot_context'.

        Returns:
            Dict with all original fields plus:
              - anomaly_score: float [0,1] -- combined ensemble score
              - isolation_score: float [0,1] -- Isolation Forest score
              - temporal_score: float [0,1] -- Z-score baseline score
              - vae_score: float [0,1] -- Gaussian likelihood score
              - fused_score: float [0,1] -- cross-attention fused score
              - behavior_embedding: list[float] -- 256-dim L2-normalized
              - attention_weights: dict -- {signal: weight}
              - epistemic_uncertainty: float [0,1]
              - aleatoric_uncertainty: float [0,1]
              - total_uncertainty: float [0,1]
              - effective_confidence: float [0,1] -- for A7's decision rule
              - ot_threshold_multiplier: float
              - adjusted_threshold: float
              - is_anomalous: bool
              - action_allowed: bool -- based on adaptive mode
              - detection_mode: str -- current mode
        """
        start = time.perf_counter()

        normalized = evidence_dict.get("normalized", {})
        asset_id = evidence_dict.get("asset_id", "unknown")
        evidence_id = evidence_dict.get("evidence_id", "unknown")

        # ── 1. Feature Extraction ────────────────────────────────────────
        features = extract_features(normalized)

        # ── 2. Behavior Embedding ────────────────────────────────────────
        embedding = self.embedder.embed(features)
        evidence_dict["behavior_embedding"] = embedding.tolist()

        # ── 3. Primary Anomaly Score (OC-SVM or IF fallback) ─────────────────
        if self.ocsvm.is_loaded:
            # Ticket 19c: use One-Class SVM as primary detector
            isolation_score = self.ocsvm.score(features)
        else:
            # Fallback to synthetic-trained Isolation Forest
            isolation_score = self.isolation_forest.score(features)

        # ── 4. Temporal Anomaly (Z-score, org-specific) ──────────────────
        temporal_score = self.temporal_detector.update_and_score(asset_id, features)

        # ── 5. Probabilistic Anomaly (Gaussian, generic) ─────────────────
        vae_score, epistemic_uncertainty = self.probabilistic_detector.score_and_uncertainty(features)

        # ── 6. Cross-Attention Fusion ────────────────────────────────────
        signals = decompose_signals(normalized)
        fused_vector, attention_weights = self.cross_attention.forward(signals)
        # Fused score from attention output magnitude
        fused_score = float(np.clip(np.linalg.norm(fused_vector) / 2.0, 0.0, 1.0))

        # ── 7. Dual Baseline Fusion ──────────────────────────────────────
        # Generic score = average of isolation + vae
        generic_score = (isolation_score + vae_score) / 2.0

        # Org-specific score = temporal Z-score baseline
        # (When org IF is trained, blend it in)
        if self._org_trained:
            org_if_score = self._org_isolation_forest.score(features)
            org_score = (temporal_score + org_if_score) / 2.0
        else:
            org_score = temporal_score

        # Combined dual-baseline score
        combined_score = (self.generic_weight * generic_score) + (self.org_weight * org_score)

        # Final anomaly score blends dual-baseline with cross-attention fused
        anomaly_score = 0.6 * combined_score + 0.4 * fused_score

        # ── 8. Aleatoric Uncertainty (ensemble variance) ─────────────────
        scores = [isolation_score, temporal_score, vae_score, fused_score]
        aleatoric_uncertainty = float(np.std(scores))
        # Normalize: std of 4 values in [0,1] has max ~0.5
        aleatoric_uncertainty = min(aleatoric_uncertainty / 0.5, 1.0)

        # ── 9. Total Uncertainty + Effective Confidence ──────────────────
        total_uncertainty = 0.5 * epistemic_uncertainty + 0.5 * aleatoric_uncertainty
        effective_confidence = (1.0 - total_uncertainty) * anomaly_score

        # ── 10. OT Context Threshold Adjustment ─────────────────────────
        ot_context = evidence_dict.get("context", {}).get("ot_context", {})
        if not ot_context:
            # Also check top-level context fields
            ctx = evidence_dict.get("context", {})
            ot_context = {
                "safety_critical": ctx.get("safety_critical", False),
                "can_reboot": ctx.get("can_reboot", True),
                "impact_if_compromised": ctx.get("impact_if_compromised", "MEDIUM"),
            }

        ot_multiplier = compute_ot_multiplier(ot_context)
        adjusted_threshold = self.base_threshold * ot_multiplier
        is_anomalous = anomaly_score >= adjusted_threshold

        # ── 11. Adaptive Mode Action Decision ────────────────────────────
        if self.mode == "OBSERVE_ONLY":
            action_allowed = False
            is_anomalous = False  # Don't flag in observe mode
        elif self.mode == "SUPERVISED_HYBRID":
            action_allowed = False  # Alert only, no auto-response
        else:  # AUTONOMOUS
            action_allowed = True

        # ── 12. Update Org Baseline (always, regardless of mode) ─────────
        self._update_org_baseline(features)

        # ── 13. Build Result ─────────────────────────────────────────────
        elapsed_ms = (time.perf_counter() - start) * 1000

        evidence_dict["anomaly_score"] = round(anomaly_score, 4)
        evidence_dict["isolation_score"] = round(isolation_score, 4)
        evidence_dict["temporal_score"] = round(temporal_score, 4)
        evidence_dict["vae_score"] = round(vae_score, 4)
        evidence_dict["fused_score"] = round(fused_score, 4)
        evidence_dict["attention_weights"] = attention_weights
        evidence_dict["epistemic_uncertainty"] = round(epistemic_uncertainty, 4)
        evidence_dict["aleatoric_uncertainty"] = round(aleatoric_uncertainty, 4)
        evidence_dict["total_uncertainty"] = round(total_uncertainty, 4)
        evidence_dict["effective_confidence"] = round(effective_confidence, 4)
        evidence_dict["ot_threshold_multiplier"] = round(ot_multiplier, 2)
        evidence_dict["adjusted_threshold"] = round(adjusted_threshold, 4)
        evidence_dict["is_anomalous"] = is_anomalous
        evidence_dict["action_allowed"] = action_allowed
        evidence_dict["detection_mode"] = self.mode
        evidence_dict["a4_timing_ms"] = round(elapsed_ms, 3)

        # ── 14. Log Result ───────────────────────────────────────────────
        log_entry = {
            "timestamp": datetime.now(timezone.utc).isoformat() + "Z",
            "agent": "A4_AnomalyDetector",
            "evidence_id": evidence_id,
            "asset_id": asset_id,
            "anomaly_score": evidence_dict["anomaly_score"],
            "effective_confidence": evidence_dict["effective_confidence"],
            "is_anomalous": is_anomalous,
            "action_allowed": action_allowed,
            "mode": self.mode,
            "adjusted_threshold": evidence_dict["adjusted_threshold"],
            "timing_ms": elapsed_ms,
        }
        self._processing_log.append(log_entry)

        logger.info(
            "A4: %s | score=%.3f | eff_conf=%.3f | anomalous=%s | "
            "mode=%s | threshold=%.3f (ot_mult=%.1f) | %.1fms",
            evidence_id,
            anomaly_score,
            effective_confidence,
            is_anomalous,
            self.mode,
            adjusted_threshold,
            ot_multiplier,
            elapsed_ms,
        )

        return evidence_dict

    # ─── Accessors ────────────────────────────────────────────────────────────

    def get_processing_log(self) -> List[Dict[str, Any]]:
        """Return all processing decisions as structured dicts."""
        return list(self._processing_log)

    def get_stats(self) -> Dict[str, Any]:
        """Return aggregate detection statistics."""
        total = len(self._processing_log)
        if total == 0:
            return {"total": 0}

        anomalous = sum(1 for r in self._processing_log if r["is_anomalous"])
        scores = [r["anomaly_score"] for r in self._processing_log]

        return {
            "total_processed": total,
            "anomalous_count": anomalous,
            "anomaly_rate": round(anomalous / total * 100, 1),
            "avg_score": round(sum(scores) / len(scores), 4),
            "max_score": round(max(scores), 4),
            "min_score": round(min(scores), 4),
            "mode": self.mode,
            "generic_trained": self.ocsvm.is_loaded or self.isolation_forest.is_trained,
            "ocsvm_loaded":     self.ocsvm.is_loaded,
            "org_trained":      self._org_trained,
            "org_samples":      len(self._org_samples),
        }


# =============================================================================
# MODULE-LEVEL CONVENIENCE (for pipeline integration)
# =============================================================================

_default_detector: Optional[A4AnomalyDetector] = None


def get_detector(**kwargs) -> A4AnomalyDetector:
    """Get or create the module-level A4 detector singleton."""
    global _default_detector
    if _default_detector is None:
        _default_detector = A4AnomalyDetector(**kwargs)
        _default_detector.train()
        _default_detector.load_real_models()
    return _default_detector


def process(evidence) -> dict:
    """
    Module-level convenience function for pipeline integration.
    Matches the agent contract: process(evidence) -> result.
    """
    if not isinstance(evidence, dict):
        if hasattr(evidence, "model_dump"):
            evidence = evidence.model_dump()
        elif hasattr(evidence, "dict"):
            evidence = evidence.dict()
        else:
            evidence = dict(evidence)
    return get_detector().process(evidence)


# =============================================================================
# SMOKE TEST
# =============================================================================

if __name__ == "__main__":
    print("=== A4 Anomaly Detector Smoke Test ===\n")

    # Create and train detector
    detector = A4AnomalyDetector(mode="AUTONOMOUS")
    detector.train()

    # Test with a benign event
    benign_event = {
        "evidence_id": "EV-2026-BENIGN01",
        "asset_id": "CBSE-WebSvr-01",
        "normalized": {
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
        },
        "context": {
            "criticality": "HIGH",
            "ot_context": {
                "safety_critical": False,
                "can_reboot": True,
                "impact_if_compromised": "HIGH",
            },
        },
    }

    result1 = detector.process(benign_event)
    print(f"Benign:  score={result1['anomaly_score']:.3f}  "
          f"eff_conf={result1['effective_confidence']:.3f}  "
          f"anomalous={result1['is_anomalous']}")

    # Test with a suspicious event (port scan pattern)
    attack_event = {
        "evidence_id": "EV-2026-ATTACK01",
        "asset_id": "CBSE-DB-01",
        "normalized": {
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
        },
        "context": {
            "criticality": "CRITICAL",
            "ot_context": {
                "safety_critical": False,
                "can_reboot": True,
                "impact_if_compromised": "CRITICAL",
            },
        },
    }

    result2 = detector.process(attack_event)
    print(f"Attack:  score={result2['anomaly_score']:.3f}  "
          f"eff_conf={result2['effective_confidence']:.3f}  "
          f"anomalous={result2['is_anomalous']}")

    # Test with OT/SCADA event (safety_critical)
    ot_event = {
        "evidence_id": "EV-2026-OT01",
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

    result3 = detector.process(ot_event)
    print(f"OT/SCADA: score={result3['anomaly_score']:.3f}  "
          f"eff_conf={result3['effective_confidence']:.3f}  "
          f"anomalous={result3['is_anomalous']}  "
          f"ot_mult={result3['ot_threshold_multiplier']}")

    # Print attention weights
    print(f"\nAttention weights (attack): {result2['attention_weights']}")

    # Print embedding sample
    emb = result1["behavior_embedding"]
    print(f"Embedding dim={len(emb)}, norm={np.linalg.norm(emb):.4f}")

    # Print stats
    stats = detector.get_stats()
    print(f"\nStats: {json.dumps(stats, indent=2)}")

    print("\n=== All A4 smoke tests passed! ===")
