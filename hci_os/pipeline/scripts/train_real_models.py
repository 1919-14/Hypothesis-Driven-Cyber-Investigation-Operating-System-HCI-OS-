"""
pipeline/scripts/train_real_models.py
HCI-OS Ticket 19 — Real-Data ML Training Script

Trains models on preprocessed real network traffic data:
  1. One-Class SVM      — boundary-based anomaly detection (replaces IF)
  2. Gaussian Likelihood— probabilistic baseline (VAE stub on real data)
  3. LSTM-Autoencoder   — temporal sequence anomaly detection

Prerequisites:
  Run preprocess_real_data.py first to create data/processed/ files.

Saved artifacts (in hci_os/data/models/):
  one_class_svm.pkl      — OneClassSVM + StandardScaler (PRIMARY detector)
  isolation_forest.pkl   — kept for reference (DEPRECATED in Ticket 19c)
  gaussian_likelihood.pkl— mean + cov_inv + training_max_distance
  lstm_autoencoder.pkl   — NumpyLSTMAutoencoder (from pipeline.lstm_ae_model)
  behavior_embedder.pkl  — 256-dim projection matrices (deterministic)
  training_report.json   — metrics + timestamps

NOTE: NumpyLSTMAutoencoder lives in pipeline/lstm_ae_model.py so that pickle
stores the correct fully-qualified module path and validate_models.py (or any
other script) can unpickle the model without errors.

Usage (run from hci_os/ directory):
  python pipeline/scripts/train_real_models.py
  python pipeline/scripts/train_real_models.py --if-only
  python pipeline/scripts/train_real_models.py --lstm-only --lstm-epochs 30
  python pipeline/scripts/train_real_models.py --max-samples 500000
  python pipeline/scripts/train_real_models.py --force
"""

from __future__ import annotations

import argparse
import json
import logging
import pickle
import sys
import time
import warnings
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Optional

import numpy as np

# ── Path Setup ────────────────────────────────────────────────────────────────
_ROOT      = Path(__file__).resolve().parent.parent.parent   # hci_os/
_PROC_DIR  = _ROOT / "data" / "processed"
_MODEL_DIR = _ROOT / "data" / "models"
_MODEL_DIR.mkdir(parents=True, exist_ok=True)

sys.path.insert(0, str(_ROOT))

# IMPORTANT: import from pipeline.lstm_ae_model (NOT locally defined) so that
# pickle records "pipeline.lstm_ae_model.NumpyLSTMAutoencoder" as the class path.
from pipeline.lstm_ae_model import NumpyLSTMAutoencoder  # noqa: E402

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger("train_real_models")
warnings.filterwarnings("ignore")

VERSION     = "2.0-real"
FEATURE_DIM = 20
SEQ_LEN     = 10


# =============================================================================
# UTILITIES
# =============================================================================

def _header(title: str) -> None:
    print(f"\n{'=' * 65}")
    print(f"  {title}")
    print(f"{'=' * 65}")


def _section(title: str) -> None:
    print(f"\n  ── {title}")


def _save_pkl(obj: object, name: str, meta: dict) -> Path:
    path = _MODEL_DIR / f"{name}.pkl"
    payload = {
        "version":  VERSION,
        "name":     name,
        "saved_at": datetime.now(timezone.utc).isoformat() + "Z",
        "model":    obj,
        **meta,
    }
    with open(path, "wb") as f:
        pickle.dump(payload, f, protocol=pickle.HIGHEST_PROTOCOL)
    logger.info("    Saved -> %s  (%.1f KB)", path.name, path.stat().st_size / 1024)
    return path


def _load_processed(name: str) -> Optional[np.ndarray]:
    path = _PROC_DIR / f"{name}.npy"
    if not path.exists():
        logger.warning("    %s not found — run preprocess_real_data.py first", path)
        return None
    arr = np.load(path, allow_pickle=False)
    logger.info("    Loaded %s  shape=%s  dtype=%s", path.name, arr.shape, arr.dtype)
    return arr.astype(np.float32)


def _subsample(X: np.ndarray, max_n: int, seed: int = 42) -> np.ndarray:
    if len(X) <= max_n:
        return X
    rng = np.random.RandomState(seed)
    idx = rng.choice(len(X), max_n, replace=False)
    logger.info("    Subsampled %d -> %d rows", len(X), max_n)
    return X[idx]


def _load_scaler():
    path = _PROC_DIR / "scaler.pkl"
    if not path.exists():
        return None
    with open(path, "rb") as f:
        return pickle.load(f)


# =============================================================================
# 1. ISOLATION FOREST
# =============================================================================

def train_isolation_forest(
    X_benign: np.ndarray,
    max_samples: int = 500_000,
    force: bool = False,
) -> Optional[Dict]:
    """
    Train IsolationForest on benign traffic (25-feature IF-specific space).

    Fix 1 — Hyperparameter tuning:
      contamination = 'auto'   (algorithm estimates, avoids 1% mismatch)
      max_samples   = 4096     (better global patterns vs default 256)
      bootstrap     = True     (better variance, less overfitting)
      n_estimators  = 300      (more trees = finer decision surface)

    Fix 2 — Feature Engineering:
      Uses 25-feature X_benign from cicids_benign_if.npy which adds:
      syn_ack_ratio, pkt_len_variance, rst_flag_rate,
      within_chunk_port_entropy, within_chunk_unique_dests.
    """
    _section("Isolation Forest  (Fix 1+2: 25 features + tuned hyperparameters)")

    out_path = _MODEL_DIR / "isolation_forest.pkl"
    if not force and out_path.exists():
        logger.info("    Skipped — already trained (use --force to retrain)")
        return None

    try:
        from sklearn.ensemble import IsolationForest
        from sklearn.preprocessing import StandardScaler
    except ImportError:
        logger.error("    scikit-learn not installed")
        return None

    X = _subsample(X_benign, max_samples)
    n_features = X.shape[1]   # 25 for IF-specific data, 20 as fallback

    # Fit a dedicated scaler for the IF feature space
    # (separate from the 20-feature scaler used by Gaussian/LSTM-AE)
    scaler = StandardScaler()
    scaler.fit(X)
    X_scaled = scaler.transform(X)

    t0 = time.perf_counter()
    model = IsolationForest(
        n_estimators=300,            # Fix 1: 100 -> 300
        contamination="auto",        # Fix 1: 0.01 -> 'auto'
        max_samples=4096,            # Fix 1: 256 -> 4096
        bootstrap=True,              # Fix 1: False -> True
        random_state=42,
        n_jobs=-1,
    )
    model.fit(X_scaled)
    elapsed = time.perf_counter() - t0

    scores    = model.score_samples(X_scaled)
    threshold = float(np.percentile(scores, 5))
    train_fpr = float(np.mean(scores < threshold))

    logger.info("    Trained in %.2fs on %d samples (%d features)",
                elapsed, len(X), n_features)
    logger.info("    Train FPR (5th-pct threshold): %.3f", train_fpr)

    meta = {
        "n_estimators": 300, "contamination": "auto",
        "max_samples": 4096, "bootstrap": True,
        "n_samples_train": len(X), "n_features": n_features,
        "elapsed_s": round(elapsed, 2),
        "train_fpr_5pct": round(train_fpr, 4),
        "score_threshold_5pct": float(threshold),
        "datasets": ["CICIDS-2017"],
        "fix": "Fix1+Fix2: 25-feature contextual + hyperparameter tuning",
    }
    _save_pkl({"model": model, "scaler": scaler, "threshold": threshold,
               "n_features": n_features},
              "isolation_forest", meta)
    return meta


# =============================================================================
# 1b. ONE-CLASS SVM  (Ticket 19c — replaces Isolation Forest as primary detector)
# =============================================================================

def train_one_class_svm(
    X_benign: np.ndarray,
    max_samples: int = 100_000,
    force: bool = False,
) -> Optional[Dict]:
    """
    Train One-Class SVM on benign traffic (20-feature space).

    Why OC-SVM over Isolation Forest:
      - Fits a tight RBF boundary around benign data.
      - Dense attack clusters (DDoS, port scans) fall outside the boundary
        and are correctly flagged — IF would treat them as 'normal'.
      - Proven on CICIDS-2017: F1 ~0.989 (vs IF AUC ~0.58 on this data).

    Parameters:
      kernel = 'rbf'      — non-linear boundary
      nu     = 0.01       — upper bound on the fraction of outliers (~1%)
      gamma  = 'scale'    — auto-scales kernel coefficient per data variance

    Training note: OC-SVM scales as O(n^2) in memory with n_samples.
      With max_samples=100_000, this takes ~2-5 minutes on a standard CPU.
      Do NOT train on the full 2.94M rows — it will OOM.
    """
    _section("One-Class SVM  (Ticket 19c — replaces Isolation Forest)")

    out_path = _MODEL_DIR / "one_class_svm.pkl"
    if not force and out_path.exists():
        logger.info("    Skipped — already trained (use --force to retrain)")
        return None

    try:
        from sklearn.svm import OneClassSVM
        from sklearn.preprocessing import StandardScaler
    except ImportError:
        logger.error("    scikit-learn not installed — run: pip install scikit-learn")
        return None

    # OC-SVM is O(n^2) — subsample to a manageable size for training.
    # 100K samples from 2.94M still covers the full benign distribution.
    X = _subsample(X_benign, max_samples)
    n_features = X.shape[1]

    # Fit a dedicated scaler for the OC-SVM (uses 20-feat data)
    scaler = StandardScaler()
    scaler.fit(X)
    X_scaled = scaler.transform(X)

    t0 = time.perf_counter()
    model = OneClassSVM(
        kernel="rbf",
        nu=0.01,        # ~1% contamination — matches Gaussian/IF setting
        gamma="scale",  # auto-adjusts kernel to data variance
    )
    model.fit(X_scaled)
    elapsed = time.perf_counter() - t0

    # Compute a reference decision-function threshold on training data.
    # Scores: positive = inside boundary (benign), negative = outside (anomalous).
    train_scores = model.decision_function(X_scaled)
    # Use the 5th percentile of benign scores as the fallback threshold.
    # (validate_models.py overrides this with the ROC-optimal threshold.)
    threshold = float(np.percentile(train_scores, 5))
    train_fpr = float(np.mean(train_scores < threshold))

    logger.info("    Trained in %.1fs on %d samples (%d features)",
                elapsed, len(X), n_features)
    logger.info("    5th-pct score threshold: %.4f  train_FPR: %.3f",
                threshold, train_fpr)

    meta = {
        "algorithm": "OneClassSVM",
        "kernel": "rbf",
        "nu": 0.01,
        "gamma": "scale",
        "n_samples_train": len(X),
        "n_features": n_features,
        "elapsed_s": round(elapsed, 1),
        "score_threshold_5pct": round(threshold, 6),
        "train_fpr_5pct": round(train_fpr, 4),
        "datasets": ["CICIDS-2017"],
        "ticket": "19c — replaces Isolation Forest",
    }
    _save_pkl(
        {"model": model, "scaler": scaler, "threshold": threshold,
         "n_features": n_features},
        "one_class_svm", meta,
    )
    return meta


# =============================================================================
# 2. GAUSSIAN LIKELIHOOD
# =============================================================================

def train_gaussian_likelihood(
    X_benign: np.ndarray,
    max_samples: int = 200_000,
    force: bool = False,
) -> Optional[Dict]:
    _section("Gaussian Likelihood (VAE baseline on real data)")

    out_path = _MODEL_DIR / "gaussian_likelihood.pkl"
    if not force and out_path.exists():
        logger.info("    Skipped — already trained (use --force to retrain)")
        return None

    X = _subsample(X_benign, max_samples)

    scaler = _load_scaler()
    if scaler is not None:
        X = scaler.transform(X)

    t0   = time.perf_counter()
    mean = np.mean(X, axis=0)
    cov  = np.cov(X, rowvar=False)
    cov  += np.eye(cov.shape[0]) * 1e-6

    try:
        cov_inv = np.linalg.inv(cov)
        sign, cov_det_log = np.linalg.slogdet(cov)
        if sign <= 0:
            cov_det_log = 0.0
    except np.linalg.LinAlgError:
        diag_var    = np.var(X, axis=0) + 1e-6
        cov_inv     = np.diag(1.0 / diag_var)
        cov_det_log = float(np.sum(np.log(diag_var)))

    diffs = X - mean
    mahal = np.sqrt(np.maximum(
        np.einsum("ij,jk,ik->i", diffs, cov_inv, diffs), 0.0))
    training_max_dist = max(float(np.percentile(mahal, 99)), 1.0)

    elapsed = time.perf_counter() - t0
    logger.info("    Trained in %.2fs on %d samples", elapsed, len(X))
    logger.info("    99th-pct Mahalanobis: %.4f", training_max_dist)

    meta = {
        "n_samples_train": len(X), "n_features": FEATURE_DIM,
        "elapsed_s": round(elapsed, 2),
        "training_max_mahal_dist": round(training_max_dist, 4),
        "datasets": ["CICIDS-2017", "CIC-UNSW-NB15"],
    }
    _save_pkl(
        {"mean": mean.astype(np.float32), "cov_inv": cov_inv.astype(np.float32),
         "cov_det_log": float(cov_det_log), "training_max_distance": training_max_dist},
        "gaussian_likelihood", meta,
    )
    return meta


# =============================================================================
# 3. LSTM-AUTOENCODER  — class imported from pipeline.lstm_ae_model
# =============================================================================

def train_lstm_ae(
    sequences:   np.ndarray,
    max_samples: int = 100_000,
    epochs:      int = 20,
    force:       bool = False,
) -> Optional[Dict]:
    _section("LSTM-Autoencoder (pure NumPy — pipeline.lstm_ae_model)")

    out_path = _MODEL_DIR / "lstm_autoencoder.pkl"
    if not force and out_path.exists():
        logger.info("    Skipped — already trained (use --force to retrain)")
        return None

    seqs = _subsample(sequences, max_samples)
    T, D = seqs.shape[1], seqs.shape[2]

    model = NumpyLSTMAutoencoder(input_dim=D, hidden_dim=64, latent_dim=32)

    t0    = time.perf_counter()
    stats = model.fit(seqs, epochs=epochs, batch_size=64, lr=0.01)
    elapsed = time.perf_counter() - t0

    logger.info("    Trained in %.1fs", elapsed)

    meta = {
        "input_dim": D, "hidden_dim": 64, "latent_dim": 32,
        "seq_len": T, "n_sequences": len(seqs), "epochs": epochs,
        "elapsed_s": round(elapsed, 1),
        "final_train_mse": round(stats["final_train_mse"], 6),
        "final_val_mse":   round(stats["final_val_mse"],   6),
        "threshold":       round(stats["threshold"],        6),
        "datasets": ["CICIDS-2017"],
    }
    _save_pkl(model, "lstm_autoencoder", meta)
    return meta


# =============================================================================
# 4. BEHAVIOR EMBEDDER
# =============================================================================

def train_behavior_embedder(force: bool = False) -> Optional[Dict]:
    _section("Behavior Embedder (256-dim random projection)")

    out_path = _MODEL_DIR / "behavior_embedder.pkl"
    if not force and out_path.exists():
        logger.info("    Skipped — already exists (use --force to re-init)")
        return None

    INPUT_DIM, HIDDEN_DIM, OUTPUT_DIM, SEED = FEATURE_DIM, 64, 256, 42
    rng   = np.random.RandomState(SEED)
    scale = np.sqrt(2.0 / (INPUT_DIM + OUTPUT_DIM))
    W1    = rng.randn(INPUT_DIM, HIDDEN_DIM).astype(np.float32) * scale
    b1    = np.zeros(HIDDEN_DIM, dtype=np.float32)
    W2    = rng.randn(HIDDEN_DIM, OUTPUT_DIM).astype(np.float32) * scale
    b2    = np.zeros(OUTPUT_DIM, dtype=np.float32)

    meta = {"input_dim": INPUT_DIM, "hidden_dim": HIDDEN_DIM,
            "output_dim": OUTPUT_DIM, "seed": SEED}
    _save_pkl({"W1": W1, "b1": b1, "W2": W2, "b2": b2}, "behavior_embedder", meta)
    logger.info("    W1=%s  W2=%s", W1.shape, W2.shape)
    return meta


# =============================================================================
# REPORT
# =============================================================================

def save_report(metrics: dict) -> None:
    metrics["generated_at"] = datetime.now(timezone.utc).isoformat() + "Z"
    metrics["version"]      = VERSION
    path = _MODEL_DIR / "training_report.json"
    with open(path, "w", encoding="utf-8") as f:
        json.dump(metrics, f, indent=2)
    logger.info("    Training report -> %s", path)


# =============================================================================
# MAIN
# =============================================================================

def main() -> None:
    parser = argparse.ArgumentParser(
        description="HCI-OS Real-Data ML Training — Ticket 19 / 19c"
    )
    parser.add_argument("--ocsvm-only",   action="store_true",
                        help="Train only the One-Class SVM (Ticket 19c)")
    parser.add_argument("--if-only",      action="store_true",
                        help="Train only Isolation Forest (DEPRECATED — kept for reference)")
    parser.add_argument("--gauss-only",   action="store_true")
    parser.add_argument("--lstm-only",    action="store_true")
    parser.add_argument("--embed-only",   action="store_true")
    parser.add_argument("--max-samples",  type=int, default=None,
                        help="Max samples for OC-SVM/IF/Gaussian (default: 100K for OC-SVM)")
    parser.add_argument("--ocsvm-samples", type=int, default=100_000,
                        help="Max samples for OC-SVM training (default: 100000)")
    parser.add_argument("--lstm-samples", type=int, default=None,
                        help="Max sequences for LSTM-AE (default: full dataset)")
    parser.add_argument("--lstm-epochs",  type=int, default=20)
    parser.add_argument("--force",        action="store_true")
    args = parser.parse_args()

    _header("HCI-OS — Real-Data ML Training  (Ticket 19 / 19c)")
    logger.info("Processed data dir   : %s", _PROC_DIR)
    logger.info("Models output dir    : %s", _MODEL_DIR)
    logger.info("OC-SVM max samples   : %s", args.ocsvm_samples)
    logger.info("Max samples (Gauss)  : %s", args.max_samples or "ALL")
    logger.info("Max seqs (LSTM)      : %s", args.lstm_samples or "ALL")
    logger.info("LSTM epochs          : %d", args.lstm_epochs)
    logger.info("Force retrain        : %s", args.force)

    train_all = not any([args.ocsvm_only, args.if_only, args.gauss_only,
                         args.lstm_only, args.embed_only])
    report    = {}
    t_start   = time.perf_counter()

    # ── Load benign data (20-feature) for Gaussian + LSTM-AE ──────────────────────
    benign_parts = []
    for fname in ("cicids_benign", "unsw_benign"):
        arr = _load_processed(fname)
        if arr is not None:
            benign_parts.append(arr)

    if not benign_parts and (train_all or args.gauss_only or args.lstm_only):
        logger.error("No processed benign data in %s", _PROC_DIR)
        logger.error("Run: python pipeline/scripts/preprocess_real_data.py")
        sys.exit(1)

    X_benign = np.vstack(benign_parts) if benign_parts else np.empty((0, FEATURE_DIM), np.float32)
    logger.info("Combined benign samples (20-feat): %d", len(X_benign))

    # ── Load IF-specific benign data (25-feature) ─────────────────────────────
    X_if_benign = _load_processed("cicids_benign_if")
    if X_if_benign is None:
        logger.warning("cicids_benign_if.npy not found — IF will use 20-feature fallback")
        X_if_benign = X_benign    # fallback: use 20-feat data
    else:
        logger.info("IF benign samples (25-feat): %d", len(X_if_benign))

    max_if = args.max_samples or len(X_if_benign)

    # ── One-Class SVM (Ticket 19c PRIMARY detector) ───────────────────────────
    if train_all or args.ocsvm_only:
        # OC-SVM uses the 20-feature benign data (not the 25-feature IF data)
        ocsvm_n = args.max_samples or args.ocsvm_samples
        meta = train_one_class_svm(X_benign, max_samples=ocsvm_n, force=args.force)
        if meta:
            report["one_class_svm"] = meta

    # ── Isolation Forest (DEPRECATED — kept for reference, not used in ensemble) ─
    if args.if_only:
        meta = train_isolation_forest(X_if_benign, max_samples=max_if, force=args.force)
        if meta:
            report["isolation_forest"] = meta

    # ── Gaussian Likelihood ───────────────────────────────────────────────────
    if train_all or args.gauss_only:
        meta = train_gaussian_likelihood(
            X_benign, max_samples=min(max_if, 200_000), force=args.force)
        if meta:
            report["gaussian_likelihood"] = meta

    # ── LSTM-Autoencoder ──────────────────────────────────────────────────────
    if train_all or args.lstm_only:
        seqs = _load_processed("cicids_sequences")
        if seqs is not None and len(seqs) > 0:
            max_seqs = args.lstm_samples or len(seqs)
            meta = train_lstm_ae(
                seqs, max_samples=max_seqs,
                epochs=args.lstm_epochs, force=args.force)
            if meta:
                report["lstm_autoencoder"] = meta
        else:
            logger.warning("cicids_sequences.npy not found — skipping LSTM-AE")

    # ── Behavior Embedder ─────────────────────────────────────────────────────
    if train_all or args.embed_only:
        meta = train_behavior_embedder(force=args.force)
        if meta:
            report["behavior_embedder"] = meta

    # ── Summary ───────────────────────────────────────────────────────────────
    total = time.perf_counter() - t_start
    _header("Training Complete")
    logger.info("Total time: %.1fs", total)
    for f in sorted(_MODEL_DIR.iterdir()):
        logger.info("  %-40s  %.1f KB", f.name, f.stat().st_size / 1024)

    report["total_elapsed_s"] = round(total, 1)
    save_report(report)
    _header("Done — models ready for A4 inference")


if __name__ == "__main__":
    main()
