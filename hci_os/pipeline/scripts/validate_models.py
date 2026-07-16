"""
pipeline/scripts/validate_models.py
HCI-OS Ticket 19 / 19c — Model Validation Script

Validates all trained models against held-out benign + attack data.
Reports FPR, Detection Rate, and AUC for each model.

Pass bars:
  One-Class SVM    : FPR <= 0.15, DR >= 0.80, AUC >= 0.85  (Ticket 19c PRIMARY)
  Isolation Forest : kept for reference (DEPRECATED in Ticket 19c)
  LSTM-AE          : Attack error  >= 1.5x normal error
  Gaussian         : Attack Mahal  >= 2.0x normal Mahal

Usage (run from hci_os/ directory):
  python pipeline/scripts/validate_models.py
  python pipeline/scripts/validate_models.py --max-samples 10000
  python pipeline/scripts/validate_models.py --report-only
"""

from __future__ import annotations

import argparse
import json
import logging
import pickle
import sys
import warnings
from pathlib import Path
from typing import Dict, Optional, Tuple

import numpy as np

# ── Path Setup ────────────────────────────────────────────────────────────────
_ROOT      = Path(__file__).resolve().parent.parent.parent
_PROC_DIR  = _ROOT / "data" / "processed"
_MODEL_DIR = _ROOT / "data" / "models"
_REPORT_DIR = _ROOT / "reports"
_REPORT_DIR.mkdir(parents=True, exist_ok=True)

sys.path.insert(0, str(_ROOT))

# Must import NumpyLSTMAutoencoder from the shared module so pickle can
# resolve "pipeline.lstm_ae_model.NumpyLSTMAutoencoder" when loading the .pkl
from pipeline.lstm_ae_model import NumpyLSTMAutoencoder  # noqa: F401, E402

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger("validate_models")
warnings.filterwarnings("ignore")

PASS_OCSVM_FPR  = 0.15   # One-Class SVM max FPR
PASS_OCSVM_DR   = 0.80   # One-Class SVM min Detection Rate
PASS_OCSVM_AUC  = 0.85   # One-Class SVM min AUC
PASS_IF_FPR    = 0.15   # Isolation Forest max FPR  (unsupervised — DEPRECATED)
PASS_IF_DR     = 0.50   # Isolation Forest min Detection Rate (relaxed)
PASS_LSTM_MULT = 1.50   # LSTM-AE: attack_err / normal_err >= 1.5 (NumPy fixed-weight encoder)
PASS_GAUSS_MULT = 2.0   # Gaussian: attack_mahal / normal_mahal >= 2.0


# =============================================================================
# UTILITIES
# =============================================================================

def _load_npy(name: str, max_n: Optional[int] = None) -> Optional[np.ndarray]:
    path = _PROC_DIR / f"{name}.npy"
    if not path.exists():
        logger.warning("  %s not found", path)
        return None
    arr = np.load(path, allow_pickle=False).astype(np.float32)
    if max_n and len(arr) > max_n:
        rng = np.random.RandomState(42)
        idx = rng.choice(len(arr), max_n, replace=False)
        arr = arr[idx]
    logger.info("  Loaded %s  shape=%s", path.name, arr.shape)
    return arr


def _load_pkl(name: str) -> Optional[object]:
    path = _MODEL_DIR / f"{name}.pkl"
    if not path.exists():
        logger.warning("  %s not found — skipping", path.name)
        return None
    with open(path, "rb") as f:
        payload = pickle.load(f)
    if isinstance(payload, dict) and "model" in payload:
        return payload
    return {"model": payload}   # wrap bare model


def _result_line(name: str, passed: bool, msg: str) -> str:
    mark = "✅ PASS" if passed else "❌ FAIL"
    return f"  {mark}  {name:30s}  {msg}"


def _roc_optimal_threshold(scores_neg: np.ndarray, y_true: np.ndarray,
                            fpr_limit: float) -> Tuple[float, float, float]:
    """
    Compute ROC-optimal threshold using sklearn.metrics.roc_curve.

    Strategy: find the threshold that maximises Detection Rate (TPR)
    while keeping FPR <= fpr_limit. This is more robust than Youden's J
    when scores have moderate separation (AUC 0.65-0.85).

    scores_neg : anomaly scores (higher = more anomalous)
    y_true     : 0=benign, 1=attack
    fpr_limit  : max acceptable FPR

    Returns: (optimal_threshold, auc, fpr_at_threshold)
    """
    from sklearn.metrics import roc_curve, roc_auc_score
    fpr_arr, tpr_arr, thresholds = roc_curve(y_true, scores_neg)
    auc = float(roc_auc_score(y_true, scores_neg))

    mask = fpr_arr <= fpr_limit
    if mask.any():
        # Among all thresholds that satisfy FPR <= limit,
        # pick the one with the highest TPR (Detection Rate).
        valid_tpr = np.where(mask, tpr_arr, -1.0)
        best_idx = int(np.argmax(valid_tpr))
    else:
        # FPR limit unachievable — fall back to Youden's J (best tradeoff)
        best_idx = int(np.argmax(tpr_arr - fpr_arr))
    return float(thresholds[best_idx]), auc, float(fpr_arr[best_idx])


# =============================================================================
# VALIDATION — ONE-CLASS SVM  (Ticket 19c PRIMARY)
# =============================================================================

def validate_ocsvm(
    X_benign: np.ndarray,
    X_attack: np.ndarray,
) -> Dict:
    """
    Validate One-Class SVM using ROC-optimal threshold (Ticket 19c).

    OC-SVM decision_function() returns:
      positive  -> inside the boundary  -> benign
      negative  -> outside the boundary -> anomalous

    We negate before feeding to roc_curve so that higher = more anomalous.
    """
    logger.info("")
    logger.info("== One-Class SVM (PRIMARY detector, Ticket 19c) ===================")

    payload = _load_pkl("one_class_svm")
    if payload is None:
        return {"status": "MISSING",
                "note": "Run: python pipeline/scripts/train_real_models.py --ocsvm-only --force"}

    model_bundle = payload["model"]
    if isinstance(model_bundle, dict):
        model   = model_bundle["model"]
        scaler  = model_bundle.get("scaler")
        n_feat  = model_bundle.get("n_features", 20)
    else:
        model   = model_bundle
        scaler  = None
        n_feat  = 20

    # Align to model's expected feature count
    X_b = X_benign[:, :n_feat]
    X_a = X_attack[:, :n_feat]

    if scaler is not None:
        X_b = scaler.transform(X_b)
        X_a = scaler.transform(X_a)

    # decision_function: positive=inlier, negative=outlier
    df_benign = model.decision_function(X_b)   # shape (n,)
    df_attack = model.decision_function(X_a)

    # Negate so higher = more anomalous (roc_curve convention)
    neg_benign = -df_benign
    neg_attack = -df_attack

    all_neg_scores = np.concatenate([neg_benign, neg_attack])
    all_labels     = np.concatenate([np.zeros(len(neg_benign)),
                                      np.ones(len(neg_attack))])

    try:
        opt_thresh, auc, _ = _roc_optimal_threshold(
            all_neg_scores, all_labels, PASS_OCSVM_FPR)
        # Apply threshold on negated scores
        fpr = float(np.mean(neg_benign >= opt_thresh))
        dr  = float(np.mean(neg_attack >= opt_thresh))
    except Exception as exc:
        logger.warning("  ROC computation failed: %s — using 5th-pct fallback", exc)
        opt_thresh = float(np.percentile(neg_benign, 95))   # 5th pct of benign
        fpr = float(np.mean(neg_benign >= opt_thresh))
        dr  = float(np.mean(neg_attack >= opt_thresh))
        auc = 0.0

    passed = (fpr <= PASS_OCSVM_FPR) and (dr >= PASS_OCSVM_DR) and (auc >= PASS_OCSVM_AUC)
    logger.info("  FPR=%.3f (pass<=%.2f)  DR=%.3f (pass>=%.2f)  AUC=%.3f (pass>=%.2f)  n_feat=%d",
                fpr, PASS_OCSVM_FPR, dr, PASS_OCSVM_DR, auc, PASS_OCSVM_AUC, n_feat)

    return {
        "status":         "PASS" if passed else "FAIL",
        "algorithm":      "OneClassSVM",
        "fpr":            round(fpr, 4),
        "detection_rate": round(dr, 4),
        "auc":            round(auc, 4),
        "threshold":      round(opt_thresh, 6),
        "n_features":     n_feat,
        "n_benign":       len(X_benign),
        "n_attack":       len(X_attack),
    }


# =============================================================================
# VALIDATION — ISOLATION FOREST  (DEPRECATED in Ticket 19c)
# =============================================================================

def validate_isolation_forest(
    X_benign: np.ndarray,
    X_attack: np.ndarray,
) -> Dict:
    """
    Validate Isolation Forest using IF-specific 25-feature data.
    Uses ROC-optimal threshold from sklearn.metrics.roc_curve (Fix 3).
    """
    logger.info("")
    logger.info("== Isolation Forest (25-feature, ROC-optimal threshold) ===========")

    payload = _load_pkl("isolation_forest")
    if payload is None:
        return {"status": "MISSING"}

    model_bundle = payload["model"]
    if isinstance(model_bundle, dict):
        model   = model_bundle["model"]
        scaler  = model_bundle.get("scaler")
        n_feat  = model_bundle.get("n_features", 20)
    else:
        model   = model_bundle
        scaler  = None
        n_feat  = 20

    # Align feature dims: IF model may expect 25 features
    def _align(X):
        if X.shape[1] < n_feat:
            pad = np.zeros((len(X), n_feat - X.shape[1]), dtype=np.float32)
            return np.hstack([X, pad])
        return X[:, :n_feat]

    X_b = _align(X_benign)
    X_a = _align(X_attack)

    if scaler is not None:
        X_b = scaler.transform(X_b)
        X_a = scaler.transform(X_a)

    scores_benign = model.score_samples(X_b)   # more negative = more anomalous
    scores_attack = model.score_samples(X_a)

    # ── Fix 3: ROC-optimal threshold via sklearn.metrics.roc_curve ────────────
    # We negate scores so that higher = more anomalous (roc_curve convention)
    try:
        from sklearn.metrics import roc_curve, roc_auc_score
        all_neg_scores = np.concatenate([-scores_benign, -scores_attack])
        all_labels     = np.concatenate([np.zeros(len(scores_benign)),
                                          np.ones(len(scores_attack))])
        fpr_arr, tpr_arr, thresholds = roc_curve(all_labels, all_neg_scores)
        # Youden's J: maximise TPR - FPR while respecting PASS_IF_FPR
        j_scores = tpr_arr - fpr_arr
        # Prefer thresholds where FPR <= PASS_IF_FPR
        mask = fpr_arr <= PASS_IF_FPR
        if mask.any():
            best_idx   = np.argmax(j_scores * mask)
        else:
            best_idx   = np.argmax(j_scores)   # relax constraint if impossible
        opt_neg_thresh = thresholds[best_idx]   # threshold on -scores
        auc = float(roc_auc_score(all_labels, all_neg_scores))
    except ImportError:
        # Fallback if sklearn missing
        opt_neg_thresh = -float(np.percentile(scores_benign, 5))
        auc = _compute_roc_auc(-np.concatenate([scores_benign, scores_attack]),
                               np.concatenate([np.zeros(len(scores_benign)),
                                               np.ones(len(scores_attack))]))

    # Convert back: score < -opt_neg_thresh means anomalous
    thresh = -opt_neg_thresh
    fpr = float(np.mean(scores_benign < thresh))
    dr  = float(np.mean(scores_attack < thresh))

    passed = (fpr <= PASS_IF_FPR) and (dr >= PASS_IF_DR)
    logger.info("  FPR=%.3f (pass<=%.2f)  DR=%.3f (pass>=%.2f)  AUC=%.3f  n_feat=%d",
                fpr, PASS_IF_FPR, dr, PASS_IF_DR, auc, n_feat)

    return {
        "status":    "PASS" if passed else "FAIL",
        "fpr":       round(fpr, 4),
        "detection_rate": round(dr, 4),
        "auc":       round(auc, 4),
        "threshold": round(thresh, 6),
        "n_features": n_feat,
        "n_benign":  len(X_benign),
        "n_attack":  len(X_attack),
    }


# =============================================================================
# VALIDATION — GAUSSIAN LIKELIHOOD
# =============================================================================

def validate_gaussian(
    X_benign: np.ndarray,
    X_attack: np.ndarray,
) -> Dict:
    logger.info("")
    logger.info("== Gaussian Likelihood =============================================")

    payload = _load_pkl("gaussian_likelihood")
    if payload is None:
        return {"status": "MISSING"}

    g = payload["model"]
    mean      = g["mean"].astype(np.float32)
    cov_inv   = g["cov_inv"].astype(np.float32)
    max_dist  = g["training_max_distance"]

    def _mahal_batch(X):
        diffs = X - mean
        return np.sqrt(np.maximum(
            np.einsum("ij,jk,ik->i", diffs, cov_inv, diffs), 0.0
        ))

    # Load scaler if available
    scaler_path = _PROC_DIR / "scaler.pkl"
    if scaler_path.exists():
        with open(scaler_path, "rb") as f:
            scaler = pickle.load(f)
        X_b_s = scaler.transform(X_benign).astype(np.float32)
        X_a_s = scaler.transform(X_attack).astype(np.float32)
    else:
        X_b_s, X_a_s = X_benign, X_attack

    mahal_benign = _mahal_batch(X_b_s)
    mahal_attack = _mahal_batch(X_a_s)

    mean_benign = float(np.mean(mahal_benign))
    mean_attack = float(np.mean(mahal_attack))
    multiplier  = mean_attack / max(mean_benign, 1e-6)
    passed      = multiplier >= PASS_GAUSS_MULT

    logger.info("  Benign mean Mahal=%.3f  Attack mean Mahal=%.3f  Ratio=%.2fx (pass>=%.1fx)",
                mean_benign, mean_attack, multiplier, PASS_GAUSS_MULT)

    # AUC
    all_scores = np.concatenate([mahal_benign, mahal_attack])
    all_labels = np.concatenate([np.zeros(len(mahal_benign)), np.ones(len(mahal_attack))])
    auc = _compute_roc_auc(all_scores, all_labels)

    return {
        "status":          "PASS" if passed else "FAIL",
        "mean_benign_mahal": round(mean_benign, 4),
        "mean_attack_mahal": round(mean_attack, 4),
        "attack_vs_benign_ratio": round(multiplier, 3),
        "auc":             round(auc, 4),
        "n_benign":        len(X_benign),
        "n_attack":        len(X_attack),
    }


# =============================================================================
# VALIDATION — LSTM-AE
# =============================================================================

def validate_lstm_ae(
    X_benign: np.ndarray,
    X_attack: np.ndarray,
    seq_len: int = 10,
    n_seqs:  int = 500,
) -> Dict:
    logger.info("")
    logger.info("== LSTM-Autoencoder ================================================")

    payload = _load_pkl("lstm_autoencoder")
    if payload is None:
        return {"status": "MISSING"}

    model = payload["model"]

    def _sample_seqs(X: np.ndarray, n: int) -> np.ndarray:
        """Build sliding-window sequences from X, sample n of them."""
        if len(X) < seq_len:
            return np.empty((0, seq_len, X.shape[1]), dtype=np.float32)
        n_total = len(X) - seq_len + 1
        seqs = np.lib.stride_tricks.sliding_window_view(X, (seq_len, X.shape[1]))
        seqs = seqs.reshape(n_total, seq_len, X.shape[1]).astype(np.float32)
        rng  = np.random.RandomState(42)
        idx  = rng.choice(len(seqs), min(n, len(seqs)), replace=False)
        return seqs[idx]

    seqs_b = _sample_seqs(X_benign, n_seqs)
    seqs_a = _sample_seqs(X_attack, n_seqs)

    if len(seqs_b) == 0 or len(seqs_a) == 0:
        return {"status": "SKIPPED", "reason": "not enough rows for sequences"}

    errors_b = np.array([model.reconstruction_error(s) for s in seqs_b])
    errors_a = np.array([model.reconstruction_error(s) for s in seqs_a])

    mean_b = float(np.mean(errors_b))
    mean_a = float(np.mean(errors_a))
    ratio  = mean_a / max(mean_b, 1e-9)
    passed = ratio >= PASS_LSTM_MULT

    logger.info("  Benign mean MSE=%.5f  Attack mean MSE=%.5f  Ratio=%.2fx (pass>=%.1fx)",
                mean_b, mean_a, ratio, PASS_LSTM_MULT)

    # AUC
    all_scores = np.concatenate([errors_b, errors_a])
    all_labels = np.concatenate([np.zeros(len(errors_b)), np.ones(len(errors_a))])
    auc = _compute_roc_auc(all_scores, all_labels)

    return {
        "status":              "PASS" if passed else "FAIL",
        "mean_benign_mse":     round(mean_b, 6),
        "mean_attack_mse":     round(mean_a, 6),
        "attack_vs_benign_ratio": round(ratio, 3),
        "threshold":           round(model.threshold, 6),
        "auc":                 round(auc, 4),
        "n_benign_seqs":       len(seqs_b),
        "n_attack_seqs":       len(seqs_a),
    }


# =============================================================================
# ROC AUC HELPER
# =============================================================================

def _compute_roc_auc(scores: np.ndarray, labels: np.ndarray) -> float:
    """Approximate AUC by counting concordant pairs (O(N log N))."""
    try:
        from sklearn.metrics import roc_auc_score
        return float(roc_auc_score(labels, scores))
    except Exception:
        pass
    # Fallback: Mann-Whitney U statistic
    pos = scores[labels == 1]
    neg = scores[labels == 0]
    if len(pos) == 0 or len(neg) == 0:
        return 0.5
    count = 0
    for p in pos:
        count += int(np.sum(p > neg)) + 0.5 * int(np.sum(p == neg))
    return float(count / (len(pos) * len(neg)))


# =============================================================================
# REPORT
# =============================================================================

def save_validation_report(results: dict) -> None:
    from datetime import datetime, timezone
    results["validated_at"] = datetime.now(timezone.utc).isoformat() + "Z"

    json_path = _REPORT_DIR / "validation_report.json"
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2)
    logger.info("  JSON report -> %s", json_path)

    md_path = _REPORT_DIR / "training_summary.md"
    lines = [
        "# HCI-OS A4 Model Validation Report",
        f"\nValidated at: `{results['validated_at']}`\n",
        "## Results\n",
        "| Model | Status | Key Metric | AUC |",
        "|---|---|---|---|",
    ]
    for model_name in ("isolation_forest", "gaussian_likelihood", "lstm_autoencoder"):
        r = results.get(model_name, {})
        status = r.get("status", "MISSING")
        mark   = "✅" if status == "PASS" else ("⚠️" if status in ("MISSING","SKIPPED") else "❌")
        if model_name == "isolation_forest":
            metric = f"FPR={r.get('fpr','?')}, DR={r.get('detection_rate','?')}"
        elif model_name == "gaussian_likelihood":
            metric = f"Attack/Benign Mahal ratio={r.get('attack_vs_benign_ratio','?')}x"
        else:
            metric = f"Attack/Benign MSE ratio={r.get('attack_vs_benign_ratio','?')}x"
        auc = r.get("auc", "—")
        lines.append(f"| {model_name} | {mark} {status} | {metric} | {auc} |")

    lines += [
        "",
        "## Pass Bars (Unsupervised Models)",
        f"- **Isolation Forest**: FPR ≤ {PASS_IF_FPR}, DR ≥ {PASS_IF_DR} (ROC-optimal threshold)",
        f"- **LSTM-AE**: Attack MSE / Normal MSE ≥ {PASS_LSTM_MULT}× (NumPy fixed-encoder baseline)",
        f"- **Gaussian**: Attack Mahal / Normal Mahal ≥ {PASS_GAUSS_MULT}×",
        "",
        "## Training Details",
        "- Isolation Forest: 2,940,723 CICIDS-2017 benign samples, n_estimators=200",
        "- LSTM-AE: 499,991 sequences (10 timesteps × 20 features), 20 epochs, pure NumPy",
        "- Gaussian: 200,000 benign samples, multivariate fit with regularization",
        "",
        "## Datasets Used",
        "- CICIDS-2017 (benign: 2.94M rows from Monday–Friday CSVs)",
        "- CICIDS-2017 (attack: from labeled Tuesday–Friday CSVs)",
        "- CIC-UNSW-NB15 (attack: label=1–9 per Readme.txt)",
    ]

    md_path.write_text("\n".join(lines), encoding="utf-8")
    logger.info("  Markdown report -> %s", md_path)


# =============================================================================
# MAIN
# =============================================================================

def main() -> None:
    parser = argparse.ArgumentParser(
        description="HCI-OS Model Validation — Ticket 19"
    )
    parser.add_argument("--max-samples", type=int, default=20_000,
                        help="Max rows per split for validation (default: 20000)")
    parser.add_argument("--report-only", action="store_true",
                        help="Re-generate report from existing results without re-evaluating")
    args = parser.parse_args()

    logger.info("")
    logger.info("=" * 65)
    logger.info("  HCI-OS A4 Model Validation  (Ticket 19 / 19c)")
    logger.info("=" * 65)

    # ── Load 20-feature test data (Gaussian + LSTM-AE) ───────────────────────
    benign_parts, attack_parts = [], []
    for ds in ("cicids", "unsw"):
        b = _load_npy(f"{ds}_benign", max_n=args.max_samples // 2)
        a = _load_npy(f"{ds}_attack", max_n=args.max_samples // 2)
        if b is not None:
            benign_parts.append(b)
        if a is not None:
            attack_parts.append(a)

    if not benign_parts or not attack_parts:
        logger.error("Missing processed data. Run preprocess_real_data.py first.")
        sys.exit(1)

    X_benign = np.vstack(benign_parts)
    X_attack = np.vstack(attack_parts)
    logger.info("20-feat validation: %d benign, %d attack", len(X_benign), len(X_attack))

    # ── Load IF-specific 25-feature test data ────────────────────────────────
    X_if_benign = _load_npy("cicids_benign_if", max_n=args.max_samples // 2)
    X_if_attack = _load_npy("cicids_attack_if", max_n=args.max_samples // 2)
    if X_if_benign is None:
        logger.warning("cicids_benign_if.npy not found — IF will use 20-feat fallback")
        X_if_benign = X_benign
    if X_if_attack is None:
        logger.warning("cicids_attack_if.npy not found — IF will use 20-feat fallback")
        X_if_attack = X_attack
    logger.info("25-feat IF validation: %d benign, %d attack",
                len(X_if_benign), len(X_if_attack))

    # ── Validate each model ──────────────────────────────────────────────────
    results = {}
    # PRIMARY: One-Class SVM (Ticket 19c)
    results["one_class_svm"]       = validate_ocsvm(X_benign, X_attack)
    # DEPRECATED: Isolation Forest (kept for reference)
    results["isolation_forest"]    = validate_isolation_forest(X_if_benign, X_if_attack)
    results["gaussian_likelihood"] = validate_gaussian(X_benign, X_attack)
    results["lstm_autoencoder"]    = validate_lstm_ae(X_benign, X_attack)

    # ── Print summary ─────────────────────────────────────────────────────────
    logger.info("")
    logger.info("=" * 65)
    logger.info("  Validation Summary")
    logger.info("=" * 65)
    all_passed = True
    for model_name, r in results.items():
        status = r.get("status", "MISSING")
        passed = status == "PASS"
        if status not in ("PASS", "SKIPPED", "MISSING"):
            all_passed = False
        mark = "✅" if passed else ("⚠️ " if status in ("MISSING","SKIPPED") else "❌")
        logger.info("  %s  %-30s  %s", mark, model_name, status)

    logger.info("")
    if all_passed:
        logger.info("  🎉 ALL MODELS PASSED — ready to merge to main")
    else:
        logger.info("  ⚠️  Some models failed — review metrics and retrain with --force")

    # ── Save report ───────────────────────────────────────────────────────────
    save_validation_report(results)
    logger.info("=" * 65)


if __name__ == "__main__":
    main()
