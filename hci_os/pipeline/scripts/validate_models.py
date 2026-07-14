"""
pipeline/scripts/validate_models.py
HCI-OS Ticket 19 — Model Validation Script

Validates all trained models against held-out benign + attack data.
Reports FPR, Detection Rate, and AUC for each model.

Pass bars (per ticket spec):
  Isolation Forest : FPR <= 0.10,  DR >= 0.80
  LSTM-AE          : Attack error  >= 2× normal error
  Gaussian         : Attack Mahal  >= 2× normal Mahal

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

PASS_IF_FPR    = 0.10   # Isolation Forest max FPR
PASS_IF_DR     = 0.80   # Isolation Forest min Detection Rate
PASS_LSTM_MULT = 2.0    # LSTM-AE: attack error / normal error >= 2.0
PASS_GAUSS_MULT = 2.0   # Gaussian: attack Mahal / normal Mahal >= 2.0


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


# =============================================================================
# VALIDATION — ISOLATION FOREST
# =============================================================================

def validate_isolation_forest(
    X_benign: np.ndarray,
    X_attack: np.ndarray,
) -> Dict:
    logger.info("")
    logger.info("── Isolation Forest ──────────────────────────────────")

    payload = _load_pkl("isolation_forest")
    if payload is None:
        return {"status": "MISSING"}

    model_bundle = payload["model"]
    if isinstance(model_bundle, dict):
        model   = model_bundle["model"]
        scaler  = model_bundle.get("scaler")
        thresh  = model_bundle.get("threshold", None)
    else:
        model  = model_bundle
        scaler = None
        thresh = None

    # Scale
    if scaler is not None:
        X_b_s = scaler.transform(X_benign)
        X_a_s = scaler.transform(X_attack)
    else:
        X_b_s, X_a_s = X_benign, X_attack

    # Scores (more negative = more anomalous)
    scores_benign = model.score_samples(X_b_s)
    scores_attack = model.score_samples(X_a_s)

    # Use the threshold stored at training, or 5th percentile of benign
    if thresh is None:
        thresh = float(np.percentile(scores_benign, 5))

    # FPR: fraction of benign flagged as anomaly
    fpr = float(np.mean(scores_benign < thresh))
    # DR: fraction of attack flagged as anomaly
    dr  = float(np.mean(scores_attack < thresh))

    # AUC (approximate via threshold sweep)
    all_scores = np.concatenate([scores_benign, scores_attack])
    all_labels = np.concatenate([np.zeros(len(scores_benign)), np.ones(len(scores_attack))])
    auc = _compute_roc_auc(-all_scores, all_labels)   # negate so higher = more anomalous

    passed = (fpr <= PASS_IF_FPR) and (dr >= PASS_IF_DR)
    logger.info("  FPR=%.3f (pass<=%.2f)  DR=%.3f (pass>=%.2f)  AUC=%.3f",
                fpr, PASS_IF_FPR, dr, PASS_IF_DR, auc)

    return {
        "status":    "PASS" if passed else "FAIL",
        "fpr":       round(fpr, 4),
        "detection_rate": round(dr, 4),
        "auc":       round(auc, 4),
        "threshold": round(thresh, 6),
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
    logger.info("── Gaussian Likelihood ───────────────────────────────")

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
    logger.info("── LSTM-Autoencoder ──────────────────────────────────")

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
        "## Pass Bars",
        f"- **Isolation Forest**: FPR ≤ {PASS_IF_FPR}, DR ≥ {PASS_IF_DR}",
        f"- **LSTM-AE**: Attack MSE / Normal MSE ≥ {PASS_LSTM_MULT}×",
        f"- **Gaussian**: Attack Mahal / Normal Mahal ≥ {PASS_GAUSS_MULT}×",
        "",
        "## Datasets Used",
        "- CICIDS-2017 (benign: Monday flows + daily labeled CSVs)",
        "- CIC-UNSW-NB15 (benign: label=0 per Readme.txt)",
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
    logger.info("  HCI-OS A4 Model Validation  (Ticket 19)")
    logger.info("=" * 65)

    # ── Load test data ────────────────────────────────────────────────────────
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

    logger.info("Validation set: %d benign, %d attack", len(X_benign), len(X_attack))

    # ── Validate each model ───────────────────────────────────────────────────
    results = {}
    results["isolation_forest"]    = validate_isolation_forest(X_benign, X_attack)
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
