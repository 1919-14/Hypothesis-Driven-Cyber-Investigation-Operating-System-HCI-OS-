"""
scripts/train_all_models.py
HCI-OS - Master ML Training Script

Trains ALL machine learning models used across the pipeline in one shot:

  [A4]  Isolation Forest      - sklearn IsolationForest (generic CICIDS baseline)
  [A4]  Gaussian Likelihood   - Multivariate Gaussian (VAE stub)
  [A4]  Behavior Embedder     - Fixed 2-layer projection (Johnson-Lindenstrauss)
  [A5]  GAT                   - Graph Attention Network (native PyTorch)
  [A5]  TGN                   - Temporal Graph Network (native PyTorch)
  [A5]  GraphSAGE             - Inductive GNN (native PyTorch)

Saved artifacts:
  data/models/isolation_forest.pkl    - scikit-learn model + scaler
  data/models/gaussian_likelihood.pkl - mean + covariance inverse
  data/models/behavior_embedder.pkl   - projection matrices W1, W2
  data/models/gat_model.pt            - GAT weights (PyTorch checkpoint)
  data/models/tgn_model.pt            - TGN weights (PyTorch checkpoint)
  data/models/graphsage_model.pt      - GraphSAGE weights (PyTorch checkpoint)

Usage:
    python scripts/train_all_models.py            # train everything
    python scripts/train_all_models.py --a4-only  # train A4 models only
    python scripts/train_all_models.py --a5-only  # train A5 GNN models only
    python scripts/train_all_models.py --force    # retrain even if models exist
"""

from __future__ import annotations

import argparse
import pickle
import sys
import time
import logging
from datetime import datetime, timezone
from pathlib import Path

import numpy as np

# -- Path Setup ----------------------------------------------------------------
_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_ROOT))

_MODELS_DIR = _ROOT / "data" / "models"
_MODELS_DIR.mkdir(parents=True, exist_ok=True)

logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")
logger = logging.getLogger("train_all_models")

VERSION = "1.0"


# =============================================================================
# UTILITIES
# =============================================================================

def _header(title: str) -> None:
    print(f"\n{'=' * 60}")
    print(f"  {title}")
    print(f"{'=' * 60}")


def _section(title: str) -> None:
    print(f"\n[{'-' * 56}]")
    print(f"  {title}")


def _save_pkl(obj: object, name: str, meta: dict) -> Path:
    """Pickle a model with version metadata."""
    path = _MODELS_DIR / f"{name}.pkl"
    payload = {
        "version": VERSION,
        "name": name,
        "saved_at": datetime.now(timezone.utc).isoformat() + "Z",
        "model": obj,
        **meta,
    }
    with open(path, "wb") as f:
        pickle.dump(payload, f, protocol=pickle.HIGHEST_PROTOCOL)
    size_kb = path.stat().st_size / 1024
    print(f"      Saved -> {path.name} ({size_kb:.1f} KB)")
    return path


def _load_pkl(name: str):
    """Load pickled model. Returns None if not found."""
    path = _MODELS_DIR / f"{name}.pkl"
    if not path.exists():
        return None
    try:
        with open(path, "rb") as f:
            payload = pickle.load(f)
        print(f"      Loaded -> {name}.pkl (version={payload.get('version')}, saved={payload.get('saved_at')[:10]})")
        return payload["model"]
    except Exception as exc:
        logger.warning("Failed to load %s (%s) - will retrain", name, exc)
        return None


# =============================================================================
# A4 - ISOLATION FOREST
# =============================================================================

def train_isolation_forest(X_train: np.ndarray, force: bool = False):
    """Train sklearn IsolationForest + StandardScaler on normal traffic."""
    _section("A4 - Isolation Forest")

    if not force and (_MODELS_DIR / "isolation_forest.pkl").exists():
        print("      Skipped - model exists (use --force to retrain)")
        return

    try:
        from sklearn.ensemble import IsolationForest
        from sklearn.preprocessing import StandardScaler
    except ImportError:
        print("      SKIPPED - scikit-learn not installed")
        return

    t0 = time.perf_counter()
    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X_train)

    model = IsolationForest(
        n_estimators=100,
        contamination=0.05,
        random_state=42,
        n_jobs=-1,
    )
    model.fit(X_scaled)

    elapsed = time.perf_counter() - t0
    print(f"      Trained in {elapsed:.2f}s on {X_train.shape[0]} samples ({X_train.shape[1]} features)")

    _save_pkl(
        {"model": model, "scaler": scaler},
        "isolation_forest",
        {"n_estimators": 100, "n_samples": X_train.shape[0], "n_features": X_train.shape[1]},
    )


# =============================================================================
# A4 - GAUSSIAN LIKELIHOOD (VAE stub)
# =============================================================================

def train_gaussian_likelihood(X_train: np.ndarray, force: bool = False):
    """Fit multivariate Gaussian (mean + covariance) on normal traffic."""
    _section("A4 - Gaussian Likelihood (VAE stub)")

    if not force and (_MODELS_DIR / "gaussian_likelihood.pkl").exists():
        print("      Skipped - model exists (use --force to retrain)")
        return

    t0 = time.perf_counter()

    mean = np.mean(X_train, axis=0)
    cov = np.cov(X_train, rowvar=False)
    cov += np.eye(cov.shape[0]) * 1e-6  # regularization

    try:
        cov_inv = np.linalg.inv(cov)
        sign, cov_det_log = np.linalg.slogdet(cov)
        if sign <= 0:
            cov_det_log = 0.0
    except np.linalg.LinAlgError:
        diag_var = np.var(X_train, axis=0) + 1e-6
        cov_inv = np.diag(1.0 / diag_var)
        cov_det_log = float(np.sum(np.log(diag_var)))

    # Compute max Mahalanobis distance for normalization
    distances = []
    for x in X_train:
        diff = x - mean
        d = float(np.sqrt(max(diff @ cov_inv @ diff, 0.0)))
        distances.append(d)
    training_max_distance = max(float(np.percentile(distances, 99)), 1.0)

    elapsed = time.perf_counter() - t0
    print(f"      Trained in {elapsed:.2f}s | max_mahal_dist={training_max_distance:.2f}")

    _save_pkl(
        {
            "mean": mean,
            "cov_inv": cov_inv,
            "cov_det_log": cov_det_log,
            "training_max_distance": training_max_distance,
        },
        "gaussian_likelihood",
        {"n_samples": X_train.shape[0], "n_features": X_train.shape[1]},
    )


# =============================================================================
# A4 - BEHAVIOR EMBEDDER
# =============================================================================

def train_behavior_embedder(force: bool = False):
    """
    Initialize the 2-layer random projection matrix.

    This is deterministic (seeded) so technically it doesn't need training,
    but we serialize it here so all components load from the same source of truth.
    """
    _section("A4 - Behavior Embedder (256-dim random projection)")

    if not force and (_MODELS_DIR / "behavior_embedder.pkl").exists():
        print("      Skipped - model exists (use --force to retrain)")
        return

    t0 = time.perf_counter()
    INPUT_DIM  = 20
    HIDDEN_DIM = 64
    OUTPUT_DIM = 256
    SEED = 42

    rng = np.random.RandomState(SEED)
    scale = np.sqrt(2.0 / (INPUT_DIM + OUTPUT_DIM))
    W1 = rng.randn(INPUT_DIM, HIDDEN_DIM).astype(np.float32) * scale
    b1 = np.zeros(HIDDEN_DIM, dtype=np.float32)
    W2 = rng.randn(HIDDEN_DIM, OUTPUT_DIM).astype(np.float32) * scale
    b2 = np.zeros(OUTPUT_DIM, dtype=np.float32)

    elapsed = time.perf_counter() - t0
    print(f"      Initialized in {elapsed:.3f}s | W1={W1.shape} W2={W2.shape}")

    _save_pkl(
        {"W1": W1, "b1": b1, "W2": W2, "b2": b2},
        "behavior_embedder",
        {"input_dim": INPUT_DIM, "hidden_dim": HIDDEN_DIM, "output_dim": OUTPUT_DIM, "seed": SEED},
    )


# =============================================================================
# A5 - GNN ENSEMBLE (GAT + TGN + GraphSAGE)
# =============================================================================

def train_gnn_ensemble(force: bool = False):
    """Train all three GNN models via the existing a5_gnn training functions."""
    _section("A5 - GNN Ensemble (GAT + TGN + GraphSAGE)")

    # Check if all three exist
    all_exist = all(
        (_MODELS_DIR / f"{nm}_model.pt").exists()
        for nm in ("gat", "tgn", "graphsage")
    )
    if not force and all_exist:
        print("      Skipped - all GNN models exist (use --force to retrain)")
        return

    from agents.a5_gnn import (
        load_graph, _build_maps, _node_features,
        _train_gat, _train_tgn, _train_sage,
    )

    graph = load_graph()
    if not graph["nodes"]:
        print("      ERROR: asset_graph.json is empty. Aborting GNN training.")
        return

    id2idx, idx2id, node_types = _build_maps(graph)
    x = _node_features(graph, id2idx, node_types)
    N = len(graph["nodes"])

    print(f"      Graph: {N} nodes, {len(graph['edges'])} edges")
    print(f"      Node feature dim: {x.size(1)}")

    # GAT
    t0 = time.perf_counter()
    if force or not (_MODELS_DIR / "gat_model.pt").exists():
        gat = _train_gat(graph, id2idx, node_types, epochs=200)
        gat_params = sum(p.numel() for p in gat.parameters())
        print(f"      GAT   trained in {time.perf_counter() - t0:.1f}s | params={gat_params}")
    else:
        print("      GAT   skipped (exists)")

    # TGN
    t0 = time.perf_counter()
    if force or not (_MODELS_DIR / "tgn_model.pt").exists():
        tgn = _train_tgn(graph, id2idx, node_types, epochs=100)
        tgn_params = sum(p.numel() for p in tgn.parameters())
        print(f"      TGN   trained in {time.perf_counter() - t0:.1f}s | params={tgn_params}")
    else:
        print("      TGN   skipped (exists)")

    # GraphSAGE
    t0 = time.perf_counter()
    if force or not (_MODELS_DIR / "graphsage_model.pt").exists():
        sage = _train_sage(graph, id2idx, node_types, epochs=100)
        sage_params = sum(p.numel() for p in sage.parameters())
        print(f"      SAGE  trained in {time.perf_counter() - t0:.1f}s | params={sage_params}")
    else:
        print("      SAGE  skipped (exists)")


# =============================================================================
# GENERATE TRAINING DATA (A4)
# =============================================================================

def generate_training_data(n_samples: int = 2000) -> np.ndarray:
    """
    Generate synthetic CICIDS-style normal traffic for A4 model training.
    Loaded from a4_anomaly.generate_synthetic_normal_data().
    """
    from agents.a4_anomaly import generate_synthetic_normal_data
    return generate_synthetic_normal_data(n_samples=n_samples, seed=42)


# =============================================================================
# VERIFICATION
# =============================================================================

def verify_models() -> None:
    """Quick sanity check on all saved models."""
    _section("Verification")
    import numpy as np

    errors = []

    # Check pkl files
    for name in ["isolation_forest", "gaussian_likelihood", "behavior_embedder"]:
        path = _MODELS_DIR / f"{name}.pkl"
        if path.exists():
            try:
                with open(path, "rb") as f:
                    payload = pickle.load(f)
                assert "version" in payload
                assert "model" in payload
                print(f"      [OK] {name}.pkl  (version={payload['version']}, {path.stat().st_size // 1024} KB)")
            except Exception as exc:
                errors.append(f"[FAIL] {name}.pkl: {exc}")
                print(f"      [FAIL] {name}.pkl: {exc}")
        else:
            print(f"      - {name}.pkl not found (skipped)")

    # Check pt files
    try:
        import torch
        for name in ["gat_model", "tgn_model", "graphsage_model"]:
            path = _MODELS_DIR / f"{name}.pt"
            if path.exists():
                try:
                    ck = torch.load(str(path), map_location="cpu", weights_only=False)
                    assert "version" in ck
                    print(f"      [OK] {name}.pt  (version={ck['version']}, {path.stat().st_size // 1024} KB)")
                except Exception as exc:
                    errors.append(f"[FAIL] {name}.pt: {exc}")
                    print(f"      [FAIL] {name}.pt: {exc}")
            else:
                print(f"      - {name}.pt not found (skipped)")
    except ImportError:
        print("      - PyTorch not available, skipping GNN verification")

    if errors:
        print(f"\n  VERIFICATION FAILURES: {len(errors)}")
        for e in errors:
            print(f"    {e}")
    else:
        print("\n  All models verified successfully.")


# =============================================================================
# MAIN
# =============================================================================

def main() -> None:
    parser = argparse.ArgumentParser(
        description="HCI-OS Master ML Training Script - trains all pipeline models"
    )
    parser.add_argument("--a4-only", action="store_true", help="Train only A4 models")
    parser.add_argument("--a5-only", action="store_true", help="Train only A5 GNN models")
    parser.add_argument("--force",   action="store_true", help="Retrain all models even if saved")
    parser.add_argument("--samples", type=int, default=2000, help="Normal traffic samples for A4 (default: 2000)")
    args = parser.parse_args()

    _header("HCI-OS - Master ML Training Script")
    print(f"  Models directory : {_MODELS_DIR}")
    print(f"  Force retrain    : {args.force}")
    started_at = datetime.now(timezone.utc)
    t_total = time.perf_counter()

    train_a4 = not args.a5_only
    train_a5 = not args.a4_only

    # ── A4 Models ────────────────--------------------------------------------
    if train_a4:
        _header("A4: Adaptive Anomaly Detector Models")
        print(f"  Generating {args.samples} synthetic CICIDS-normal training samples...")
        t0 = time.perf_counter()
        X_train = generate_training_data(n_samples=args.samples)
        print(f"  Generated in {time.perf_counter() - t0:.2f}s | shape={X_train.shape}")

        train_isolation_forest(X_train, force=args.force)
        train_gaussian_likelihood(X_train, force=args.force)
        train_behavior_embedder(force=args.force)

    # ── A5 GNN Models ────────────────-----------------------------------------
    if train_a5:
        _header("A5: GNN Ensemble Models")
        train_gnn_ensemble(force=args.force)

    # ── Summary ────────────────────────────────-------------------------------
    total_elapsed = time.perf_counter() - t_total
    _header("Training Complete")

    model_files = list(_MODELS_DIR.iterdir())
    total_size_kb = sum(f.stat().st_size for f in model_files if f.is_file()) / 1024

    print(f"  Total time     : {total_elapsed:.1f}s")
    print(f"  Models dir     : {_MODELS_DIR}")
    print(f"  Files saved    : {len(model_files)}")
    print(f"  Total size     : {total_size_kb:.1f} KB")
    print(f"  Started at     : {started_at.strftime('%Y-%m-%d %H:%M:%S')} UTC")
    print()

    for f in sorted(model_files):
        print(f"    {f.name:40s}  {f.stat().st_size // 1024:5d} KB")

    # ── Verification ────────────────────────────────--------------------------
    verify_models()

    print(f"\n{'=' * 60}")
    print("  All HCI-OS ML models are ready.")
    print(f"{'=' * 60}\n")


if __name__ == "__main__":
    main()
