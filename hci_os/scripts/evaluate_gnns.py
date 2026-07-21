"""
scripts/evaluate_gnns.py
=======================================================
Evaluation script to load trained checkpoints and compute
standard binary classification metrics on the HELD-OUT TEST
SPLIT only (not the training data the model was fit on).
"""

from __future__ import annotations

import logging
import sys
import time
from pathlib import Path
from typing import Dict, List, Tuple

import torch
import torch.nn.functional as F
import numpy as np
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, roc_auc_score

_ROOT = Path(__file__).resolve().parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from stores.neo4j_store import Neo4jStore, get_store
from models.gat        import GAT
from models.graphsage  import GraphSAGE
from models.tgn        import TGN
from scripts.split_utils import load_splits

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(name)s] %(levelname)s %(message)s")
logger = logging.getLogger("evaluate_gnns")

MODELS_DIR = _ROOT / "data" / "models"
DEVICE = torch.device("cuda" if torch.cuda.is_available() else "cpu")


def export_tensors(store: Neo4jStore):
    from scripts.build_and_train_gnn import export_tensors as _export
    return _export(store)


def evaluate_model(
    name: str,
    log_probs: torch.Tensor,
    Y: torch.Tensor,
    mask: torch.Tensor,
) -> Dict[str, float]:
    """Calculate binary classification metrics on the TEST split only."""
    log_probs = log_probs[mask]
    Y_sub = Y[mask]

    probs = torch.exp(log_probs).detach().cpu().numpy()[:, 1]
    preds = log_probs.argmax(dim=1).detach().cpu().numpy()
    y_true = Y_sub.cpu().numpy()

    acc = float(accuracy_score(y_true, preds))
    prec = float(precision_score(y_true, preds, zero_division=0))
    rec = float(recall_score(y_true, preds, zero_division=0))
    f1 = float(f1_score(y_true, preds, zero_division=0))

    try:
        auc = float(roc_auc_score(y_true, probs))
    except ValueError:
        auc = 0.5

    return {
        "Accuracy": acc,
        "Precision": prec,
        "Recall": rec,
        "F1-Score": f1,
        "ROC-AUC": auc,
        "n_test_nodes": int(mask.sum().item()),
        "n_test_attack": int(y_true.sum()),
    }


def main() -> None:
    logger.info("Connecting to Neo4j database...")
    store = get_store()

    X, edge_index, adj, Y, events = export_tensors(store)

    splits_path = MODELS_DIR / "splits.pt"
    if not splits_path.exists():
        logger.error(
            "No splits.pt found at %s. Re-run build_and_train_gnn.py "
            "(the updated version) first -- evaluation without a "
            "held-out split is not a valid measurement.", splits_path,
        )
        return

    train_mask, val_mask, test_mask = load_splits(splits_path)
    logger.info(
        "Evaluating on TEST split only: %d nodes (%d attack nodes)",
        test_mask.sum().item(), Y[test_mask].sum().item(),
    )

    results = {}

    # 1. Evaluate GAT
    gat_path = MODELS_DIR / "gat_model.pt"
    if gat_path.exists():
        logger.info("Evaluating GAT model on held-out test set...")
        checkpoint = torch.load(gat_path, map_location=DEVICE)
        model = GAT(in_channels=checkpoint["in_ch"], hidden_channels=32, out_channels=2).to(DEVICE)
        state = checkpoint.get("model_state_dict", checkpoint.get("model_state"))
        model.load_state_dict(state)
        model.eval()

        with torch.no_grad():
            log_probs, _ = model(X.to(DEVICE), edge_index.to(DEVICE))
            results["GAT"] = evaluate_model("GAT", log_probs, Y, test_mask)
    else:
        logger.warning("GAT model checkpoint not found at %s", gat_path)

    # 2. Evaluate GraphSAGE
    sage_path = MODELS_DIR / "graphsage_model.pt"
    if sage_path.exists():
        logger.info("Evaluating GraphSAGE model on held-out test set...")
        checkpoint = torch.load(sage_path, map_location=DEVICE)
        model = GraphSAGE(in_channels=checkpoint["in_ch"], hidden_channels=32, out_channels=2, sample_size=10).to(DEVICE)
        state = checkpoint.get("model_state_dict", checkpoint.get("model_state"))
        model.load_state_dict(state)
        model.eval()

        with torch.no_grad():
            log_probs, _ = model(X.to(DEVICE), adj)
            results["GraphSAGE"] = evaluate_model("GraphSAGE", log_probs, Y, test_mask)
    else:
        logger.warning("GraphSAGE model checkpoint not found at %s", sage_path)

    # 3. Evaluate TGN
    tgn_path = MODELS_DIR / "tgn_model.pt"
    touched_path = MODELS_DIR / "tgn_touched_mask.pt"
    if tgn_path.exists() and touched_path.exists():
        logger.info("Evaluating TGN model on held-out test set (touched nodes only)...")
        checkpoint = torch.load(tgn_path, map_location=DEVICE)
        model = TGN(num_nodes=checkpoint["num_nodes"], node_feat_dim=checkpoint["in_ch"], memory_dim=32, time_dim=16).to(DEVICE)
        state = checkpoint.get("model_state_dict", checkpoint.get("model_state"))
        model.load_state_dict(state)
        model.eval()

        window = checkpoint.get("window", min(len(events), 20000))
        ev_win = events[:window]
        touched_mask = torch.load(touched_path)["touched_mask"]
        tgn_test_mask = test_mask & touched_mask

        if tgn_test_mask.sum().item() == 0:
            logger.warning(
                "TGN: zero test nodes were touched within the event window -- "
                "cannot honestly report a metric here. Document this as a "
                "known limitation rather than reporting a number."
            )
        else:
            with torch.no_grad():
                log_probs, _ = model(ev_win)
                results["TGN"] = evaluate_model("TGN", log_probs, Y, tgn_test_mask)
    else:
        logger.warning("TGN model/touched-mask checkpoint not found")

    if not results:
        logger.error("No models were successfully evaluated.")
        return

    print("\n" + "="*100)
    print("            GNN MODEL EVALUATION METRICS  (HELD-OUT TEST SET ONLY)")
    print("="*100)
    print(f"{'Model':<15} | {'Accuracy':<10} | {'Precision':<10} | {'Recall':<10} | {'F1':<10} | {'ROC-AUC':<10} | {'TestN':<8} | {'TestAttack':<10}")
    print("-"*100)
    for model_name, metrics in results.items():
        print(f"{model_name:<15} | {metrics['Accuracy']:<10.4f} | {metrics['Precision']:<10.4f} | {metrics['Recall']:<10.4f} | {metrics['F1-Score']:<10.4f} | {metrics['ROC-AUC']:<10.4f} | {metrics['n_test_nodes']:<8} | {metrics['n_test_attack']:<10}")
    print("="*100 + "\n")


if __name__ == "__main__":
    main()