"""
scripts/evaluate_gnns.py
=======================================================
Evaluation script to load trained checkpoints and compute
standard binary classification metrics on anomaly/attack detection.
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

# Ensure hci_os package root on path
_ROOT = Path(__file__).resolve().parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from stores.neo4j_store import Neo4jStore, get_store
from models.gat        import GAT
from models.graphsage  import GraphSAGE
from models.tgn        import TGN

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(name)s] %(levelname)s %(message)s")
logger = logging.getLogger("evaluate_gnns")

MODELS_DIR = _ROOT / "data" / "models"
DEVICE = torch.device("cuda" if torch.cuda.is_available() else "cpu")


def export_tensors(store: Neo4jStore):
    """Import and execute the export tensor function from build_and_train_gnn."""
    from scripts.build_and_train_gnn import export_tensors as _export
    return _export(store)


def evaluate_model(
    name: str,
    log_probs: torch.Tensor,
    Y: torch.Tensor,
) -> Dict[str, float]:
    """Calculate binary classification metrics."""
    # Convert log probs to probabilities and predictions
    probs = torch.exp(log_probs).detach().cpu().numpy()[:, 1]  # positive class probability
    preds = log_probs.argmax(dim=1).detach().cpu().numpy()
    y_true = Y.cpu().numpy()

    acc = accuracy_score(y_true, preds)
    # Use zero_division parameter to handle cases with no predicted/true positive classes gracefully
    prec = precision_score(y_true, preds, zero_division=0)
    rec = recall_score(y_true, preds, zero_division=0)
    f1 = f1_score(y_true, preds, zero_division=0)
    
    try:
        auc = roc_auc_score(y_true, probs)
    except ValueError:
        auc = 0.5  # default if only one class is present in y_true

    return {
        "Accuracy": acc,
        "Precision": prec,
        "Recall": rec,
        "F1-Score": f1,
        "ROC-AUC": auc,
    }


def main() -> None:
    logger.info("Connecting to Neo4j database...")
    store = get_store()
    
    # Load graph data
    X, edge_index, adj, Y, events = export_tensors(store)
    
    results = {}
    
    # 1. Evaluate GAT
    gat_path = MODELS_DIR / "gat.pt"
    if gat_path.exists():
        logger.info("Evaluating GAT model...")
        checkpoint = torch.load(gat_path, map_location=DEVICE)
        model = GAT(in_channels=checkpoint["in_ch"], hidden_channels=32, out_channels=2).to(DEVICE)
        model.load_state_dict(checkpoint["model_state"])
        model.eval()
        
        with torch.no_grad():
            log_probs, _ = model(X.to(DEVICE), edge_index.to(DEVICE))
            results["GAT"] = evaluate_model("GAT", log_probs, Y)
    else:
        logger.warning("GAT model checkpoint not found at %s", gat_path)

    # 2. Evaluate GraphSAGE
    sage_path = MODELS_DIR / "graphsage.pt"
    if sage_path.exists():
        logger.info("Evaluating GraphSAGE model...")
        checkpoint = torch.load(sage_path, map_location=DEVICE)
        model = GraphSAGE(in_channels=checkpoint["in_ch"], hidden_channels=32, out_channels=2, sample_size=10).to(DEVICE)
        model.load_state_dict(checkpoint["model_state"])
        model.eval()
        
        with torch.no_grad():
            # Sage takes a dictionary adjacency format
            log_probs, _ = model(X.to(DEVICE), adj)
            results["GraphSAGE"] = evaluate_model("GraphSAGE", log_probs, Y)
    else:
        logger.warning("GraphSAGE model checkpoint not found at %s", sage_path)

    # 3. Evaluate TGN
    tgn_path = MODELS_DIR / "tgn.pt"
    if tgn_path.exists():
        logger.info("Evaluating TGN model...")
        checkpoint = torch.load(tgn_path, map_location=DEVICE)
        model = TGN(num_nodes=checkpoint["num_nodes"], node_feat_dim=checkpoint["in_ch"], memory_dim=32, time_dim=16).to(DEVICE)
        model.load_state_dict(checkpoint["model_state"])
        model.eval()
        
        # Use window of events
        window = min(len(events), 2000)
        ev_win = events[:window]
        
        with torch.no_grad():
            log_probs, _ = model(ev_win)
            results["TGN"] = evaluate_model("TGN", log_probs, Y)
    else:
        logger.warning("TGN model checkpoint not found at %s", tgn_path)

    # Output beautiful results table
    if not results:
        logger.error("No models were successfully evaluated.")
        return

    print("\n" + "="*80)
    print("                      GNN MODEL EVALUATION METRICS")
    print("="*80)
    print(f"{'Model':<15} | {'Accuracy':<10} | {'Precision':<10} | {'Recall':<10} | {'F1-Score':<10} | {'ROC-AUC':<10}")
    print("-"*80)
    for model_name, metrics in results.items():
        print(f"{model_name:<15} | {metrics['Accuracy']:<10.4f} | {metrics['Precision']:<10.4f} | {metrics['Recall']:<10.4f} | {metrics['F1-Score']:<10.4f} | {metrics['ROC-AUC']:<10.4f}")
    print("="*80 + "\n")


if __name__ == "__main__":
    main()
