"""
scripts/build_and_train_gnn.py
=======================================================
One-shot script: Build all 5 Knowledge Graphs → Train 3 GNNs
with a real, stratified train/val/test split.

Stages
------
1. BUILD GRAPHS   Load all available datasets into Neo4jStore
2. EXPORT TENSORS  Convert Neo4j/networkx graph → PyTorch tensors
3. SPLIT           Stratified train/val/test node masks (NEW)
4. TRAIN GNNS      Train GAT, GraphSAGE, TGN on TRAIN split only,
                    evaluate loss dynamics honestly

Usage
-----
  cd hci_os
  python scripts/build_and_train_gnn.py
  python scripts/build_and_train_gnn.py --skip-build   # retrain only
  python scripts/build_and_train_gnn.py --skip-train   # rebuild graph only
"""

from __future__ import annotations

import argparse
import logging
import sys
import time
from pathlib import Path
from typing import Dict, List, Tuple, Any

_ROOT = Path(__file__).resolve().parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

import torch.utils._pytree as _pytree
if hasattr(_pytree, "_register_pytree_node"):
    orig_register = _pytree._register_pytree_node
    def patched_register(typ, to_flat_fn, from_flat_fn, *args, **kwargs):
        kwargs.pop("serialized_type_name", None)
        return orig_register(typ, to_flat_fn, from_flat_fn, *args, **kwargs)
    _pytree.register_pytree_node = patched_register
    _pytree._register_pytree_node = patched_register

import torch
import torch.nn.functional as F

from stores.neo4j_store import Neo4jStore, get_store
from models.gat        import GAT
from models.graphsage  import GraphSAGE
from models.tgn        import TGN
from scripts.split_utils import make_stratified_masks, touched_node_mask, save_splits

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(name)s] %(levelname)s %(message)s")
logger = logging.getLogger("build_and_train_gnn")

MODELS_DIR = _ROOT / "data" / "models"
MODELS_DIR.mkdir(parents=True, exist_ok=True)

DEVICE = torch.device("cuda" if torch.cuda.is_available() else "cpu")
logger.info("Using device: %s", DEVICE)


# =============================================================================
# STAGE 1 — BUILD GRAPHS
# =============================================================================

def build_graphs(store: Neo4jStore) -> None:
    logger.info("=" * 60)
    logger.info("STAGE 1: Building Knowledge Graphs from real datasets")
    logger.info("=" * 60)

    logger.info("--- Entity/Infrastructure Graph: asset_graph.json ---")
    n = store.import_from_asset_json()
    logger.info("Inserted %d asset nodes", n)

    logger.info("--- Entity Graph: LANL redteam.txt (750 events) ---")
    n = store.import_redteam_events(limit=750)
    logger.info("Inserted %d red-team edges", n)

    logger.info("--- Threat Graph: enterprise-attack.json (500 objects) ---")
    n = store.import_mitre_stix(limit=500)
    logger.info("Inserted %d MITRE objects", n)

    logger.info("--- Evidence Graph: DAPT2020 CSVs (5000 rows/file) ---")
    n = store.import_dapt_flows(limit_per_file=5000)
    logger.info("Inserted %d DAPT flow edges", n)

    logger.info("--- Decision/OT Graph: SWaT logs (5000 rows/file) ---")
    n = store.import_swat_logs(limit=5000)
    logger.info("Inserted %d SWaT sensor rows", n)

    logger.info("--- Flow Graph: LANL flows.txt (5000 lines) ---")
    n = store.import_lanl_flows()
    logger.info("Inserted %d LANL flow edges", n)

    logger.info("--- Evidence Graph: UNSW-NB15 / CICIDS TrafficLabelling (2000 rows/file) ---")
    n = store.import_cicids_flows()
    logger.info("Inserted %d CICIDS flow edges", n)

    logger.info(
        "Graph build complete → %d nodes, %d edges",
        store.get_node_count(), store.get_edge_count(),
    )


# =============================================================================
# STAGE 2 — EXPORT TENSORS
# =============================================================================

def export_tensors(
    store: Neo4jStore,
) -> Tuple[torch.Tensor, torch.Tensor, Dict[int, List[int]], torch.Tensor, List[Tuple[int,int,float]]]:
    """
    Convert graph store to PyTorch tensors.

    Returns
    -------
    X          : [N, F] float  node features
    edge_index : [2, E] long   directed edges
    adj        : {i: [j,...]}  adjacency list
    Y          : [N] long      node labels (0=benign, 1=attack)
    events     : [(src,dst,t)] temporal event list for TGN
    """
    logger.info("=" * 60)
    logger.info("STAGE 2: Exporting graph tensors")
    logger.info("=" * 60)

    cyto = store.get_cytoscape_elements()
    nodes = cyto["nodes"]
    edges = cyto["edges"]

    if not nodes:
        raise RuntimeError("Graph is empty! Run build_graphs first.")

    node_ids = [n["data"]["id"] for n in nodes]
    id2idx   = {nid: i for i, nid in enumerate(node_ids)}
    N        = len(node_ids)
    F_DIM    = 8

    X = torch.zeros(N, F_DIM, dtype=torch.float32)
    Y = torch.zeros(N, dtype=torch.long)

    NODE_TYPE_MAP = {
        "computer": 0, "ip": 1, "user": 2, "technique": 3,
        "tactic": 4, "threatgroup": 5, "otsensor": 6, "asset": 7,
    }

    for i, n in enumerate(nodes):
        d     = n["data"]
        ntype = str(d.get("type", "asset")).lower()
        type_idx = NODE_TYPE_MAP.get(ntype, 7)
        X[i, 0] = type_idx / 8.0
        X[i, 1] = float(d.get("criticality", 0.5))
        X[i, 2] = float(d.get("feat_cpu_load", 0.0))
        X[i, 3] = float(d.get("feat_network_traffic_mbps", 0.0)) / 1500.0
        X[i, 4] = float(d.get("feat_open_connections", 0.0))    / 1000.0
        X[i, 5] = 1.0 if d.get("source") == "LANL"  else 0.0
        X[i, 6] = 1.0 if d.get("source") == "DAPT2020" else 0.0
        X[i, 7] = 1.0 if d.get("source") == "SWaT"   else 0.0

    src_list, dst_list = [], []
    adj: Dict[int, List[int]] = {i: [] for i in range(N)}
    events: List[Tuple[int, int, float]] = []

    for e in edges:
        d   = e["data"]
        src = id2idx.get(d.get("source", ""))
        dst = id2idx.get(d.get("target", ""))
        if src is None or dst is None:
            continue

        src_list.append(src)
        dst_list.append(dst)
        adj[src].append(dst)
        adj[dst].append(src)

        if int(d.get("label", 0)) == 1:
            Y[dst] = 1

        t_sec = float(d.get("time_sec", 0.0))
        events.append((src, dst, t_sec))

    edge_index = torch.tensor([src_list, dst_list], dtype=torch.long)
    events.sort(key=lambda x: x[2])

    logger.info(
        "Tensors: N=%d nodes, E=%d edges, attack_nodes=%d, events=%d",
        N, edge_index.size(1), int(Y.sum().item()), len(events),
    )
    return X, edge_index, adj, Y, events


# =============================================================================
# STAGE 3 — TRAIN GNNs (train-split only; no leakage into eval)
# =============================================================================

def train_gat(X: torch.Tensor, edge_index: torch.Tensor, Y: torch.Tensor, train_mask: torch.Tensor) -> None:
    logger.info("--- Training GAT (train-split only) ---")
    in_ch  = X.size(1)
    model  = GAT(in_channels=in_ch, hidden_channels=32, out_channels=2).to(DEVICE)
    opt    = torch.optim.Adam(model.parameters(), lr=0.005, weight_decay=5e-4)
    X_d    = X.to(DEVICE)
    E_d    = edge_index.to(DEVICE)
    Y_d    = Y.to(DEVICE)
    mask_d = train_mask.to(DEVICE)

    from tqdm import tqdm
    epochs = 100
    t0     = time.time()
    pbar   = tqdm(range(1, epochs + 1), desc="GAT Training")
    for epoch in pbar:
        model.train()
        opt.zero_grad()
        log_probs, _ = model(X_d, E_d)
        loss = F.nll_loss(log_probs[mask_d], Y_d[mask_d])
        loss.backward()
        opt.step()
        pbar.set_postfix({"loss": f"{loss.item():.4f}"})
        if epoch % 20 == 0:
            logger.info("  GAT epoch %d/%d  loss=%.4f", epoch, epochs, loss.item())

    elapsed = time.time() - t0
    logger.info("GAT training done in %.1fs", elapsed)

    out_path = MODELS_DIR / "gat_model.pt"
    torch.save({
        "model_state": model.state_dict(),
        "model_state_dict": model.state_dict(),
        "in_ch": in_ch,
        "version": "1.1-split",
        "saved_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }, out_path)
    logger.info("GAT saved -> %s", out_path)


def train_graphsage(
    X: torch.Tensor,
    adj: Dict[int, List[int]],
    Y: torch.Tensor,
    train_mask: torch.Tensor,
) -> None:
    logger.info("--- Training GraphSAGE (train-split only) ---")
    in_ch  = X.size(1)
    model  = GraphSAGE(in_channels=in_ch, hidden_channels=32, out_channels=2, sample_size=10).to(DEVICE)
    opt    = torch.optim.Adam(model.parameters(), lr=0.005, weight_decay=5e-4)
    X_d    = X.to(DEVICE)
    Y_d    = Y.to(DEVICE)
    mask_d = train_mask.to(DEVICE)

    y_train = Y_d[mask_d]
    num_benign = max(1, (y_train == 0).sum().item())
    num_attack = max(1, (y_train == 1).sum().item())
    weights = torch.tensor([1.0, float(num_benign) / float(num_attack)], device=DEVICE)

    from tqdm import tqdm
    epochs = 100
    t0     = time.time()
    pbar   = tqdm(range(1, epochs + 1), desc="GraphSAGE Training")
    for epoch in pbar:
        model.train()
        opt.zero_grad()
        log_probs, _ = model(X_d, adj)
        loss = F.nll_loss(log_probs[mask_d], y_train, weight=weights)
        loss.backward()
        opt.step()
        pbar.set_postfix({"loss": f"{loss.item():.4f}"})
        if epoch % 20 == 0:
            logger.info("  SAGE epoch %d/%d  loss=%.4f", epoch, epochs, loss.item())

    elapsed = time.time() - t0
    logger.info("GraphSAGE training done in %.1fs", elapsed)

    out_path = MODELS_DIR / "graphsage_model.pt"
    torch.save({
        "model_state": model.state_dict(),
        "model_state_dict": model.state_dict(),
        "in_ch": in_ch,
        "version": "1.1-split",
        "saved_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }, out_path)
    logger.info("GraphSAGE saved -> %s", out_path)


def train_tgn(
    X: torch.Tensor,
    events: List[Tuple[int, int, float]],
    Y: torch.Tensor,
    num_nodes: int,
    train_mask: torch.Tensor,
) -> torch.Tensor:
    """Returns touched_mask so evaluate_gnns.py can reuse the same
    definition of 'nodes this model actually had a chance to learn about'."""
    logger.info("--- Training TGN (train-split + touched-nodes only) ---")
    in_ch   = X.size(1)
    model   = TGN(num_nodes=num_nodes, node_feat_dim=in_ch, memory_dim=32, time_dim=16).to(DEVICE)
    opt     = torch.optim.Adam(model.parameters(), lr=0.005)
    Y_d     = Y.to(DEVICE)
    mask_d  = train_mask.to(DEVICE)

    # Larger window than before (was 2000) to cover more of the graph.
    window  = min(len(events), 10000)
    ev_win  = events[:window]

    # CRITICAL FIX: only nodes actually touched by an event in this
    # window ever get their memory updated. Scoring untouched nodes
    # (zero-init memory) against real labels caused the near-random
    # 0.118 accuracy / 0.0036 precision result seen previously.
    touched = touched_node_mask(ev_win, num_nodes).to(DEVICE)
    eff_mask = mask_d & touched

    if eff_mask.sum().item() < 2 or Y_d[eff_mask].unique().numel() < 2:
        logger.warning(
            "TGN: too few touched+train nodes with both classes (%d nodes). "
            "Consider raising `window` above, or report this honestly as "
            "a documented limitation rather than forcing a number.",
            int(eff_mask.sum().item()),
        )

    y_eff = Y_d[eff_mask]
    num_benign = max(1, (y_eff == 0).sum().item())
    num_attack = max(1, (y_eff == 1).sum().item())
    weights = torch.tensor([1.0, float(num_benign) / float(num_attack)], device=DEVICE)

    from tqdm import tqdm
    epochs = 50
    t0     = time.time()
    pbar   = tqdm(range(1, epochs + 1), desc="TGN Training")
    for epoch in pbar:
        model.train()
        opt.zero_grad()
        log_probs, _ = model(ev_win)
        loss = F.nll_loss(log_probs[eff_mask], y_eff, weight=weights)
        loss.backward()
        opt.step()
        pbar.set_postfix({"loss": f"{loss.item():.4f}"})
        if epoch % 10 == 0:
            logger.info("  TGN epoch %d/%d  loss=%.4f", epoch, epochs, loss.item())

    elapsed = time.time() - t0
    logger.info("TGN training done in %.1fs", elapsed)

    out_path = MODELS_DIR / "tgn_model.pt"
    torch.save({
        "model_state": model.state_dict(),
        "model_state_dict": model.state_dict(),
        "in_ch":       in_ch,
        "num_nodes":   num_nodes,
        "window":      window,
        "version": "1.1-split",
        "saved_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }, out_path)
    logger.info("TGN saved -> %s", out_path)
    return touched.cpu()


def train_all(
    X: torch.Tensor,
    edge_index: torch.Tensor,
    adj: Dict[int, List[int]],
    Y: torch.Tensor,
    events: List[Tuple[int, int, float]],
) -> None:
    logger.info("=" * 60)
    logger.info("STAGE 3: Training 3 GNNs (with held-out test split)")
    logger.info("=" * 60)
    N = X.size(0)

    train_mask, val_mask, test_mask = make_stratified_masks(Y, seed=42)
    logger.info(
        "Split sizes -> train=%d val=%d test=%d | attack nodes: train=%d val=%d test=%d",
        train_mask.sum().item(), val_mask.sum().item(), test_mask.sum().item(),
        Y[train_mask].sum().item(), Y[val_mask].sum().item(), Y[test_mask].sum().item(),
    )
    save_splits(MODELS_DIR / "splits.pt", train_mask, val_mask, test_mask)

    train_gat(X, edge_index, Y, train_mask)
    train_graphsage(X, adj, Y, train_mask)
    touched_mask = train_tgn(X, events, Y, num_nodes=N, train_mask=train_mask)
    torch.save({"touched_mask": touched_mask}, MODELS_DIR / "tgn_touched_mask.pt")

    logger.info("All 3 GNN models trained and saved to %s", MODELS_DIR)


# =============================================================================
# MAIN
# =============================================================================

def main() -> None:
    parser = argparse.ArgumentParser(description="Build KG graphs and train GNNs")
    parser.add_argument("--skip-build",  action="store_true", help="Skip graph build (use existing graph)")
    parser.add_argument("--skip-train",  action="store_true", help="Skip GNN training")
    parser.add_argument("--clear-first", action="store_true", help="Clear existing graph before build")
    args = parser.parse_args()

    store = get_store()
    try:
        if not args.skip_build:
            if args.clear_first:
                logger.warning("Clearing existing graph data...")
                store.clear()
            build_graphs(store)

        if not args.skip_train:
            X, edge_index, adj, Y, events = export_tensors(store)
            train_all(X, edge_index, adj, Y, events)
    finally:
        store.close()

    logger.info("Done.")


if __name__ == "__main__":
    main()