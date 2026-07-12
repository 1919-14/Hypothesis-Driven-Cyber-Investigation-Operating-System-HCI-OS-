"""
scripts/train_gnns.py
Pre-training script for HCI-OS GNN Ensemble (GAT + TGN + GraphSAGE).

Run once before starting the server:
    python scripts/train_gnns.py

This script:
  1. Loads data/asset_graph.json
  2. Generates synthetic 7-day temporal events
  3. Trains GAT (200 epochs), TGN (100 epochs), GraphSAGE (100 epochs)
  4. Saves models to data/models/ with version metadata (Gap #1)

Gap Fixes applied:
  #1  Saves version + metadata with checkpoints
  #2  Exact ISO-8601 timestamp format on edges
  #7  Per-GNN label generation
  #10 Reports model size + training time
"""

from __future__ import annotations

import sys
import time
import logging
from pathlib import Path

# Add hci_os root to path
_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_ROOT))

from agents.a5_gnn import (
    load_graph, _build_maps, _node_features, _edge_index,
    _adj_dict, _temporal_events, _labels, _train_gat, _train_tgn, _train_sage,
)

logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")
logger = logging.getLogger("train_gnns")


def main():
    print("=" * 60)
    print("HCI-OS GNN Ensemble — Pre-Training Script")
    print("=" * 60)

    t_total = time.perf_counter()

    graph = load_graph()
    if not graph["nodes"]:
        print("ERROR: asset_graph.json is empty. Aborting.")
        sys.exit(1)

    id2idx, idx2id, node_types = _build_maps(graph)
    N = len(graph["nodes"])
    x = _node_features(graph, id2idx, node_types)
    events = _temporal_events(graph, id2idx)

    print(f"\nGraph: {N} nodes, {len(graph['edges'])} edges, {len(events)} temporal events")
    print(f"Node feature dim: {x.size(1)}")
    print(f"Attack path: {graph.get('metadata', {}).get('attack_path', [])}")

    # ── Train GAT ──────────────────────────────────────────────────────────────
    print("\n[1/3] Training GAT (200 epochs)...")
    t0 = time.perf_counter()
    gat = _train_gat(graph, id2idx, node_types, epochs=200)
    gat_time = time.perf_counter() - t0
    gat_params = sum(p.numel() for p in gat.parameters())
    print(f"      Done in {gat_time:.1f}s | params={gat_params}")

    # ── Train TGN ──────────────────────────────────────────────────────────────
    print("[2/3] Training TGN (100 epochs)...")
    t0 = time.perf_counter()
    tgn = _train_tgn(graph, id2idx, node_types, epochs=100)
    tgn_time = time.perf_counter() - t0
    tgn_params = sum(p.numel() for p in tgn.parameters())
    print(f"      Done in {tgn_time:.1f}s | params={tgn_params}")

    # ── Train GraphSAGE ────────────────────────────────────────────────────────
    print("[3/3] Training GraphSAGE (100 epochs)...")
    t0 = time.perf_counter()
    sage = _train_sage(graph, id2idx, node_types, epochs=100)
    sage_time = time.perf_counter() - t0
    sage_params = sum(p.numel() for p in sage.parameters())
    print(f"      Done in {sage_time:.1f}s | params={sage_params}")

    total_time = time.perf_counter() - t_total
    print("\n" + "=" * 60)
    print("Training complete!")
    print(f"  Total time : {total_time:.1f}s")
    print(f"  Models saved to: data/models/")
    print(f"  GAT  : {gat_params} params, {gat_time:.1f}s")
    print(f"  TGN  : {tgn_params} params, {tgn_time:.1f}s")
    print(f"  SAGE : {sage_params} params, {sage_time:.1f}s")
    print("=" * 60)


if __name__ == "__main__":
    main()
