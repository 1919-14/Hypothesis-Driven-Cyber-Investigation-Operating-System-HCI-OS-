"""
scripts/train_sage_tgn.py
=======================================================
Helper script to train ONLY GraphSAGE and TGN models,
reusing the connection and data pipeline but skipping GAT.
"""

from __future__ import annotations

import logging
import sys
from pathlib import Path

# Ensure hci_os package root is on path
_ROOT = Path(__file__).resolve().parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from stores.neo4j_store import get_store
from scripts.build_and_train_gnn import export_tensors, train_graphsage, train_tgn

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(name)s] %(levelname)s %(message)s")
logger = logging.getLogger("train_sage_tgn")


def main() -> None:
    logger.info("Initializing Neo4j store...")
    store = get_store()
    try:
        # Load and export tensors from the database
        X, edge_index, adj, Y, events = export_tensors(store)
        N = X.size(0)
        
        logger.info("=" * 60)
        logger.info("TRAINING: GraphSAGE and TGN Only (Skipping GAT)")
        logger.info("=" * 60)
        
        # Train only the other two models
        train_graphsage(X, adj, Y)
        train_tgn(X, events, Y, num_nodes=N)
        
        logger.info("GraphSAGE and TGN models trained successfully!")
    finally:
        store.close()


if __name__ == "__main__":
    main()
