"""
scripts/restore_neo4j_from_json.py
=======================================================
Restore script to import the Neo4j Knowledge Graph 
from a structured JSON backup file.
"""

from __future__ import annotations

import json
import logging
import sys
import time
from pathlib import Path

# Ensure hci_os package root is on path
_ROOT = Path(__file__).resolve().parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from dotenv import load_dotenv
# Make sure we load the env file relative to the script
load_dotenv(_ROOT / "hci_os" / ".env")

from stores.neo4j_store import get_store

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(name)s] %(levelname)s %(message)s")
logger = logging.getLogger("restore_neo4j")
# Suppress verbose Neo4j driver / notification logs
logging.getLogger("neo4j").setLevel(logging.WARNING)
logging.getLogger("neo4j.notifications").setLevel(logging.WARNING)


def main() -> None:
    logger.info("Initializing Neo4j store...")
    store = get_store()
    
    if store.use_fallback:
        logger.error("Neo4jStore is running in networkx fallback mode. Cannot write to a live Neo4j database.")
        logger.error("Please verify that Neo4j is running and credentials in hci_os/.env are correct.")
        sys.exit(1)
        
    # Check all possible paths for the backup file
    possible_paths = [
        _ROOT / "hci_os" / "data" / "models" / "neo4j_kg_backup.json" / "neo4j_kg_backup.json",
        _ROOT / "data" / "models" / "neo4j_kg_backup.json" / "neo4j_kg_backup.json",
        Path("c:/Users/sujee/Desktop/Hypothesis-Driven-Cyber-Investigation-Operating-System-HCI-OS-/hci_os/data/models/neo4j_kg_backup.json/neo4j_kg_backup.json"),
    ]
    
    backup_path = None
    for p in possible_paths:
        if p.exists():
            backup_path = p
            break
            
    if not backup_path:
        logger.error("Backup file 'neo4j_kg_backup.json' not found at any expected location:")
        for p in possible_paths:
            logger.error(f"  - {p}")
        sys.exit(1)
        
    logger.info(f"Using backup file: {backup_path}")
    t0 = time.perf_counter()
    with open(backup_path, "r", encoding="utf-8") as f:
        backup_data = json.load(f)
    logger.info(f"Loaded backup file in {time.perf_counter() - t0:.1f}s")
    
    nodes = backup_data.get("nodes", [])
    edges = backup_data.get("edges", [])
    metadata = backup_data.get("metadata", {})
    
    logger.info(f"Backup Metadata: {metadata}")
    logger.info(f"Loaded {len(nodes)} nodes and {len(edges)} edges from backup.")
    
    # 1. Clear database
    logger.info("Clearing existing Neo4j database (DETACH DELETE)...")
    try:
        store.clear()
        logger.info("Existing database cleared successfully.")
    except Exception as exc:
        logger.error(f"Failed to clear database: {exc}")
        sys.exit(1)
        
    # 2. Extract unique labels to create uniqueness constraints
    unique_labels = set()
    for node in nodes:
        for label in node.get("labels", []):
            unique_labels.add(label)
            
    logger.info(f"Creating unique constraints for labels: {sorted(list(unique_labels))}")
    for label in unique_labels:
        try:
            store._run(
                f"CREATE CONSTRAINT IF NOT EXISTS FOR (n:`{label}`) "
                f"REQUIRE n.id IS UNIQUE"
            )
            logger.info(f"Constraint ensured for label: {label}")
        except Exception as exc:
            logger.warning(f"Constraint creation failed for {label}: {exc}")
            
    # 3. Import nodes in batches
    # We group nodes by their label combination to MERGE them efficiently
    nodes_by_labels = {}
    for node in nodes:
        labels_tuple = tuple(sorted(node.get("labels", [])))
        if not labels_tuple:
            continue
        if labels_tuple not in nodes_by_labels:
            nodes_by_labels[labels_tuple] = []
        nodes_by_labels[labels_tuple].append(node)
        
    logger.info("Importing nodes in batches...")
    t_nodes = time.perf_counter()
    total_nodes_imported = 0
    
    for labels, group_nodes in nodes_by_labels.items():
        # Format label string for Cypher query, e.g. :IP:Asset
        labels_str = "".join(f":`{l}`" for l in labels)
        
        # Batch nodes
        batch_size = 500
        for i in range(0, len(group_nodes), batch_size):
            batch = group_nodes[i:i+batch_size]
            batch_data = []
            for n in batch:
                batch_data.append({
                    "id": n["id"],
                    "properties": n.get("properties", {})
                })
                
            query = (
                f"UNWIND $batch_data AS row "
                f"MERGE (n{labels_str} {{id: row.id}}) "
                f"SET n += row.properties"
            )
            try:
                store._run(query, batch_data=batch_data)
                total_nodes_imported += len(batch)
                if total_nodes_imported % 5000 == 0 or total_nodes_imported == len(nodes):
                    logger.info(f"Imported {total_nodes_imported}/{len(nodes)} nodes...")
            except Exception as exc:
                logger.error(f"Error importing node batch for labels {labels}: {exc}")
                
    logger.info(f"Nodes import finished: {total_nodes_imported} nodes in {time.perf_counter() - t_nodes:.1f}s")
    
    # 4. Map of node_id to their primary label (first label) for efficient edge matching
    node_to_label = {}
    for node in nodes:
        if node.get("labels"):
            node_to_label[node["id"]] = node["labels"][0]
            
    # 5. Import edges in batches
    # We group edges by (relationship_type, source_label, target_label)
    edges_by_key = {}
    for edge in edges:
        rel_type = edge["type"]
        src = edge["source"]
        dst = edge["target"]
        
        src_label = node_to_label.get(src)
        dst_label = node_to_label.get(dst)
        
        if not src_label or not dst_label:
            # Fallback if endpoint labels are missing
            src_label = ""
            dst_label = ""
            
        key = (rel_type, src_label, dst_label)
        if key not in edges_by_key:
            edges_by_key[key] = []
        edges_by_key[key].append(edge)
        
    logger.info("Importing relationships in batches...")
    t_edges = time.perf_counter()
    total_edges_imported = 0
    
    for key, group_edges in edges_by_key.items():
        rel_type, src_label, dst_label = key
        
        # If we have labels, specify them in MATCH for maximum speed using indices
        src_match = f"a:`{src_label}`" if src_label else "a"
        dst_match = f"b:`{dst_label}`" if dst_label else "b"
        
        query = (
            f"UNWIND $batch_data AS row "
            f"MATCH ({src_match} {{id: row.source}}), ({dst_match} {{id: row.target}}) "
            f"MERGE (a)-[r:`{rel_type}`]->(b) "
            f"SET r += row.properties"
        )
        
        batch_size = 500
        for i in range(0, len(group_edges), batch_size):
            batch = group_edges[i:i+batch_size]
            batch_data = []
            for e in batch:
                batch_data.append({
                    "source": e["source"],
                    "target": e["target"],
                    "properties": e.get("properties", {})
                })
                
            try:
                store._run(query, batch_data=batch_data)
                total_edges_imported += len(batch)
                if total_edges_imported % 5000 == 0 or total_edges_imported == len(edges):
                    logger.info(f"Imported {total_edges_imported}/{len(edges)} edges...")
            except Exception as exc:
                logger.error(f"Error importing edge batch for key {key}: {exc}")
                
    logger.info(f"Relationships import finished: {total_edges_imported} edges in {time.perf_counter() - t_edges:.1f}s")
    
    logger.info("=" * 60)
    logger.info(f"SUCCESS: Neo4j Knowledge Graph successfully restored!")
    logger.info(f"Total time elapsed: {time.perf_counter() - t0:.1f}s")
    logger.info("=" * 60)
    
    store.close()


if __name__ == "__main__":
    main()
