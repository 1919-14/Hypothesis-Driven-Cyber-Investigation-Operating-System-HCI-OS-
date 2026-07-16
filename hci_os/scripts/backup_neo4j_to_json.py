"""
scripts/backup_neo4j_to_json.py
=======================================================
Backup script to export the entire Neo4j Knowledge Graph 
into a structured JSON backup file for future restoration.
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

from stores.neo4j_store import get_store

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(name)s] %(levelname)s %(message)s")
logger = logging.getLogger("backup_neo4j")


def main() -> None:
    logger.info("Connecting to Neo4j database...")
    store = get_store()
    
    nodes = []
    edges = []
    
    try:
        with store.driver.session(database=store.database) as session:
            logger.info("Fetching all nodes...")
            # Retrieve all nodes
            result = session.run("MATCH (n) RETURN id(n) AS internal_id, labels(n) AS labels, n")
            for record in result:
                node_obj = record["n"]
                labels = list(record["labels"])
                properties = dict(node_obj.items())
                
                # Check for 'id' property, fallback to internal_id
                node_id = properties.get("id", str(record["internal_id"]))
                
                nodes.append({
                    "id": node_id,
                    "internal_id": record["internal_id"],
                    "labels": labels,
                    "properties": properties
                })
                
            logger.info("Fetching all relationships...")
            # Retrieve all relationships
            result = session.run(
                "MATCH (a)-[r]->(b) "
                "RETURN id(r) AS rel_id, type(r) AS rel_type, a.id AS src, b.id AS dst, r"
            )
            for record in result:
                rel_obj = record["r"]
                properties = dict(rel_obj.items())
                
                src_id = record["src"]
                dst_id = record["dst"]
                
                edges.append({
                    "id": record["rel_id"],
                    "type": record["rel_type"],
                    "source": src_id,
                    "target": dst_id,
                    "properties": properties
                })
                
        backup_path = _ROOT / "data" / "neo4j_kg_backup.json"
        
        backup_data = {
            "metadata": {
                "exported_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                "node_count": len(nodes),
                "edge_count": len(edges)
            },
            "nodes": nodes,
            "edges": edges
        }
        
        logger.info("Writing backup to JSON file...")
        with open(backup_path, "w", encoding="utf-8") as f:
            json.dump(backup_data, f, indent=2, ensure_ascii=False)
            
        logger.info("=" * 60)
        logger.info("SUCCESS: Neo4j Knowledge Graph successfully exported!")
        logger.info("Saved %d nodes and %d edges.", len(nodes), len(edges))
        logger.info("Backup File: %s", backup_path)
        logger.info("=" * 60)
        
    finally:
        store.close()


if __name__ == "__main__":
    main()
