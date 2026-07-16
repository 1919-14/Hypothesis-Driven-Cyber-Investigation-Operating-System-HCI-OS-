"""
stores/neo4j_store.py
Neo4j Store — DS3: 5 Knowledge Graphs

Manages the 5 typed subgraphs inside the hcios Neo4j database:
  - Entity Graph       : Users, Computers, Processes
  - Infrastructure Graph: Subnets, Segments, Zones
  - Threat Graph       : MITRE ATT&CK Techniques, Tactics, Groups
  - Evidence Graph     : Evidence nodes linked to hypotheses
  - Decision Graph     : SOAR decisions, playbooks, outcomes

Dual-mode:
  LIVE     — neo4j Python driver + Cypher (requires NEO4J_* env vars)
  FALLBACK — networkx.MultiDiGraph in-memory (no install needed)

Used by: A5 (GNN input), A6 (threat traversal), /api/gnn/visualization
"""

from __future__ import annotations

import json
import logging
import os
from pathlib import Path
from typing import Any, Dict, List, Optional

import networkx as nx

from dotenv import load_dotenv
load_dotenv()

logger = logging.getLogger("Neo4jStore")

# ── Optional driver import ────────────────────────────────────────────────────
try:
    from neo4j import GraphDatabase
    _HAS_NEO4J = True
except ImportError:
    _HAS_NEO4J = False
    logger.warning("Neo4jStore: 'neo4j' package not installed — fallback mode only.")

# ── Dataset paths ─────────────────────────────────────────────────────────────
_DATA_DIR = Path(__file__).resolve().parent.parent / "data"
_GNN_DATASET_DIR = _DATA_DIR / "ET HCI GNN Dataset"
_ASSET_GRAPH_PATH = _DATA_DIR / "asset_graph.json"


# =============================================================================
# NEO4J STORE
# =============================================================================

class Neo4jStore:
    """
    Dual-mode Neo4j graph store.

    In LIVE mode:  Connects to Neo4j via bolt protocol. All writes/reads
                   use parameterized Cypher queries (safe from injection).
    In FALLBACK:   Uses networkx.MultiDiGraph for identical interface
                   without requiring a running database.
    """

    def __init__(
        self,
        uri: Optional[str] = None,
        user: Optional[str] = None,
        password: Optional[str] = None,
        database: Optional[str] = None,
    ):
        self.uri      = uri      or os.getenv("NEO4J_URI",      "neo4j://127.0.0.1:7687")
        self.user     = user     or os.getenv("NEO4J_USER",     "neo4j")
        self.password = password or os.getenv("NEO4J_PASSWORD", "")
        self.database = database or os.getenv("NEO4J_DATABASE", "neo4j")

        self.use_fallback   = True
        self.driver         = None
        self.fallback_graph = nx.MultiDiGraph()

        # Transparent buffering for fast database batch operations
        self.node_buffer = {}
        self.edge_buffer = {}
        self.batch_size = 100

        # ── NEW: track label of every node id we've seen so edge MATCHes ────
        # can be scoped to the correct label instead of scanning all labels.
        self._node_labels: Dict[str, str] = {}

        # Labels that get a uniqueness constraint on `id` (created once,
        # idempotent). Add here whenever a new import_* introduces a label.
        self._KNOWN_LABELS = [
            "Computer", "IP", "User", "Asset", "OTSensor",
            "Technique", "Tactic", "ThreatGroup", "Mitigation",
            "Software", "Campaign",
        ]

        if _HAS_NEO4J and self.password:
            try:
                self.driver = GraphDatabase.driver(
                    self.uri,
                    auth=(self.user, self.password),
                )
                with self.driver.session(database=self.database) as session:
                    session.run("RETURN 1")
                self.use_fallback = False
                logger.info("Neo4jStore: Connected → %s  db=%s", self.uri, self.database)
                self._ensure_constraints()
            except Exception as exc:
                logger.warning("Neo4jStore: Connection failed (%s). Using networkx fallback.", exc)
        else:
            logger.info("Neo4jStore: Running in networkx fallback mode.")

    def _ensure_constraints(self) -> None:
        """
        Create a uniqueness constraint (id) per label, once.

        Why this matters at "massive dataset" scale:
          - Without it, `MATCH (n {id: $x})` (used when flushing edges) has
            no index to use and falls back to a full label/property scan —
            this gets brutally slow as node counts grow into the thousands.
          - It also *prevents* MERGE from silently creating duplicate nodes
            for the same id under load / retries.
        """
        for label in self._KNOWN_LABELS:
            try:
                self._run(
                    f"CREATE CONSTRAINT IF NOT EXISTS FOR (n:`{label}`) "
                    f"REQUIRE n.id IS UNIQUE"
                )
            except Exception as exc:
                logger.warning("Neo4jStore._ensure_constraints: %s failed: %s", label, exc)

    # ── Internal helpers ──────────────────────────────────────────────────────

    def _run(self, query: str, **params) -> List[Dict[str, Any]]:
        """Execute a Cypher query and return list of record dicts."""
        with self.driver.session(database=self.database) as session:
            result = session.run(query, **params)
            return [dict(rec) for rec in result]

    # ── Node operations ───────────────────────────────────────────────────────

    def add_node(self, node_id: str, label: str, properties: Dict[str, Any]) -> None:
        """Upsert a node. Buffers in LIVE mode; flushes every batch_size records."""
        safe_props = _safe_props(properties)
        safe_props["id"] = node_id

        # Remember which label this id belongs to — add_edge needs this to
        # scope its MATCH to the right label instead of an unlabeled scan.
        self._node_labels[node_id] = label

        if self.use_fallback:
            nx_props = {k: v for k, v in safe_props.items() if k != "label"}
            self.fallback_graph.add_node(node_id, label=label, **nx_props)
            if "label" in safe_props:
                self.fallback_graph.nodes[node_id]["display_label"] = safe_props["label"]
            return

        if label not in self.node_buffer:
            self.node_buffer[label] = []
        # ── Flatten: no nested dicts — avoids packstream struct errors ──────
        row = {"_nid": node_id, "_label": label}
        for k, v in safe_props.items():
            row[f"p_{k}"] = v
        self.node_buffer[label].append(row)

        if len(self.node_buffer[label]) >= self.batch_size:
            self.flush_nodes(label)

    def add_edge(
        self,
        src_id: str,
        dst_id: str,
        relation: str,
        properties: Optional[Dict[str, Any]] = None,
        event: bool = False,
    ) -> None:
        """
        Upsert (or, if `event=True`, always CREATE) a directed edge.
        Buffers in LIVE mode; flushes every batch_size records.

        event=False (default) — MERGE semantics. Use this for structural /
            taxonomy relationships that should exist at most once between
            two nodes (e.g. MITRE SUBTECHNIQUE_OF, MITIGATES, USES).

        event=True — CREATE semantics. Use this for time-series / log-style
            relationships (flows, sensor readings, lateral-movement events,
            logins) where the SAME pair of nodes legitimately interacts many
            times. With MERGE, every repeat interaction between the same
            pair just overwrites the one relationship's properties — you
            silently lose every event except the last one written. That is
            almost certainly why SENSOR_READING only has 50 edges despite
            importing 5000 SWaT rows, and why RED_TEAM_LATERAL / APT_FLOW /
            CIC_FLOW counts look low relative to the rows you fed in.
        """
        safe_props = _safe_props(properties or {})

        if self.use_fallback:
            # networkx MultiDiGraph already supports parallel edges natively,
            # so fallback mode was never affected by this bug — only live
            # Neo4j MERGE was.
            self.fallback_graph.add_edge(src_id, dst_id, key=relation, **safe_props)
            return

        src_label = self._node_labels.get(src_id, "")
        dst_label = self._node_labels.get(dst_id, "")
        if not src_label or not dst_label:
            logger.warning(
                "Neo4jStore.add_edge: unknown label for %r->%r (rel=%s); "
                "call add_node for both endpoints before add_edge.",
                src_id, dst_id, relation,
            )

        key = (relation, src_label, dst_label, event)
        if key not in self.edge_buffer:
            self.edge_buffer[key] = []
        # ── Flatten: no nested dicts — avoids packstream struct errors ──────
        row = {"_src": src_id, "_dst": dst_id}
        for k, v in safe_props.items():
            row[f"p_{k}"] = v
        self.edge_buffer[key].append(row)

        if len(self.edge_buffer[key]) >= self.batch_size:
            self.flush_edges(key)

    def flush_nodes(self, label: str) -> None:
        """Flush buffered nodes for a label using a single optimized UNWIND query."""
        if self.use_fallback or label not in self.node_buffer or not self.node_buffer[label]:
            return
        batch = self.node_buffer[label]
        self.node_buffer[label] = []

        # Re-construct a flat batch payload for Cypher UNWIND
        batch_data = []
        for row in batch:
            props = {k[2:]: v for k, v in row.items() if k.startswith("p_")}
            batch_data.append({"nid": row["_nid"], "props": props})

        query = (
            f"UNWIND $batch_data AS row "
            f"MERGE (n:`{label}` {{id: row.nid}}) "
            f"SET n += row.props"
        )
        try:
            self._run(query, batch_data=batch_data)
            logger.info("Neo4jStore.flush_nodes: flushed %d `%s` nodes", len(batch), label)
        except Exception as exc:
            logger.error("Neo4jStore.flush_nodes error for label %s: %s", label, exc)

    def flush_edges(self, key) -> None:
        """
        Flush buffered edges for one (relation, src_label, dst_label, event)
        group using a single optimized UNWIND query.

        `key` is the tuple produced by add_edge. Labels are included in the
        MATCH clauses so this scans only the correct label's index instead
        of every node in the database with a matching `id` — both a
        correctness fix (no more cross-label id collisions) and a big
        performance win at "massive dataset" scale.
        """
        if self.use_fallback or key not in self.edge_buffer or not self.edge_buffer[key]:
            return

        relation, src_label, dst_label, event = key

        # ── CRITICAL: flush all pending nodes first so endpoints exist ──────
        for lbl in list(self.node_buffer.keys()):
            self.flush_nodes(lbl)

        batch = self.edge_buffer[key]
        self.edge_buffer[key] = []

        batch_data = []
        for row in batch:
            props = {k[2:]: v for k, v in row.items() if k.startswith("p_")}
            batch_data.append({"src": row["_src"], "dst": row["_dst"], "props": props})

        src_match = f"(a:`{src_label}` {{id: row.src}})" if src_label else "(a {id: row.src})"
        dst_match = f"(b:`{dst_label}` {{id: row.dst}})" if dst_label else "(b {id: row.dst})"

        if event:
            # Event/log-style edges: never collapse repeats into one row.
            edge_clause = f"CREATE (a)-[r:`{relation}`]->(b) SET r += row.props"
        else:
            # Structural/taxonomy edges: one relationship per pair, upsert props.
            edge_clause = f"MERGE (a)-[r:`{relation}`]->(b) SET r += row.props"

        query = (
            f"UNWIND $batch_data AS row "
            f"MATCH {src_match} "
            f"MATCH {dst_match} "
            f"{edge_clause}"
        )
        try:
            self._run(query, batch_data=batch_data)
            logger.info(
                "Neo4jStore.flush_edges: flushed %d `%s` edges (%s->%s, event=%s)",
                len(batch), relation, src_label, dst_label, event,
            )
        except Exception as exc:
            logger.error("Neo4jStore.flush_edges error for relation %s: %s", relation, exc)

    def flush(self) -> None:
        """Flush all remaining buffers — nodes first, then edges."""
        if self.use_fallback:
            return
        logger.info("Flushing Neo4j write buffers (all labels → all relations)...")
        for label in list(self.node_buffer.keys()):
            self.flush_nodes(label)
        for key in list(self.edge_buffer.keys()):
            self.flush_edges(key)

    # ── Bulk / dataset import ─────────────────────────────────────────────────

    def import_from_asset_json(self, json_path: Optional[str] = None) -> int:
        """
        Load asset_graph.json (or any compatible JSON) into the store.
        Returns number of nodes inserted.
        Schema expected:
          { "nodes": [{id, type, label, criticality, features:{...}}],
            "edges": [{from, to, protocol, weight, timestamps:[]}] }
        """
        path = Path(json_path) if json_path else _ASSET_GRAPH_PATH
        logger.info("Neo4jStore.import_from_asset_json: loading %s", path)
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)

        count = 0
        for node in data.get("nodes", []):
            nid   = node.get("id", "")
            ntype = node.get("type", "Asset")
            props: Dict[str, Any] = {
                "label":       node.get("label", nid),
                "criticality": float(node.get("criticality", 0.5)),
            }
            feats = node.get("features", {})
            for k, v in feats.items():
                props[f"feat_{k}"] = v
            self.add_node(nid, ntype, props)
            count += 1

        for edge in data.get("edges", []):
            src      = edge.get("from", "")
            dst      = edge.get("to", "")
            relation = (edge.get("protocol") or "COMMUNICATES_WITH").upper().replace("-", "_")
            props    = {
                "weight":     float(edge.get("weight", 0.5)),
                "timestamps": json.dumps(edge.get("timestamps", [])),
            }
            self.add_edge(src, dst, relation, props)

        logger.info("Neo4jStore.import_from_asset_json: inserted %d nodes", count)
        return count

    def import_redteam_events(self, txt_path: Optional[str] = None, limit: int = 750) -> int:
        """
        Load LANL redteam.txt lateral-movement events.
        Format: time,user@domain,src_computer,dst_computer
        Each line becomes:
          (:Computer)-[:RED_TEAM_LATERAL {user, time_sec}]->(:Computer)
        """
        path = txt_path or str(_GNN_DATASET_DIR / "redteam.txt" / "redteam.txt")
        logger.info("Neo4jStore.import_redteam_events: loading %s", path)
        count = 0
        with open(path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                parts = line.split(",")
                if len(parts) < 4:
                    continue
                time_sec, user, src, dst = parts[0], parts[1], parts[2], parts[3]
                # Upsert nodes
                self.add_node(src, "Computer", {"source": "LANL"})
                self.add_node(dst, "Computer", {"source": "LANL"})
                self.add_node(user, "User",     {"source": "LANL"})
                # User → src computer (logged in from)
                self.add_edge(user, src, "LOGGED_IN_FROM", {"time_sec": int(time_sec)}, event=True)
                # src → dst (lateral movement)
                self.add_edge(src, dst, "RED_TEAM_LATERAL", {
                    "user":     user,
                    "time_sec": int(time_sec),
                    "label":    1,          # ground-truth attack label
                }, event=True)
                count += 1
                if count >= limit:
                    break

        logger.info("Neo4jStore.import_redteam_events: inserted %d lateral-movement edges", count)
        return count

    def import_mitre_stix(self, json_path: Optional[str] = None, limit: int = 500) -> int:
        """
        Load MITRE ATT&CK enterprise-attack.json STIX bundle into Threat Graph.
        Inserts Technique, Tactic, ThreatGroup nodes (up to `limit`, primary types)
        plus lazily-created Mitigation/Software/Campaign stub nodes for any
        relationship endpoint, then wires up every relationship whose *both*
        endpoints exist as nodes.

        NOTE: the previous implementation broke out of the whole objects loop
        as soon as `limit` node-objects had been seen. Since STIX bundles list
        hundreds of attack-pattern objects before any relationship objects,
        that `break` fired before most/any relationships were ever read —
        producing a graph full of disconnected Technique/Tactic/Group nodes.
        This version decouples the node-count cap from relationship scanning,
        and never emits an edge with a dangling endpoint.
        """
        path = json_path or str(_GNN_DATASET_DIR / "enterprise-attack.json")
        logger.info("Neo4jStore.import_mitre_stix: loading %s", path)

        with open(path, "r", encoding="utf-8") as f:
            bundle = json.load(f)

        objects = bundle.get("objects", [])

        # STIX type -> (Neo4j label, counts against `limit`)
        TYPE_MAP = {
            "attack-pattern":   ("Technique",   True),
            "x-mitre-tactic":   ("Tactic",      True),
            "intrusion-set":    ("ThreatGroup", True),
            "course-of-action": ("Mitigation",  False),
            "malware":          ("Software",    False),
            "tool":             ("Software",    False),
            "campaign":         ("Campaign",    False),
        }

        # Pass 1: decide which objects become nodes. Primary types (technique/
        # tactic/group) are capped at `limit`; supporting types are unlimited
        # since they only get created as relationship endpoints below.
        id_info: Dict[str, Dict[str, str]] = {}
        primary_count = 0
        for obj in objects:
            obj_type = obj.get("type", "")
            if obj_type not in TYPE_MAP:
                continue
            label, is_primary = TYPE_MAP[obj_type]
            if is_primary and primary_count >= limit:
                continue
            obj_id = obj.get("id", "")
            id_info[obj_id] = {
                "label":       label,
                "name":        obj.get("name", obj_id),
                "description": str(obj.get("description", ""))[:200],
                "mitre_id":    _extract_mitre_id(obj) if obj_type == "attack-pattern" else "",
            }
            if is_primary:
                primary_count += 1

        # Pass 2: create the nodes.
        for obj_id, info in id_info.items():
            self.add_node(obj_id, info["label"], {
                "name":        info["name"],
                "description": info["description"],
                "mitre_id":    info["mitre_id"],
            })
        count = len(id_info)

        # Pass 3: relationships — only added when BOTH endpoints exist as
        # nodes, so we never create an edge that points at nothing.
        edge_count = 0
        for obj in objects:
            if obj.get("type") != "relationship":
                continue
            src_ref = obj.get("source_ref", "")
            tgt_ref = obj.get("target_ref", "")
            if src_ref in id_info and tgt_ref in id_info:
                rel_type = obj.get("relationship_type", "RELATES_TO").upper().replace("-", "_")
                self.add_edge(src_ref, tgt_ref, rel_type)
                edge_count += 1

        logger.info(
            "Neo4jStore.import_mitre_stix: inserted %d nodes (%d technique/tactic/group + %d supporting), %d edges",
            count, primary_count, count - primary_count, edge_count,
        )
        return count

    def import_dapt_flows(self, limit_per_file: int = 5000) -> int:
        """
        Load DAPT2020 APT flow CSVs into Evidence Graph.
        Each row: (src_ip, dst_ip, protocol, label) → Evidence nodes + FLOW edges.
        """
        dapt_dir = _GNN_DATASET_DIR / "DAPT2020"
        total    = 0

        for csv_file in sorted(dapt_dir.glob("*.csv")):
            logger.info("Neo4jStore.import_dapt_flows: processing %s", csv_file.name)
            try:
                import csv
                with open(csv_file, "r", encoding="utf-8", errors="ignore") as f:
                    reader = csv.DictReader(f)
                    headers = reader.fieldnames or []
                    # Resolve flexible column names
                    src_col = _find_col(headers, ["Src IP", "src_ip", "Source IP"])
                    dst_col = _find_col(headers, ["Dst IP", "dst_ip", "Destination IP"])
                    lbl_col = _find_col(headers, ["Label", "label", "Attack"])
                    proto_col = _find_col(headers, ["Protocol", "protocol"])

                    count = 0
                    for row in reader:
                        if count >= limit_per_file:
                            break
                        src  = row.get(src_col, "").strip()
                        dst  = row.get(dst_col, "").strip()
                        lbl  = str(row.get(lbl_col, "Benign")).strip()
                        proto = str(row.get(proto_col, "TCP")).strip()

                        if not src or not dst:
                            continue

                        self.add_node(src, "IP", {"source": "DAPT2020"})
                        self.add_node(dst, "IP", {"source": "DAPT2020"})
                        self.add_edge(src, dst, "APT_FLOW", {
                            "protocol": proto,
                            "label":    0 if lbl.lower() in ("benign", "normal", "0") else 1,
                            "source":   "DAPT2020",
                        }, event=True)
                        count += 1
                    total += count
            except Exception as exc:
                logger.warning("Neo4jStore.import_dapt_flows: skipped %s (%s)", csv_file.name, exc)

        logger.info("Neo4jStore.import_dapt_flows: total %d DAPT flow edges", total)
        return total

    def import_swat_logs(self, limit: int = 5000) -> int:
        """
        Load SWaT OT attack/normal CSVs into Decision Graph.
        Inserts Sensor nodes + SENSOR_READING edges with attack labels.
        """
        swat_dir = _GNN_DATASET_DIR / "SWaT (Secure Water Treatment) Network Logs"
        total    = 0

        for fname in ("normal.csv", "attack.csv"):
            path = swat_dir / fname
            if not path.exists():
                continue
            is_attack = fname == "attack.csv"
            try:
                import csv
                with open(path, "r", encoding="utf-8", errors="ignore") as f:
                    reader = csv.DictReader(f)
                    headers = reader.fieldnames or []
                    lbl_col = _find_col(headers, ["Normal/Attack", "label", "Attack"])
                    count   = 0
                    for row in reader:
                        if count >= limit:
                            break
                        lbl_val = str(row.get(lbl_col, "Normal")).strip()
                        label   = 0 if lbl_val.lower() in ("normal", "0") else 1

                        # Each sensor column becomes a node; connect sequentially
                        prev = None
                        for col in headers:
                            if col == lbl_col:
                                continue
                            val = row.get(col, "0")
                            try:
                                float_val = float(val)
                            except ValueError:
                                continue
                            node_id = f"SWaT_Sensor_{col}"
                            self.add_node(node_id, "OTSensor", {
                                "sensor_name": col, "source": "SWaT"
                            })
                            if prev:
                                self.add_edge(prev, node_id, "SENSOR_READING", {
                                    "value":  float_val,
                                    "label":  label,
                                    "attack": int(is_attack),
                                }, event=True)
                            prev = node_id
                        count += 1
                    total += count
            except Exception as exc:
                logger.warning("Neo4jStore.import_swat_logs: skipped %s (%s)", fname, exc)

        logger.info("Neo4jStore.import_swat_logs: total %d OT sensor rows", total)
        return total

    def import_lanl_flows(self, txt_path: Optional[str] = None, limit: int = 5000) -> int:
        """
        Load a subset of LANL flows.txt to represent network flow edges.
        Format: time, duration, source_computer, source_port, destination_computer, destination_port, protocol, packet_count, byte_count
        """
        path = txt_path or str(_GNN_DATASET_DIR / "flows.txt")
        if not Path(path).exists():
            logger.warning("Neo4jStore.import_lanl_flows: flows.txt not found at %s", path)
            return 0
        logger.info("Neo4jStore.import_lanl_flows: loading %s (limit: %d)", path, limit)
        count = 0
        with open(path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                parts = line.split(",")
                if len(parts) < 9:
                    continue
                # time, duration, src, src_port, dst, dst_port, proto, packets, bytes
                time_sec, duration, src, _, dst, _, proto, _, _ = parts
                self.add_node(src, "Computer", {"source": "LANL_Flow"})
                self.add_node(dst, "Computer", {"source": "LANL_Flow"})
                self.add_edge(src, dst, "FLOW", {
                    "time_sec": int(time_sec),
                    "protocol": proto,
                    "source": "LANL_Flow",
                    "label": 0  # Default to benign; redteam overlay will set malicious labels
                }, event=True)
                count += 1
                if count >= limit:
                    break
        logger.info("Neo4jStore.import_lanl_flows: inserted %d flow edges", count)
        return count

    def import_cicids_flows(self, limit_per_file: int = 2000) -> int:
        """
        Load UNSW-NB15 / CICIDS2017 TrafficLabelling CSV files.
        Inserts IP nodes and flow edges with corresponding attack labels.
        """
        cic_dir = _GNN_DATASET_DIR / "UNSW-NB15 Mapped NetFlow Graph" / "TrafficLabelling"
        if not cic_dir.exists():
            logger.warning("Neo4jStore.import_cicids_flows: TrafficLabelling directory not found at %s", cic_dir)
            return 0
        total = 0
        for csv_file in sorted(cic_dir.glob("*.csv")):
            logger.info("Neo4jStore.import_cicids_flows: processing %s", csv_file.name)
            try:
                import csv
                with open(csv_file, "r", encoding="utf-8", errors="ignore") as f:
                    reader = csv.DictReader(f)
                    headers = reader.fieldnames or []
                    # Strip spaces from header keys to be safe
                    h_clean = [h.strip() for h in headers]
                    
                    src_col = _find_col(headers, ["Source IP", "src_ip", "Source_IP"])
                    dst_col = _find_col(headers, ["Destination IP", "dst_ip", "Destination_IP"])
                    lbl_col = _find_col(headers, ["Label", "label"])
                    proto_col = _find_col(headers, ["Protocol", "protocol"])

                    count = 0
                    for row in reader:
                        if count >= limit_per_file:
                            break
                        src = row.get(src_col, "").strip()
                        dst = row.get(dst_col, "").strip()
                        lbl = str(row.get(lbl_col, "BENIGN")).strip()
                        proto = str(row.get(proto_col, "6")).strip()

                        if not src or not dst:
                            continue

                        self.add_node(src, "IP", {"source": "CICIDS2017"})
                        self.add_node(dst, "IP", {"source": "CICIDS2017"})
                        self.add_edge(src, dst, "CIC_FLOW", {
                            "protocol": proto,
                            "label": 0 if lbl.upper() == "BENIGN" else 1,
                            "source": "CICIDS2017",
                        }, event=True)
                        count += 1
                    total += count
            except Exception as exc:
                logger.warning("Neo4jStore.import_cicids_flows: skipped %s (%s)", csv_file.name, exc)
        logger.info("Neo4jStore.import_cicids_flows: total %d CIC flow edges", total)
        return total

    # ── Read operations ───────────────────────────────────────────────────────

    def get_cytoscape_elements(
        self,
        node_limit: int = 50_000,
        edge_limit: int = 200_000,
    ) -> Dict[str, List[Dict[str, Any]]]:
        """
        Return graph as Cytoscape-compatible JSON:
          { "nodes": [{group:"nodes", data:{id,...}}],
            "edges": [{group:"edges", data:{source,target,relation,...}}] }

        IMPORTANT — edge-driven node selection:
        The previous version ran two *independent* LIMIT-capped queries —
        one for nodes, one for edges — with no relationship between which
        nodes and which edges came back. On a small graph that's harmless
        because everything fits under both limits anyway. On a massive
        dataset, a `LIMIT 2000` node sample and a `LIMIT 5000` edge sample
        are two unrelated random slices of the graph: almost none of the
        edges' endpoints land inside the node sample. Downstream,
        export_tensors() does `id2idx.get(src)` / `id2idx.get(dst)` and
        silently drops any edge whose endpoint isn't in the node list —
        so nearly every edge got thrown away, producing a graph of
        isolated dots with no visible connections.

        Fix: fetch edges FIRST, collect exactly the node ids they
        reference, then fetch those nodes by id — guaranteeing every
        returned edge has both endpoints present in the node list. Any
        remaining budget under node_limit is used to top up with
        additional nodes (including genuinely isolated ones), so those
        aren't lost either, but they never crowd out connected nodes.
        """
        elements: Dict[str, List] = {"nodes": [], "edges": []}

        if self.use_fallback:
            for n_id, data in self.fallback_graph.nodes(data=True):
                elements["nodes"].append({"group": "nodes", "data": {"id": n_id, **data}})
            for u, v, key, data in self.fallback_graph.edges(keys=True, data=True):
                edge_data = {"source": u, "target": v, "relation": key}
                edge_data.update(data)
                elements["edges"].append({"group": "edges", "data": edge_data})
            return elements

        # ── LIVE: edges FIRST — these are what determine which nodes matter ──
        edge_rows = self._run(
            "MATCH (a)-[r]->(b) RETURN a.id AS src, b.id AS dst, type(r) AS rel, r "
            "LIMIT $limit",
            limit=edge_limit,
        )
        referenced_ids: set = set()
        for rec in edge_rows:
            d = dict(rec.get("r") or {})
            d.update({"source": rec["src"], "target": rec["dst"], "relation": rec["rel"]})
            elements["edges"].append({"group": "edges", "data": d})
            referenced_ids.add(rec["src"])
            referenced_ids.add(rec["dst"])

        # Fetch exactly the nodes referenced by those edges — every edge
        # above is now guaranteed to have both endpoints in `elements["nodes"]`.
        seen_ids: set = set()
        if referenced_ids:
            node_rows = self._run(
                "MATCH (n) WHERE n.id IN $ids RETURN n, labels(n) AS lbls",
                ids=list(referenced_ids),
            )
            for rec in node_rows:
                node  = rec["n"]
                label = rec["lbls"][0] if rec["lbls"] else "Entity"
                d     = dict(node)
                d["type"] = label
                elements["nodes"].append({"group": "nodes", "data": d})
                seen_ids.add(d.get("id"))

        # Top up with additional nodes (e.g. genuinely isolated ones, or
        # nodes with no outgoing/incoming edges captured above) up to
        # node_limit, without displacing any connected node already added.
        remaining = node_limit - len(seen_ids)
        if remaining > 0:
            extra_rows = self._run(
                "MATCH (n) WHERE NOT n.id IN $seen RETURN n, labels(n) AS lbls LIMIT $lim",
                seen=list(seen_ids),
                lim=remaining,
            )
            for rec in extra_rows:
                node  = rec["n"]
                label = rec["lbls"][0] if rec["lbls"] else "Entity"
                d     = dict(node)
                d["type"] = label
                elements["nodes"].append({"group": "nodes", "data": d})

        return elements

    def get_node_count(self) -> int:
        if self.use_fallback:
            return self.fallback_graph.number_of_nodes()
        rows = self._run("MATCH (n) RETURN count(n) AS c")
        return rows[0]["c"] if rows else 0

    def get_edge_count(self) -> int:
        if self.use_fallback:
            return self.fallback_graph.number_of_edges()
        rows = self._run("MATCH ()-[r]->() RETURN count(r) AS c")
        return rows[0]["c"] if rows else 0

    def clear(self) -> None:
        """Delete ALL nodes and relationships. Use with care."""
        if self.use_fallback:
            self.fallback_graph.clear()
            return
        self._run("MATCH (n) DETACH DELETE n")
        logger.warning("Neo4jStore.clear: all data deleted from database '%s'", self.database)

    def close(self) -> None:
        self.flush()
        if self.driver:
            self.driver.close()


# =============================================================================
# HELPERS
# =============================================================================

def _safe_props(props: Dict[str, Any]) -> Dict[str, Any]:
    """Flatten props so all values are Neo4j-compatible primitives."""
    out: Dict[str, Any] = {}
    for k, v in props.items():
        if isinstance(v, (str, int, float, bool)):
            out[k] = v
        elif isinstance(v, list):
            # neo4j supports lists of primitives only
            out[k] = [str(x) for x in v]
        else:
            out[k] = str(v)
    return out


def _extract_mitre_id(obj: Dict[str, Any]) -> str:
    for ref in obj.get("external_references", []):
        if ref.get("source_name") == "mitre-attack":
            return ref.get("external_id", "")
    return ""


def _find_col(headers: List[str], candidates: List[str]) -> str:
    """Return first candidate column name that exists in headers (case-insensitive)."""
    h_lower = {h.strip().lower(): h for h in headers}
    for c in candidates:
        if c.strip().lower() in h_lower:
            return h_lower[c.strip().lower()]
    return candidates[0]  # fallback: first candidate (may raise KeyError)


# =============================================================================
# MODULE-LEVEL SINGLETON
# =============================================================================

_store: Optional[Neo4jStore] = None


def get_store() -> Neo4jStore:
    """Return the module-level singleton (lazy init)."""
    global _store
    if _store is None:
        _store = Neo4jStore()
    return _store