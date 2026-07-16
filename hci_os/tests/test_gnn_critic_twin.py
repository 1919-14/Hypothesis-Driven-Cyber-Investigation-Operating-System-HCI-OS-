"""
tests/test_gnn_critic_twin.py
Comprehensive unit tests for Ticket 13 & 13.5:
  - A5 GNN Agent: GAT model training, attention extraction, predict_next_hop
  - A8 Critic Agent: LLM mock fallback, counter-evidence, FP likelihood
  - A14 Digital Twin: simulate_attack, synthetic log schema, node rendering

Gap Coverage:
  #1  Model persistence — load pre-trained
  #2  Synthetic log format — explicit schema
  #3  Model save/load
  #4  Hypothesis update with predictions
  #5  Critic → A7 integration (FP > 0.5)
  #7  Cytoscape.js export format
  #8  Groq mock responses
  #9  Attack timeline with timestamps
  #10 Programmatic training labels

Run:
  pytest tests/test_gnn_critic_twin.py -v
"""

from __future__ import annotations

import json
import sys
import time
from pathlib import Path
from typing import Any, Dict

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import agents.a5_gnn as a5
import agents.a8_critic as a8
from agents.digital_twin import DigitalTwin


# =============================================================================
# FIXTURES
# =============================================================================

@pytest.fixture()
def tmp_model_dir(tmp_path):
    """Create a temp directory for model persistence tests."""
    return tmp_path


@pytest.fixture()
def graph_data():
    """Load the seeded graph for tests."""
    return a5.load_graph()


@pytest.fixture()
def sample_evidence():
    """Create a minimal Evidence-like dict for testing."""
    return {
        "asset_id": "CBSE-WebSvr-01",
        "source": "web_access_log",
        "evidence_id": "EV-TEST-001",
        "normalized": {
            "src_ip": "185.23.147.82",
            "method": "GET",
            "path": "/api/admin/users",
        },
        "context": {
            "criticality": "HIGH",
            "mission": "exam_portal",
            "anomaly_score": 0.85,
        },
        "confidence": 0.87,
    }


@pytest.fixture()
def sample_hypothesis():
    """Create a minimal Hypothesis for testing."""
    from objects.hypothesis import Hypothesis
    return Hypothesis.model_validate({
        "goal": "Investigate Log4Shell exploitation on CBSE-WebSvr-01",
        "confidence": 0.85,
        "mitre_chain": ["T1595", "T1190"],
        "supporting_evidence": ["EV-TEST-001"],
    })


# =============================================================================
# A5 GNN: GRAPH LOADING
# =============================================================================

class TestA5GraphLoading:
    def test_load_graph_has_nodes(self, graph_data):
        assert len(graph_data["nodes"]) >= 25
        assert len(graph_data["nodes"]) <= 40

    def test_load_graph_has_edges(self, graph_data):
        assert len(graph_data["edges"]) >= 20

    def test_load_graph_has_attack_path(self, graph_data):
        meta = graph_data.get("metadata", {})
        path = meta.get("attack_path", [])
        assert len(path) >= 3
        assert "CBSE-WebSvr-01" in path

    def test_node_types_mapping(self, graph_data):
        node_types = graph_data.get("node_types", {})
        assert "web_server" in node_types
        assert "database" in node_types
        assert "crown_jewel" in node_types

    def test_all_nodes_have_type(self, graph_data):
        for node in graph_data["nodes"]:
            assert "type" in node, f"Node {node['id']} missing type"

    def test_all_edges_have_weight(self, graph_data):
        for edge in graph_data["edges"]:
            assert "weight" in edge, f"Edge {edge['from']}->{edge['to']} missing weight"
            assert 0.0 < edge["weight"] <= 1.0

    def test_attack_path_edges_have_high_weights(self, graph_data):
        """Attack path edges should have weight >= 0.85 (scripted)."""
        attack_edges = {
            ("CBSE-WebSvr-01", "CBSE-AppSrv-03"),
            ("CBSE-AppSrv-03", "CBSE-DB-01"),
            ("CBSE-DB-01", "CrownJewel-ExamDB"),
        }
        for edge in graph_data["edges"]:
            key = (edge["from"], edge["to"])
            if key in attack_edges:
                assert edge["weight"] >= 0.85, f"Attack edge {key} weight too low: {edge['weight']}"


# =============================================================================
# A5 GNN: MODEL TRAINING & PERSISTENCE
# =============================================================================

class TestA5GATModel:
    def test_model_initialization(self):
        model = a5.GAT(in_channels=19, hidden_channels=32, out_channels=2)
        assert model is not None
        params = sum(p.numel() for p in model.parameters())
        assert params > 0

    def test_train_gat_runs_200_epochs(self, tmp_model_dir, graph_data):
        """Gap #10: Training with programmatic labels from attack path."""
        model, stats = a5.train_gat(
            graph=graph_data,
            epochs=200,
            save_path=tmp_model_dir / "gat_model.pt",
        )
        assert stats["epochs"] == 200
        assert stats["final_loss"] < 1.0  # should converge
        assert stats["n_compromised"] == 4  # attack path has 4 nodes

    def test_model_saved_to_disk(self, tmp_model_dir, graph_data):
        """Gap #3: Model is saved to disk after training."""
        save_path = tmp_model_dir / "gat_model.pt"
        a5.train_gat(graph=graph_data, epochs=50, save_path=save_path)
        assert save_path.exists()
        assert save_path.stat().st_size > 0

    def test_load_pre_trained_model(self, tmp_model_dir, graph_data):
        """Gap #1: Load pre-trained model from disk."""
        save_path = tmp_model_dir / "gat_model.pt"
        a5.train_gat(graph=graph_data, epochs=50, save_path=save_path)

        # Clear cache
        a5._cached_model = None

        model, graph, maps = a5.load_or_train(model_path=save_path)
        assert model is not None
        id_to_idx, idx_to_id, node_types = maps
        assert len(id_to_idx) >= 25

    def test_gat_forward_pass_shape(self, graph_data):
        """Verify model output shapes match expectations."""
        id_to_idx, idx_to_id, node_types = a5._build_index_maps(graph_data)
        num_types = max(len(node_types), 16)
        x, edge_index, _, y = a5._to_tensors(graph_data, id_to_idx, node_types)

        model = a5.GAT(in_channels=num_types, hidden_channels=32, out_channels=2)
        out, attn = model(x, edge_index)

        assert out.shape[0] == x.shape[0]   # one output per node
        assert out.shape[1] == 2             # 2 classes
        assert attn.shape[0] == edge_index.shape[1]  # one weight per edge

    def test_training_labels_from_attack_path(self, graph_data):
        """Gap #10: Labels are generated from attack path nodes."""
        id_to_idx, _, node_types = a5._build_index_maps(graph_data)
        _, _, _, y = a5._to_tensors(graph_data, id_to_idx, node_types)
        compromised = int(y.sum().item())
        assert compromised == len(a5.DEFAULT_ATTACK_PATH)


# =============================================================================
# A5 GNN: ATTENTION WEIGHTS & PREDICTION
# =============================================================================

class TestA5Attention:
    def test_extract_attention_weights(self, tmp_model_dir, graph_data):
        save_path = tmp_model_dir / "gat_model.pt"
        model, _ = a5.train_gat(graph=graph_data, epochs=50, save_path=save_path)
        attn = a5.extract_attention_weights(model, graph_data)
        assert isinstance(attn, dict)
        assert len(attn) > 0
        # All values should be in [0, 1]
        for k, v in attn.items():
            assert 0.0 <= v <= 1.0, f"Attention weight {k} = {v} out of range"

    def test_predict_next_hop_returns_ranked_list(self, tmp_model_dir, graph_data):
        save_path = tmp_model_dir / "gat_model.pt"
        model, _ = a5.train_gat(graph=graph_data, epochs=50, save_path=save_path)
        attn = a5.extract_attention_weights(model, graph_data)

        predictions = a5.predict_next_hop("CBSE-WebSvr-01", graph_data, attn, top_k=3)
        assert isinstance(predictions, list)
        assert len(predictions) >= 1
        # Should be sorted descending by score
        if len(predictions) >= 2:
            assert predictions[0][1] >= predictions[1][1]

    def test_predict_next_hop_top_k(self, tmp_model_dir, graph_data):
        save_path = tmp_model_dir / "gat_model.pt"
        model, _ = a5.train_gat(graph=graph_data, epochs=50, save_path=save_path)
        attn = a5.extract_attention_weights(model, graph_data)

        preds = a5.predict_next_hop("CBSE-WebSvr-01", graph_data, attn, top_k=2)
        assert len(preds) <= 2

    def test_predict_unknown_node_returns_empty(self, graph_data):
        preds = a5.predict_next_hop("NONEXISTENT-NODE", graph_data, {}, top_k=2)
        assert preds == []


# =============================================================================
# A5 GNN: CYTOSCAPE EXPORT (Gap #7)
# =============================================================================

class TestA5Cytoscape:
    def test_export_has_elements_key(self, graph_data):
        result = a5.export_cytoscape_json(graph=graph_data, attention_weights={})
        assert "elements" in result
        assert "metadata" in result

    def test_export_nodes_have_required_fields(self, graph_data):
        result = a5.export_cytoscape_json(graph=graph_data, attention_weights={})
        nodes = [e for e in result["elements"] if e["group"] == "nodes"]
        assert len(nodes) >= 25
        for node in nodes:
            assert "id" in node["data"]
            assert "label" in node["data"]
            assert "type" in node["data"]
            assert "status" in node["data"]
            assert "color" in node["data"]

    def test_export_edges_have_required_fields(self, graph_data):
        result = a5.export_cytoscape_json(graph=graph_data, attention_weights={})
        edges = [e for e in result["elements"] if e["group"] == "edges"]
        assert len(edges) >= 20
        for edge in edges:
            assert "source" in edge["data"]
            assert "target" in edge["data"]
            assert "weight" in edge["data"]

    def test_compromised_nodes_are_red(self, graph_data):
        result = a5.export_cytoscape_json(
            graph=graph_data,
            attention_weights={},
            compromised_nodes=["CBSE-WebSvr-01"],
        )
        nodes = {e["data"]["id"]: e for e in result["elements"] if e["group"] == "nodes"}
        assert nodes["CBSE-WebSvr-01"]["data"]["status"] == "compromised"
        assert nodes["CBSE-WebSvr-01"]["data"]["color"] == "#e74c3c"

    def test_predicted_nodes_are_grey(self, graph_data):
        result = a5.export_cytoscape_json(
            graph=graph_data,
            attention_weights={},
            predicted_nodes=["CBSE-AppSrv-03"],
        )
        nodes = {e["data"]["id"]: e for e in result["elements"] if e["group"] == "nodes"}
        assert nodes["CBSE-AppSrv-03"]["data"]["status"] == "predicted"


# =============================================================================
# A5 GNN: PROCESS ENTRY POINT (Gap #4)
# =============================================================================

class TestA5Process:
    def test_process_updates_hypothesis(self, tmp_model_dir, graph_data, sample_hypothesis):
        """Gap #4: predicted_next_moves is populated."""
        save_path = tmp_model_dir / "gat_model.pt"
        a5.train_gat(graph=graph_data, epochs=50, save_path=save_path)
        a5._cached_model = None
        a5._MODEL_PATH = save_path

        result = a5.process(
            {"asset_id": "CBSE-WebSvr-01"},
            sample_hypothesis,
        )
        # Should have added predicted moves
        assert len(result.predicted_next_moves) >= 1

    def test_process_with_dict_evidence(self, sample_evidence):
        """Process accepts dict evidence gracefully."""
        result = a5.process(sample_evidence)
        # Should not crash — returns evidence when no hypothesis
        assert result is not None


# =============================================================================
# A8 CRITIC: MOCK RESPONSES (Gap #8)
# =============================================================================

class TestA8MockResponses:
    def test_exam_portal_mock(self, sample_evidence, sample_hypothesis):
        """Gap #8: Explicit mock for exam_portal mission."""
        result = a8._get_mock_response(sample_hypothesis, sample_evidence)
        assert "counter_evidence" in result
        assert "false_positive_likelihood" in result
        assert "reasoning" in result
        assert result["false_positive_likelihood"] < 0.5

    def test_power_management_mock(self):
        ev = {"context": {"mission": "power_management"}}
        hyp = {"goal": "Power grid attack"}
        result = a8._get_mock_response(hyp, ev)
        assert result["false_positive_likelihood"] < 0.5

    def test_patient_records_mock(self):
        ev = {"context": {"mission": "patient_records"}}
        hyp = {"goal": "AIIMS data breach"}
        result = a8._get_mock_response(hyp, ev)
        assert 0.0 <= result["false_positive_likelihood"] <= 1.0

    def test_default_mock(self):
        ev = {"context": {"mission": "unknown"}}
        hyp = {"goal": "Generic threat"}
        result = a8._get_mock_response(hyp, ev)
        assert result["false_positive_likelihood"] == 0.12

    def test_mock_has_5_counter_evidence_checks(self, sample_evidence, sample_hypothesis):
        result = a8._get_mock_response(sample_hypothesis, sample_evidence)
        assert len(result["counter_evidence"]) == 5
        types = {ce["type"] for ce in result["counter_evidence"]}
        assert "whitelist" in types
        assert "known_scanner" in types
        assert "redteam_window" in types


# =============================================================================
# A8 CRITIC: PROCESS (Gap #5)
# =============================================================================

class TestA8Process:
    def test_process_returns_hypothesis(self, sample_evidence, sample_hypothesis):
        result = a8.process(sample_evidence, sample_hypothesis)
        assert result is not None
        assert hasattr(result, "contradicting_evidence")

    def test_process_adds_contradicting_evidence(self, sample_evidence, sample_hypothesis):
        result = a8.process(sample_evidence, sample_hypothesis)
        assert len(result.contradicting_evidence) >= 1
        # Should contain the critic verdict
        assert any("A8 Critic verdict" in ce for ce in result.contradicting_evidence)

    def test_process_adds_timeline_event(self, sample_evidence, sample_hypothesis):
        original_len = len(sample_hypothesis.timeline)
        a8.process(sample_evidence, sample_hypothesis)
        assert len(sample_hypothesis.timeline) > original_len

    def test_process_sets_fp_likelihood_in_world_model(self, sample_evidence, sample_hypothesis):
        """Gap #5: FP likelihood stored in world_model.safety_constraints."""
        from objects.hypothesis import WorldModel
        sample_hypothesis.world_model = WorldModel(
            industry="education", mission="exam_portal", criticality="HIGH",
        )
        a8.process(sample_evidence, sample_hypothesis)
        assert "critic_fp_likelihood" in sample_hypothesis.world_model.safety_constraints

    def test_user_prompt_generation(self, sample_evidence, sample_hypothesis):
        prompt = a8._build_user_prompt(sample_hypothesis, sample_evidence)
        assert "Log4Shell" in prompt
        assert "T1595" in prompt


# =============================================================================
# A14 DIGITAL TWIN: GRAPH LOADING
# =============================================================================

class TestDigitalTwinGraph:
    def test_init_loads_graph(self):
        twin = DigitalTwin()
        assert twin.graph.number_of_nodes() >= 25
        assert twin.graph.number_of_edges() >= 20

    def test_node_attributes(self):
        twin = DigitalTwin()
        data = twin.graph.nodes["CBSE-WebSvr-01"]
        assert "type" in data
        assert "criticality" in data

    def test_edge_attributes(self):
        twin = DigitalTwin()
        edges = list(twin.graph.edges(data=True))
        assert len(edges) > 0
        for _, _, data in edges[:5]:
            assert "weight" in data
            assert "protocol" in data


# =============================================================================
# A14 DIGITAL TWIN: ATTACK SIMULATION (Gap #6, #9)
# =============================================================================

class TestDigitalTwinSimulation:
    def test_simulate_attack_finds_path(self):
        twin = DigitalTwin()
        result = twin.simulate_attack(feed_pipeline=False)
        assert result["attack_path"][0] == "CBSE-WebSvr-01"
        assert result["reached_target"] is True
        assert "CrownJewel-ExamDB" in result["attack_path"]

    def test_simulate_attack_no_cycles(self):
        twin = DigitalTwin()
        result = twin.simulate_attack(feed_pipeline=False)
        path = result["attack_path"]
        # No duplicates (no cycles)
        assert len(path) == len(set(path))

    def test_simulate_attack_timeline(self):
        """Gap #9: Timeline has timestamped events per hop."""
        twin = DigitalTwin()
        result = twin.simulate_attack(feed_pipeline=False)
        timeline = result["timeline"]
        assert len(timeline) == len(result["attack_path"])
        for event in timeline:
            assert "timestamp" in event
            assert "node" in event
            assert "description" in event
            assert "hop" in event

    def test_timeline_timestamps_are_sequential(self):
        """Gap #9: Timestamps should be in order."""
        twin = DigitalTwin()
        result = twin.simulate_attack(feed_pipeline=False)
        timestamps = [e["timestamp"] for e in result["timeline"]]
        assert timestamps == sorted(timestamps)

    def test_simulate_attack_has_simulation_id(self):
        twin = DigitalTwin()
        result = twin.simulate_attack(feed_pipeline=False)
        assert result["simulation_id"].startswith("SIM-")

    def test_node_states_color_coding(self):
        """Node states should have correct colors."""
        twin = DigitalTwin()
        result = twin.simulate_attack(feed_pipeline=False)
        states = result["node_states"]
        # Entry point should be orange
        assert states["CBSE-WebSvr-01"]["status"] == "entry_point"
        # Target should be dark red
        assert states["CrownJewel-ExamDB"]["status"] == "target_reached"
        # Clean nodes should be green
        clean_nodes = [k for k, v in states.items() if v["status"] == "clean"]
        assert len(clean_nodes) > 0


# =============================================================================
# A14 DIGITAL TWIN: SYNTHETIC LOG FORMAT (Gap #2)
# =============================================================================

class TestDigitalTwinSyntheticLogs:
    def test_synthetic_event_has_required_fields(self):
        """Gap #2: Synthetic logs must match A1/A2 input format."""
        twin = DigitalTwin()
        result = twin.simulate_attack(feed_pipeline=False)
        # Access the internal method to check event format
        from agents.digital_twin import _ATTACK_TEMPLATES
        template = _ATTACK_TEMPLATES["web_server"]
        event = twin._build_synthetic_event(
            node_id="CBSE-WebSvr-01",
            node_type="web_server",
            template=template,
            attacker_ip="185.23.147.82",
            hop_time=__import__("datetime").datetime.now(__import__("datetime").timezone.utc),
            hop_index=0,
            prev_node=None,
        )
        assert "timestamp" in event
        assert "source" in event
        assert "asset_id" in event
        assert "src_ip" in event
        assert "event_type" in event
        assert event["source"] == "digital_twin_simulation"

    def test_lateral_movement_event_has_prev_node(self):
        twin = DigitalTwin()
        from agents.digital_twin import _ATTACK_TEMPLATES
        event = twin._build_synthetic_event(
            node_id="CBSE-AppSrv-03",
            node_type="app_server",
            template=_ATTACK_TEMPLATES["app_server"],
            attacker_ip="185.23.147.82",
            hop_time=__import__("datetime").datetime.now(__import__("datetime").timezone.utc),
            hop_index=1,
            prev_node="CBSE-WebSvr-01",
        )
        assert event["lateral_from"] == "CBSE-WebSvr-01"
        assert event["attack_stage"] == "hop_1"


# =============================================================================
# A14 DIGITAL TWIN: CYTOSCAPE EXPORT
# =============================================================================

class TestDigitalTwinCytoscape:
    def test_cytoscape_elements(self):
        twin = DigitalTwin()
        result = twin.get_cytoscape_elements()
        assert "elements" in result
        nodes = [e for e in result["elements"] if e["group"] == "nodes"]
        edges = [e for e in result["elements"] if e["group"] == "edges"]
        assert len(nodes) >= 25
        assert len(edges) >= 20

    def test_attack_path_edges_highlighted(self):
        twin = DigitalTwin()
        path = ["CBSE-WebSvr-01", "CBSE-AppSrv-03", "CBSE-DB-01"]
        result = twin.get_cytoscape_elements(attack_path=path)
        edges = [e for e in result["elements"] if e["group"] == "edges"]
        attack_edges = [e for e in edges if e["data"].get("in_attack_path")]
        assert len(attack_edges) >= 2
