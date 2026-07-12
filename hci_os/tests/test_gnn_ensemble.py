"""
tests/test_gnn_ensemble.py
Unit tests for Ticket 13 — GNN Ensemble (GAT + TGN + GraphSAGE)

Gap Coverage:
  #1  Model persistence with version + metadata
  #2  Temporal timestamps on edges
  #3  Fixed-size neighbor sampling
  #4  Cytoscape JSON schema
  #5  Fusion weight validation
  #6  Hypothesis confidence update formula
  #7  Per-GNN label generation
  #8  Digital Twin GNN-guided simulation
  #9  Error handling / fallback to training
  #10 Model size + inference time tracking

Run:
  pytest tests/test_gnn_ensemble.py -v
"""
from __future__ import annotations
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import torch
import pytest
from models.gat import GAT, GATLayer
from models.tgn import TGN, TimeEncoder, _ts_to_seconds
from models.graphsage import GraphSAGE
from agents.a5_gnn import (
    load_graph, _build_maps, _node_features, _edge_index,
    _adj_dict, _temporal_events, _labels, GNNEnsemble,
    DEFAULT_ATTACK_PATH,
)


# ── Fixtures ──────────────────────────────────────────────────────────────────

@pytest.fixture(scope="module")
def graph():
    return load_graph()

@pytest.fixture(scope="module")
def graph_maps(graph):
    return _build_maps(graph)

@pytest.fixture(scope="module")
def node_feats(graph, graph_maps):
    id2idx, _, nt = graph_maps
    return _node_features(graph, id2idx, nt)

@pytest.fixture(scope="module")
def edge_idx(graph, graph_maps):
    id2idx, _, _ = graph_maps
    ei, w = _edge_index(graph, id2idx)
    return ei, w

@pytest.fixture(scope="module")
def adj(graph, graph_maps):
    id2idx, _, _ = graph_maps
    return _adj_dict(graph, id2idx)

@pytest.fixture(scope="module")
def events(graph, graph_maps):
    id2idx, _, _ = graph_maps
    return _temporal_events(graph, id2idx)

@pytest.fixture(scope="module")
def labels_tensor(graph, graph_maps):
    id2idx, _, _ = graph_maps
    return _labels(graph, id2idx)

@pytest.fixture(scope="module")
def ensemble_trained(tmp_path_factory):
    tmpdir = tmp_path_factory.mktemp("models")
    import agents.a5_gnn as a5m
    orig = a5m._MODELS
    a5m._MODELS = tmpdir
    a5m._ensemble = None          # reset cache
    ens = GNNEnsemble().load_or_train()
    yield ens
    a5m._MODELS = orig
    a5m._ensemble = None


# ── Graph Data Tests (Gap #2) ─────────────────────────────────────────────────

class TestGraphData:
    def test_node_count(self, graph):
        assert 25 <= len(graph["nodes"]) <= 40

    def test_edges_have_timestamps(self, graph):
        for e in graph["edges"]:
            assert "timestamps" in e, f"Edge {e['from']}->{e['to']} missing timestamps"
            assert len(e["timestamps"]) >= 1

    def test_timestamps_iso8601(self, graph):
        from datetime import datetime, timezone
        for e in graph["edges"]:
            for ts in e["timestamps"]:
                dt = datetime.strptime(ts, "%Y-%m-%dT%H:%M:%SZ")
                assert dt is not None

    def test_nodes_have_features(self, graph):
        for n in graph["nodes"]:
            assert "features" in n
            assert "cpu_load" in n["features"]
            assert "network_traffic_mbps" in n["features"]

    def test_attack_path_in_metadata(self, graph):
        path = graph.get("metadata", {}).get("attack_path", [])
        assert len(path) >= 3

    def test_timestamps_sorted(self, events):
        secs = [t for _, _, t in events]
        assert secs == sorted(secs)


# ── GAT Tests ─────────────────────────────────────────────────────────────────

class TestGAT:
    def test_forward_output_shape(self, node_feats, edge_idx):
        ei, _ = edge_idx
        model = GAT(in_channels=node_feats.size(1), hidden_channels=32, out_channels=2)
        out, attn = model(node_feats, ei)
        assert out.shape == (node_feats.size(0), 2)
        assert attn.shape[0] == ei.shape[1]

    def test_attention_non_negative(self, node_feats, edge_idx):
        ei, _ = edge_idx
        model = GAT(in_channels=node_feats.size(1), hidden_channels=32, out_channels=2)
        _, attn = model(node_feats, ei)
        assert (attn >= 0).all(), "Attention weights must be non-negative"

    def test_embed_shape(self, node_feats, edge_idx):
        ei, _ = edge_idx
        model = GAT(in_channels=node_feats.size(1))
        emb = model.embed(node_feats, ei)
        assert emb.shape[0] == node_feats.size(0)

    def test_log_softmax_output(self, node_feats, edge_idx):
        ei, _ = edge_idx
        model = GAT(in_channels=node_feats.size(1))
        out, _ = model(node_feats, ei)
        probs = out.exp()
        assert torch.allclose(probs.sum(dim=1), torch.ones(node_feats.size(0)), atol=1e-5)


# ── TGN Tests ─────────────────────────────────────────────────────────────────

class TestTGN:
    def test_time_encoder_shape(self):
        enc = TimeEncoder(d_model=16)
        t = torch.tensor([0.0, 100.0, 3600.0])
        out = enc(t)
        assert out.shape == (3, 16)

    def test_ts_to_seconds(self):
        s = _ts_to_seconds("2026-01-10T01:00:00Z", "2026-01-10T00:00:00Z")
        assert abs(s - 3600.0) < 1.0

    def test_forward_output_shape(self, graph, graph_maps, node_feats, events):
        id2idx, _, _ = graph_maps
        N = len(graph["nodes"])
        model = TGN(num_nodes=N, node_feat_dim=node_feats.size(1))
        out, mem = model(events[:10])
        assert out.shape == (N, 2)
        assert mem.shape == (N, 32)

    def test_memory_updates_after_events(self, graph, graph_maps, node_feats, events):
        """Gap #7: TGN memory changes as temporal events are processed."""
        id2idx, _, _ = graph_maps
        N = len(graph["nodes"])
        model = TGN(num_nodes=N, node_feat_dim=node_feats.size(1))
        _, mem_before = model([])
        _, mem_after  = model(events[:20])
        diff = (mem_after - mem_before).abs().sum()
        assert diff.item() > 0, "Memory should change after processing events"

    def test_temporal_anomaly_score(self, graph, graph_maps, node_feats, events):
        id2idx, _, _ = graph_maps
        N = len(graph["nodes"])
        model = TGN(num_nodes=N, node_feat_dim=node_feats.size(1))
        _, baseline = model(events[:5])
        _, current  = model(events[:30])
        scores = model.temporal_anomaly_score(current, baseline)
        assert scores.shape == (N,)
        assert (scores >= 0).all() and (scores <= 1).all()


# ── GraphSAGE Tests ───────────────────────────────────────────────────────────

class TestGraphSAGE:
    def test_forward_output_shape(self, node_feats, adj):
        model = GraphSAGE(in_channels=node_feats.size(1), hidden_channels=32, out_channels=2)
        out, emb = model(node_feats, adj)
        assert out.shape == (node_feats.size(0), 2)
        assert emb.shape == (node_feats.size(0), 32)

    def test_neighbor_sampling_fixed_size(self):
        """Gap #3: Fixed-size sampling (10 neighbors max)."""
        from models.graphsage import SAGEConv
        x = torch.rand(20, 8)
        # Node 0 has 15 neighbors — should be sampled down to 10
        adj = {0: list(range(1, 16)), **{i: [0] for i in range(1, 20)}}
        conv = SAGEConv(8, 16)
        out = conv(x, adj, sample_size=10)
        assert out.shape == (20, 16)

    def test_new_node_inference(self, node_feats):
        """GraphSAGE handles new/unseen nodes (inductive)."""
        model = GraphSAGE(in_channels=node_feats.size(1))
        new_feat  = torch.rand(node_feats.size(1))
        nbr_feats = node_feats[:3]
        emb = model.infer_new_node(new_feat, nbr_feats)
        assert emb.shape[0] == 32   # hidden_channels

    def test_anomaly_score_range(self, node_feats, adj):
        model = GraphSAGE(in_channels=node_feats.size(1))
        _, emb = model(node_feats, adj)
        benign_mask = torch.ones(node_feats.size(0), dtype=torch.bool)
        benign_mask[0] = False
        scores = model.sage_anomaly_score(emb, benign_mask)
        assert (scores >= 0).all() and (scores <= 1).all()


# ── Fusion & Ensemble Tests ───────────────────────────────────────────────────

class TestFusion:
    def test_fusion_weight_validation(self):
        """Gap #5: weights must sum to 1.0."""
        with pytest.raises(ValueError):
            GNNEnsemble(w_gat=0.5, w_tgn=0.5, w_sage=0.5)

    def test_valid_weights(self):
        ens = GNNEnsemble(w_gat=0.4, w_tgn=0.3, w_sage=0.3)
        assert ens.w_gat == 0.4

    def test_predict_returns_all_scores(self, ensemble_trained):
        preds = ensemble_trained.predict()
        assert "gat_scores"   in preds
        assert "tgn_scores"   in preds
        assert "sage_scores"  in preds
        assert "fused_scores" in preds

    def test_fused_scores_in_range(self, ensemble_trained):
        preds = ensemble_trained.predict()
        for v in preds["fused_scores"].values():
            assert 0.0 <= v <= 1.0, f"Fused score {v} out of range"

    def test_perf_tracked(self, ensemble_trained):
        """Gap #10: inference time is recorded."""
        ensemble_trained.predict()
        assert "last_inference_ms" in ensemble_trained._perf
        assert ensemble_trained._perf["last_inference_ms"] >= 0


# ── Model Persistence Tests (Gap #1) ──────────────────────────────────────────

class TestPersistence:
    def test_models_saved_to_disk(self, tmp_path, graph, graph_maps, node_feats, events):
        id2idx, _, nt = graph_maps
        from agents.a5_gnn import _train_gat
        model = _train_gat(graph, id2idx, nt, epochs=5)
        path = tmp_path / "gat_model.pt"
        import agents.a5_gnn as a5m
        orig = a5m._MODELS
        a5m._MODELS = tmp_path
        from agents.a5_gnn import _save
        _save(model, "gat", {"in_channels": node_feats.size(1)})
        a5m._MODELS = orig
        assert (tmp_path / "gat_model.pt").exists()

    def test_checkpoint_has_version(self, tmp_path, graph, graph_maps, node_feats):
        id2idx, _, nt = graph_maps
        from agents.a5_gnn import _train_gat, _save
        import agents.a5_gnn as a5m
        orig = a5m._MODELS
        a5m._MODELS = tmp_path
        model = _train_gat(graph, id2idx, nt, epochs=5)
        a5m._MODELS = orig
        ck = torch.load(str(tmp_path / "gat_model.pt"), map_location="cpu", weights_only=False)
        assert "version" in ck
        assert "saved_at" in ck
        assert "name" in ck

    def test_load_fallback_on_corrupt_file(self, tmp_path):
        """Gap #9: fallback to training if load fails."""
        bad = tmp_path / "gat_model.pt"
        bad.write_bytes(b"not a valid checkpoint")
        from models.gat import GAT
        from agents.a5_gnn import _load
        model = GAT(in_channels=10)
        ok = _load(model, "gat")
        assert ok is False  # returns False on failure


# ── Cytoscape JSON Schema Tests (Gap #4) ─────────────────────────────────────

class TestCytoscapeSchema:
    def test_elements_key_exists(self, ensemble_trained):
        cyto = ensemble_trained.export_cytoscape()
        assert "elements" in cyto
        assert "metadata" in cyto

    def test_node_data_fields(self, ensemble_trained):
        cyto = ensemble_trained.export_cytoscape()
        nodes = [e for e in cyto["elements"] if e["group"] == "nodes"]
        assert len(nodes) >= 25
        for n in nodes:
            for field in ["id", "label", "type", "criticality", "status", "color", "gnn_score"]:
                assert field in n["data"], f"Missing field {field} in node data"

    def test_edge_data_fields(self, ensemble_trained):
        cyto = ensemble_trained.export_cytoscape()
        edges = [e for e in cyto["elements"] if e["group"] == "edges"]
        assert len(edges) >= 20
        for e in edges:
            for field in ["id", "source", "target", "weight", "protocol", "attention"]:
                assert field in e["data"], f"Missing field {field} in edge data"

    def test_compromised_node_is_red(self, ensemble_trained):
        cyto = ensemble_trained.export_cytoscape(
            compromised=["CBSE-WebSvr-01"]
        )
        nodes = {e["data"]["id"]: e for e in cyto["elements"] if e["group"] == "nodes"}
        assert nodes["CBSE-WebSvr-01"]["data"]["status"] == "compromised"
        assert nodes["CBSE-WebSvr-01"]["data"]["color"] == "#e74c3c"


# ── Hypothesis Update Tests (Gap #6) ─────────────────────────────────────────

class TestHypothesisUpdate:
    def test_confidence_increases(self, ensemble_trained):
        from objects.hypothesis import Hypothesis
        hyp = Hypothesis.model_validate({
            "goal": "Test GNN update",
            "confidence": 0.5,
            "supporting_evidence": [],
        })
        orig_conf = hyp.confidence
        from agents.a5_gnn import process
        process({"asset_id": "CBSE-WebSvr-01"}, hyp)
        assert hyp.confidence >= orig_conf

    def test_confidence_capped_at_1(self, ensemble_trained):
        from objects.hypothesis import Hypothesis
        hyp = Hypothesis.model_validate({
            "goal": "Test confidence cap",
            "confidence": 0.99,
            "supporting_evidence": [],
        })
        from agents.a5_gnn import process
        process({"asset_id": "CBSE-WebSvr-01"}, hyp)
        assert hyp.confidence <= 1.0

    def test_predicted_moves_added(self, ensemble_trained):
        from objects.hypothesis import Hypothesis
        hyp = Hypothesis.model_validate({
            "goal": "Test moves",
            "confidence": 0.5,
            "supporting_evidence": [],
        })
        from agents.a5_gnn import process
        process({"asset_id": "CBSE-WebSvr-01"}, hyp)
        assert len(hyp.predicted_next_moves) >= 1


# ── Digital Twin GNN-Guided Tests (Gap #8) ───────────────────────────────────

class TestDigitalTwinGNN:
    def test_gnn_guided_returns_path(self):
        from agents.digital_twin import DigitalTwin
        twin = DigitalTwin()
        result = twin.simulate_gnn_guided()
        assert "attack_path" in result
        assert result["mode"] == "gnn_guided"
        assert len(result["attack_path"]) >= 1

    def test_gnn_guided_has_fused_scores(self):
        from agents.digital_twin import DigitalTwin
        twin = DigitalTwin()
        result = twin.simulate_gnn_guided()
        assert "gnn_fused_scores" in result

    def test_gnn_guided_timeline_has_scores(self):
        from agents.digital_twin import DigitalTwin
        twin = DigitalTwin()
        result = twin.simulate_gnn_guided()
        for event in result["timeline"]:
            assert "gnn_fused_score" in event
