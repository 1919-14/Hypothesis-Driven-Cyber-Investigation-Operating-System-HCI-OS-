"""
models/graphsage.py
GraphSAGE — native PyTorch inductive implementation.

Aggregates neighbor features via mean pooling.
Supports new/unseen nodes at inference time (inductive).

Gap #3: Fixed-size neighbor sampling with fallback padding for scalability.
Gap #7: Per-SAGE labels = compromised nodes in attack path.
"""
from __future__ import annotations
import random
import torch
import torch.nn as nn
import torch.nn.functional as F
from typing import Dict, List, Tuple, Optional


class SAGEConv(nn.Module):
    """
    Single GraphSAGE convolution layer.
    h_v = ReLU(W · concat(h_v, mean(h_u for u in sample(N(v)))))
    """

    def __init__(self, in_channels: int, out_channels: int, normalize: bool = True):
        super().__init__()
        # concat of self + mean-neighbor → out
        self.lin = nn.Linear(in_channels * 2, out_channels, bias=True)
        self.normalize = normalize

    def forward(
        self,
        x: torch.Tensor,
        adj: Dict[int, List[int]],
        sample_size: int = 10,
    ) -> torch.Tensor:
        """
        x:   [N, in_channels] node features
        adj: {node_idx: [neighbor_idx, ...]} adjacency list
        """
        N = x.size(0)
        agg = torch.zeros(N, x.size(1), device=x.device)

        for i in range(N):
            nbrs = adj.get(i, [])
            # Gap #3: fixed-size sampling
            if len(nbrs) >= sample_size:
                sampled = random.sample(nbrs, sample_size)
            elif len(nbrs) > 0:
                # Pad with repetition if fewer neighbors than sample_size
                sampled = nbrs + random.choices(nbrs, k=sample_size - len(nbrs))
            else:
                sampled = [i]  # self-loop fallback

            agg[i] = x[sampled].mean(0)

        out = self.lin(torch.cat([x, agg], dim=1))
        if self.normalize:
            out = F.normalize(out, p=2, dim=1)
        return F.relu(out)


class GraphSAGE(nn.Module):
    """
    Two-layer GraphSAGE with inductive inference.
    Layer 1: SAGEConv(in, hidden)
    Layer 2: SAGEConv(hidden, out)
    """

    def __init__(self, in_channels: int, hidden_channels: int = 32, out_channels: int = 2,
                 sample_size: int = 10):
        super().__init__()
        self.sample_size = sample_size
        self.conv1 = SAGEConv(in_channels, hidden_channels)
        self.conv2 = SAGEConv(hidden_channels, out_channels)
        self.drop = nn.Dropout(0.2)

    def forward(
        self, x: torch.Tensor, adj: Dict[int, List[int]],
    ) -> Tuple[torch.Tensor, torch.Tensor]:
        """
        Returns:
            log_probs:   [N, out_channels]
            embeddings:  [N, hidden_channels] (after conv1)
        """
        h = self.conv1(x, adj, self.sample_size)
        h = self.drop(h)
        embeddings = h.clone()
        h = self.conv2(h, adj, self.sample_size)
        return F.log_softmax(h, dim=1), embeddings

    def infer_new_node(
        self,
        new_feat: torch.Tensor,
        neighbor_feats: torch.Tensor,
    ) -> torch.Tensor:
        """
        Inductive inference for an unseen node.
        new_feat:       [in_channels]
        neighbor_feats: [K, in_channels]
        Returns:        [hidden_channels] embedding
        """
        if neighbor_feats.numel() == 0:
            neighbor_feats = new_feat.unsqueeze(0)
        agg = neighbor_feats.mean(0)
        h = self.conv1.lin(torch.cat([new_feat, agg]).unsqueeze(0))
        h = F.relu(h)
        return F.normalize(h.squeeze(0), p=2, dim=0)

    def sage_anomaly_score(self, embeddings: torch.Tensor, benign_mask: torch.Tensor) -> torch.Tensor:
        """
        Cosine distance from centroid of benign embeddings.
        Returns per-node anomaly score in [0, 1].
        """
        if benign_mask.sum() == 0:
            return torch.zeros(embeddings.size(0))
        benign_center = embeddings[benign_mask].mean(0)
        sims = F.cosine_similarity(embeddings, benign_center.unsqueeze(0).expand_as(embeddings))
        scores = (1.0 - sims).clamp(0, 1)
        return scores
