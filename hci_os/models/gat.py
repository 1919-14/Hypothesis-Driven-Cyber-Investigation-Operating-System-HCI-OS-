"""
models/gat.py
Graph Attention Network — native PyTorch implementation.

Multi-head attention over graph edges.
Returns node embeddings + per-edge attention weights for Cytoscape visualization.
"""
from __future__ import annotations
import torch
import torch.nn as nn
import torch.nn.functional as F
from typing import Tuple, Dict


class GATLayer(nn.Module):
    """Single-head or multi-head GAT layer."""

    def __init__(self, in_features: int, out_features: int,
                 heads: int = 1, dropout: float = 0.2,
                 alpha: float = 0.2, concat: bool = True):
        super().__init__()
        self.out_features = out_features
        self.heads = heads
        self.concat = concat
        self.dropout = dropout

        self.W = nn.ModuleList([nn.Linear(in_features, out_features, bias=False) for _ in range(heads)])
        self.a = nn.ParameterList([nn.Parameter(torch.empty(2 * out_features, 1)) for _ in range(heads)])
        for p in self.a:
            nn.init.xavier_uniform_(p.data, gain=1.414)
        self.leakyrelu = nn.LeakyReLU(alpha)

    def forward(self, h: torch.Tensor, edge_index: torch.Tensor) -> Tuple[torch.Tensor, torch.Tensor]:
        num_nodes = h.size(0)
        row, col = edge_index[0], edge_index[1]
        head_outs, first_attn = [], None

        for k in range(self.heads):
            Wh = self.W[k](h)
            e = self.leakyrelu(
                torch.matmul(torch.cat([Wh[row], Wh[col]], dim=1), self.a[k]).squeeze(1)
            )

            # Vectorized softmax grouping by col
            e_stable = e - e.max()
            exp_e = torch.exp(e_stable)
            sum_exp = torch.zeros(num_nodes, device=h.device)
            sum_exp.index_add_(0, col, exp_e)
            alpha = exp_e / (sum_exp[col] + 1e-12)

            alpha_drop = F.dropout(alpha, p=self.dropout, training=self.training)

            # Vectorized aggregation using index_add_
            weighted_features = alpha_drop.unsqueeze(1) * Wh[row]
            h_prime = torch.zeros_like(Wh)
            h_prime.index_add_(0, col, weighted_features)

            head_outs.append(h_prime)
            if first_attn is None:
                first_attn = alpha

        out = torch.cat(head_outs, dim=1) if self.concat else torch.stack(head_outs).mean(0)
        return out, first_attn if first_attn is not None else torch.zeros(edge_index.size(1))


class GAT(nn.Module):
    """
    Two-layer Graph Attention Network.
    Layer 1: GATLayer(in, hidden, heads=4, concat=True)
    Layer 2: GATLayer(hidden*4, out, heads=1, concat=False)
    """

    def __init__(self, in_channels: int, hidden_channels: int = 32, out_channels: int = 2):
        super().__init__()
        self.conv1 = GATLayer(in_channels, hidden_channels, heads=4, concat=True)
        self.conv2 = GATLayer(hidden_channels * 4, out_channels, heads=1, concat=False)
        self.drop = nn.Dropout(0.2)

    def forward(self, x: torch.Tensor, edge_index: torch.Tensor) -> Tuple[torch.Tensor, torch.Tensor]:
        h, attn = self.conv1(x, edge_index)
        h = F.elu(self.drop(h))
        h, _ = self.conv2(h, edge_index)
        return F.log_softmax(h, dim=1), attn

    def embed(self, x: torch.Tensor, edge_index: torch.Tensor) -> torch.Tensor:
        """Return intermediate embeddings (after layer 1)."""
        h, _ = self.conv1(x, edge_index)
        return F.elu(h)
