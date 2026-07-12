"""
models/tgn.py
Temporal Graph Network — native PyTorch implementation.

Detects low-and-slow APTs using:
  - Sinusoidal time encoding (positional encoding over seconds)
  - Per-node GRU memory updated on each temporal event
  - MLP classifier: memory → compromised/benign

Gap #2: Timestamps are ISO-8601 strings parsed to elapsed seconds.
Gap #7: Per-TGN label = nodes compromised at that point in the attack timeline.
"""
from __future__ import annotations
import math
import torch
import torch.nn as nn
import torch.nn.functional as F
from typing import Dict, List, Tuple, Optional


def _ts_to_seconds(ts: str, base_ts: str = "2026-01-10T00:00:00Z") -> float:
    """Convert ISO-8601 timestamp string to elapsed seconds from base."""
    from datetime import datetime, timezone
    fmt = "%Y-%m-%dT%H:%M:%SZ"
    t = datetime.strptime(ts, fmt).replace(tzinfo=timezone.utc)
    b = datetime.strptime(base_ts, fmt).replace(tzinfo=timezone.utc)
    return max(0.0, (t - b).total_seconds())


class TimeEncoder(nn.Module):
    """Sinusoidal positional time encoding (d_model dimensional)."""

    def __init__(self, d_model: int = 16):
        super().__init__()
        self.d_model = d_model
        div = torch.exp(torch.arange(0, d_model, 2).float() * (-math.log(10000.0) / d_model))
        self.register_buffer("div", div)

    def forward(self, t: torch.Tensor) -> torch.Tensor:
        """t: [B] seconds → [B, d_model]"""
        t = t.unsqueeze(1)  # [B,1]
        enc = torch.zeros(t.size(0), self.d_model, device=t.device)
        enc[:, 0::2] = torch.sin(t * self.div)
        enc[:, 1::2] = torch.cos(t * self.div)
        return enc


class TGN(nn.Module):
    """
    Temporal Graph Network with per-node GRU memory.

    Per-node state: memory vector of size `memory_dim`.
    On each event (src→dst at time t):
      msg = concat(memory[src], memory[dst], time_enc(t))
      memory[src] = GRU(msg, memory[src])
      memory[dst] = GRU(msg, memory[dst])
    Classifier: Linear(memory_dim, 2)
    """

    def __init__(self, num_nodes: int, node_feat_dim: int,
                 memory_dim: int = 32, time_dim: int = 16):
        super().__init__()
        self.num_nodes = num_nodes
        self.memory_dim = memory_dim
        self.time_enc = TimeEncoder(time_dim)

        msg_dim = 2 * memory_dim + time_dim
        self.gru = nn.GRUCell(msg_dim, memory_dim)
        self.classifier = nn.Linear(memory_dim, 2)

        # Node features projection (initial embed)
        self.feat_proj = nn.Linear(node_feat_dim, memory_dim)

    def init_memory(self, device: torch.device) -> torch.Tensor:
        return torch.zeros(self.num_nodes, self.memory_dim, device=device)

    def process_event(
        self, src: int, dst: int, t_sec: float,
        memory: torch.Tensor,
    ) -> torch.Tensor:
        """Update memory for src and dst given one temporal event."""
        t_tensor = torch.tensor([t_sec], dtype=torch.float32, device=memory.device)
        t_enc = self.time_enc(t_tensor)  # [1, time_dim]

        msg = torch.cat([memory[src].unsqueeze(0), memory[dst].unsqueeze(0), t_enc], dim=1)
        new_memory = memory.clone()
        new_memory[src] = self.gru(msg, memory[src].unsqueeze(0)).squeeze(0)
        new_memory[dst] = self.gru(msg, memory[dst].unsqueeze(0)).squeeze(0)
        return new_memory

    def forward(
        self,
        events: List[Tuple[int, int, float]],  # (src_idx, dst_idx, seconds)
        init_memory: Optional[torch.Tensor] = None,
    ) -> Tuple[torch.Tensor, torch.Tensor]:
        """
        Process a sequence of temporal events.

        Returns:
            log_probs: [num_nodes, 2] classification output
            memory:    [num_nodes, memory_dim] final memory state
        """
        device = next(self.parameters()).device
        memory = init_memory if init_memory is not None else self.init_memory(device)

        for src, dst, t_sec in events:
            memory = self.process_event(src, dst, t_sec, memory)

        logits = self.classifier(memory)
        return F.log_softmax(logits, dim=1), memory

    def temporal_anomaly_score(self, memory: torch.Tensor, baseline: torch.Tensor) -> torch.Tensor:
        """Compute per-node deviation from baseline memory (L2 distance, normalized)."""
        diff = (memory - baseline).norm(dim=1)
        mx = diff.max()
        return diff / (mx + 1e-8)
