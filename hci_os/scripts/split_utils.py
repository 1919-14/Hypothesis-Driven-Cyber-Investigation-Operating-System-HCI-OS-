"""
scripts/split_utils.py
=======================================================
Stratified train/val/test split for node classification.

Ensures attack nodes (the minority class) are spread across
train/val/test rather than all landing in one split by chance
(critical here since there are only 16 attack nodes out of 5,026).
"""
from __future__ import annotations

import torch
from typing import Tuple


def make_stratified_masks(
    Y: torch.Tensor,
    train_frac: float = 0.70,
    val_frac: float = 0.15,
    seed: int = 42,
) -> Tuple[torch.Tensor, torch.Tensor, torch.Tensor]:
    g = torch.Generator().manual_seed(seed)
    N = Y.size(0)
    train_mask = torch.zeros(N, dtype=torch.bool)
    val_mask   = torch.zeros(N, dtype=torch.bool)
    test_mask  = torch.zeros(N, dtype=torch.bool)

    for cls in Y.unique().tolist():
        idx = (Y == cls).nonzero(as_tuple=True)[0]
        perm = idx[torch.randperm(idx.size(0), generator=g)]

        n = perm.size(0)
        n_train = max(1, int(round(n * train_frac)))
        n_val   = max(1, int(round(n * val_frac))) if n > 2 else 0

        if n_train + n_val >= n and n >= 3:
            n_train = max(1, n - 2)
            n_val = 1

        train_idx = perm[:n_train]
        val_idx   = perm[n_train:n_train + n_val]
        test_idx  = perm[n_train + n_val:]

        train_mask[train_idx] = True
        val_mask[val_idx]     = True
        test_mask[test_idx]   = True

    return train_mask, val_mask, test_mask


def touched_node_mask(events, num_nodes: int) -> torch.Tensor:
    """
    Nodes actually touched (as src or dst) within an event window.
    TGN nodes never touched keep zero-init memory, so they must be
    excluded from both training loss and evaluation metrics.
    """
    mask = torch.zeros(num_nodes, dtype=torch.bool)
    for src, dst, _t in events:
        mask[src] = True
        mask[dst] = True
    return mask


def save_splits(path, train_mask, val_mask, test_mask) -> None:
    torch.save(
        {"train_mask": train_mask, "val_mask": val_mask, "test_mask": test_mask},
        path,
    )


def load_splits(path):
    d = torch.load(path)
    return d["train_mask"], d["val_mask"], d["test_mask"]