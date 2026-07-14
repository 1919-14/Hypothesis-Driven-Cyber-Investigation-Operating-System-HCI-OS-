"""
pipeline/lstm_ae_model.py
HCI-OS — Shared LSTM-Autoencoder Model Definition

Kept in a standalone module so that pickle can find NumpyLSTMAutoencoder
regardless of which script trains or loads it.

Imported by:
  pipeline/scripts/train_real_models.py
  pipeline/scripts/validate_models.py
  agents/a4_anomaly.py (inference)
"""

from __future__ import annotations

from typing import Dict

import numpy as np

FEATURE_DIM = 20
SEQ_LEN     = 10


# =============================================================================
# HELPERS
# =============================================================================

def _sigmoid(x: np.ndarray) -> np.ndarray:
    return 1.0 / (1.0 + np.exp(-np.clip(x, -20, 20)))


class _LSTMCell:
    """Single LSTM layer in pure NumPy."""

    def __init__(self, input_dim: int, hidden_dim: int, seed: int = 0):
        rng   = np.random.RandomState(seed)
        scale = np.sqrt(2.0 / (input_dim + hidden_dim))
        self.W = rng.randn(input_dim + hidden_dim, 4 * hidden_dim).astype(np.float32) * scale
        self.b = np.zeros(4 * hidden_dim, dtype=np.float32)
        self.b[hidden_dim : 2 * hidden_dim] = 1.0   # forget-gate bias = 1

    def forward_sequence(self, X: np.ndarray) -> np.ndarray:
        """X: (T, input_dim) -> hidden states (T, hidden_dim)"""
        T, _ = X.shape
        H    = self.W.shape[1] // 4
        h    = np.zeros(H, dtype=np.float32)
        c    = np.zeros(H, dtype=np.float32)
        hs   = []
        for t in range(T):
            xh    = np.concatenate([X[t], h])
            gates = xh @ self.W + self.b
            i_g   = _sigmoid(gates[0    : H])
            f_g   = _sigmoid(gates[H    : 2 * H])
            g     = np.tanh (gates[2*H  : 3 * H])
            o_g   = _sigmoid(gates[3*H  : 4 * H])
            c     = f_g * c + i_g * g
            h     = o_g * np.tanh(c)
            hs.append(h.copy())
        return np.stack(hs)    # (T, H)


# =============================================================================
# NUMPY LSTM AUTOENCODER
# =============================================================================

class NumpyLSTMAutoencoder:
    """
    Two-layer LSTM Autoencoder in pure NumPy (no PyTorch required).

    Architecture:
      Encoder : LSTM(input_dim → hidden_dim) → LSTM(hidden_dim → latent_dim)
      Decoder : repeat(latent, T) → LSTM(latent_dim → hidden_dim)
                                  → LSTM(hidden_dim → hidden_dim)
                                  → Linear(hidden_dim → input_dim)

    Training:
      Output layer (W_out, b_out) is updated via closed-form least-squares
      each mini-batch.  LSTM weights are fixed after random initialisation
      (Johnson-Lindenstrauss–style random encoder).  This makes it fully
      trainable without autograd while still being a real sequence model.

    For production swap the LSTM weights update with torch.optim.Adam.
    """

    def __init__(
        self,
        input_dim:  int = FEATURE_DIM,
        hidden_dim: int = 64,
        latent_dim: int = 32,
        seed:       int = 42,
    ) -> None:
        self.input_dim  = input_dim
        self.hidden_dim = hidden_dim
        self.latent_dim = latent_dim

        self.enc1 = _LSTMCell(input_dim,  hidden_dim, seed=seed)
        self.enc2 = _LSTMCell(hidden_dim, latent_dim, seed=seed + 1)
        self.dec1 = _LSTMCell(latent_dim, hidden_dim, seed=seed + 2)
        self.dec2 = _LSTMCell(hidden_dim, hidden_dim, seed=seed + 3)

        rng         = np.random.RandomState(seed)
        scale       = np.sqrt(2.0 / (hidden_dim + input_dim))
        self.W_out  = rng.randn(hidden_dim, input_dim).astype(np.float32) * scale
        self.b_out  = np.zeros(input_dim, dtype=np.float32)
        self.threshold: float = 0.05

    # ── internal ──────────────────────────────────────────────────────────────

    def _encode(self, seq: np.ndarray) -> np.ndarray:
        h1 = self.enc1.forward_sequence(seq)
        h2 = self.enc2.forward_sequence(h1)
        return h2[-1]

    def _decode(self, latent: np.ndarray, T: int) -> np.ndarray:
        repeated = np.tile(latent, (T, 1))
        h1 = self.dec1.forward_sequence(repeated)
        h2 = self.dec2.forward_sequence(h1)
        return h2 @ self.W_out + self.b_out

    # ── public API ────────────────────────────────────────────────────────────

    def reconstruct(self, seq: np.ndarray) -> np.ndarray:
        """seq: (T, D) -> reconstructed (T, D)"""
        return self._decode(self._encode(seq), seq.shape[0])

    def reconstruction_error(self, seq: np.ndarray) -> float:
        """Mean squared reconstruction error for one (T, D) sequence."""
        recon = self.reconstruct(seq)
        return float(np.mean((seq - recon) ** 2))

    def score(self, seq: np.ndarray) -> float:
        """
        Anomaly score in [0, 1].
        0 = normal (low error), 1 = highly anomalous.
        """
        err = self.reconstruction_error(seq)
        return float(np.clip(err / max(self.threshold, 1e-9), 0.0, 1.0))

    # ── training ──────────────────────────────────────────────────────────────

    def fit(
        self,
        sequences:    np.ndarray,   # (N, T, D)
        epochs:       int   = 20,
        batch_size:   int   = 64,
        lr:           float = 0.01,
        val_fraction: float = 0.10,
        seed:         int   = 42,
        verbose:      bool  = True,
    ) -> Dict:
        import logging
        log = logging.getLogger("NumpyLSTMAutoencoder")

        rng = np.random.RandomState(seed)
        N, T, D = sequences.shape

        if verbose:
            log.info("Training LSTM-AE on %d sequences (%d timesteps, %d features)", N, T, D)
            log.info("Epochs: %d  BatchSize: %d  LR: %.4f", epochs, batch_size, lr)

        n_val      = max(1, int(N * val_fraction))
        idx        = rng.permutation(N)
        val_seqs   = sequences[idx[:n_val]]
        train_seqs = sequences[idx[n_val:]]

        history = {"train_mse": [], "val_mse": []}

        for epoch in range(1, epochs + 1):
            rng.shuffle(train_seqs)
            batch_losses = []

            for start in range(0, len(train_seqs), batch_size):
                batch = train_seqs[start : start + batch_size]
                if len(batch) == 0:
                    continue

                latents = np.stack([self._encode(s) for s in batch])   # (B, latent_dim)
                targets = batch.reshape(len(batch) * T, D)             # (B*T, D)

                h_stack = []
                for s, lat in zip(batch, latents):
                    repeated = np.tile(lat, (T, 1))
                    h1 = self.dec1.forward_sequence(repeated)
                    h2 = self.dec2.forward_sequence(h1)
                    h_stack.append(h2)
                h_all = np.vstack(h_stack)   # (B*T, hidden_dim)

                # Closed-form least-squares update for W_out
                HtH = h_all.T @ h_all + np.eye(self.hidden_dim, dtype=np.float32) * 1e-4
                Hty = h_all.T @ targets
                try:
                    W_new = np.linalg.solve(HtH, Hty)
                except np.linalg.LinAlgError:
                    W_new = np.linalg.lstsq(h_all, targets, rcond=None)[0]

                self.W_out = ((1.0 - lr) * self.W_out + lr * W_new).astype(np.float32)
                self.b_out = (
                    (1.0 - lr) * self.b_out
                    + lr * np.mean(targets - h_all @ self.W_out, axis=0)
                ).astype(np.float32)

                recons = h_all @ self.W_out + self.b_out
                batch_losses.append(float(np.mean((targets - recons) ** 2)))

            train_mse = float(np.mean(batch_losses)) if batch_losses else float("nan")
            val_mse   = float(np.mean([self.reconstruction_error(s) for s in val_seqs[:50]]))
            history["train_mse"].append(train_mse)
            history["val_mse"].append(val_mse)

            if verbose and (epoch % 5 == 0 or epoch == 1):
                log.info("Epoch %3d/%d  train_mse=%.5f  val_mse=%.5f",
                         epoch, epochs, train_mse, val_mse)

        # Set threshold at 99th pct of training reconstruction errors
        sample_errors = [self.reconstruction_error(s) for s in train_seqs[:2000]]
        self.threshold = float(np.percentile(sample_errors, 99))
        if verbose:
            log.info("Threshold (99th-pct): %.5f", self.threshold)

        return {
            "final_train_mse": history["train_mse"][-1] if history["train_mse"] else 0.0,
            "final_val_mse":   history["val_mse"][-1]   if history["val_mse"]   else 0.0,
            "threshold":       self.threshold,
            "history":         history,
        }
