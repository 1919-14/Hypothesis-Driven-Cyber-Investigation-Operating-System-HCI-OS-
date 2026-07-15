"""
pipeline/scripts/preprocess_real_data.py
HCI-OS Ticket 19 — Real Dataset Preprocessor

Reads the real network traffic CSVs from hci_os/data/real_data/ and produces
clean, 20-feature NumPy arrays saved to hci_os/data/processed/:

  processed/cicids_benign.npy   — CICIDS-2017 benign traffic (IF + VAE train)
  processed/cicids_attack.npy   — CICIDS-2017 attack traffic (validation only)
  processed/unsw_benign.npy     — CIC-UNSW-NB15 benign traffic (IF + VAE train)
  processed/unsw_attack.npy     — CIC-UNSW-NB15 attack traffic (validation only)
  processed/cicids_sequences.npy  — CICIDS-2017 windows for LSTM-AE (shape: N,10,20)
  processed/feature_stats.pkl    — StandardScaler fitted on benign data

Datasets in data/real_data/:
  CICIDS-2017 files (Label column: "BENIGN" = normal)
    cic.csv, Monday-WorkingHours.pcap_ISCX.csv ... Friday-...csv
  CIC-UNSW-NB15 files (Label column from Readme.txt: 0 = Benign)
    Data.csv  +  Label.csv

Usage (run from hci_os/ directory):
    python pipeline/scripts/preprocess_real_data.py
    python pipeline/scripts/preprocess_real_data.py --max-rows 500000
    python pipeline/scripts/preprocess_real_data.py --cicids-only
    python pipeline/scripts/preprocess_real_data.py --unsw-only
"""

from __future__ import annotations

import argparse
import logging
import pickle
import sys
import time
import warnings
from pathlib import Path
from typing import List, Optional, Tuple

import numpy as np

# ── Path Setup ────────────────────────────────────────────────────────────────
_ROOT = Path(__file__).resolve().parent.parent.parent   # hci_os/
_DATA_RAW  = _ROOT / "data" / "real_data"
_DATA_PROC = _ROOT / "data" / "processed"
_DATA_PROC.mkdir(parents=True, exist_ok=True)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger("preprocess_real_data")
warnings.filterwarnings("ignore")

# ── 20 Feature Specification (must match a4_anomaly.py extract_features()) ───
#
# Dimensions:
#  0  bytes               (Total Length of Fwd Packet)
#  1  src_port
#  2  dst_port
#  3  flow_duration       (Flow Duration)
#  4  fwd_packets         (Total Fwd Packet)
#  5  bwd_packets         (Total Bwd packets)
#  6  protocol_tcp        (one-hot)
#  7  protocol_udp        (one-hot)
#  8  protocol_icmp       (one-hot)
#  9  status_code         (normalized 0-5 mapped to 0-1)
# 10  hour_of_day         (0-23 / 23)
# 11  day_of_week         (0-6 / 6)
# 12  is_off_hours        (bool 0/1)
# 13  is_night            (bool 0/1)
# 14  port_entropy        (derived)
# 15  byte_rate           (bytes / max(flow_duration,1))
# 16  packet_ratio        (fwd / max(fwd+bwd,1))
# 17  is_privileged_port  (dst_port < 1024)
# 18  is_high_port        (dst_port >= 49152)
# 19  connection_density  (fwd+bwd / max(flow_duration,1e-3))

FEATURE_DIM = 20
IF_FEATURE_DIM = 25   # extended feature set for Isolation Forest only
SEQUENCE_LEN = 10    # sliding window length for LSTM-AE

# ── CICIDS-2017 column mapping (base 20 features) ────────────────────────────
CICIDS_COLUMNS = {
    "bytes":          [" Total Length of Fwd Packets", "Total Length of Fwd Packet",
                       "TotalLengthofFwdPackets", "totlenFwdPkts"],
    "src_port":       [" Source Port", "Src Port", "SourcePort"],
    "dst_port":       [" Destination Port", "Dst Port", "DestinationPort"],
    "flow_duration":  [" Flow Duration", "Flow Duration", "FlowDuration"],
    "fwd_packets":    [" Total Fwd Packets", "Total Fwd Packet",
                       "TotalFwdPackets", "totFwdPkts"],
    "bwd_packets":    [" Total Backward Packets", "Total Bwd packets",
                       "TotalBwdPackets", "totBwdPkts"],
    "protocol":       [" Protocol", "Protocol"],
    "timestamp":      [" Timestamp", "Timestamp"],
    "label":          [" Label", "Label"],
}

# ── CICIDS-2017 extended columns (used only for IF 25-feature set) ────────────
CICIDS_IF_EXTRA_COLUMNS = {
    "syn_flag":    [" SYN Flag Count", "SYN Flag Count", "SYNFlagCount"],
    "ack_flag":    [" ACK Flag Count", "ACK Flag Count", "ACKFlagCount"],
    "rst_flag":    [" RST Flag Count", "RST Flag Count", "RSTFlagCount"],
    "pkt_len_var": [" Packet Length Variance", "Packet Length Variance",
                   "PacketLengthVariance"],
    "src_ip":      [" Source IP", "Src IP", "SourceIP"],
    "dst_ip":      [" Destination IP", "Dst IP", "DestinationIP"],
}

# ── CIC-UNSW-NB15 column mapping ─────────────────────────────────────────────
UNSW_COLUMNS = {
    "bytes":         ["sbytes", "dbytes", "spkts"],
    "src_port":      ["sport"],
    "dst_port":      ["dport"],
    "flow_duration": ["dur"],
    "fwd_packets":   ["spkts"],
    "bwd_packets":   ["dpkts"],
    "protocol":      ["proto"],
    "label":         ["label"],
}


# =============================================================================
# HELPER UTILITIES
# =============================================================================

def _find_col(df_columns: list, candidates: List[str]) -> Optional[str]:
    """Return first candidate column that exists in df_columns."""
    col_set = set(df_columns)
    for c in candidates:
        if c in col_set:
            return c
    return None


def _safe_float(series, default: float = 0.0):
    """Coerce series to numeric, filling errors with default."""
    import pandas as pd
    return pd.to_numeric(series, errors="coerce").fillna(default)


def _build_features_from_dict(rows: dict, timestamps=None) -> np.ndarray:
    """
    Construct 20-dim feature matrix from a dict of named series.
    All series must be aligned (same index).

    rows keys: bytes, src_port, dst_port, flow_duration,
               fwd_packets, bwd_packets, protocol (numeric 6/17/1)
    """
    import pandas as pd

    n = len(rows["bytes"])
    X = np.zeros((n, FEATURE_DIM), dtype=np.float32)

    bytes_       = np.clip(_safe_float(rows["bytes"]).values, 0, 1e9)
    src_port     = np.clip(_safe_float(rows["src_port"]).values, 0, 65535)
    dst_port     = np.clip(_safe_float(rows["dst_port"]).values, 0, 65535)
    flow_dur     = np.clip(_safe_float(rows["flow_duration"]).values, 0, 1e9)
    fwd_pkt      = np.clip(_safe_float(rows["fwd_packets"]).values, 0, 1e6)
    bwd_pkt      = np.clip(_safe_float(rows["bwd_packets"]).values, 0, 1e6)
    proto        = _safe_float(rows["protocol"]).values.astype(int)

    # Protocol one-hot
    proto_tcp  = (proto == 6).astype(np.float32)
    proto_udp  = (proto == 17).astype(np.float32)
    proto_icmp = (proto == 1).astype(np.float32)

    # Time features from timestamps
    if timestamps is not None:
        try:
            ts = pd.to_datetime(timestamps, errors="coerce")
            hour       = ts.dt.hour.fillna(12).values.astype(np.float32) / 23.0
            dow        = ts.dt.dayofweek.fillna(0).values.astype(np.float32) / 6.0
            is_off     = ((ts.dt.hour < 8) | (ts.dt.hour >= 18)).astype(np.float32)
            is_night   = ((ts.dt.hour < 6) | (ts.dt.hour >= 22)).astype(np.float32)
        except Exception:
            hour, dow, is_off, is_night = (
                np.full(n, 0.5, np.float32), np.full(n, 0.5, np.float32),
                np.zeros(n, np.float32), np.zeros(n, np.float32),
            )
    else:
        hour, dow, is_off, is_night = (
            np.full(n, 0.5, np.float32), np.full(n, 0.5, np.float32),
            np.zeros(n, np.float32), np.zeros(n, np.float32),
        )

    # Derived features
    port_range    = np.maximum(np.abs(dst_port - src_port), 1.0)
    port_entropy  = np.log1p(port_range) / np.log1p(65535)
    byte_rate     = bytes_ / np.maximum(flow_dur / 1e6, 1e-3)   # dur in µs
    byte_rate     = np.clip(byte_rate / 1e9, 0, 1)
    total_pkts    = fwd_pkt + bwd_pkt + 1e-6
    pkt_ratio     = fwd_pkt / total_pkts
    is_priv_port  = (dst_port < 1024).astype(np.float32)
    is_high_port  = (dst_port >= 49152).astype(np.float32)
    conn_density  = total_pkts / np.maximum(flow_dur / 1e6, 1e-3)
    conn_density  = np.clip(conn_density / 1e6, 0, 1)

    X[:, 0]  = np.clip(bytes_ / 1e6, 0, 1)
    X[:, 1]  = src_port / 65535.0
    X[:, 2]  = dst_port / 65535.0
    X[:, 3]  = np.clip(flow_dur / 1e8, 0, 1)
    X[:, 4]  = np.clip(fwd_pkt / 1e4, 0, 1)
    X[:, 5]  = np.clip(bwd_pkt / 1e4, 0, 1)
    X[:, 6]  = proto_tcp
    X[:, 7]  = proto_udp
    X[:, 8]  = proto_icmp
    X[:, 9]  = 0.0          # status_code not in raw flows (set 0)
    X[:, 10] = hour
    X[:, 11] = dow
    X[:, 12] = is_off
    X[:, 13] = is_night
    X[:, 14] = port_entropy.astype(np.float32)
    X[:, 15] = byte_rate.astype(np.float32)
    X[:, 16] = pkt_ratio.astype(np.float32)
    X[:, 17] = is_priv_port
    X[:, 18] = is_high_port
    X[:, 19] = conn_density.astype(np.float32)

    # Replace inf/nan
    X = np.nan_to_num(X, nan=0.0, posinf=1.0, neginf=0.0)
    return X


def _build_if_features_from_dict(
    rows: dict,
    timestamps=None,
    df_for_ctx=None,
) -> np.ndarray:
    """
    Construct 25-dim feature matrix for Isolation Forest.

    First 20 dims = same as _build_features_from_dict().
    Extra 5 dims (contextual — Fix 2):
      20  syn_ack_ratio         SYN / (ACK + 1)                  flood detection
      21  pkt_len_variance      Packet Length Variance (norm)     fragmented attacks
      22  rst_flag_rate         RST / total_packets               TCP RST scanning
      23  within_chunk_port_entropy  Shannon entropy of dst_port   port-scan detection
                                   per src_ip group in this chunk
      24  within_chunk_unique_dests  unique dst_ips per src_ip     lateral movement
    """
    import pandas as pd
    from math import log2

    # Build the base 20 features
    X_base = _build_features_from_dict(rows, timestamps)
    n = len(X_base)
    X_if = np.zeros((n, IF_FEATURE_DIM), dtype=np.float32)
    X_if[:, :FEATURE_DIM] = X_base

    # ── Feature 20: SYN/ACK ratio ─────────────────────────────────────────────
    syn = _safe_float(rows.get("syn_flag", pd.Series([0.0] * n))).values
    ack = _safe_float(rows.get("ack_flag", pd.Series([0.0] * n))).values
    fwd = _safe_float(rows.get("fwd_packets", pd.Series([1.0] * n))).values
    bwd = _safe_float(rows.get("bwd_packets", pd.Series([0.0] * n))).values
    X_if[:, 20] = np.clip(syn / np.maximum(ack + 1.0, 1.0), 0, 20) / 20.0

    # ── Feature 21: Packet length variance (normalised) ───────────────────────
    pkt_var = _safe_float(rows.get("pkt_len_var", pd.Series([0.0] * n))).values
    X_if[:, 21] = np.clip(pkt_var / 1e6, 0, 1)

    # ── Feature 22: RST flag rate ─────────────────────────────────────────────
    rst = _safe_float(rows.get("rst_flag", pd.Series([0.0] * n))).values
    total_pkts = np.maximum(fwd + bwd, 1.0)
    X_if[:, 22] = np.clip(rst / total_pkts, 0, 1)

    # ── Features 23–24: within-chunk src_ip aggregates ────────────────────────
    # These use df_for_ctx (the raw DataFrame slice) for groupby operations.
    if df_for_ctx is not None and len(df_for_ctx) > 0:
        cols = df_for_ctx.columns.tolist()

        # Resolve src_ip and dst_ip column names
        src_ip_col = _find_col(cols, CICIDS_IF_EXTRA_COLUMNS["src_ip"])
        dst_ip_col = _find_col(cols, CICIDS_IF_EXTRA_COLUMNS["dst_ip"])
        dst_port_col = _find_col(cols, CICIDS_COLUMNS["dst_port"])

        if src_ip_col and dst_port_col:
            # Feature 23: Shannon entropy of dst_port per src_ip (in this chunk)
            def _port_entropy(series):
                vc = series.value_counts(normalize=True)
                return float(-np.sum(vc.values * np.log2(np.maximum(vc.values, 1e-12))))

            port_ent = df_for_ctx.groupby(src_ip_col)[dst_port_col].transform(
                lambda x: _port_entropy(pd.to_numeric(x, errors="coerce").fillna(0))
            ).values.astype(np.float32)
            # Normalise: max entropy for 65536 ports ≈ 16 bits
            X_if[:, 23] = np.clip(port_ent / 16.0, 0, 1)
        # else stays 0.0

        if src_ip_col and dst_ip_col:
            # Feature 24: unique destination IPs per src_ip (in this chunk)
            unique_d = df_for_ctx.groupby(src_ip_col)[dst_ip_col].transform("nunique").values
            # Normalise: assume max ~1000 unique dests is extreme
            X_if[:, 24] = np.clip(unique_d / 1000.0, 0, 1).astype(np.float32)
        # else stays 0.0

    X_if = np.nan_to_num(X_if, nan=0.0, posinf=1.0, neginf=0.0)
    return X_if


def _make_sequences(X: np.ndarray, window: int = SEQUENCE_LEN) -> np.ndarray:
    """
    Create sliding-window sequences of shape (N_windows, window, 20).
    Simple non-grouped version (treats all rows as one stream).
    """
    if len(X) < window:
        return np.empty((0, window, FEATURE_DIM), dtype=np.float32)
    n_seqs = len(X) - window + 1
    seqs = np.lib.stride_tricks.sliding_window_view(X, (window, FEATURE_DIM))
    return seqs.reshape(n_seqs, window, FEATURE_DIM).astype(np.float32)


# =============================================================================
# CICIDS-2017 PREPROCESSOR
# =============================================================================

def preprocess_cicids(max_rows: Optional[int] = None) -> Tuple[np.ndarray, np.ndarray]:
    """
    Load CICIDS-2017 CSVs, extract 20 features, split benign / attack.

    Priority order (largest coverage first):
      1. Monday-WorkingHours.pcap_ISCX.csv  — all BENIGN (~529K rows)
      2. cic.csv                             — mix, large (3.49GB)
      3. Per-day CSVs                        — Tuesday through Friday

    Returns:
      X_benign: (N_b, 20) float32
      X_attack: (N_a, 20) float32
    """
    import pandas as pd

    logger.info("=" * 60)
    logger.info("CICIDS-2017 Preprocessing")
    logger.info("=" * 60)

    CHUNK = 200_000
    benign_chunks, attack_chunks = [], []

    # Priority: Monday (all benign) first, then remaining daily CSVs
    candidate_files = [
        "Monday-WorkingHours.pcap_ISCX.csv",
        "Tuesday-WorkingHours.pcap_ISCX.csv",
        "Wednesday-workingHours.pcap_ISCX.csv",
        "Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv",
        "Thursday-WorkingHours-Afternoon-Infilteration.pcap_ISCX.csv",
        "Friday-WorkingHours-Morning.pcap_ISCX.csv",
        "Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv",
        "Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv",
        "cic.csv",           # fallback to big merged file
    ]

    files_loaded = 0
    rows_seen    = 0

    for fname in candidate_files:
        fpath = _DATA_RAW / fname
        if not fpath.exists():
            continue

        logger.info("  Loading %s (%.1f MB)...", fname, fpath.stat().st_size / 1e6)
        files_loaded += 1

        try:
            for chunk in pd.read_csv(
                fpath,
                chunksize=CHUNK,
                low_memory=False,
                encoding="utf-8",
                encoding_errors="replace",
            ):
                chunk.columns = [c.strip() for c in chunk.columns]

                # Find label column
                label_col = _find_col(chunk.columns.tolist(), CICIDS_COLUMNS["label"])
                if label_col is None:
                    logger.warning("    No Label column in %s — skipping chunk", fname)
                    continue

                is_benign = chunk[label_col].astype(str).str.strip().str.upper() == "BENIGN"
                benign_df = chunk[is_benign]
                attack_df = chunk[~is_benign]

                benign_if_chunks: list = getattr(preprocess_cicids, "_if_benign", [])
                attack_if_chunks: list = getattr(preprocess_cicids, "_if_attack", [])

                for df, store, if_store in [
                    (benign_df, benign_chunks, benign_if_chunks),
                    (attack_df, attack_chunks, attack_if_chunks),
                ]:
                    if len(df) == 0:
                        continue
                    row_dict = {}
                    ts_series = None
                    for feat, candidates in CICIDS_COLUMNS.items():
                        if feat in ("label", "timestamp"):
                            continue
                        col = _find_col(df.columns.tolist(), candidates)
                        row_dict[feat] = df[col] if col else pd.Series([0.0] * len(df))
                    ts_col = _find_col(df.columns.tolist(), CICIDS_COLUMNS["timestamp"])
                    if ts_col:
                        ts_series = df[ts_col]

                    # Base 20-feature matrix (LSTM-AE / Gaussian unchanged)
                    X = _build_features_from_dict(row_dict, ts_series)
                    store.append(X)

                    # Extended 25-feature matrix for IF (Fix 2)
                    # Also pass extra columns that are available in this chunk
                    for extra_feat, extra_cands in CICIDS_IF_EXTRA_COLUMNS.items():
                        col = _find_col(df.columns.tolist(), extra_cands)
                        row_dict[extra_feat] = df[col] if col else pd.Series([0.0] * len(df))
                    X_if = _build_if_features_from_dict(row_dict, ts_series, df_for_ctx=df)
                    if_store.append(X_if)

                # Store IF chunk lists back as function attributes
                preprocess_cicids._if_benign = benign_if_chunks
                preprocess_cicids._if_attack = attack_if_chunks

                rows_seen += len(chunk)
                if max_rows and rows_seen >= max_rows:
                    logger.info("  max_rows=%d reached — stopping early", max_rows)
                    break

        except Exception as exc:
            logger.warning("  Error reading %s: %s", fname, exc)
            continue

        if max_rows and rows_seen >= max_rows:
            break

    if files_loaded == 0:
        logger.error("No CICIDS-2017 CSV files found in %s", _DATA_RAW)
        return np.empty((0, FEATURE_DIM), np.float32), np.empty((0, FEATURE_DIM), np.float32)

    X_benign = np.vstack(benign_chunks) if benign_chunks else np.empty((0, FEATURE_DIM), np.float32)
    X_attack = np.vstack(attack_chunks) if attack_chunks else np.empty((0, FEATURE_DIM), np.float32)

    logger.info("  CICIDS benign : %d rows", len(X_benign))
    logger.info("  CICIDS attack : %d rows", len(X_attack))
    return X_benign, X_attack


# =============================================================================
# CIC-UNSW-NB15 PREPROCESSOR
# =============================================================================

def preprocess_unsw(max_rows: Optional[int] = None) -> Tuple[np.ndarray, np.ndarray]:
    """
    Load CIC-UNSW-NB15 Data.csv + Label.csv, extract 20 features.
    Label mapping (from Readme.txt): 0 = Benign, 1-9 = various attacks.

    Returns:
      X_benign: (N_b, 20) float32
      X_attack: (N_a, 20) float32
    """
    import pandas as pd

    logger.info("=" * 60)
    logger.info("CIC-UNSW-NB15 Preprocessing")
    logger.info("=" * 60)

    data_path  = _DATA_RAW / "Data.csv"
    label_path = _DATA_RAW / "Label.csv"

    if not data_path.exists():
        logger.error("Data.csv not found at %s", data_path)
        return np.empty((0, FEATURE_DIM), np.float32), np.empty((0, FEATURE_DIM), np.float32)

    CHUNK = 100_000
    benign_chunks, attack_chunks = [], []
    rows_seen = 0

    # Load labels in full (only ~895 KB)
    if label_path.exists():
        try:
            labels_df = pd.read_csv(label_path, header=None, names=["label"])
            label_array = labels_df["label"].values
            logger.info("  Labels loaded: %d entries", len(label_array))
        except Exception as exc:
            logger.warning("  Failed to read Label.csv: %s — inferring from Data.csv", exc)
            label_array = None
    else:
        label_array = None
        logger.warning("  Label.csv not found — will look for label column in Data.csv")

    row_offset = 0
    try:
        for chunk in pd.read_csv(data_path, chunksize=CHUNK, low_memory=False,
                                  encoding="utf-8", encoding_errors="replace"):
            chunk.columns = [c.strip().lower() for c in chunk.columns]
            n = len(chunk)

            # Determine label vector for this chunk
            if label_array is not None:
                chunk_labels = label_array[row_offset : row_offset + n]
                is_benign = (chunk_labels == 0)
            else:
                label_col = _find_col(chunk.columns.tolist(), ["label", " label", "labels"])
                if label_col:
                    is_benign = (pd.to_numeric(chunk[label_col], errors="coerce").fillna(1) == 0)
                else:
                    logger.warning("  No label column found — treating all as benign")
                    is_benign = np.ones(n, dtype=bool)

            for mask, store in [(is_benign, benign_chunks), (~is_benign, attack_chunks)]:
                df = chunk[mask]
                if len(df) == 0:
                    continue

                row_dict = {}
                for feat, candidates in UNSW_COLUMNS.items():
                    if feat == "label":
                        continue
                    col = _find_col(df.columns.tolist(), candidates)
                    if feat == "protocol" and col:
                        # UNSW uses string protocol names: tcp=6, udp=17, icmp=1
                        proto_str = df[col].astype(str).str.lower()
                        proto_num = proto_str.map({"tcp": 6, "udp": 17, "icmp": 1}).fillna(0)
                        row_dict[feat] = proto_num
                    else:
                        row_dict[feat] = df[col] if col else pd.Series([0.0] * len(df))

                # UNSW has sbytes + dbytes; use sbytes as primary bytes metric
                if "sbytes" in df.columns and "dbytes" in df.columns:
                    import pandas as _pd
                    row_dict["bytes"] = (_pd.to_numeric(df["sbytes"], errors="coerce").fillna(0)
                                        + _pd.to_numeric(df["dbytes"], errors="coerce").fillna(0))

                X = _build_features_from_dict(row_dict)
                store.append(X)

            row_offset += n
            rows_seen  += n
            if max_rows and rows_seen >= max_rows:
                logger.info("  max_rows=%d reached — stopping UNSW early", max_rows)
                break

    except Exception as exc:
        logger.error("  Error reading Data.csv: %s", exc)

    X_benign = np.vstack(benign_chunks) if benign_chunks else np.empty((0, FEATURE_DIM), np.float32)
    X_attack = np.vstack(attack_chunks) if attack_chunks else np.empty((0, FEATURE_DIM), np.float32)

    logger.info("  UNSW benign : %d rows", len(X_benign))
    logger.info("  UNSW attack : %d rows", len(X_attack))
    return X_benign, X_attack


# =============================================================================
# SCALER FITTING
# =============================================================================

def fit_and_save_scaler(X_benign: np.ndarray) -> object:
    """Fit a StandardScaler on combined benign traffic and save to disk."""
    from sklearn.preprocessing import StandardScaler

    logger.info("Fitting StandardScaler on %d benign samples...", len(X_benign))
    scaler = StandardScaler()
    scaler.fit(X_benign)

    scaler_path = _DATA_PROC / "scaler.pkl"
    with open(scaler_path, "wb") as f:
        pickle.dump(scaler, f, protocol=pickle.HIGHEST_PROTOCOL)
    logger.info("  Scaler saved -> %s", scaler_path)
    return scaler


# =============================================================================
# MAIN
# =============================================================================

def main() -> None:
    parser = argparse.ArgumentParser(
        description="HCI-OS Real Dataset Preprocessor — Ticket 19"
    )
    parser.add_argument("--max-rows", type=int, default=None,
                        help="Max rows to read per dataset file (for quick tests)")
    parser.add_argument("--cicids-only", action="store_true", help="Only process CICIDS-2017")
    parser.add_argument("--unsw-only",   action="store_true", help="Only process CIC-UNSW-NB15")
    parser.add_argument("--no-sequences", action="store_true",
                        help="Skip LSTM-AE sequence creation (faster)")
    args = parser.parse_args()

    t0 = time.perf_counter()

    logger.info("")
    logger.info("HCI-OS Real Dataset Preprocessor")
    logger.info("Data directory  : %s", _DATA_RAW)
    logger.info("Output directory: %s", _DATA_PROC)
    logger.info("")

    all_benign = []
    all_attack = []

    # ── CICIDS-2017 ───────────────────────────────────────────────────────────
    if not args.unsw_only:
        # Reset IF chunk accumulators before preprocessing
        preprocess_cicids._if_benign = []
        preprocess_cicids._if_attack = []

        cb, ca = preprocess_cicids(max_rows=args.max_rows)
        if len(cb) > 0:
            np.save(_DATA_PROC / "cicids_benign.npy", cb)
            logger.info("  Saved cicids_benign.npy (%d rows, 20 features)", len(cb))
            all_benign.append(cb)
        if len(ca) > 0:
            np.save(_DATA_PROC / "cicids_attack.npy",  ca)
            logger.info("  Saved cicids_attack.npy  (%d rows, 20 features)", len(ca))
            all_attack.append(ca)

        # Save IF-specific 25-feature files
        if_benign = preprocess_cicids._if_benign
        if_attack = preprocess_cicids._if_attack
        if if_benign:
            X_if_b = np.vstack(if_benign)
            np.save(_DATA_PROC / "cicids_benign_if.npy", X_if_b)
            logger.info("  Saved cicids_benign_if.npy (%d rows, %d features)",
                        len(X_if_b), IF_FEATURE_DIM)
        if if_attack:
            X_if_a = np.vstack(if_attack)
            np.save(_DATA_PROC / "cicids_attack_if.npy", X_if_a)
            logger.info("  Saved cicids_attack_if.npy  (%d rows, %d features)",
                        len(X_if_a), IF_FEATURE_DIM)

    # ── CIC-UNSW-NB15 ─────────────────────────────────────────────────────────
    if not args.cicids_only:
        ub, ua = preprocess_unsw(max_rows=args.max_rows)
        if len(ub) > 0:
            np.save(_DATA_PROC / "unsw_benign.npy", ub)
            logger.info("  Saved unsw_benign.npy (%d rows)", len(ub))
            all_benign.append(ub)
        if len(ua) > 0:
            np.save(_DATA_PROC / "unsw_attack.npy",  ua)
            logger.info("  Saved unsw_attack.npy  (%d rows)", len(ua))
            all_attack.append(ua)

    # ── Fit Scaler on ALL benign data ─────────────────────────────────────────
    if all_benign:
        X_all_benign = np.vstack(all_benign)
        fit_and_save_scaler(X_all_benign)

        # ── LSTM-AE Sequences ─────────────────────────────────────────────────
        if not args.no_sequences:
            logger.info("Creating LSTM-AE sequences (window=%d)...", SEQUENCE_LEN)
            seqs = _make_sequences(X_all_benign[:500_000])   # cap at 500K for memory
            np.save(_DATA_PROC / "cicids_sequences.npy", seqs)
            logger.info("  Saved cicids_sequences.npy shape=%s", seqs.shape)
    else:
        logger.warning("No benign data loaded — check that real_data/ files are present")

    elapsed = time.perf_counter() - t0
    logger.info("")
    logger.info("=" * 60)
    logger.info("Preprocessing complete in %.1fs", elapsed)
    logger.info("Output files in: %s", _DATA_PROC)
    for p in sorted(_DATA_PROC.iterdir()):
        logger.info("  %-35s  %.1f MB", p.name, p.stat().st_size / 1e6)
    logger.info("=" * 60)


if __name__ == "__main__":
    main()
