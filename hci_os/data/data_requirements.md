# HCI-OS: Real Data Requirements for GNN, ML Models & 5 Knowledge Graphs

## Quick Summary

| Model | What you need | Where to get it |
|-------|--------------|-----------------|
| GNN (GAT/TGN/GraphSAGE) | Network flow logs, auth logs, lateral movement traces as graph edges | CICIDS-2017/2018, LANL, UNSW-NB15 |
| Isolation Forest | Normal baseline + anomaly samples (tabular: bytes, duration, packet counts) | CICIDS-2017 |
| LSTM-AE | Long time-series sequences of normal traffic per-asset | SWAT, KDD-NSL, CICIDS |
| VAE | Same as LSTM-AE, but benefits from more varied distributions | CICIDS, UNSW-NB15 |

---

## 1. GNN Training Data — What You Need

The 5 graphs in HCI-OS are built from **network telemetry as graph edges**.

### 1a. Graph 1: Entity Graph
**Nodes:** IP addresses, users, hostnames, processes  
**Edges:** "communicated_with", "authenticated_as", "ran_process"

**Data needed (real):**
- Windows Security Event Logs (EventID 4624, 4625, 4768, 4776) — auth events
- Netflow/PCAP captures — src_ip→dst_ip→port edges
- DNS query logs — hostname→IP resolution edges

**Datasets:**
| Dataset | Link | Format | Size |
|---------|------|--------|------|
| LANL Unified Host and Network Dataset | https://csr.lanl.gov/data/cyber1/ | CSV + JSON | 58 GB (use 1% sample) |
| CERT Insider Threat Dataset | https://kilthub.cmu.edu/articles/dataset/CERT_Insider_Threat_Dataset/12841247 | CSV | ~500 MB |
| UNSW-NB15 | https://research.unsw.edu.au/projects/unsw-nb15-dataset | CSV | ~100 MB |

**Minimum to build the graph:**  
~50K auth events + ~200K netflow records → builds ~500-node, ~2K-edge entity graph.

---

### 1b. Graph 2: Infrastructure Graph
**Nodes:** Assets (servers, databases, OT devices)  
**Edges:** "connects_to", "depends_on", "communicates_with"

**Data needed (real):**
- `asset_inventory.json` (already built in HCI-OS) — provides node attributes
- Network topology scans (Nmap, CMDB exports)
- Service dependency maps

**For hackathon:** Use `data/asset_inventory.json` + manually define edges from CBSE/AIIMS topology. No external dataset needed — **build from our asset inventory**.

---

### 1c. Graph 3: Threat Graph
**Nodes:** MITRE techniques (T1595, T1190, etc.), CVEs, APT groups  
**Edges:** "uses_technique", "exploits_cve", "attributed_to"

**Data needed (real):**
- MITRE ATT&CK STIX 2.1: https://github.com/mitre/cti → `enterprise-attack/attack-pattern/`
- NVD CVE JSON: https://nvd.nist.gov/vuln/data-feeds → `nvdcve-1.1-2021.json.gz`

**Script to download:**
```bash
# MITRE ATT&CK STIX (full enterprise)
curl -L https://github.com/mitre/cti/raw/master/enterprise-attack/enterprise-attack.json \
     -o data/enterprise_attack_full.json

# NVD CVE 2021 (Log4Shell year)
curl -L https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-2021.json.gz \
     -o data/nvdcve-2021.json.gz && gunzip data/nvdcve-2021.json.gz
```

**Estimated size:** MITRE STIX ~8MB, NVD 2021 ~70MB

---

### 1d. Graph 4: Evidence Graph (DAG)
**Nodes:** Evidence objects  
**Edges:** "preceded_by", "caused_by", "same_campaign_as"

**Data needed:** This graph is built **live by HCI-OS itself** as evidence flows through the pipeline. No pre-existing dataset needed — it accumulates during operation.

**For training:** Use the LANL dataset's sequence logs to simulate a "past run" and build a synthetic Evidence DAG for training.

---

### 1e. Graph 5: Decision Graph
**Nodes:** Decision objects (audit ledger entries)  
**Edges:** "led_to", "followed", "corrected_by"

**Data needed:** Also built live. For GNN training pre-seeding, use historical SOAR ticket data if available, or simulate from CICIDS-2018 attack scenarios.

---

## 2. ML Model Training Data

### 2a. Isolation Forest (A4 — Anomaly Scoring)

**What it needs:** Tabular feature vectors of network events. Trained on normal traffic; anomalies score as outliers.

**Features per row:**
- `flow_duration`, `bytes_fwd`, `bytes_bwd`, `packet_rate`
- `dst_port`, `protocol`, `flag_count`, `src_ip_entropy`
- OT-specific: `modbus_function_code`, `dnp3_object_type` if available

**Recommended datasets:**

| Dataset | Why | Link | Label? |
|---------|-----|------|--------|
| **CICIDS-2017** | Gold standard, labeled, matches your demo scenario | https://www.unb.ca/cic/datasets/ids-2017.html | Yes |
| **CICIDS-2018** | Bigger, newer, includes botnet/DoS/brute force | https://www.unb.ca/cic/datasets/ids-2018.html | Yes |
| **NSL-KDD** | Classic benchmark, good for baselines | https://www.unb.ca/cic/datasets/nsl.html | Yes |
| **SWaT (Secure Water Treatment)** | Real OT/SCADA dataset — critical for OT anomaly | https://itrust.sutd.edu.sg/itrust-labs_datasets/ (request access) | Yes |

**Minimum viable:** CICIDS-2017 BENIGN rows for training Isolation Forest (~2M rows). Use only BENIGN for fit, then score all rows.

---

### 2b. LSTM Autoencoder (A4 — Temporal Anomaly)

**What it needs:** Time-series sequences of network events per-source-IP. Each sequence = 20-100 consecutive events from the same source.

**Features per timestep:**
- `bytes`, `duration`, `dst_port`, `protocol`, `flag_count`

**Training:** Reconstruct normal sequences; high reconstruction error = anomaly.

**Recommended datasets:**

| Dataset | Why | Notes |
|---------|-----|-------|
| **CICIDS-2017** | Has timestamps → sequence extraction easy | Sort by src_ip + timestamp |
| **KDD Cup 1999** | Older but classic for LSTM-AE benchmarks | Available on Kaggle |
| **SWaT** | Best for OT/SCADA temporal anomaly | Requires access request |

**Sequence extraction code (sketch):**
```python
import pandas as pd
df = pd.read_csv("cicids_2017.csv")
df = df.sort_values([" Source IP", " Timestamp"])
sequences = df.groupby(" Source IP").apply(
    lambda g: g[feature_cols].values.tolist()
)
# Take sliding windows of length 20
```

---

### 2c. VAE (Variational Autoencoder — optional, complements LSTM-AE)

**Same data as LSTM-AE.** VAE learns a latent distribution rather than exact reconstruction — better for rare/novel anomalies.

**Extra benefit:** Use VAE's latent space as input features to the GNN (richer node embeddings).

**No additional dataset needed** — same CICIDS-2017 sequences.

---

## 3. GNN Training Specifics

### Pre-processing pipeline for graph construction:

```
CICIDS-2017 / LANL CSV
         ↓
  Extract (src_ip, dst_ip, timestamp, bytes, label)
         ↓
  Build NetworkX graph: nodes=IPs, edges=flows with features
         ↓
  Convert to PyTorch Geometric Data object
         ↓
  Node features: [degree, avg_bytes, entropy, is_internal, ...]
  Edge features: [bytes, duration, protocol_encoded, flag_count]
  Node labels: 0=benign, 1=anomalous (from CICIDS labels)
         ↓
  GAT / GraphSAGE / TGN training
```

### Minimum graph size for meaningful GNN training:
- **Nodes:** 200+ unique IPs/assets
- **Edges:** 10,000+ flow connections
- **Labeled anomaly nodes:** 5-20% of nodes

---

## 4. Seeded vs Real — What We've Already Done

| Component | Status | Notes |
|-----------|--------|-------|
| `data/mitre_stix.json` | ✅ Seeded (12 techniques) | Replace with full STIX for production |
| `data/nvd_cves.json` | ✅ Seeded (6 CVEs) | Add NVD 2021 feed for full coverage |
| `data/cert_in_advisories.json` | ✅ Hand-written (7 advisories) | Real scraping from cert-in.org.in for production |
| `data/known_campaigns.json` | ✅ Seeded (5 APT campaigns) | Update from MITRE Groups |
| `data/asset_inventory.json` | ✅ Real schema (12 assets) | Add real CMDB data for production |
| `data/sample_logs.csv` | ✅ 8 rows | Replace with CICIDS-2017 Tuesday CSV |
| FAISS RAG index | 🔄 Built at runtime | Pre-build with full MITRE+NVD for demo |
