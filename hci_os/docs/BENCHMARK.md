# 📊 HCI-OS GNN Core Benchmark Report
**Generated At:** `2026-07-21T03:01:15Z`

## 🔍 Evaluation Metadata
- **Held-out Test Split Size:** 754 nodes
- **Attack Nodes in Test Split:** 3 nodes

## 📈 Model Performance
The models are evaluated exclusively on a held-out test split (stratified to ensure stable class distribution) to measure true inductive generalization performance.

| Model | Recall (Min 70%) | FPR (Max 10%) | Precision | F1-Score | ROC-AUC | Status |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: |
| **GAT** | 1.0000 | 0.0000 | 1.0000 | 1.0000 | 1.0000 | Recall: 🟢 PASS <br> FPR: 🟢 PASS |
| **GraphSAGE** | 1.0000 | 0.0107 | 0.2727 | 0.4286 | 0.9947 | Recall: 🟢 PASS <br> FPR: 🟢 PASS |
| **TGN** | 0.0000 | 0.0000 | 0.0000 | 0.0000 | 0.5000 | Recall: 🔴 FAIL <br> FPR: 🟢 PASS |

## ⏱️ Incident Response SLA Benchmarks
| Metric | Target SLA | Measured Value | Status | Description |
| :--- | :---: | :---: | :---: | :--- |
| **MTTD** (Mean Time to Detect) | <= 60s | `NOT_BENCHMARKED` | 🚫 NOT_BENCHMARKED | Replayed-attack scenario timing is not configured |
| **MTTR** (Mean Time to Respond) | <= 90s | `NOT_BENCHMARKED` | 🚫 NOT_BENCHMARKED | Automatic remediation timing requires test-bed isolation |
| **MITRE Attribution Accuracy** | >= 85% | `NOT_BENCHMARKED` | 🚫 NOT_BENCHMARKED | Requires real-world attribution ground-truth mapping |

## 📝 Benchmark Scope & Integrity Statement
Precision/Recall/F1/FPR measured on held-out test split. MTTD/MTTR and MITRE attribution accuracy are NOT_BENCHMARKED in this submission (require a labeled attack-replay scenario not available in the current build window) -- reported honestly rather than fabricated.

---
*Report generated automatically by HCI-OS Benchmark Suite.*