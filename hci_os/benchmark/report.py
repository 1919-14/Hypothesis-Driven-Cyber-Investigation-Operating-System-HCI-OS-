"""
benchmark/report.py
=======================================================
Generates a human-readable Markdown report from the benchmark JSON output.
Saves the final report to docs/BENCHMARK.md for presentation and documentation.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

RESULTS_JSON = _ROOT / "benchmark" / "benchmark_results.json"
OUTPUT_MD = _ROOT / "docs" / "BENCHMARK.md"


def main() -> None:
    if not RESULTS_JSON.exists():
        print(f"Error: {RESULTS_JSON} not found. Please run `python benchmark/benchmark.py` first.")
        sys.exit(1)

    with open(RESULTS_JSON, "r") as f:
        data = json.load(f)

    # Build Markdown Content
    lines = [
        "# 📊 HCI-OS GNN Core Benchmark Report",
        f"**Generated At:** `{data.get('generated_at')}`",
        "",
        "## 🔍 Evaluation Metadata",
        f"- **Held-out Test Split Size:** {data.get('test_split_size')} nodes",
        f"- **Attack Nodes in Test Split:** {data.get('test_split_attack_nodes')} nodes",
        "",
        "## 📈 Model Performance",
        "The models are evaluated exclusively on a held-out test split (stratified to ensure stable class distribution) to measure true inductive generalization performance.",
        "",
        "| Model | Recall (Min 70%) | FPR (Max 10%) | Precision | F1-Score | ROC-AUC | Status |",
        "| :--- | :---: | :---: | :---: | :---: | :---: | :---: |"
    ]

    for name, m in data.get("models", {}).items():
        if m.get("status") == "NOT_BENCHMARKED":
            lines.append(f"| **{name}** | - | - | - | - | - | 🚫 `{m.get('reason')}` |")
            continue

        pass_recall = "🟢 PASS" if str(m.get("pass_recall")) in ("True", "true") or m.get("pass_recall") is True else "🔴 FAIL"
        pass_fpr = "🟢 PASS" if str(m.get("pass_fpr")) in ("True", "true") or m.get("pass_fpr") is True else "🔴 FAIL"
        status_str = f"Recall: {pass_recall} <br> FPR: {pass_fpr}"

        fpr_str = f"{m.get('FPR'):.4f}" if m.get("FPR") == m.get("FPR") else "NaN"

        lines.append(
            f"| **{name}** | {m.get('Recall'):.4f} | {fpr_str} | {m.get('Precision'):.4f} | "
            f"{m.get('F1-Score'):.4f} | {m.get('ROC-AUC'):.4f} | {status_str} |"
        )

    lines.extend([
        "",
        "## ⏱️ Incident Response SLA Benchmarks",
        "| Metric | Target SLA | Measured Value | Status | Description |",
        "| :--- | :---: | :---: | :---: | :--- |",
        f"| **MTTD** (Mean Time to Detect) | <= 60s | `{data.get('MTTD_seconds')}` | 🚫 NOT_BENCHMARKED | Replayed-attack scenario timing is not configured |",
        f"| **MTTR** (Mean Time to Respond) | <= 90s | `{data.get('MTTR_seconds')}` | 🚫 NOT_BENCHMARKED | Automatic remediation timing requires test-bed isolation |",
        f"| **MITRE Attribution Accuracy** | >= 85% | `{data.get('MITRE_attribution_accuracy')}` | 🚫 NOT_BENCHMARKED | Requires real-world attribution ground-truth mapping |",
        "",
        "## 📝 Benchmark Scope & Integrity Statement",
        data.get("scope_note", ""),
        "",
        "---",
        "*Report generated automatically by HCI-OS Benchmark Suite.*"
    ])

    OUTPUT_MD.parent.mkdir(parents=True, exist_ok=True)
    with open(OUTPUT_MD, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))

    print(f"Markdown benchmark report saved -> {OUTPUT_MD}")


if __name__ == "__main__":
    main()
