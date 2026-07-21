# 🚀 CERT-In Report Generator - Quick Start Guide

## ✅ Installation Complete!

The CERT-In Report Generator has been successfully integrated into HCI-OS.

## 📁 What Was Created

```
hci_os/reports/
├── __init__.py              # Module initialization
├── generator.py             # Main orchestrator (ReportGenerator)
├── aggregator.py            # Data collection (DataAggregator)
├── analyzer.py              # AI analysis (AIAnalyzer)
├── exporter.py              # Multi-format export (ReportExporter)
├── cli.py                   # Command-line interface
├── demo.py                  # Interactive demo script
├── README.md                # Full documentation
├── assets/                  # Logo and resources
│   ├── README.md            # Instructions for adding logo
│   └── certin_logo.png      # ⚠️ ADD YOUR LOGO HERE
├── output/                  # Generated reports go here
└── templates/               # Configuration templates
```

## 🎯 Next Steps

### 1. Add the CERT-In Logo

Save the CERT-In logo as:
```
hci_os/reports/assets/certin_logo.png
```

The logo you provided should be saved as a PNG file (800x240 pixels recommended).

### 2. Run the Demo

Try the interactive demo:

```bash
python hci_os/reports/demo.py
```

This will:
- Show summary statistics from your HCI-OS data
- Optionally generate a full sample report
- Open the report in your browser

### 3. Generate Your First Report

Use the command-line interface:

```bash
# Quick summary (fast, no files generated)
python -m hci_os.reports.cli \
  --start 2024-01-01 \
  --end 2024-12-31 \
  --summary-only

# Full report (all formats)
python -m hci_os.reports.cli \
  --start 2024-01-01 \
  --end 2024-12-31 \
  --type annual \
  --formats html pdf markdown json
```

### 4. Or Use Python API

```python
from datetime import datetime
from hci_os.reports.generator import ReportGenerator

# Initialize
generator = ReportGenerator()

# Generate report
result = generator.generate(
    start_date=datetime(2024, 1, 1),
    end_date=datetime(2024, 12, 31),
    report_type="annual",
    output_formats=["pdf", "html"]
)

print(f"✅ Report generated: {result['output_paths']}")
```

## 📊 Features Implemented

✅ **Data Aggregation**
- Reads from A12 audit logs (`audit_log.jsonl`)
- Reads from A12 cognitive memory (`cognitive_memory.jsonl`)
- Integrates A13 federation data (`federation_store.json`)
- Uses CERT-In advisories (`cert_in_advisories.json`)
- Maps sectors from asset inventory

✅ **Incident Classification**
- Automatic categorization using MITRE ATT&CK
- CERT-In taxonomy (Phishing, Ransomware, DDoS, etc.)
- Sector-based analysis
- Threat actor attribution

✅ **AI-Powered Analysis**
- Executive summaries (200-300 words)
- Trend analysis with period comparisons
- Actionable recommendations (5-10 prioritized)
- Template fallback (no API key required)

✅ **Multi-Format Export**
- **PDF**: Professional styling with CERT-In colors
- **HTML**: Self-contained, browser-ready
- **Markdown**: Collaboration-friendly
- **JSON**: API-ready structured data

✅ **CERT-In Compliance**
- Matches official CERT-In report structure
- Professional cover page with logo
- Statistics tables and charts
- Sector analysis sections
- Threat actor attribution
- Recommendations with MITRE mappings

✅ **Security Features**
- PII redaction (configurable)
- Audit trail integration (A12)
- SHA-256 content hashing
- Immutable logging

## 🧪 Tests

All 14 tests passing ✅

```bash
pytest hci_os/tests/test_report_generator.py -v
```

## 📖 Full Documentation

See `hci_os/reports/README.md` for:
- Complete CLI reference
- Python API examples
- Configuration options
- Troubleshooting guide
- Architecture details

## ⚡ Quick Commands Reference

```bash
# Interactive demo
python hci_os/reports/demo.py

# Quick summary
python -m hci_os.reports.cli --start 2024-01-01 --end 2024-12-31 --summary-only

# Annual report (HTML only, fast)
python -m hci_os.reports.cli --start 2024-01-01 --end 2024-12-31 --formats html

# Full report (all formats)
python -m hci_os.reports.cli --start 2024-01-01 --end 2024-12-31

# Sector-specific report
python -m hci_os.reports.cli --start 2024-01-01 --end 2024-12-31 --sector Finance

# Without AI (faster, no API key needed)
python -m hci_os.reports.cli --start 2024-01-01 --end 2024-12-31 --no-llm

# Validate configuration
python -m hci_os.reports.cli --start 2024-01-01 --end 2024-12-31 --dry-run
```

## 🔧 Optional: Enable AI-Powered Content

For AI-generated executive summaries and recommendations:

1. Install OpenAI library (already in requirements.txt):
   ```bash
   pip install langchain-openai
   ```

2. Set your API key:
   ```bash
   export OPENAI_API_KEY="your-api-key-here"
   ```

3. Generate reports with `--llm` (default) or without `--no-llm` (template-based)

**Note**: Template-based generation works perfectly well without API keys!

## 📦 Dependencies Added

Added to `requirements.txt`:
- `reportlab==4.0.7` - PDF generation
- `langchain-openai==0.0.5` - AI content (optional)
- `weasyprint==60.1` - Alternative PDF engine (optional)

Install with:
```bash
pip install reportlab langchain-openai
```

## 🎨 Customization

Create a config file at `hci_os/reports/templates/config.json`:

```json
{
  "title": "HCI-OS Cybersecurity Report",
  "organization": "Your Organization Name",
  "logo_path": "hci_os/reports/assets/certin_logo.png",
  "color_scheme": {
    "primary": "#2B5B9B",
    "secondary": "#1a3a6b"
  }
}
```

## 🆘 Troubleshooting

**"No data found"**
- HCI-OS needs to have processed incidents in the specified date range
- Check that `hci_os/data/audit_log.jsonl` exists and has data

**"PDF generation failed"**
- Install ReportLab: `pip install reportlab`
- Or use HTML only: `--formats html`

**"Logo not appearing"**
- Save logo as `hci_os/reports/assets/certin_logo.png`
- PNG format recommended (800x240 pixels)

## 🎉 Ready to Use!

The CERT-In Report Generator is fully integrated and ready to produce professional cybersecurity reports for your HCI-OS deployment.

Generate your first report now:
```bash
python hci_os/reports/demo.py
```

---

**Need Help?**
- Full docs: `hci_os/reports/README.md`
- Test coverage: `hci_os/tests/test_report_generator.py`
- Examples: See README for CLI examples and Python API usage
