# CERT-In Report Generator for HCI-OS

Professional cybersecurity report generation in CERT-In format with AI-powered insights.

## Features

- **Multi-Format Export**: Generate reports in PDF, Markdown, JSON, and HTML
- **AI-Powered Analysis**: Executive summaries, trend analysis, and recommendations using LLM
- **Data Integration**: Aggregates data from all HCI-OS agents (A1-A13)
- **CERT-In Compliance**: Follows official CERT-In report structure and styling
- **Incident Classification**: Automatic categorization using MITRE ATT&CK TTPs
- **Sector Analysis**: Breakdown by critical infrastructure sectors
- **Threat Attribution**: Track threat actors and campaigns
- **Audit Trail**: Immutable logging via A12 with SHA-256 chaining

## Quick Start

### Demo Mode

Run the interactive demo to generate a sample report:

```bash
cd "ET Hackathon 2.0"
python hci_os/reports/demo.py
```

### Command Line Interface

Generate reports using the CLI:

```bash
# Annual report for 2024
python -m hci_os.reports.cli --start 2024-01-01 --end 2024-12-31 --type annual

# Quarterly report (Q4 2024)
python -m hci_os.reports.cli --start 2024-10-01 --end 2024-12-31 --type quarterly

# Monthly report with specific sector
python -m hci_os.reports.cli --start 2024-12-01 --end 2024-12-31 --type monthly --sector Finance

# Generate HTML and PDF only
python -m hci_os.reports.cli --start 2024-01-01 --end 2024-12-31 --formats html pdf

# Quick summary (no full report)
python -m hci_os.reports.cli --start 2024-01-01 --end 2024-12-31 --summary-only
```

### Python API

Use the report generator programmatically:

```python
from datetime import datetime
from hci_os.reports.generator import ReportGenerator

# Initialize generator
generator = ReportGenerator(
    data_dir="hci_os/data",
    output_dir="hci_os/reports/output",
    use_llm=True  # Enable AI-powered content generation
)

# Generate report
result = generator.generate(
    start_date=datetime(2024, 1, 1),
    end_date=datetime(2024, 12, 31),
    report_type="annual",
    output_formats=["pdf", "html", "json"]
)

print(f"Report ID: {result['report_id']}")
print(f"PDF: {result['output_paths']['pdf']}")
```

## CLI Options

```
--start DATE              Start date (YYYY-MM-DD) [required]
--end DATE                End date (YYYY-MM-DD) [required]
--type TYPE               Report type: annual, quarterly, monthly
--sector SECTOR           Filter by sector (Power, Finance, Healthcare, etc.)
--formats FORMAT [...]    Output formats: pdf, markdown, json, html
--no-appendices          Exclude detailed incident listings
--no-llm                 Disable LLM (use template-based generation)
--output-dir DIR         Output directory
--data-dir DIR           HCI-OS data directory
--summary-only           Generate quick summary only
--dry-run                Validate configuration without generating
```

## Report Structure

Generated reports follow CERT-In format:

1. **Cover Page** - Title, period, logo, metadata
2. **Executive Summary** - AI-generated 200-300 word overview
3. **Incident Statistics**
   - Total incidents and decisions
   - Breakdown by type (Phishing, Ransomware, DDoS, etc.)
   - Resolution time statistics
4. **Sector Analysis**
   - Incidents per sector
   - Risk scores
   - Sector-specific distributions
5. **Threat Actor Attribution**
   - Active threat actors
   - Campaign tracking
   - MITRE ATT&CK TTP matrices
6. **Trend Analysis** - Period-over-period comparisons
7. **Recommendations** - AI-generated actionable recommendations
8. **Appendices** (optional) - Detailed incident listings

## Data Sources

The report generator aggregates data from:

- **A12 Audit Log** (`audit_log.jsonl`) - Decision records
- **A12 Cognitive Memory** (`cognitive_memory.jsonl`) - Hypothesis objects
- **A13 Federation** (`federation_store.json`) - STIX 2.1 indicators
- **CERT-In Advisories** (`cert_in_advisories.json`) - Advisory metadata
- **Asset Inventory** (`asset_inventory.json`) - Asset and sector mappings
- **Asset Graph** (`asset_graph.json`) - Network topology

## Dependencies

Required Python packages:

```bash
pip install reportlab  # PDF generation
pip install langchain langchain-openai  # AI-powered content (optional)
```

For PDF generation, ReportLab is required. If not available, reports fall back to HTML.

For AI-powered content generation, set your OpenAI API key:

```bash
export OPENAI_API_KEY="your-api-key"
```

If no API key is set, the generator uses template-based content generation.

## Output Formats

### PDF
- Professional styling with CERT-In colors
- Embedded logo and charts
- A4 page size with proper margins
- Suitable for formal distribution

### Markdown
- CommonMark-compliant format
- YAML frontmatter with metadata
- Tables and formatted statistics
- Ideal for review and collaboration

### JSON
- Structured data following JSON schema
- Complete incident records included
- Programmatically accessible
- Suitable for APIs and data lakes

### HTML
- Self-contained with embedded CSS
- Responsive design (768px - 1920px)
- Interactive tables
- Browser-ready for web portals

## Configuration

Create a template configuration at `hci_os/reports/templates/config.json`:

```json
{
  "title": "HCI-OS Cybersecurity Report",
  "organization": "Your Organization",
  "logo_path": "hci_os/reports/assets/certin_logo.png",
  "color_scheme": {
    "primary": "#2B5B9B",
    "secondary": "#1a3a6b"
  },
  "font_family": "Helvetica"
}
```

## Incident Classification

Incidents are automatically classified based on MITRE ATT&CK TTPs:

| Category | MITRE TTPs |
|----------|------------|
| Phishing | T1566 |
| Ransomware | T1486 |
| DDoS | T1499 |
| Unauthorized Access | T1003, T1078, T1021 |
| Vulnerability Exploitation | T1190 |
| Malicious Code | T1204, T1059 |
| Network Scanning | T1595 |

## Examples

### Generate Annual Report for 2024

```bash
python -m hci_os.reports.cli \
  --start 2024-01-01 \
  --end 2024-12-31 \
  --type annual \
  --formats pdf html markdown json
```

### Generate Finance Sector Report

```bash
python -m hci_os.reports.cli \
  --start 2024-01-01 \
  --end 2024-12-31 \
  --sector Finance \
  --formats pdf html
```

### Generate Report Without AI

```bash
python -m hci_os.reports.cli \
  --start 2024-01-01 \
  --end 2024-12-31 \
  --no-llm \
  --formats html
```

## Troubleshooting

**No data found:**
- Ensure HCI-OS has processed incidents in the specified period
- Check that `audit_log.jsonl` and `cognitive_memory.jsonl` exist
- Verify timestamps are within the reporting period

**PDF generation fails:**
- Install ReportLab: `pip install reportlab`
- Or use HTML output instead: `--formats html`

**LLM generation fails:**
- Set `OPENAI_API_KEY` environment variable
- Or disable LLM: `--no-llm`
- Template-based generation will be used as fallback

**Logo not appearing:**
- Place logo at `hci_os/reports/assets/certin_logo.png`
- Supported formats: PNG, JPG
- Recommended size: 800x240 pixels

## Architecture

```
reports/
├── __init__.py          # Module exports
├── generator.py         # Main orchestrator
├── aggregator.py        # Data collection from HCI-OS
├── analyzer.py          # AI-powered analysis
├── exporter.py          # Multi-format export
├── cli.py              # Command-line interface
├── demo.py             # Interactive demo
├── README.md           # This file
├── assets/             # Logo and resources
│   └── certin_logo.png
├── output/             # Generated reports
└── templates/          # Configuration templates
    └── config.json
```

## Integration with HCI-OS

The report generator integrates seamlessly with HCI-OS agents:

- **A1-A11**: Incident detection and analysis flows into audit logs
- **A12 (Audit)**: Report generation is logged to audit trail with SHA-256 chaining
- **A13 (Federation)**: Cross-organization intelligence included in reports
- **A6 (Attribution)**: Threat actor and campaign data used for attribution sections

## License

Part of the HCI-OS project. See main repository for license details.

## Support

For issues or questions, contact the HCI-OS development team.
