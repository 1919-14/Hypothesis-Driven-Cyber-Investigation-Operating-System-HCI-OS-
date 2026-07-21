"""
CLI Interface for CERT-In Report Generator
"""

import argparse
from datetime import datetime
import sys
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from hci_os.reports.generator import ReportGenerator


def parse_date(date_str: str) -> datetime:
    """Parse date string in YYYY-MM-DD format"""
    try:
        return datetime.strptime(date_str, "%Y-%m-%d")
    except ValueError:
        raise argparse.ArgumentTypeError(f"Invalid date format: {date_str}. Use YYYY-MM-DD")


def main():
    """Main CLI entry point"""
    parser = argparse.ArgumentParser(
        description="Generate CERT-In style cybersecurity reports for HCI-OS",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Generate annual report for 2024
  python -m hci_os.reports.cli --start 2024-01-01 --end 2024-12-31 --type annual
  
  # Generate quarterly report with PDF only
  python -m hci_os.reports.cli --start 2024-10-01 --end 2024-12-31 --type quarterly --formats pdf
  
  # Generate sector-specific report
  python -m hci_os.reports.cli --start 2024-01-01 --end 2024-12-31 --sector Finance
  
  # Quick summary without full report
  python -m hci_os.reports.cli --start 2024-01-01 --end 2024-12-31 --summary-only
        """
    )
    
    parser.add_argument(
        "--start", "--period-start",
        required=True,
        type=parse_date,
        help="Start date of reporting period (YYYY-MM-DD)"
    )
    
    parser.add_argument(
        "--end", "--period-end",
        required=True,
        type=parse_date,
        help="End date of reporting period (YYYY-MM-DD)"
    )
    
    parser.add_argument(
        "--type",
        choices=["annual", "quarterly", "monthly"],
        default="annual",
        help="Type of report (default: annual)"
    )
    
    parser.add_argument(
        "--sector",
        help="Filter by sector (e.g., Power, Finance, Healthcare)"
    )
    
    parser.add_argument(
        "--formats",
        nargs="+",
        choices=["pdf", "markdown", "json", "html"],
        default=["pdf", "markdown", "json", "html"],
        help="Output formats (default: all formats)"
    )
    
    parser.add_argument(
        "--no-appendices",
        action="store_true",
        help="Exclude detailed incident appendices"
    )
    
    parser.add_argument(
        "--no-llm",
        action="store_true",
        help="Disable LLM-based content generation (use templates)"
    )
    
    parser.add_argument(
        "--output-dir",
        default="hci_os/reports/output",
        help="Output directory for reports (default: hci_os/reports/output)"
    )
    
    parser.add_argument(
        "--data-dir",
        default="hci_os/data",
        help="Data directory containing HCI-OS logs (default: hci_os/data)"
    )
    
    parser.add_argument(
        "--summary-only",
        action="store_true",
        help="Generate quick summary only (no full report)"
    )
    
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Validate configuration without generating report"
    )
    
    args = parser.parse_args()
    
    # Validate dates
    if args.start >= args.end:
        print("❌ Error: Start date must be before end date")
        return 1
    
    print("=" * 70)
    print("  HCI-OS CERT-In Report Generator")
    print("=" * 70)
    print()
    print(f"Configuration:")
    print(f"  Period: {args.start.date()} to {args.end.date()}")
    print(f"  Report Type: {args.type}")
    print(f"  Sector Filter: {args.sector or 'None'}")
    print(f"  Output Formats: {', '.join(args.formats)}")
    print(f"  LLM Enabled: {not args.no_llm}")
    print(f"  Output Directory: {args.output_dir}")
    print()
    
    if args.dry_run:
        print("✓ Dry run complete - configuration is valid")
        return 0
    
    # Initialize generator
    generator = ReportGenerator(
        data_dir=args.data_dir,
        output_dir=args.output_dir,
        use_llm=not args.no_llm
    )
    
    try:
        if args.summary_only:
            print("Generating quick summary...")
            print()
            summary = generator.generate_quick_summary(args.start, args.end)
            
            print("=" * 70)
            print("  SUMMARY STATISTICS")
            print("=" * 70)
            print()
            print(f"Period: {summary['period']}")
            print(f"Total Incidents: {summary['total_incidents']}")
            print()
            
            print("Incidents by Type:")
            for inc_type, count in sorted(summary['incidents_by_type'].items(), key=lambda x: x[1], reverse=True):
                pct = (count / summary['total_incidents'] * 100) if summary['total_incidents'] > 0 else 0
                print(f"  - {inc_type}: {count} ({pct:.1f}%)")
            print()
            
            print("Incidents by Sector:")
            for sector, count in sorted(summary['incidents_by_sector'].items(), key=lambda x: x[1], reverse=True):
                print(f"  - {sector}: {count}")
            print()
            
            if summary['top_threat_actors']:
                print("Top Threat Actors:")
                for actor, count in summary['top_threat_actors'].items():
                    print(f"  - {actor}: {count} incidents")
            
            print()
            print("=" * 70)
            
        else:
            # Generate full report
            result = generator.generate(
                start_date=args.start,
                end_date=args.end,
                report_type=args.type,
                sector_filter=args.sector,
                output_formats=args.formats,
                include_appendices=not args.no_appendices
            )
            
            print()
            print("=" * 70)
            print("  REPORT GENERATION COMPLETE")
            print("=" * 70)
            print()
            print(f"Report ID: {result['report_id']}")
            print()
            print("Generated Files:")
            for format_type, path in result['output_paths'].items():
                print(f"  [{format_type.upper()}] {path}")
            print()
            print("Statistics:")
            print(f"  Total Incidents: {result['statistics']['total_incidents']}")
            print(f"  Total Decisions: {result['statistics']['total_decisions']}")
            print()
            print("=" * 70)
        
        return 0
        
    except FileNotFoundError as e:
        print(f"❌ Error: Required data file not found - {e}")
        print("   Make sure HCI-OS data directory contains audit logs and other required files")
        return 1
    except Exception as e:
        print(f"❌ Error: Report generation failed - {e}")
        import traceback
        traceback.print_exc()
        return 1


if __name__ == "__main__":
    sys.exit(main())
