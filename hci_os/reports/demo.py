"""
Demo Script for CERT-In Report Generator
Generates a sample report with demo data
"""

from datetime import datetime, timedelta
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from hci_os.reports.generator import ReportGenerator


def run_demo():
    """Run a quick demo of the report generator"""
    print("=" * 70)
    print("  HCI-OS CERT-In Report Generator - DEMO")
    print("=" * 70)
    print()
    print("This demo will generate a sample cybersecurity report using")
    print("existing HCI-OS data from the last 30 days.")
    print()
    
    # Calculate date range (last 30 days)
    end_date = datetime.now()
    start_date = end_date - timedelta(days=30)
    
    print(f"Report Period: {start_date.date()} to {end_date.date()}")
    print()
    
    # Initialize generator
    print("Initializing report generator...")
    generator = ReportGenerator(
        data_dir="hci_os/data",
        output_dir="hci_os/reports/output",
        use_llm=False  # Use template-based generation for demo
    )
    
    print("✓ Generator initialized")
    print()
    
    # Try quick summary first
    try:
        print("Generating quick summary...")
        summary = generator.generate_quick_summary(start_date, end_date)
        
        print()
        print("📊 SUMMARY STATISTICS")
        print("-" * 70)
        print(f"Total Incidents: {summary['total_incidents']}")
        print()
        
        if summary['incidents_by_type']:
            print("Top Incident Types:")
            for inc_type, count in list(summary['incidents_by_type'].items())[:5]:
                pct = (count / summary['total_incidents'] * 100) if summary['total_incidents'] > 0 else 0
                print(f"  • {inc_type}: {count} ({pct:.1f}%)")
        print()
        
        if summary['incidents_by_sector']:
            print("Top Targeted Sectors:")
            for sector, count in list(summary['incidents_by_sector'].items())[:5]:
                print(f"  • {sector}: {count}")
        print()
        
        if summary['top_threat_actors']:
            print("Top Threat Actors:")
            for actor, count in summary['top_threat_actors'].items():
                print(f"  • {actor}: {count} incidents")
        print()
        
    except Exception as e:
        print(f"⚠️  Warning: Could not generate summary - {e}")
        print("   This may be because data files are not yet populated.")
        print()
    
    # Ask user if they want to generate full report
    response = input("Generate full report? (y/n): ").strip().lower()
    
    if response == 'y':
        print()
        print("Generating full report (all formats)...")
        print()
        
        try:
            result = generator.generate(
                start_date=start_date,
                end_date=end_date,
                report_type="monthly",
                output_formats=["html", "markdown", "json"],  # Skip PDF for faster demo
                include_appendices=False
            )
            
            print()
            print("✅ REPORT GENERATED SUCCESSFULLY")
            print("=" * 70)
            print()
            print(f"Report ID: {result['report_id']}")
            print()
            print("Output Files:")
            for format_type, path in result['output_paths'].items():
                print(f"  [{format_type.upper()}] {path}")
            print()
            print("You can now open these files to view the report!")
            print()
            
            # Try to open HTML in browser
            if 'html' in result['output_paths']:
                html_path = result['output_paths']['html']
                print(f"Opening report in browser: {html_path}")
                try:
                    import webbrowser
                    webbrowser.open(f"file:///{Path(html_path).absolute()}")
                except:
                    pass
            
        except Exception as e:
            print(f"❌ Error generating report: {e}")
            import traceback
            traceback.print_exc()
    else:
        print()
        print("Demo complete. To generate reports, use the CLI:")
        print()
        print("  python -m hci_os.reports.cli --start 2024-01-01 --end 2024-12-31")
        print()


if __name__ == "__main__":
    run_demo()
