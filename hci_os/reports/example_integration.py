"""
Example: Integrating Report Generator with HCI-OS Pipeline

This demonstrates how to generate reports after HCI-OS processes incidents.
"""

from datetime import datetime, timedelta
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from hci_os.reports.generator import ReportGenerator


def generate_weekly_report():
    """
    Example: Generate weekly report automatically
    This could be scheduled as a cron job or triggered after incident processing
    """
    print("=" * 70)
    print("  Weekly Automated Report Generation")
    print("=" * 70)
    print()
    
    # Calculate last week's date range
    end_date = datetime.now()
    start_date = end_date - timedelta(days=7)
    
    print(f"Generating report for: {start_date.date()} to {end_date.date()}")
    print()
    
    # Initialize generator
    generator = ReportGenerator(
        data_dir="hci_os/data",
        output_dir="hci_os/reports/output",
        use_llm=False  # Use template-based for automated reports
    )
    
    try:
        # Generate report
        result = generator.generate(
            start_date=start_date,
            end_date=end_date,
            report_type="weekly",
            output_formats=["html", "json"],  # Fast formats for automation
            include_appendices=False  # Keep it concise for weekly reports
        )
        
        print("✅ Weekly report generated successfully!")
        print(f"   Report ID: {result['report_id']}")
        print(f"   Total Incidents: {result['statistics']['total_incidents']}")
        print(f"   HTML: {result['output_paths'].get('html', 'N/A')}")
        print(f"   JSON: {result['output_paths'].get('json', 'N/A')}")
        print()
        
        return result
        
    except Exception as e:
        print(f"❌ Error generating weekly report: {e}")
        return None


def generate_monthly_executive_report():
    """
    Example: Generate comprehensive monthly report for executives
    This includes AI-powered analysis and all formats
    """
    print("=" * 70)
    print("  Monthly Executive Report Generation")
    print("=" * 70)
    print()
    
    # Calculate last month
    today = datetime.now()
    first_of_this_month = today.replace(day=1)
    end_date = first_of_this_month - timedelta(days=1)  # Last day of previous month
    start_date = end_date.replace(day=1)  # First day of previous month
    
    print(f"Generating executive report for: {start_date.date()} to {end_date.date()}")
    print()
    
    # Initialize generator with AI enabled
    generator = ReportGenerator(
        data_dir="hci_os/data",
        output_dir="hci_os/reports/output",
        use_llm=True  # Enable AI for executive reports
    )
    
    try:
        # Generate comprehensive report
        result = generator.generate(
            start_date=start_date,
            end_date=end_date,
            report_type="monthly",
            output_formats=["pdf", "html", "markdown"],  # Multiple formats
            include_appendices=True  # Include detailed incidents
        )
        
        print("✅ Executive report generated successfully!")
        print(f"   Report ID: {result['report_id']}")
        print(f"   Total Incidents: {result['statistics']['total_incidents']}")
        print()
        print("   Output Files:")
        for format_type, path in result['output_paths'].items():
            print(f"   - [{format_type.upper()}] {path}")
        print()
        
        # Send notification (example)
        print("📧 Next step: Email report to stakeholders")
        print(f"   - Attach PDF: {result['output_paths'].get('pdf', 'N/A')}")
        print(f"   - Link HTML: {result['output_paths'].get('html', 'N/A')}")
        print()
        
        return result
        
    except Exception as e:
        print(f"❌ Error generating executive report: {e}")
        return None


def generate_sector_specific_report(sector: str = "Finance"):
    """
    Example: Generate sector-specific report
    Useful for sector-specific compliance or stakeholder reporting
    """
    print("=" * 70)
    print(f"  {sector} Sector Security Report")
    print("=" * 70)
    print()
    
    # Last quarter
    end_date = datetime.now()
    start_date = end_date - timedelta(days=90)
    
    print(f"Sector: {sector}")
    print(f"Period: {start_date.date()} to {end_date.date()}")
    print()
    
    generator = ReportGenerator(
        data_dir="hci_os/data",
        output_dir="hci_os/reports/output",
        use_llm=False
    )
    
    try:
        result = generator.generate(
            start_date=start_date,
            end_date=end_date,
            report_type="quarterly",
            sector_filter=sector,  # Filter by sector
            output_formats=["pdf", "html"],
            include_appendices=False
        )
        
        print(f"✅ {sector} sector report generated!")
        print(f"   Sector Incidents: {result['statistics']['total_incidents']}")
        print(f"   PDF: {result['output_paths'].get('pdf', 'N/A')}")
        print()
        
        return result
        
    except Exception as e:
        print(f"❌ Error generating sector report: {e}")
        return None


def generate_incident_summary_after_processing():
    """
    Example: Quick summary after HCI-OS processes a batch of incidents
    This could be triggered by the investigation loop
    """
    print("=" * 70)
    print("  Post-Processing Incident Summary")
    print("=" * 70)
    print()
    
    # Last 24 hours
    end_date = datetime.now()
    start_date = end_date - timedelta(hours=24)
    
    generator = ReportGenerator(
        data_dir="hci_os/data",
        output_dir="hci_os/reports/output",
        use_llm=False
    )
    
    try:
        # Quick summary - no full report generated
        summary = generator.generate_quick_summary(start_date, end_date)
        
        print("📊 24-Hour Incident Summary:")
        print("-" * 70)
        print(f"Period: {summary['period']}")
        print(f"Total Incidents: {summary['total_incidents']}")
        print()
        
        if summary['incidents_by_type']:
            print("Incident Types:")
            for inc_type, count in list(summary['incidents_by_type'].items())[:3]:
                print(f"  • {inc_type}: {count}")
        
        if summary['incidents_by_sector']:
            print()
            print("Top Sectors:")
            for sector, count in list(summary['incidents_by_sector'].items())[:3]:
                print(f"  • {sector}: {count}")
        
        print()
        print("✅ Summary complete")
        print()
        
        return summary
        
    except Exception as e:
        print(f"⚠️  Warning: Could not generate summary - {e}")
        return None


def main():
    """
    Run example integrations
    """
    print("\n" + "=" * 70)
    print("  HCI-OS Report Generator - Integration Examples")
    print("=" * 70)
    print()
    print("This demonstrates various ways to integrate report generation")
    print("with your HCI-OS deployment.")
    print()
    
    examples = [
        ("1", "24-Hour Incident Summary (Quick)", generate_incident_summary_after_processing),
        ("2", "Weekly Automated Report", generate_weekly_report),
        ("3", "Monthly Executive Report", generate_monthly_executive_report),
        ("4", "Sector-Specific Report (Finance)", lambda: generate_sector_specific_report("Finance")),
    ]
    
    print("Available examples:")
    for num, title, _ in examples:
        print(f"  [{num}] {title}")
    print(f"  [0] Run all examples")
    print()
    
    choice = input("Select example to run (0-4, or 'q' to quit): ").strip()
    print()
    
    if choice == 'q':
        return
    elif choice == '0':
        for num, title, func in examples:
            print(f"\n{'=' * 70}")
            print(f"Running Example {num}: {title}")
            print('=' * 70)
            func()
            input("\nPress Enter to continue...")
    else:
        for num, title, func in examples:
            if choice == num:
                func()
                break
        else:
            print("Invalid choice")


if __name__ == "__main__":
    main()
