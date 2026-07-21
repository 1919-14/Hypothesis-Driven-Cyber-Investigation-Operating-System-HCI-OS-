"""
Main Report Generator - Orchestrates the report generation process
"""

from datetime import datetime
from typing import Optional, List
from pathlib import Path
import uuid

from .aggregator import DataAggregator
from .analyzer import AIAnalyzer
from .exporter import ReportExporter


class ReportGenerator:
    """
    Main Report Generator for HCI-OS
    Generates CERT-In style cybersecurity reports
    """
    
    def __init__(
        self,
        data_dir: str = None,
        output_dir: str = None,
        use_llm: bool = True
    ):
        """
        Initialize Report Generator
        """
        base_dir = Path(__file__).parent.parent.absolute()
        if data_dir is None:
            data_dir = str(base_dir / "data")
        else:
            data_dir = str(Path(data_dir).absolute())
            
        if output_dir is None:
            output_dir = str(base_dir / "reports" / "output")
        else:
            output_dir = str(Path(output_dir).absolute())

        self.aggregator = DataAggregator(data_dir)
        self.analyzer = AIAnalyzer(use_llm=use_llm)
        self.exporter = ReportExporter(output_dir)
        self.data_dir = Path(data_dir)
        self.output_dir = Path(output_dir)
    
    def generate(
        self,
        start_date: datetime,
        end_date: datetime,
        report_type: str = "annual",
        sector_filter: Optional[str] = None,
        output_formats: List[str] = None,
        include_appendices: bool = True
    ) -> dict:
        """
        Generate a complete CERT-In style report
        
        Args:
            start_date: Start of reporting period
            end_date: End of reporting period
            report_type: Type of report (annual, quarterly, monthly)
            sector_filter: Optional sector to filter (Power, Finance, Healthcare, etc.)
            output_formats: List of formats to generate (pdf, markdown, json, html)
            include_appendices: Whether to include detailed incident appendices
            
        Returns:
            Dictionary with report paths and metadata
        """
        if output_formats is None:
            output_formats = ["pdf", "markdown", "json", "html"]
        
        print(f"[*] Aggregating data from {start_date.date()} to {end_date.date()}...")
        
        # Step 1: Aggregate data
        data = self.aggregator.aggregate_for_period(
            start_date, 
            end_date, 
            sector_filter
        )
        
        print(f"[+] Aggregated {data['statistics']['total_incidents']} incidents")
        
        # Step 2: Generate AI analysis
        print("[*] Generating AI-powered analysis...")
        
        executive_summary = self.analyzer.generate_executive_summary(data)
        trend_analysis = self.analyzer.generate_trend_analysis(data)
        recommendations = self.analyzer.generate_recommendations(data)
        
        print(f"[+] Generated executive summary and {len(recommendations)} recommendations")
        
        # Step 3: Compile report data
        report_id = str(uuid.uuid4())
        report_data = {
            "report_id": report_id,
            "title": f"HCI-OS Cybersecurity Report - {report_type.capitalize()}",
            "report_type": report_type,
            "period": f"{start_date.date()} to {end_date.date()}",
            "generated_at": datetime.now().isoformat(),
            "sector_filter": sector_filter,
            "executive_summary": executive_summary,
            "statistics": data["statistics"],
            "trend_analysis": trend_analysis,
            "recommendations": recommendations,
            "data_sources": data["metadata"]["data_sources"],
            "include_appendices": include_appendices
        }
        
        if include_appendices:
            report_data["incidents"] = data.get("hypotheses", [])[:50]  # Limit to top 50
        
        # Step 4: Export to requested formats
        print(f"[*] Exporting report to {len(output_formats)} format(s)...")
        
        filename_base = f"{report_type}_{start_date.strftime('%Y%m%d')}_{end_date.strftime('%Y%m%d')}_{report_id[:8]}"
        
        output_paths = {}
        
        if "json" in output_formats:
            output_paths["json"] = self.exporter.export_json(report_data, filename_base)
            print(f"[+] JSON: {output_paths['json']}")
        
        if "markdown" in output_formats:
            output_paths["markdown"] = self.exporter.export_markdown(report_data, filename_base)
            print(f"[+] Markdown: {output_paths['markdown']}")
        
        if "html" in output_formats:
            output_paths["html"] = self.exporter.export_html(report_data, filename_base)
            print(f"[+] HTML: {output_paths['html']}")
        
        if "pdf" in output_formats:
            output_paths["pdf"] = self.exporter.export_pdf(report_data, filename_base)
            print(f"[+] PDF: {output_paths['pdf']}")
        
        # Step 5: Log to audit trail (A12)
        self._log_to_audit_trail(report_data, output_paths)
        
        print("[+] Report generation complete!")
        
        return {
            "report_id": report_id,
            "status": "success",
            "output_paths": output_paths,
            "statistics": data["statistics"]
        }
    
    def _log_to_audit_trail(self, report_data: dict, output_paths: dict):
        """Log report generation to A12 audit trail"""
        import json
        import hashlib
        
        audit_entry = {
            "entry_type": "REPORT_GENERATED",
            "report_id": report_data["report_id"],
            "report_type": report_data["report_type"],
            "period": report_data["period"],
            "generated_at": report_data["generated_at"],
            "data_sources": report_data["data_sources"],
            "output_formats": list(output_paths.keys()),
            "statistics": report_data["statistics"],
            "stored_at": datetime.now().isoformat()
        }
        
        # Compute content hash
        content_str = json.dumps(report_data, sort_keys=True)
        audit_entry["report_content_hash"] = hashlib.sha256(content_str.encode()).hexdigest()
        
        # Append to audit log
        audit_log_path = self.data_dir / "audit_log.jsonl"
        try:
            with open(audit_log_path, 'a', encoding='utf-8') as f:
                f.write(json.dumps(audit_entry) + '\n')
        except Exception as e:
            print(f"Warning: Could not write to audit log: {e}")
    
    def generate_quick_summary(
        self,
        start_date: datetime,
        end_date: datetime
    ) -> dict:
        """
        Generate a quick summary without full report generation
        
        Args:
            start_date: Start date
            end_date: End date
            
        Returns:
            Dictionary with summary statistics
        """
        data = self.aggregator.aggregate_for_period(start_date, end_date)
        return {
            "period": f"{start_date.date()} to {end_date.date()}",
            "total_incidents": data["statistics"]["total_incidents"],
            "incidents_by_type": data["statistics"]["incidents_by_type"],
            "incidents_by_sector": data["statistics"]["incidents_by_sector"],
            "top_threat_actors": dict(
                sorted(
                    data["statistics"]["threat_actors"].items(),
                    key=lambda x: x[1],
                    reverse=True
                )[:5]
            )
        }
