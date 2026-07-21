"""
Test cases for CERT-In Report Generator
"""

import pytest
from datetime import datetime, timedelta
from pathlib import Path
import json
import sys

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from hci_os.reports.generator import ReportGenerator
from hci_os.reports.aggregator import DataAggregator
from hci_os.reports.analyzer import AIAnalyzer
from hci_os.reports.exporter import ReportExporter


class TestDataAggregator:
    """Test data aggregation functionality"""
    
    def test_aggregator_initialization(self):
        """Test aggregator can be initialized"""
        aggregator = DataAggregator("hci_os/data")
        assert aggregator.data_dir.exists()
    
    def test_categorize_incident_phishing(self):
        """Test incident categorization for phishing"""
        aggregator = DataAggregator("hci_os/data")
        category = aggregator._categorize_incident(["T1566"])
        assert category == "Phishing"
    
    def test_categorize_incident_ransomware(self):
        """Test incident categorization for ransomware"""
        aggregator = DataAggregator("hci_os/data")
        category = aggregator._categorize_incident(["T1486"])
        assert category == "Ransomware"
    
    def test_categorize_incident_ddos(self):
        """Test incident categorization for DDoS"""
        aggregator = DataAggregator("hci_os/data")
        category = aggregator._categorize_incident(["T1499"])
        assert category == "DDoS"
    
    def test_categorize_incident_unauthorized_access(self):
        """Test incident categorization for unauthorized access"""
        aggregator = DataAggregator("hci_os/data")
        category = aggregator._categorize_incident(["T1078"])
        assert category == "Unauthorized Access"


class TestAIAnalyzer:
    """Test AI analysis functionality"""
    
    def test_analyzer_initialization(self):
        """Test analyzer can be initialized"""
        analyzer = AIAnalyzer(use_llm=False)
        assert analyzer.use_llm == False
    
    def test_generate_summary_template(self):
        """Test template-based summary generation"""
        analyzer = AIAnalyzer(use_llm=False)
        
        stats = {
            "total_incidents": 100,
            "incidents_by_type": {"Phishing": 40, "Ransomware": 30},
            "incidents_by_sector": {"Finance": 50, "Healthcare": 30}
        }
        
        summary = analyzer._generate_summary_template(
            stats, 
            "2024-01-01",
            "2024-12-31"
        )
        
        assert "100" in summary
        assert "Phishing" in summary or "incident" in summary.lower()
        assert len(summary) > 100
    
    def test_generate_recommendations(self):
        """Test recommendation generation"""
        analyzer = AIAnalyzer(use_llm=False)
        
        data = {
            "statistics": {
                "total_incidents": 100,
                "incidents_by_type": {
                    "Phishing": 40,
                    "Ransomware": 10,
                    "Unauthorized Access": 5
                },
                "mitre_ttps": {
                    "T1190": 5
                }
            }
        }
        
        recommendations = analyzer.generate_recommendations(data)
        
        assert len(recommendations) > 0
        assert all("title" in rec for rec in recommendations)
        assert all("priority" in rec for rec in recommendations)
        assert all("description" in rec for rec in recommendations)


class TestReportExporter:
    """Test report export functionality"""
    
    def test_exporter_initialization(self):
        """Test exporter can be initialized"""
        exporter = ReportExporter("hci_os/reports/output")
        assert exporter.output_dir.exists()
    
    def test_export_json(self, tmp_path):
        """Test JSON export"""
        exporter = ReportExporter(str(tmp_path))
        
        report_data = {
            "title": "Test Report",
            "period": "2024-01-01 to 2024-12-31",
            "statistics": {"total_incidents": 10}
        }
        
        output_path = exporter.export_json(report_data, "test_report")
        
        assert Path(output_path).exists()
        
        with open(output_path, 'r') as f:
            loaded_data = json.load(f)
        
        assert loaded_data["title"] == "Test Report"
        assert loaded_data["statistics"]["total_incidents"] == 10
    
    def test_export_markdown(self, tmp_path):
        """Test Markdown export"""
        exporter = ReportExporter(str(tmp_path))
        
        report_data = {
            "title": "Test Report",
            "period": "2024-01-01 to 2024-12-31",
            "generated_at": "2024-12-21T10:00:00",
            "report_type": "annual",
            "executive_summary": "This is a test summary.",
            "statistics": {
                "total_incidents": 10,
                "total_decisions": 5,
                "incidents_by_type": {"Phishing": 5},
                "incidents_by_sector": {"Finance": 5},
                "threat_actors": {}
            },
            "trend_analysis": "Test trends",
            "recommendations": []
        }
        
        output_path = exporter.export_markdown(report_data, "test_report")
        
        assert Path(output_path).exists()
        
        with open(output_path, 'r') as f:
            content = f.read()
        
        assert "Test Report" in content
        assert "10" in content
    
    def test_export_html(self, tmp_path):
        """Test HTML export"""
        exporter = ReportExporter(str(tmp_path))
        
        report_data = {
            "title": "Test Report",
            "period": "2024-01-01 to 2024-12-31",
            "generated_at": "2024-12-21T10:00:00",
            "executive_summary": "This is a test summary.",
            "statistics": {
                "total_incidents": 10,
                "total_decisions": 5,
                "incidents_by_type": {"Phishing": 5},
                "incidents_by_sector": {"Finance": 5},
                "threat_actors": {}
            },
            "trend_analysis": "Test trends",
            "recommendations": []
        }
        
        output_path = exporter.export_html(report_data, "test_report")
        
        assert Path(output_path).exists()
        
        with open(output_path, 'r') as f:
            content = f.read()
        
        assert "<!DOCTYPE html>" in content
        assert "Test Report" in content
        assert "<table>" in content


class TestReportGenerator:
    """Test main report generator"""
    
    def test_generator_initialization(self):
        """Test generator can be initialized"""
        generator = ReportGenerator(
            data_dir="hci_os/data",
            output_dir="hci_os/reports/output",
            use_llm=False
        )
        
        assert generator.aggregator is not None
        assert generator.analyzer is not None
        assert generator.exporter is not None
    
    def test_quick_summary_no_data(self):
        """Test quick summary handles missing data gracefully"""
        generator = ReportGenerator(
            data_dir="hci_os/data",
            output_dir="hci_os/reports/output",
            use_llm=False
        )
        
        end_date = datetime.now()
        start_date = end_date - timedelta(days=30)
        
        try:
            summary = generator.generate_quick_summary(start_date, end_date)
            
            assert "period" in summary
            assert "total_incidents" in summary
            assert isinstance(summary["total_incidents"], int)
        except Exception as e:
            # If data files don't exist, this is expected
            assert "audit_log" in str(e) or "data" in str(e).lower()


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
