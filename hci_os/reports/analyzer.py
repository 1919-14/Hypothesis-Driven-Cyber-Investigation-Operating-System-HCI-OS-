"""
AI Analyzer - Generates insights, summaries, and recommendations using LLM
"""

import os
from typing import Dict, List, Any
from datetime import datetime


class AIAnalyzer:
    """AI-powered analysis and content generation for reports"""
    
    def __init__(self, use_llm: bool = True):
        self.use_llm = use_llm
        self.llm = None
        
        if use_llm:
            try:
                from langchain_openai import ChatOpenAI
                api_key = os.getenv("OPENAI_API_KEY")
                if api_key:
                    self.llm = ChatOpenAI(
                        model="gpt-4",
                        temperature=0.3,
                        max_tokens=4000
                    )
            except ImportError:
                print("Warning: LangChain not available, using template-based generation")
                self.use_llm = False
    
    def generate_executive_summary(self, data: Dict[str, Any]) -> str:
        """
        Generate executive summary from aggregated data
        
        Args:
            data: Aggregated data dictionary
            
        Returns:
            Executive summary text (200-300 words)
        """
        stats = data["statistics"]
        period_start = data["metadata"]["period_start"]
        period_end = data["metadata"]["period_end"]
        
        if self.use_llm and self.llm:
            return self._generate_summary_llm(data)
        else:
            return self._generate_summary_template(stats, period_start, period_end)
    
    def _generate_summary_llm(self, data: Dict[str, Any]) -> str:
        """Generate summary using LLM"""
        stats = data["statistics"]
        
        prompt = f"""You are generating an executive summary for a cybersecurity report in the style of CERT-In (Computer Emergency Response Team India) annual reports.

Generate a professional, formal executive summary (200-300 words) based on these statistics:

- Total Incidents: {stats['total_incidents']}
- Incident Types: {stats['incidents_by_type']}
- Sectors Affected: {stats['incidents_by_sector']}
- Threat Actors: {stats['threat_actors']}

Requirements:
- Use formal, objective tone matching CERT-In style
- Highlight key findings and trends
- No speculation - only factual statements
- No PII or sensitive information
- Focus on actionable insights

Generate the executive summary:"""
        
        try:
            response = self.llm.invoke(prompt)
            return response.content
        except Exception as e:
            print(f"LLM generation failed: {e}, falling back to template")
            return self._generate_summary_template(stats, data["metadata"]["period_start"], data["metadata"]["period_end"])
    
    def _generate_summary_template(self, stats: Dict, period_start: str, period_end: str) -> str:
        """Generate summary using template"""
        total = stats.get("total_incidents", 0)
        
        # Handle case with no incidents
        if total == 0:
            return f"""During the reporting period from {period_start} to {period_end}, HCI-OS monitoring was active but no cybersecurity incidents were detected. The system's 13-agent architecture maintained continuous surveillance across all monitored assets and sectors.

This absence of detected incidents may indicate effective security controls, a low-threat environment, or a period requiring additional data collection. The GNN-based correlation engine (Agent A5) and anomaly detection system (Agent A4) remained operational throughout the period.

The federation intelligence sharing (Agent A13) and threat hunting capabilities (Agent A10) continued to ingest threat intelligence from external sources. It is recommended to verify that all data collection endpoints are functioning correctly and that the reporting period aligns with expected system activity.

For future reporting periods with active incident data, this report will include detailed statistics on incident types, sector analysis, threat actor attribution, and actionable security recommendations."""
        
        top_type = max(stats.get("incidents_by_type", {"Unknown": 0}).items(), 
                      key=lambda x: x[1], default=("Unknown", 0))
        top_sector = max(stats.get("incidents_by_sector", {"Unknown": 0}).items(), 
                        key=lambda x: x[1], default=("Unknown", 0))
        
        summary = f"""During the reporting period from {period_start} to {period_end}, HCI-OS handled a total of {total} cybersecurity incidents across various sectors of the organization. The system's 13-agent architecture successfully detected, analyzed, and responded to threats through coordinated multi-agent operations.

The most prevalent incident type was {top_type[0]} with {top_type[1]} incidents ({(top_type[1]/total*100):.1f}% of total), indicating continued focus on this attack vector by adversaries. The {top_sector[0]} sector experienced the highest impact with {top_sector[1]} incidents, requiring enhanced security measures and monitoring.

The AI-powered attribution system (Agent A6) successfully identified and tracked threat actor campaigns, enabling proactive defense measures. The GNN-based correlation engine (Agent A5) provided rapid incident analysis through graph-based threat modeling, while the SOAR system (Agent A7) automated containment responses.

Federation intelligence sharing (Agent A13) contributed significantly to early threat detection, with cross-organization indicators enhancing our defensive posture. The audit trail maintained by Agent A12 ensures complete incident traceability and compliance with regulatory requirements.

These findings demonstrate the effectiveness of the HCI-OS multi-agent approach in handling complex cyber threats and highlight areas requiring continued vigilance and resource allocation."""
        
        return summary
    
    def generate_trend_analysis(self, data: Dict[str, Any], previous_data: Dict[str, Any] = None) -> str:
        """
        Generate trend analysis comparing current to previous period
        
        Args:
            data: Current period data
            previous_data: Previous period data for comparison
            
        Returns:
            Trend analysis text
        """
        stats = data["statistics"]
        
        if previous_data:
            prev_stats = previous_data["statistics"]
            change = stats["total_incidents"] - prev_stats["total_incidents"]
            change_pct = (change / prev_stats["total_incidents"] * 100) if prev_stats["total_incidents"] > 0 else 0
            
            trend = f"""## Trend Analysis

**Incident Volume Trends:**
Total incidents changed by {change:+d} ({change_pct:+.1f}%) compared to the previous period.
"""
            
            if abs(change_pct) >= 20:
                trend += f"\n**SIGNIFICANT CHANGE DETECTED:** The {abs(change_pct):.1f}% {'increase' if change > 0 else 'decrease'} represents a major shift in threat activity.\n"
            
            # Compare incident types
            trend += "\n**Incident Type Changes:**\n"
            for inc_type, count in stats["incidents_by_type"].items():
                prev_count = prev_stats["incidents_by_type"].get(inc_type, 0)
                if prev_count > 0:
                    type_change = ((count - prev_count) / prev_count * 100)
                    if abs(type_change) >= 30:
                        trend += f"- {inc_type}: {type_change:+.1f}% change (from {prev_count} to {count})\n"
        else:
            trend = """## Trend Analysis

**Note:** No previous period data available for comparison. This analysis shows current period statistics only.

"""
            trend += f"Total incidents: {stats['total_incidents']}\n"
            trend += "\n**Top Incident Types:**\n"
            sorted_types = sorted(stats["incidents_by_type"].items(), key=lambda x: x[1], reverse=True)[:5]
            for inc_type, count in sorted_types:
                pct = (count / stats["total_incidents"] * 100) if stats["total_incidents"] > 0 else 0
                trend += f"- {inc_type}: {count} incidents ({pct:.1f}%)\n"
        
        return trend
    
    def generate_recommendations(self, data: Dict[str, Any]) -> List[Dict[str, str]]:
        """
        Generate actionable security recommendations
        
        Args:
            data: Aggregated data
            
        Returns:
            List of recommendation dictionaries
        """
        stats = data["statistics"]
        recommendations = []
        
        # Analyze incident types for recommendations
        incidents_by_type = stats.get("incidents_by_type", {})
        total_incidents = max(1, stats.get("total_incidents", 1))
        
        # Phishing recommendations
        phishing_count = incidents_by_type.get("Phishing", 0)
        if phishing_count / total_incidents > 0.3:
            recommendations.append({
                "priority": "HIGH",
                "title": "Implement Enhanced Email Security Training",
                "description": f"Phishing incidents represent {(phishing_count/total_incidents*100):.1f}% of total incidents. Recommend mandatory security awareness training for all users with simulated phishing exercises.",
                "mitre_mitigation": "M1017 - User Training"
            })
        
        # Ransomware recommendations
        ransomware_count = incidents_by_type.get("Ransomware", 0)
        if ransomware_count > 0:
            recommendations.append({
                "priority": "CRITICAL",
                "title": "Strengthen Backup and Recovery Procedures",
                "description": f"{ransomware_count} ransomware incidents detected. Implement network segmentation, offline backups, and backup validation procedures.",
                "mitre_mitigation": "M1053 - Data Backup"
            })
        
        # Unauthorized access recommendations
        unauth_count = incidents_by_type.get("Unauthorized Access", 0)
        if unauth_count > 2:
            recommendations.append({
                "priority": "HIGH",
                "title": "Enforce Multi-Factor Authentication",
                "description": f"{unauth_count} unauthorized access incidents indicate credential compromise. Deploy MFA across all privileged accounts and VPN access.",
                "mitre_mitigation": "M1032 - Multi-factor Authentication"
            })
        
        # CVE-based recommendations
        mitre_ttps = stats.get("mitre_ttps", {})
        if "T1190" in mitre_ttps and mitre_ttps["T1190"] >= 3:
            recommendations.append({
                "priority": "HIGH",
                "title": "Patch Management Enhancement",
                "description": f"Vulnerability exploitation detected in {mitre_ttps['T1190']} incidents. Accelerate patch deployment for internet-facing applications.",
                "mitre_mitigation": "M1051 - Update Software"
            })
        
        # General recommendation
        if len(recommendations) == 0:
            recommendations.append({
                "priority": "MEDIUM",
                "title": "Continue Security Monitoring",
                "description": "Maintain current security posture with regular assessments and updates to threat intelligence feeds.",
                "mitre_mitigation": "M1031 - Network Intrusion Prevention"
            })
        
        return recommendations[:10]  # Limit to top 10
