"""
Data Aggregator - Collects and consolidates data from HCI-OS components
"""

import json
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Any, Optional
from collections import defaultdict


class DataAggregator:
    """Aggregates incident data from HCI-OS agents and data stores"""
    
    def __init__(self, data_dir: str = "hci_os/data"):
        self.data_dir = Path(data_dir)
        self.audit_log_path = self.data_dir / "audit_log.jsonl"
        self.cognitive_memory_path = self.data_dir / "cognitive_memory.jsonl"
        self.federation_store_path = self.data_dir / "federation_store.json"
        self.cert_advisories_path = self.data_dir / "cert_in_advisories.json"
        self.asset_inventory_path = self.data_dir / "asset_inventory.json"
        self.asset_graph_path = self.data_dir / "asset_graph.json"
        
    def aggregate_for_period(
        self, 
        start_date: datetime, 
        end_date: datetime,
        sector_filter: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Aggregate all data for specified time period
        
        Args:
            start_date: Start of reporting period
            end_date: End of reporting period
            sector_filter: Optional sector to filter by
            
        Returns:
            Dictionary containing aggregated data
        """
        data = {
            "metadata": {
                "period_start": start_date.isoformat(),
                "period_end": end_date.isoformat(),
                "generated_at": datetime.now().isoformat(),
                "sector_filter": sector_filter,
                "data_sources": []
            },
            "decisions": [],
            "hypotheses": [],
            "federation_data": {},
            "advisories": [],
            "assets": {},
            "statistics": {}
        }
        
        # Load audit log (Decisions from A12)
        if self.audit_log_path.exists():
            data["decisions"] = self._load_audit_log(start_date, end_date)
            data["metadata"]["data_sources"].append("audit_log")
        
        # Load cognitive memory (Hypotheses from A12)
        if self.cognitive_memory_path.exists():
            data["hypotheses"] = self._load_cognitive_memory(start_date, end_date)
            data["metadata"]["data_sources"].append("cognitive_memory")
        
        # Load federation data (A13)
        if self.federation_store_path.exists():
            data["federation_data"] = self._load_federation_data()
            data["metadata"]["data_sources"].append("federation_store")
        
        # Load CERT-In advisories
        if self.cert_advisories_path.exists():
            data["advisories"] = self._load_advisories()
            data["metadata"]["data_sources"].append("cert_advisories")
        
        # Load asset data
        if self.asset_inventory_path.exists():
            data["assets"] = self._load_assets()
            data["metadata"]["data_sources"].append("asset_inventory")
        
        # Filter by sector if specified
        if sector_filter:
            data = self._apply_sector_filter(data, sector_filter)
        
        # Compute aggregate statistics
        data["statistics"] = self._compute_statistics(data)
        
        return data
    
    def _load_audit_log(self, start_date: datetime, end_date: datetime) -> List[Dict]:
        """Load decisions from audit log within time period"""
        decisions = []
        try:
            with open(self.audit_log_path, 'r', encoding='utf-8') as f:
                for line in f:
                    if line.strip():
                        try:
                            entry = json.loads(line)
                            stored_at = entry.get("stored_at", "")
                            # Handle different ISO format variations
                            stored_at = stored_at.replace('+00:00Z', '+00:00').replace('Z', '')
                            entry_time = datetime.fromisoformat(stored_at).replace(tzinfo=None)
                            if start_date <= entry_time <= end_date:
                                if entry.get("entry_type") == "DECISION":
                                    decisions.append(entry)
                        except (ValueError, KeyError) as e:
                            # Skip malformed entries
                            continue
        except Exception as e:
            print(f"Warning: Could not load audit log: {e}")
        return decisions
    
    def _load_cognitive_memory(self, start_date: datetime, end_date: datetime) -> List[Dict]:
        """Load hypotheses from cognitive memory within time period"""
        hypotheses = []
        try:
            with open(self.cognitive_memory_path, 'r', encoding='utf-8') as f:
                for line in f:
                    if line.strip():
                        try:
                            entry = json.loads(line)
                            stored_at = entry.get("stored_at", "")
                            # Handle different ISO format variations
                            stored_at = stored_at.replace('+00:00Z', '+00:00').replace('Z', '')
                            entry_time = datetime.fromisoformat(stored_at).replace(tzinfo=None)
                            if start_date <= entry_time <= end_date:
                                hypotheses.append(entry)
                        except (ValueError, KeyError) as e:
                            # Skip malformed entries
                            continue
        except Exception as e:
            print(f"Warning: Could not load cognitive memory: {e}")
        return hypotheses
    
    def _load_federation_data(self) -> Dict:
        """Load federation intelligence from A13"""
        try:
            with open(self.federation_store_path, 'r', encoding='utf-8') as f:
                return json.load(f)
        except Exception as e:
            print(f"Warning: Could not load federation data: {e}")
            return {}
    
    def _load_advisories(self) -> List[Dict]:
        """Load CERT-In advisories"""
        try:
            with open(self.cert_advisories_path, 'r', encoding='utf-8') as f:
                return json.load(f)
        except Exception as e:
            print(f"Warning: Could not load advisories: {e}")
            return []
    
    def _load_assets(self) -> Dict:
        """Load asset inventory"""
        try:
            with open(self.asset_inventory_path, 'r', encoding='utf-8') as f:
                return json.load(f)
        except Exception as e:
            print(f"Warning: Could not load assets: {e}")
            return {}
    
    def _apply_sector_filter(self, data: Dict, sector: str) -> Dict:
        """Filter data by sector"""
        # Filter hypotheses by sector
        filtered_hypotheses = []
        for hyp in data["hypotheses"]:
            asset_id = hyp.get("asset_id", "")
            asset_info = data["assets"].get(asset_id, {})
            if asset_info.get("sector") == sector:
                filtered_hypotheses.append(hyp)
        data["hypotheses"] = filtered_hypotheses
        return data
    
    def _compute_statistics(self, data: Dict) -> Dict:
        """Compute aggregate statistics"""
        stats = {
            "total_incidents": len(data["hypotheses"]),
            "total_decisions": len(data["decisions"]),
            "incidents_by_type": defaultdict(int),
            "incidents_by_sector": defaultdict(int),
            "threat_actors": defaultdict(int),
            "mitre_ttps": defaultdict(int)
        }
        
        # Categorize incidents
        for hyp in data["hypotheses"]:
            # Categorize by MITRE TTP
            mitre_chain = hyp.get("mitre_chain", [])
            incident_type = self._categorize_incident(mitre_chain)
            stats["incidents_by_type"][incident_type] += 1
            
            # Count TTPs
            for ttp in mitre_chain:
                stats["mitre_ttps"][ttp] += 1
            
            # Count by sector
            asset_id = hyp.get("asset_id", "")
            asset_info = data["assets"].get(asset_id, {})
            sector = asset_info.get("sector", "Unknown")
            stats["incidents_by_sector"][sector] += 1
            
            # Count threat actors
            attribution = hyp.get("attribution", {})
            if "actor" in attribution:
                stats["threat_actors"][attribution["actor"]] += 1
        
        # Convert defaultdicts to regular dicts
        stats["incidents_by_type"] = dict(stats["incidents_by_type"])
        stats["incidents_by_sector"] = dict(stats["incidents_by_sector"])
        stats["threat_actors"] = dict(stats["threat_actors"])
        stats["mitre_ttps"] = dict(stats["mitre_ttps"])
        
        return stats
    
    def _categorize_incident(self, mitre_chain: List[str]) -> str:
        """Categorize incident based on MITRE ATT&CK TTPs"""
        if not mitre_chain:
            return "Unknown"
        
        # CERT-In incident categories
        if "T1566" in mitre_chain:  # Phishing
            return "Phishing"
        elif "T1486" in mitre_chain:  # Ransomware
            return "Ransomware"
        elif "T1499" in mitre_chain:  # DDoS
            return "DDoS"
        elif any(ttp in mitre_chain for ttp in ["T1003", "T1078", "T1021"]):
            return "Unauthorized Access"
        elif "T1190" in mitre_chain:  # Exploit Public-Facing Application
            return "Vulnerability Exploitation"
        elif any(ttp in mitre_chain for ttp in ["T1204", "T1059"]):
            return "Malicious Code"
        elif "T1595" in mitre_chain:  # Active Scanning
            return "Network Scanning"
        else:
            return "Other"
