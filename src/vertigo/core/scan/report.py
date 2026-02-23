"""Final scan report assembly"""

from typing import Dict, Any, List, Optional
from dataclasses import dataclass, asdict


@dataclass
class ScanMetadata:
    """Scan metadata"""
    target: str
    entry: str
    session_fingerprint: str
    authenticated: bool
    scan_begin: int
    scan_end: int
    status: str  # 'COMPLETE', 'PARTIAL', 'BLOCKED'
    stats: Dict[str, Any]


class ScanReport:
    """Assembles and formats scan reports"""
    
    @staticmethod
    def create_report(
        metadata: ScanMetadata,
        asset_fingerprint: str,
        endpoints: List[Dict],
        forms: List[Dict],
        dynamic_endpoints: List[Dict],
        stats: Dict[str, int]
    ) -> Dict[str, Any]:
        """Create complete scan report"""
        
        report = {
            'metadata': asdict(metadata),
            'asset_fingerprint': asset_fingerprint,
            'endpoints': endpoints,
            'forms': forms,
            'dynamic_endpoints': dynamic_endpoints,
            'summary': {
                'total_urls': stats.get('urls_crawled', 0),
                'total_endpoints': len(endpoints),
                'total_forms': len(forms),
                'dynamic_endpoints': len(dynamic_endpoints),
                'dynamic_endpoints_runtime': stats.get('dynamic_endpoints_found', 0),
                'dynamic_endpoints_static': stats.get('static_endpoints_found', 0),
                'anomalies': stats.get('anomalies_detected', 0),
                'depth_reached': stats.get('depth_reached', 0),
            }
        }
        
        return report
    
    @staticmethod
    def format_summary(report: Dict[str, Any]) -> str:
        """Format report summary for logging"""
        meta = report.get('metadata', {})
        summary = report.get('summary', {})
        
        lines = [
            f"Scan Status: {meta.get('status', 'UNKNOWN')}",
            f"Target: {meta.get('target', 'N/A')}",
            f"URLs Crawled: {summary.get('total_urls', 0)}",
            f"Endpoints Found: {summary.get('total_endpoints', 0)}",
            f"Forms Found: {summary.get('total_forms', 0)}",
            f"Dynamic Endpoints: {summary.get('dynamic_endpoints', 0)} " +
            f"(runtime: {summary.get('dynamic_endpoints_runtime', 0)}, " +
            f"static: {summary.get('dynamic_endpoints_static', 0)})",
            f"Asset Fingerprint: {report.get('asset_fingerprint', 'N/A')}",
        ]
        
        return '\n'.join(lines)
