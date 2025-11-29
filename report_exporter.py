"""
Export functionality for scan reports.
Converts HTML reports to JSON and Markdown formats.
"""
import os
import json
from typing import Dict, List, Optional
from datetime import datetime
from bs4 import BeautifulSoup


def parse_html_report(report_path: str) -> Dict:
    """
    Parse HTML report and extract structured vulnerability data.
    
    Returns:
        Dictionary with scan results and vulnerabilities
    """
    if not os.path.exists(report_path):
        return {"error": "Report not found"}
    
    try:
        with open(report_path, 'r', encoding='utf-8') as f:
            soup = BeautifulSoup(f.read(), 'html.parser')
        
        # Extract metadata
        title = soup.find('h1')
        title_text = title.get_text() if title else "Unknown Scan"
        
        # Extract all vulnerability sections
        vulnerabilities = []
        
        # Look for common vulnerability indicators
        vuln_indicators = soup.find_all(['h2', 'h3', 'div'], class_=lambda x: x and ('vuln' in x.lower() or 'finding' in x.lower()))
        
        for indicator in vuln_indicators:
            vuln = {}
            
            # Get vulnerability type from heading
            vuln['type'] = indicator.get_text().strip()
            
            # Get severity from text or emoji
            text = indicator.get_text()
            if '🔴' in text or 'CRITICAL' in text.upper():
                vuln['severity'] = 'CRITICAL'
            elif '🟠' in text or 'HIGH' in text.upper():
                vuln['severity'] = 'HIGH'
            elif '🟡' in text or 'MEDIUM' in text.upper():
                vuln['severity'] = 'MEDIUM'
            elif '🔵' in text or 'LOW' in text.upper():
                vuln['severity'] = 'LOW'
            else:
                vuln['severity'] = 'INFO'
            
            # Get description from next paragraph
            next_elem = indicator.find_next('p')
            if next_elem:
                vuln['description'] = next_elem.get_text().strip()
            
            # Get URL if present
            url_elem = indicator.find_next('code') or indicator.find_next('a')
            if url_elem:
                vuln['url'] = url_elem.get_text().strip()
            
            vulnerabilities.append(vuln)
        
        return {
            "scan_title": title_text,
            "scan_date": datetime.now().isoformat(),
            "total_vulnerabilities": len(vulnerabilities),
            "vulnerabilities": vulnerabilities,
            "severity_breakdown": {
                "critical": sum(1 for v in vulnerabilities if v.get('severity') == 'CRITICAL'),
                "high": sum(1 for v in vulnerabilities if v.get('severity') == 'HIGH'),
                "medium": sum(1 for v in vulnerabilities if v.get('severity') == 'MEDIUM'),
                "low": sum(1 for v in vulnerabilities if v.get('severity') == 'LOW'),
                "info": sum(1 for v in vulnerabilities if v.get('severity') == 'INFO'),
            }
        }
    except Exception as e:
        return {"error": f"Failed to parse report: {str(e)}"}


def export_to_json(report_path: str) -> str:
    """
    Convert HTML report to JSON format.
    
    Returns:
        JSON string with structured data
    """
    data = parse_html_report(report_path)
    return json.dumps(data, indent=2, ensure_ascii=False)


def export_to_markdown(report_path: str) -> str:
    """
    Convert HTML report to Markdown format.
    
    Returns:
        Markdown formatted string
    """
    data = parse_html_report(report_path)
    
    if "error" in data:
        return f"# Error\n\n{data['error']}"
    
    md = f"""# {data['scan_title']}

**Scan Date:** {data['scan_date']}  
**Total Vulnerabilities:** {data['total_vulnerabilities']}

## Severity Breakdown

| Severity | Count |
|----------|-------|
| 🔴 Critical | {data['severity_breakdown']['critical']} |
| 🟠 High | {data['severity_breakdown']['high']} |
| 🟡 Medium | {data['severity_breakdown']['medium']} |
| 🔵 Low | {data['severity_breakdown']['low']} |
| ℹ️ Info | {data['severity_breakdown']['info']} |

## Findings

"""
    
    # Group by severity
    for severity in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']:
        vulns_by_severity = [v for v in data['vulnerabilities'] if v.get('severity') == severity]
        if vulns_by_severity:
            emoji = {
                'CRITICAL': '🔴',
                'HIGH': '🟠',
                'MEDIUM': '🟡',
                'LOW': '🔵',
                'INFO': 'ℹ️'
            }.get(severity, '•')
            
            md += f"### {emoji} {severity}\n\n"
            
            for vuln in vulns_by_severity:
                md += f"#### {vuln['type']}\n\n"
                
                if 'description' in vuln:
                    md += f"{vuln['description']}\n\n"
                
                if 'url' in vuln:
                    md += f"**URL:** `{vuln['url']}`\n\n"
                
                md += "---\n\n"
    
    md += f"""
## Report Information

- **Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
- **Tool:** BugBounty Arsenal v2.0
- **Format:** Markdown Export

"""
    
    return md


def count_vulnerabilities_from_report(report_path: str) -> int:
    """Quick count of vulnerabilities in report"""
    data = parse_html_report(report_path)
    return data.get('total_vulnerabilities', 0)
