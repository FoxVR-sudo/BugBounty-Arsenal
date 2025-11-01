#!/usr/bin/env python3
"""
Generate a comprehensive, detailed security report with full evidence
"""

import json
import os
from datetime import datetime

REPORTS_DIR = "reports"
OUTPUT_FILE = "reports/detailed_comprehensive_report.html"

def read_evidence_file(filepath):
    """Read raw evidence from file"""
    try:
        full_path = filepath if os.path.exists(filepath) else os.path.join(REPORTS_DIR, filepath)
        with open(full_path, 'r', encoding='utf-8', errors='ignore') as f:
            return f.read()
    except:
        return "Evidence file not found"

def read_h1_report(filepath):
    """Read HackerOne markdown report"""
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            return f.read()
    except:
        return ""

def escape_html(text):
    """Escape HTML special characters"""
    if not text:
        return ""
    return (text
            .replace('&', '&amp;')
            .replace('<', '&lt;')
            .replace('>', '&gt;')
            .replace('"', '&quot;')
            .replace("'", '&#39;'))

def generate_detailed_report():
    """Generate comprehensive HTML report"""
    
    # Read main report
    with open(os.path.join(REPORTS_DIR, 'report.json'), 'r') as f:
        data = json.load(f)
    
    results = data['results']
    metadata = data.get('metadata', {})
    
    # Sort by severity
    severity_order = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3}
    results_sorted = sorted(results, key=lambda x: (severity_order.get(x['severity'], 4), -len(x.get('evidence', ''))))
    
    # Filter out duplicates and low confidence scan errors
    results_filtered = []
    seen_urls = set()
    for r in results_sorted:
        if r['type'] == 'Scan Error' and r['severity'] == 'low':
            continue
        key = f"{r['url']}_{r['type']}"
        if key not in seen_urls or r['severity'] in ['critical', 'high']:
            results_filtered.append(r)
            seen_urls.add(key)
    
    # Group by severity
    findings_by_severity = {
        'critical': [r for r in results_filtered if r['severity'] == 'critical'],
        'high': [r for r in results_filtered if r['severity'] == 'high'],
        'medium': [r for r in results_filtered if r['severity'] == 'medium'],
        'low': [r for r in results_filtered if r['severity'] == 'low']
    }
    
    # Generate HTML
    html = f"""<!DOCTYPE html>
<html lang="bg">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Подробен Security Scan Report</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;
            line-height: 1.6;
            color: #333;
            background: #f5f5f5;
            padding: 20px;
        }}
        
        .container {{
            max-width: 1400px;
            margin: 0 auto;
            background: white;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }}
        
        .header {{
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 40px;
            text-align: center;
        }}
        
        .header h1 {{
            font-size: 2.5em;
            margin-bottom: 10px;
        }}
        
        .header .subtitle {{
            font-size: 1.2em;
            opacity: 0.9;
        }}
        
        .summary {{
            padding: 30px 40px;
            background: #f8f9fa;
            border-bottom: 3px solid #dee2e6;
        }}
        
        .summary h2 {{
            margin-bottom: 20px;
            color: #495057;
        }}
        
        .stats {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin-top: 20px;
        }}
        
        .stat-box {{
            padding: 20px;
            border-radius: 8px;
            text-align: center;
            color: white;
        }}
        
        .stat-box.critical {{ background: #dc3545; }}
        .stat-box.high {{ background: #fd7e14; }}
        .stat-box.medium {{ background: #ffc107; color: #333; }}
        .stat-box.low {{ background: #28a745; }}
        
        .stat-box .number {{
            font-size: 3em;
            font-weight: bold;
        }}
        
        .stat-box .label {{
            font-size: 1.1em;
            margin-top: 5px;
            text-transform: uppercase;
        }}
        
        .metadata {{
            padding: 20px 40px;
            background: #e9ecef;
            font-size: 0.95em;
        }}
        
        .metadata-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 15px;
            margin-top: 15px;
        }}
        
        .metadata-item {{
            background: white;
            padding: 12px;
            border-radius: 5px;
            border-left: 3px solid #667eea;
        }}
        
        .metadata-item strong {{
            color: #495057;
        }}
        
        .findings {{
            padding: 40px;
        }}
        
        .severity-section {{
            margin-bottom: 50px;
        }}
        
        .severity-header {{
            padding: 15px 20px;
            border-radius: 8px 8px 0 0;
            color: white;
            font-size: 1.8em;
            font-weight: bold;
        }}
        
        .severity-header.critical {{ background: #dc3545; }}
        .severity-header.high {{ background: #fd7e14; }}
        .severity-header.medium {{ background: #ffc107; color: #333; }}
        .severity-header.low {{ background: #28a745; }}
        
        .finding {{
            background: white;
            border: 2px solid #dee2e6;
            border-top: none;
            margin-bottom: 30px;
            border-radius: 0 0 8px 8px;
            overflow: hidden;
        }}
        
        .finding-header {{
            padding: 20px 25px;
            background: #f8f9fa;
            border-bottom: 2px solid #dee2e6;
        }}
        
        .finding-title {{
            font-size: 1.5em;
            color: #212529;
            margin-bottom: 10px;
            font-weight: 600;
        }}
        
        .finding-url {{
            color: #0066cc;
            word-break: break-all;
            font-family: 'Courier New', monospace;
            font-size: 0.95em;
            background: #e9ecef;
            padding: 8px 12px;
            border-radius: 4px;
            margin-top: 10px;
        }}
        
        .finding-meta {{
            display: flex;
            gap: 20px;
            margin-top: 15px;
            flex-wrap: wrap;
        }}
        
        .badge {{
            padding: 6px 12px;
            border-radius: 20px;
            font-size: 0.85em;
            font-weight: 600;
        }}
        
        .badge.confidence-high {{ background: #d4edda; color: #155724; }}
        .badge.confidence-medium {{ background: #fff3cd; color: #856404; }}
        .badge.confidence-low {{ background: #f8d7da; color: #721c24; }}
        
        .badge.detector {{ background: #d1ecf1; color: #0c5460; }}
        
        .finding-body {{
            padding: 25px;
        }}
        
        .section {{
            margin-bottom: 25px;
        }}
        
        .section-title {{
            font-size: 1.2em;
            color: #495057;
            margin-bottom: 12px;
            padding-bottom: 8px;
            border-bottom: 2px solid #dee2e6;
            font-weight: 600;
        }}
        
        .section-content {{
            padding: 15px;
            background: #f8f9fa;
            border-radius: 5px;
            line-height: 1.8;
        }}
        
        .code-block {{
            background: #282c34;
            color: #abb2bf;
            padding: 20px;
            border-radius: 5px;
            overflow-x: auto;
            font-family: 'Courier New', monospace;
            font-size: 0.9em;
            margin: 10px 0;
            white-space: pre-wrap;
            word-wrap: break-word;
        }}
        
        .command {{
            background: #1e1e1e;
            color: #4ec9b0;
            padding: 15px;
            border-radius: 5px;
            font-family: 'Courier New', monospace;
            margin: 10px 0;
            border-left: 4px solid #4ec9b0;
            overflow-x: auto;
        }}
        
        .evidence-block {{
            background: #fff;
            border: 1px solid #dee2e6;
            border-radius: 5px;
            padding: 20px;
            margin: 15px 0;
            max-height: 600px;
            overflow-y: auto;
        }}
        
        .evidence-block pre {{
            margin: 0;
            white-space: pre-wrap;
            word-wrap: break-word;
            font-size: 0.85em;
        }}
        
        .highlight {{
            background: #ffeb3b;
            padding: 2px 5px;
            border-radius: 3px;
            font-weight: bold;
        }}
        
        .impact-box {{
            background: #fff3cd;
            border-left: 4px solid #ffc107;
            padding: 15px;
            margin: 15px 0;
            border-radius: 0 5px 5px 0;
        }}
        
        .impact-box h4 {{
            color: #856404;
            margin-bottom: 10px;
        }}
        
        .mitigation-box {{
            background: #d4edda;
            border-left: 4px solid #28a745;
            padding: 15px;
            margin: 15px 0;
            border-radius: 0 5px 5px 0;
        }}
        
        .mitigation-box h4 {{
            color: #155724;
            margin-bottom: 10px;
        }}
        
        .mitigation-box ul {{
            margin-left: 20px;
            margin-top: 10px;
        }}
        
        .mitigation-box li {{
            margin-bottom: 8px;
        }}
        
        .timeline {{
            margin: 15px 0;
            padding: 15px;
            background: #e9ecef;
            border-radius: 5px;
        }}
        
        .timeline-item {{
            margin-bottom: 8px;
            padding-left: 20px;
            position: relative;
        }}
        
        .timeline-item:before {{
            content: "▶";
            position: absolute;
            left: 0;
            color: #667eea;
        }}
        
        .http-details {{
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 20px;
            margin: 15px 0;
        }}
        
        .http-box {{
            background: #f8f9fa;
            border: 1px solid #dee2e6;
            border-radius: 5px;
            padding: 15px;
        }}
        
        .http-box h4 {{
            color: #495057;
            margin-bottom: 10px;
            padding-bottom: 8px;
            border-bottom: 1px solid #dee2e6;
        }}
        
        .no-findings {{
            text-align: center;
            padding: 40px;
            color: #6c757d;
            font-size: 1.1em;
        }}
        
        @media (max-width: 768px) {{
            .http-details {{
                grid-template-columns: 1fr;
            }}
            
            .header h1 {{
                font-size: 1.8em;
            }}
            
            .stats {{
                grid-template-columns: 1fr 1fr;
            }}
        }}
        
        .toc {{
            background: #f8f9fa;
            padding: 20px 40px;
            border-bottom: 2px solid #dee2e6;
        }}
        
        .toc h2 {{
            margin-bottom: 15px;
            color: #495057;
        }}
        
        .toc ul {{
            list-style: none;
            padding-left: 0;
        }}
        
        .toc li {{
            padding: 8px 0;
            border-bottom: 1px solid #dee2e6;
        }}
        
        .toc a {{
            color: #667eea;
            text-decoration: none;
            font-weight: 500;
        }}
        
        .toc a:hover {{
            color: #764ba2;
            text-decoration: underline;
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔐 Подробен Security Scan Report</h1>
            <div class="subtitle">Детайлен анализ на всички открити уязвимости с пълни доказателства</div>
            <div style="margin-top: 20px; opacity: 0.8;">
                Генериран на: {datetime.now().strftime('%d.%m.%Y в %H:%M:%S')}
            </div>
        </div>
        
        <div class="summary">
            <h2>📊 Обобщение</h2>
            <div class="stats">
                <div class="stat-box critical">
                    <div class="number">{len(findings_by_severity['critical'])}</div>
                    <div class="label">Critical</div>
                </div>
                <div class="stat-box high">
                    <div class="number">{len(findings_by_severity['high'])}</div>
                    <div class="label">High</div>
                </div>
                <div class="stat-box medium">
                    <div class="number">{len(findings_by_severity['medium'])}</div>
                    <div class="label">Medium</div>
                </div>
                <div class="stat-box low">
                    <div class="number">{len(findings_by_severity['low'])}</div>
                    <div class="label">Low</div>
                </div>
            </div>
            <div style="margin-top: 25px; padding: 15px; background: white; border-radius: 5px;">
                <strong>Общо находки:</strong> {len(results_filtered)} уязвимости
            </div>
        </div>
        
        <div class="metadata">
            <h3>ℹ️ Информация за сканирането</h3>
            <div class="metadata-grid">
                <div class="metadata-item">
                    <strong>Начало:</strong> {metadata.get('start_time', 'N/A')}
                </div>
                <div class="metadata-item">
                    <strong>Край:</strong> {metadata.get('end_time', 'N/A')}
                </div>
                <div class="metadata-item">
                    <strong>Продължителност:</strong> {round(metadata.get('duration', 0), 2)} секунди
                </div>
                <div class="metadata-item">
                    <strong>Concurrency:</strong> {metadata.get('concurrency', 'N/A')}
                </div>
                <div class="metadata-item">
                    <strong>Timeout:</strong> {metadata.get('scan_options', {}).get('timeout', 'N/A')} секунди
                </div>
                <div class="metadata-item">
                    <strong>Retries:</strong> {metadata.get('scan_options', {}).get('retries', 'N/A')}
                </div>
                <div class="metadata-item">
                    <strong>Scanner версия:</strong> {metadata.get('scanner_version', 'N/A')}
                </div>
                <div class="metadata-item">
                    <strong>Автоматично потвърждаване:</strong> {'Да' if metadata.get('auto_confirm') else 'Не'}
                </div>
            </div>
        </div>
"""
    
    # Table of contents
    if results_filtered:
        html += """
        <div class="toc">
            <h2>📑 Съдържание</h2>
            <ul>
"""
        finding_num = 1
        for severity in ['critical', 'high', 'medium', 'low']:
            findings = findings_by_severity[severity]
            if findings:
                html += f'                <li><strong>{severity.upper()}</strong></li>\n'
                for finding in findings:
                    html += f'                <li><a href="#finding-{finding_num}">{finding_num}. {escape_html(finding["type"])} - {escape_html(finding["url"][:80])}...</a></li>\n'
                    finding_num += 1
        
        html += """            </ul>
        </div>
"""
    
    # Findings section
    html += """
        <div class="findings">
"""
    
    finding_counter = 1
    
    for severity in ['critical', 'high', 'medium', 'low']:
        findings = findings_by_severity[severity]
        
        if not findings:
            continue
            
        severity_labels = {
            'critical': '🔴 КРИТИЧНИ УЯЗВИМОСТИ',
            'high': '🟠 ВИСОКИ УЯЗВИМОСТИ',
            'medium': '🟡 СРЕДНИ УЯЗВИМОСТИ',
            'low': '🟢 НИСКИ УЯЗВИМОСТИ'
        }
        
        html += f"""
            <div class="severity-section" id="{severity}-section">
                <div class="severity-header {severity}">
                    {severity_labels[severity]}
                </div>
"""
        
        for finding in findings:
            # Read evidence file
            evidence_content = ""
            if finding.get('evidence_path'):
                evidence_content = read_evidence_file(finding['evidence_path'])
            
            # Read H1 report for additional context
            h1_content = ""
            if finding.get('h1_md_path'):
                h1_content = read_h1_report(finding['h1_md_path'])
            
            # Parse request/response headers
            req_headers = finding.get('request_headers', '{}')
            resp_headers = finding.get('response_headers', '{}')
            
            try:
                req_headers_dict = json.loads(req_headers) if isinstance(req_headers, str) else req_headers
                resp_headers_dict = json.loads(resp_headers) if isinstance(resp_headers, str) else resp_headers
            except:
                req_headers_dict = {}
                resp_headers_dict = {}
            
            # Confidence badge
            confidence = finding.get('confidence', 'low')
            confidence_class = f"confidence-{confidence}"
            
            html += f"""
                <div class="finding" id="finding-{finding_counter}">
                    <div class="finding-header">
                        <div class="finding-title">
                            #{finding_counter}. {escape_html(finding['type'])}
                        </div>
                        <div class="finding-url">
                            🔗 {escape_html(finding['url'])}
                        </div>
                        <div class="finding-meta">
                            <span class="badge {confidence_class}">
                                Confidence: {confidence.upper()}
                            </span>
                            <span class="badge detector">
                                Детектор: {escape_html(finding.get('detector', 'unknown'))}
                            </span>
"""
            
            if finding.get('status'):
                html += f"""
                            <span class="badge" style="background: #e9ecef; color: #495057;">
                                HTTP Status: {finding['status']}
                            </span>
"""
            
            if finding.get('response_time'):
                html += f"""
                            <span class="badge" style="background: #e9ecef; color: #495057;">
                                Response Time: {round(finding['response_time'], 2)}s
                            </span>
"""
            
            html += """
                        </div>
                    </div>
                    
                    <div class="finding-body">
"""
            
            # Evidence section
            if finding.get('evidence'):
                html += f"""
                        <div class="section">
                            <div class="section-title">🔍 Доказателства</div>
                            <div class="section-content">
                                {escape_html(finding['evidence'])}
                            </div>
                        </div>
"""
            
            # How it was found
            if finding.get('how_found'):
                html += f"""
                        <div class="section">
                            <div class="section-title">🎯 Как е открито</div>
                            <div class="timeline">
                                <div class="timeline-item">Метод: <strong>{escape_html(finding['how_found'])}</strong></div>
"""
                if finding.get('payload'):
                    html += f"""
                                <div class="timeline-item">Използван payload: <code class="highlight">{escape_html(str(finding['payload']))}</code></div>
"""
                
                html += f"""
                                <div class="timeline-item">Детектор: <strong>{escape_html(finding.get('detector', 'N/A'))}</strong></div>
                            </div>
                        </div>
"""
            
            # Reproduction command
            if finding.get('repro_command'):
                html += f"""
                        <div class="section">
                            <div class="section-title">⚙️ Команда за възпроизвеждане</div>
                            <div class="command">
{escape_html(finding['repro_command'])}
                            </div>
                            <div style="margin-top: 10px; padding: 10px; background: #d1ecf1; border-radius: 5px; font-size: 0.9em;">
                                💡 <strong>Инструкции:</strong> Копирай тази команда и я изпълни в терминал, за да възпроизведеш уязвимостта.
                            </div>
                        </div>
"""
            
            # HTTP Request/Response details
            if req_headers_dict or resp_headers_dict:
                html += """
                        <div class="section">
                            <div class="section-title">📡 HTTP Детайли</div>
                            <div class="http-details">
"""
                
                if req_headers_dict:
                    html += f"""
                                <div class="http-box">
                                    <h4>Request Headers</h4>
                                    <div class="code-block">{escape_html(json.dumps(req_headers_dict, indent=2, ensure_ascii=False))}</div>
                                </div>
"""
                
                if resp_headers_dict:
                    html += f"""
                                <div class="http-box">
                                    <h4>Response Headers</h4>
                                    <div class="code-block">{escape_html(json.dumps(resp_headers_dict, indent=2, ensure_ascii=False))}</div>
                                </div>
"""
                
                html += """
                            </div>
                        </div>
"""
            
            # Full evidence from file
            if evidence_content and len(evidence_content) > 10:
                # Limit to first 3000 chars
                evidence_preview = evidence_content[:3000]
                if len(evidence_content) > 3000:
                    evidence_preview += "\n\n... (truncated, see full file for complete response)"
                
                html += f"""
                        <div class="section">
                            <div class="section-title">📄 Пълен HTTP Response</div>
                            <div class="evidence-block">
                                <pre>{escape_html(evidence_preview)}</pre>
                            </div>
"""
                if finding.get('evidence_path'):
                    html += f"""
                            <div style="margin-top: 10px; font-size: 0.9em; color: #6c757d;">
                                📎 Пълния файл с доказателства: <code>{escape_html(finding['evidence_path'])}</code>
                            </div>
"""
                html += """
                        </div>
"""
            
            # Impact
            impact_text = get_impact_description(finding['type'], finding['severity'])
            if impact_text:
                html += f"""
                        <div class="impact-box">
                            <h4>⚠️ Въздействие</h4>
                            <p>{impact_text}</p>
                        </div>
"""
            
            # Mitigation
            mitigation_text = get_mitigation_steps(finding['type'])
            if mitigation_text:
                html += f"""
                        <div class="mitigation-box">
                            <h4>🛡️ Препоръки за поправка</h4>
                            {mitigation_text}
                        </div>
"""
            
            # Additional files
            if finding.get('h1_md_path'):
                html += f"""
                        <div class="section">
                            <div class="section-title">📋 Допълнителни файлове</div>
                            <ul>
                                <li>HackerOne Report: <code>{escape_html(finding['h1_md_path'])}</code></li>
"""
                if finding.get('evidence_path'):
                    html += f"""
                                <li>Evidence File: <code>{escape_html(finding['evidence_path'])}</code></li>
"""
                html += """
                            </ul>
                        </div>
"""
            
            html += """
                    </div>
                </div>
"""
            
            finding_counter += 1
        
        html += """
            </div>
"""
    
    if not results_filtered:
        html += """
            <div class="no-findings">
                <h2>✅ Не са открити уязвимости</h2>
                <p>Сканирането не е открило проблеми със сигурността.</p>
            </div>
"""
    
    html += """
        </div>
    </div>
</body>
</html>
"""
    
    # Write to file
    with open(OUTPUT_FILE, 'w', encoding='utf-8') as f:
        f.write(html)
    
    print(f"✅ Детайлен репорт генериран: {OUTPUT_FILE}")
    print(f"   Общо находки: {len(results_filtered)}")
    print(f"   Critical: {len(findings_by_severity['critical'])}")
    print(f"   High: {len(findings_by_severity['high'])}")
    print(f"   Medium: {len(findings_by_severity['medium'])}")
    print(f"   Low: {len(findings_by_severity['low'])}")


def get_impact_description(vuln_type, severity):
    """Get impact description based on vulnerability type"""
    impacts = {
        'SSRF Injection Candidate': 'SSRF (Server-Side Request Forgery) уязвимостта позволява на атакуващия да накара сървъра да прави заявки към произволни URLs. Това може да доведе до: достъп до вътрешни ресурси и услуги, изтичане на чувствителни данни, сканиране на вътрешната мрежа, или атаки срещу други системи от името на сървъра.',
        
        'XSS Injection Candidate': 'Cross-Site Scripting (XSS) позволява на атакуващия да инжектира злонамерен JavaScript код в страницата. Това може да доведе до: кражба на session cookies и tokens, keylogging, пренасочване към фишинг сайтове, промяна на съдържанието на страницата, или извършване на действия от името на жертвата.',
        
        'Reflected XSS (possible)': 'Reflected XSS уязвимостта позволява инжектиране на JavaScript код, който се изпълнява в браузъра на жертвата. Атакуващият може да открадне credentials, session tokens, или да изпълни действия от името на потребителя.',
        
        'Local File Inclusion (possible)': 'LFI уязвимостта може да позволи на атакуващия да чете произволни файлове от сървъра. Това може да доведе до: изтичане на конфигурационни файлове с пароли, четене на source code, достъп до sensitive data, или в комбинация с други уязвимости - remote code execution.',
        
        'SQL Injection Candidate': 'SQL Injection позволява на атакуващия да манипулира database queries. Това може да доведе до: изтичане на цялата база данни, изтриване или модифициране на данни, bypass на authentication, или в някои случаи - remote code execution на сървъра.',
        
        'Missing Security Headers': 'Липсата на security headers прави приложението по-уязвимо на различни атаки като XSS, clickjacking, MIME-type sniffing и други. Препоръчва се имплементирането на headers като Content-Security-Policy, X-Frame-Options, X-Content-Type-Options.',
        
        'Reflected Input': 'User input-ът се рефлектира в отговора без proper encoding. Въпреки че сам по себе си може да не е критична уязвимост, това е индикатор за липса на input validation и може да доведе до XSS или други injection атаки.',
        
        'Header Injection / Header Reflection': 'Header Injection може да позволи на атакуващия да манипулира HTTP headers. Това може да доведе до: HTTP response splitting, cache poisoning, XSS чрез header reflection, или session hijacking.',
        
        'Potential Secret': 'Открити са потенциално чувствителни данни като API keys, tokens, пароли или други credentials в response-а. Това може да доведе до: unauthorized достъп до услуги, кражба на данни, или компрометиране на други системи.',
        
        'IDOR (Insecure Direct Object Reference)': 'IDOR уязвимостта позволява на атакуващия да получи достъп до обекти на други потребители чрез манипулиране на ID параметри. Това може да доведе до: неоторизиран достъп до чувствителни данни на други потребители, преглед/модификация на чужди документи, orders, профили, или пълно компрометиране на privacy и data segregation между потребителите.',
    }
    
    return impacts.get(vuln_type, f'Уязвимост от тип {vuln_type} може да компрометира сигурността на приложението.')


def get_mitigation_steps(vuln_type):
    """Get mitigation steps based on vulnerability type"""
    mitigations = {
        'SSRF Injection Candidate': '''
            <ul>
                <li>Валидирай и whitelist-вай всички URLs преди да правиш server-side requests</li>
                <li>Блокирай достъпа до private IP ranges (127.0.0.1, 10.0.0.0/8, 192.168.0.0/16, etc.)</li>
                <li>Използвай URL parser за да валидираш scheme, host и port</li>
                <li>Имплементирай rate limiting за external requests</li>
                <li>Използвай отделен network segment за external requests</li>
                <li>Никога не връщай raw response от external URLs директно на потребителя</li>
            </ul>
        ''',
        
        'XSS Injection Candidate': '''
            <ul>
                <li>Винаги escape-вай user input преди да го показваш в HTML (използвай HTML entity encoding)</li>
                <li>Имплементирай Content Security Policy (CSP) header</li>
                <li>Използвай HTTPOnly и Secure flags за cookies</li>
                <li>Валидирай и sanitize input на server-side</li>
                <li>Използвай современни templating engines с auto-escaping</li>
                <li>Избягвай използването на innerHTML, eval(), или подобни dangerous functions</li>
            </ul>
        ''',
        
        'Reflected XSS (possible)': '''
            <ul>
                <li>Escape всички user inputs преди рендериране (HTML entity encoding)</li>
                <li>Имплементирай строг Content Security Policy</li>
                <li>Използвай contextual output encoding (HTML, JavaScript, URL, CSS)</li>
                <li>Валидирай input на server-side срещу whitelist на позволени символи</li>
                <li>Използвай HTTPOnly cookies</li>
            </ul>
        ''',
        
        'Local File Inclusion (possible)': '''
            <ul>
                <li>Никога не използвай user input директно в file paths</li>
                <li>Използвай whitelist на позволени файлове</li>
                <li>Валидирай file paths и премахни traversal sequences (../, .\\)</li>
                <li>Използвай absolute paths и провери дали requested file е в allowed directory</li>
                <li>Използвай safe file handling functions</li>
                <li>Ограничи file permissions на web server процеса</li>
            </ul>
        ''',
        
        'SQL Injection Candidate': '''
            <ul>
                <li>ВИНАГИ използвай prepared statements или parameterized queries</li>
                <li>Никога не concatenate user input директно в SQL queries</li>
                <li>Използвай ORM frameworks където е възможно</li>
                <li>Валидирай и sanitize всички inputs</li>
                <li>Използвай least privilege за database accounts</li>
                <li>Disable detailed error messages в production</li>
            </ul>
        ''',
        
        'Missing Security Headers': '''
            <ul>
                <li>Content-Security-Policy: Define approved sources of content</li>
                <li>X-Frame-Options: DENY или SAMEORIGIN за защита от clickjacking</li>
                <li>X-Content-Type-Options: nosniff за да предотвратиш MIME sniffing</li>
                <li>Strict-Transport-Security: Enforce HTTPS connections</li>
                <li>X-XSS-Protection: 1; mode=block (за по-стари browsers)</li>
                <li>Referrer-Policy: Control referrer information</li>
            </ul>
        ''',
        
        'Header Injection / Header Reflection': '''
            <ul>
                <li>Валидирай и sanitize всички user inputs използвани в HTTP headers</li>
                <li>Премахни или escape newline characters (\\r, \\n) от input</li>
                <li>Използвай built-in framework functions за set headers</li>
                <li>Не рефлектирай user input директно в headers без validation</li>
            </ul>
        ''',
        
        'Potential Secret': '''
            <ul>
                <li>Премахни всички hardcoded secrets от source code</li>
                <li>Използвай environment variables или secret management systems</li>
                <li>Rotate всички exposed credentials НЕЗАБАВНО</li>
                <li>Имплементирай proper .gitignore за config files</li>
                <li>Използвай secret scanning tools в CI/CD pipeline</li>
                <li>Никога не логвай sensitive data</li>
            </ul>
        ''',
        
        'IDOR (Insecure Direct Object Reference)': '''
            <ul>
                <li>ВИНАГИ имплементирай authorization checks преди достъп до обекти</li>
                <li>Провери дали текущият потребител има права да достъпи конкретния object ID</li>
                <li>Използвай indirect object references (mapping table) вместо директни IDs</li>
                <li>Имплементирай Role-Based Access Control (RBAC) или Attribute-Based Access Control (ABAC)</li>
                <li>Логвай всички access attempts към sensitive resources</li>
                <li>Използвай UUIDs вместо sequential IDs където е възможно</li>
                <li>Никога не разчитай само на URL obfuscation за security</li>
            </ul>
        ''',
    }
    
    return mitigations.get(vuln_type, '''
        <ul>
            <li>Валидирай и sanitize всички user inputs</li>
            <li>Имплементирай proper error handling</li>
            <li>Използвай latest security patches</li>
            <li>Следвай security best practices за съответната технология</li>
        </ul>
    ''')


if __name__ == '__main__':
    generate_detailed_report()
