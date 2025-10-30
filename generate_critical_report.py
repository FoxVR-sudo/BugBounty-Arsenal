import os
import json

REPORTS_DIR = "reports"
SCREENSHOTS_DIR = "screenshots"
OUTPUT_REPORT = "reports/critical_findings_report.html"

html_header = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Critical Findings Report</title>
    <style>
        body { font-family: Arial, sans-serif; }
        .finding { border: 1px solid #ccc; margin: 20px 0; padding: 15px; }
        .screenshot { max-width: 600px; border: 1px solid #888; }
        .payload { background: #f4f4f4; padding: 5px; border-radius: 3px; }
    </style>
</head>
<body>
    <h1>Critical Findings Report</h1>
"""

html_footer = """
</body>
</html>
"""

findings_html = ""

for fname in os.listdir(REPORTS_DIR):
    if not fname.endswith(".json"):
        continue
    with open(os.path.join(REPORTS_DIR, fname), "r", encoding="utf-8") as f:
        findings = json.load(f)
    for finding in findings:
        if not isinstance(finding, dict):
            continue  # пропусни, ако не е речник
        severity = (finding.get("severity") or "").lower()
        if severity != "critical":
            continue
        url = finding.get("url", "")
        payload = finding.get("payload", "")
        evidence = finding.get("evidence", "")
        screenshot_path = finding.get("screenshot_path", "")
        findings_html += f"""
        <div class="finding">
            <h2>Critical Vulnerability</h2>
            <strong>URL:</strong> <a href="{url}">{url}</a><br>
            <strong>Payload:</strong> <span class="payload">{payload}</span><br>
            <strong>Evidence:</strong> {evidence}<br>
        """
        if screenshot_path and os.path.exists(screenshot_path):
            rel_path = os.path.relpath(screenshot_path, os.path.dirname(OUTPUT_REPORT))
            findings_html += f'<div><img class="screenshot" src="{rel_path}" alt="Screenshot"></div>'
        findings_html += "</div>\n"

with open(OUTPUT_REPORT, "w", encoding="utf-8") as out:
    out.write(html_header + findings_html + html_footer)

print(f"Critical findings report generated: {OUTPUT_REPORT}")