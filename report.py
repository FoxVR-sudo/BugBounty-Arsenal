from jinja2 import Template
import datetime

def generate_html_report(data, out_path):
    template = """<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>Safe Bug Bounty Report</title>
<style>
body{font-family:sans-serif;margin:20px;}
table{border-collapse:collapse;width:100%;margin-bottom:30px;}
th,td{border:1px solid #ccc;padding:6px;}
th{background:#eee;}
h2{margin-top:40px;}
</style></head><body>
<h1>Safe Bug Bounty Report</h1>
<p>Generated: {{ date }}</p>

<h2>In Scope</h2>
<ul>{% for u in in_scope %}<li>{{ u }}</li>{% endfor %}</ul>

<h2>Out of Scope</h2>
<ul>{% for u in out_scope %}<li>{{ u }}</li>{% endfor %}</ul>

<h2>Findings</h2>
{% for r in results %}
<h3>{{ r.url }}</h3>
<table>
<tr><th>Check</th><th>Result</th></tr>
<tr><td>Reflections</td><td>{{ r.reflections|length }}</td></tr>
<tr><td>SQL Patterns</td><td>{{ r.sql_patterns|length }}</td></tr>
<tr><td>SSRF Indicators</td><td>{{ r.ssrf|length }}</td></tr>
<tr><td>XSS Indicators</td><td>{{ r.xss|length }}</td></tr>
</table>
{% endfor %}
</body></html>"""
    html = Template(template).render(date=datetime.datetime.now(), **data)
    with open(out_path, "w", encoding="utf-8") as f:
        f.write(html)
