# report_generator.py
from jinja2 import Template
from datetime import datetime
import os
import json
import re
import hashlib
from collections import Counter, defaultdict
from urllib.parse import urlparse

def _safe_filename(s: str, maxlen: int = 60) -> str:
    if not s:
        s = "finding"
    name = re.sub(r"[^A-Za-z0-9\-_\.]", "_", s)
    return name[:maxlen]

# conservative secret regexes used for masking in reports
SECRET_RX = [
    re.compile(r"\b(AKIA[0-9A-Z]{16})\b"),
    re.compile(r"\b(AIza[0-9A-Za-z\-_]{35})\b"),
    re.compile(r"\b(eyJ[A-Za-z0-9_\-\.]+=*)\b"),
    re.compile(r"\b(xox[pabo]-?[A-Za-z0-9-]{8,})\b"),
    re.compile(r"\b(sk_live|sk_test)_[0-9a-zA-Z]{24,}\b"),
    re.compile(r"AccountKey=([A-Za-z0-9\+\/=]+)"),
    re.compile(r"\b([A-Za-z0-9\-_\/+=]{32,128})\b"),
]

def _mask_token(token: str) -> str:
    if not token:
        return token
    n = len(token)
    if n <= 8:
        return token[0] + "*" * max(0, n-2) + token[-1] if n > 2 else "*" * n
    return token[:4] + "*" * (n-8) + token[-4:]

def _mask_secrets_in_text(s: str) -> str:
    if not s:
        return s
    out = s
    try:
        for rx in SECRET_RX:
            def repl(m):
                tok = (m.group(1) if m.groups() else m.group(0))
                return _mask_token(tok)
            out = rx.sub(lambda m: repl(m), out)
    except Exception:
        pass
    return out

def _h1_markdown_fields(finding: dict, idx: int, metadata: dict) -> str:
    sev = (finding.get("severity") or "low").capitalize()
    conf = (finding.get("confidence") or "low").upper()
    title = f"{finding.get('type','Finding')} on {finding.get('url','')}"
    rationale_parts = []
    if finding.get("evidence"):
        rationale_parts.append("evidence present")
    if finding.get("evidence_path"):
        rationale_parts.append("raw response saved")
    if finding.get("payload"):
        rationale_parts.append("payload used")
    if finding.get("repro_command"):
        rationale_parts.append("repro command available")
    if finding.get("how_found"):
        rationale_parts.append(f"how_found: {finding.get('how_found')}")
    rationale = "; ".join(rationale_parts) if rationale_parts else "heuristic assessment"

    lines = []
    lines.append(f"# {idx+1}. {title}\n")
    lines.append(f"**Severity:** {sev}  \n**Confidence:** {conf}\n\n")
    lines.append(f"**Confidence rationale:** {rationale}\n\n")

    summary = finding.get("description") or finding.get("evidence") or ""
    if summary:
        lines.append("## Summary\n\n")
        lines.append(f"{summary}\n\n")

    lines.append("## Affected URL(s)\n\n")
    method = "GET"
    repro_cmd = finding.get("repro_command")
    if repro_cmd and ( "-X POST" in repro_cmd.upper() or " -d " in repro_cmd):
        method = "POST"
    lines.append(f"- {finding.get('url','') } ({method})\n\n")

    lines.append("## Steps to Reproduce\n\n")
    if repro_cmd:
        lines.append("1. Run the following command (or adapt to your client):\n\n")
        lines.append("```\n")
        lines.append(repro_cmd.strip() + "\n")
        lines.append("```\n\n")
    else:
        url = finding.get("url") or ""
        if url:
            lines.append("1. Send the following request (or visit in your browser):\n\n")
            lines.append("```\n")
            lines.append(f"curl -i \"{url}\"\n")
            lines.append("```\n\n")
        else:
            lines.append("1. Manual reproduction steps required.\n\n")

    lines.append("2. Observe the response — evidence is shown in the PoC / Evidence section.\n\n")

    lines.append("## Proof of Concept (PoC) / Evidence\n\n")
    if finding.get("evidence"):
        lines.append("```\n")
        lines.append(f"{finding.get('evidence')}\n")
        lines.append("```\n\n")
    if finding.get("evidence_path"):
        raw_path = finding.get("evidence_path") or ""
        rel = raw_path.replace("\\", "/")
        lines.append(f"Raw response saved: `{rel}`\n\n")

    if finding.get("payload"):
        lines.append(f"Payload used:\n\n```\n{finding.get('payload')}\n```\n\n")

    lines.append("## Impact\n\n")
    t = (finding.get("type") or "").lower()
    d = (finding.get("description") or "").lower()
    if "xss" in t or "xss" in d:
        lines.append("Reflected XSS may allow execution of arbitrary JavaScript in the victim's browser — possible account takeover, session theft, CSRF bypass, or phishing.\n\n")
    elif "ssrf" in t or "ssrf" in d:
        lines.append("SSRF may allow server-side requests to internal resources and data exfiltration or access to internal services.\n\n")
    elif "sql" in t or "sql" in d:
        lines.append("Potential SQL injection may allow data exfiltration or modification of database records.\n\n")
    else:
        if sev.lower() in ("high", "critical"):
            lines.append("High-severity issue — potential significant impact depending on context (authentication, sensitive data exposure, etc.).\n\n")
        else:
            lines.append((finding.get("description") or "") + "\n\n")

    lines.append("## Mitigation / Fix\n\n")
    lines.append("- Validate and contextually encode/escape user input.\n")
    lines.append("- Implement least privilege and server-side validation.\n")
    lines.append("- For XSS: apply proper output encoding and CSP; avoid inline scripts.\n")
    lines.append("- For SSRF: restrict outgoing requests, enforce allowlists, validate URL inputs.\n\n")

    lines.append("## Notes / Metadata\n\n")
    if metadata:
        lines.append(f"- Scan run: {metadata.get('timestamp', 'N/A')}\n")
        lines.append(f"- Scanner version: {metadata.get('scanner_version', 'N/A')}\n")
        lines.append(f"- Duration (s): {metadata.get('duration', 'N/A')}\n")
        if metadata.get("proxy"):
            lines.append(f"- Proxy: {metadata.get('proxy')}\n")
    if finding.get("detector"):
        lines.append(f"- Detector: {finding.get('detector')}\n")
    if finding.get("status") is not None:
        lines.append(f"- HTTP status observed: {finding.get('status')}\n")
    if finding.get("response_time") is not None:
        lines.append(f"- Response time (s): {finding.get('response_time')}\n")
    lines.append("\n")

    lines.append("## Attachments\n\n")
    if finding.get("h1_md_path"):
        lines.append(f"- Individual H1 markdown (this file): `{finding.get('h1_md_path')}`\n")
    if finding.get("evidence_path"):
        raw_path2 = finding.get("evidence_path") or ""
        rel2 = raw_path2.replace("\\", "/")
        lines.append(f"- Raw response file: `{rel2}`\n")
    lines.append("- Exported report JSON: `reports/report.json`\n\n")

    lines.append("----\n\n")
    return "".join(lines)

def generate_html_report(results, output_path="reports/report.html", duration_seconds=None, metadata=None):
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    h1_dir = os.path.join(os.path.dirname(output_path), "hackerone")
    os.makedirs(h1_dir, exist_ok=True)

    def key_for(r):
        return (
            (r.get("url") or "").strip(),
            (r.get("type") or "").strip(),
            (r.get("description") or "").strip(),
            ((r.get("payload") or "").strip())
        )

    keys = [key_for(r) for r in results]
    counts = Counter(keys)

    enriched = []
    for idx, r in enumerate(results):
        k = key_for(r)
        r2 = dict(r)
        r2["is_duplicate"] = counts[k] > 1
        r2["severity"] = (r2.get("severity") or "low").lower()
        r2["confidence"] = (r2.get("confidence") or "low").lower()

        title_hint = (r2.get("type") or r2.get("url") or "")[:80]
        base = _safe_filename(title_hint)
        short = hashlib.sha1((r2.get("url","") + base + str(idx)).encode("utf-8")).hexdigest()[:8]
        fname = f"h1_{idx+1}_{base}_{short}.md"
        path = os.path.join(h1_dir, fname)

        r2["h1_md_path"] = os.path.join("hackerone", fname).replace("\\", "/")
        md = _h1_markdown_fields(r2, idx, metadata or {})
        header = f"<!-- Generated by scanner {metadata.get('scanner_version') if metadata else 'N/A'} on {datetime.now().isoformat()} -->\n\n"
        try:
            with open(path, "w", encoding="utf-8") as mf:
                mf.write(header)
                mf.write(md)
        except Exception:
            r2["h1_md_path"] = r2.get("h1_md_path")

        # Mask secrets in headers & evidence before dumping to HTML
        try:
            r2["request_headers"] = _mask_secrets_in_text(json.dumps(r2.get("request_headers", {}), ensure_ascii=False, indent=2))
        except Exception:
            r2["request_headers"] = json.dumps(r2.get("request_headers", {}), ensure_ascii=False)
        try:
            r2["response_headers"] = _mask_secrets_in_text(json.dumps(r2.get("response_headers", {}), ensure_ascii=False, indent=2))
        except Exception:
            r2["response_headers"] = json.dumps(r2.get("response_headers", {}), ensure_ascii=False)
        # mask evidence text and evidence_details if present
        if r2.get("evidence"):
            r2["evidence"] = _mask_secrets_in_text(str(r2["evidence"]))
        if r2.get("evidence_details"):
            # evidence_details may contain HTML, but produced by detectors as safe HTML; mask tokens in the raw text portion
            try:
                r2["evidence_details"] = r2["evidence_details"].replace("<b>", "[[B]]").replace("</b>", "[[/B]]")
                r2["evidence_details"] = _mask_secrets_in_text(r2["evidence_details"])
                r2["evidence_details"] = r2["evidence_details"].replace("[[B]]", "<b>").replace("[[/B]]", "</b>")
            except Exception:
                pass

        enriched.append(r2)

    agg_all_path = os.path.join(h1_dir, "hackerone_all_findings.md")
    try:
        with open(agg_all_path, "w", encoding="utf-8") as af:
            af.write(f"# All findings — aggregated {datetime.now().isoformat()}\n\n")
            if not enriched:
                af.write("No findings.\n")
            for i, f in enumerate(enriched):
                per = os.path.join(os.path.dirname(output_path), f.get('h1_md_path', ""))
                if os.path.isfile(per):
                    af.write(f"<!-- Included from {f.get('h1_md_path')} -->\n\n")
                    with open(per, "r", encoding="utf-8") as pf:
                        af.write(pf.read())
                        af.write("\n\n---\n\n")
                else:
                    af.write(_h1_markdown_fields(f, i, metadata or {}))
    except Exception:
        pass

    json_path = os.path.splitext(output_path)[0] + ".json"
    with open(json_path, "w", encoding="utf-8") as jf:
        json.dump({"date": datetime.now().isoformat(), "metadata": metadata or {}, "results": enriched}, jf, ensure_ascii=False, indent=2)

    # Group by severity for clearer HTML presentation
    grouped = {"critical": [], "high": [], "medium": [], "low": []}
    for f in enriched:
        sev = (f.get("severity") or "low").lower()
        if sev in ("critical", "high"):
            grouped["high"].append(f)
        elif sev == "medium":
            grouped["medium"].append(f)
        else:
            grouped["low"].append(f)

    template_str = """
    <!DOCTYPE html>
    <html lang="en">
    <head>
      <meta charset="utf-8"/>
      <title>Safe Bug Bounty Report</title>
      <style>
        body { font-family: Arial, Helvetica, sans-serif; padding:20px; color:#222; }
        .finding { padding:10px;border:1px solid #ccc;margin-bottom:8px;border-radius:6px; background:#fff; }
        .badge { padding:2px 6px;border-radius:4px;color:#fff;font-size:0.9em;margin-left:8px; }
        .badge-high { background:#dc3545; } .badge-medium { background:#ffc107;color:#000; } .badge-low { background:#6c757d; }
        .meta { background:#f7f7f7;padding:12px;border-radius:6px;margin-bottom:12px;}
        .h1-link { margin-left:12px; font-size:0.9em; }
        pre { background:#f4f4f4;padding:8px;border-radius:6px; overflow:auto; white-space:pre-wrap; }
        .small-meta { font-size:0.9em; color:#444; margin-left:12px; }
        details { margin-top:8px; margin-bottom:8px; }
        .section { margin: 12px 0; padding: 10px; border-radius:6px; }
        .section h2 { margin-top:0; }
      </style>
    </head>
    <body>
      <h1>Safe Bug Bounty Scanner — Report</h1>
      <div class="meta">
        <p><b>Date:</b> {{ date }}</p>
        <p><b>Total findings:</b> {{ enriched|length }} — <a href="{{ agg_all_rel }}">Download aggregated .md (all findings)</a></p>
        {% if combined_exists %}
          <p><a href="combined_evidence.html">Open combined side-by-side evidence</a></p>
        {% endif %}
        <div>
          <label>Search: <input id="search" type="search" placeholder="search url, type, evidence..."></label>
          <label>Severity:
            <select id="sevfilter">
              <option value="all">All</option>
              <option value="high">High/Critical</option>
              <option value="medium">Medium</option>
              <option value="low">Low</option>
            </select>
          </label>
        </div>
        {% if metadata %}
          <h4>Run metadata</h4>
          <ul>
            <li>Triggered by: {{ metadata.triggered_by }}</li>
            <li>Scanner version: {{ metadata.scanner_version }}</li>
            <li>Start: {{ metadata.start_time }}</li>
            <li>End: {{ metadata.end_time }}</li>
            <li>Duration (s): {{ metadata.duration }}</li>
            <li>Scan options: {{ metadata.scan_options }}</li>
          </ul>
        {% endif %}
      </div>

      {% for label, listname in [('High / Critical', grouped.high), ('Medium', grouped.medium), ('Low', grouped.low)] %}
        {% if listname %}
          <div class="section" data-section="{{ label }}">
            <h2>{{ label }} ({{ listname|length }})</h2>
            {% for f in listname %}
              <div class="finding" data-severity="{{ f.severity }}" data-url="{{ f.url|e }}" data-type="{{ f.type|e }}">
                <h3>{{ loop.index }}. {{ f.type|e }}
                  <span class="badge {% if f.severity in ['critical','high'] %}badge-high{% elif f.severity=='medium' %}badge-medium{% else %}badge-low{% endif %}">
                    {{ (f.severity or 'low')|upper }}
                  </span>
                  <span class="small-meta">Confidence: {{ (f.confidence or 'low')|upper }}</span>
                  {% if f.h1_md_path %}
                    <a class="h1-link" href="{{ f.h1_md_path }}" download>Download H1 .md</a>
                  {% endif %}
                </h3>
                <p><b>Host:</b> {{ f.url.split('://')[-1].split('/')[0]|e }}</p>
                <p><b>URL:</b> <a href="{{ f.url|e }}">{{ f.url|e }}</a></p>
                <p><b>Summary:</b> {{ f.description|e }}</p>
                <details>
                  <summary>Details & evidence</summary>
                  <p><b>Evidence:</b></p>
                  <p>{{ f.evidence|e }}</p>
                  {% if f.evidence_details %}
                    <p><b>Evidence excerpt:</b></p>
                    <div style="background:#f7f7f7;padding:8px;border-radius:4px;">{{ f.evidence_details|safe }}</div>
                  {% endif %}
                  <p><b>Detector:</b> {{ f.detector|default('n/a') }}</p>
                  <p><b>Status:</b> {{ f.status|default('n/a') }}</p>
                  <p><b>Response time (s):</b> {{ f.response_time|default('n/a') }}</p>
                  <p><b>Request headers:</b></p>
                  <pre>{{ f.request_headers }}</pre>
                  <p><b>Response headers:</b></p>
                  <pre>{{ f.response_headers }}</pre>
                  {% if f.evidence_path %}
                    <p><b>Raw file:</b> <a href="{{ f.evidence_path|e }}">{{ f.evidence_path|e }}</a></p>
                  {% endif %}
                </details>
                {% if f.payload %}<pre>Payload: {{ f.payload|e }}</pre>{% endif %}
              </div>
            {% endfor %}
          </div>
        {% endif %}
      {% endfor %}

      <script>
        // basic client-side search + severity filter
        const searchInput = document.getElementById('search');
        const sevSelect = document.getElementById('sevfilter');
        function filter() {
          const q = (searchInput.value || '').toLowerCase();
          const sev = sevSelect.value;
          document.querySelectorAll('.finding').forEach(function(node){
            const url = (node.getAttribute('data-url')||'').toLowerCase();
            const type = (node.getAttribute('data-type')||'').toLowerCase();
            const text = (node.innerText||'').toLowerCase();
            const matchesQuery = !q || url.includes(q) || type.includes(q) || text.includes(q);
            const matchesSev = (sev === 'all') || (sev === 'high' && (node.getAttribute('data-severity')==='high' || node.getAttribute('data-severity')==='critical')) || (sev === node.getAttribute('data-severity'));
            node.style.display = (matchesQuery && matchesSev) ? '' : 'none';
          });
        }
        searchInput.addEventListener('input', filter);
        sevSelect.addEventListener('change', filter);
      </script>

    </body>
    </html>
    """

    combined_exists = os.path.exists(os.path.join(os.path.dirname(output_path), "combined_evidence.html"))
    agg_all_rel = os.path.join("hackerone", os.path.basename(agg_all_path)).replace("\\", "/")
    html = Template(template_str).render(
        enriched=enriched,
        date=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        agg_all_rel=agg_all_rel,
        metadata=metadata or {},
        grouped=type("G", (), {"high": grouped["high"], "medium": grouped["medium"], "low": grouped["low"]}),
        combined_exists=combined_exists
    )

    with open(output_path, "w", encoding="utf-8") as f:
        f.write(html)

    return output_path, json_path