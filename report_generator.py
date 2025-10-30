from jinja2 import Template
from datetime import datetime
import os
import json
import re
import hashlib
from collections import Counter

def _safe_filename(s: str, maxlen: int = 60) -> str:
    if not s:
        s = "finding"
    # keep alnum, dash, underscore, dot; replace others with underscore
    name = re.sub(r"[^A-Za-z0-9\-_\.]", "_", s)
    if len(name) > maxlen:
        name = name[:maxlen]
    return name

def _h1_markdown_fields(finding: dict, idx: int, metadata: dict) -> str:
    """
    Build a HackerOne-style markdown string for a single finding.
    """
    sev = (finding.get("severity") or "low").capitalize()
    conf = (finding.get("confidence") or "low").upper()
    title = f"{finding.get('type','Finding')} on {finding.get('url','')}"
    # short rationale for confidence (derived from fields present)
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

    # Summary
    summary = finding.get("description") or finding.get("evidence") or ""
    if summary:
        lines.append("## Summary\n\n")
        lines.append(f"{summary}\n\n")

    # Affected URL(s)
    lines.append("## Affected URL(s)\n\n")
    method = "GET"
    repro_cmd = finding.get("repro_command")
    if repro_cmd and ( "-X POST" in repro_cmd.upper() or " -d " in repro_cmd):
        method = "POST"
    lines.append(f"- {finding.get('url','') } ({method})\n\n")

    # Steps to Reproduce
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

    # PoC / Evidence
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

    # Impact
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

    # Mitigation
    lines.append("## Mitigation / Fix\n\n")
    lines.append("- Validate and contextually encode/escape user input.\n")
    lines.append("- Implement least privilege and server-side validation.\n")
    lines.append("- For XSS: apply proper output encoding and CSP; avoid inline scripts.\n")
    lines.append("- For SSRF: restrict outgoing requests, enforce allowlists, validate URL inputs.\n\n")

    # Notes / Metadata
    lines.append("## Notes / Metadata\n\n")
    if metadata:
        lines.append(f"- Scan run: {metadata.get('timestamp', 'N/A')}\n")
        lines.append(f"- Scanner version: {metadata.get('scanner_version', 'N/A')}\n")
        lines.append(f"- Duration (s): {metadata.get('duration', 'N/A')}\n")
        if metadata.get("proxy"):
            lines.append(f"- Proxy: {metadata.get('proxy')}\n")
        if metadata.get("used_public_dns"):
            lines.append(f"- Used public DNS fallback: {metadata.get('used_public_dns')}\n")
        if metadata.get("skipped_unresolved"):
            lines.append(f"- Skipped unresolved (count): {len(metadata.get('skipped_unresolved', []))}\n")
    if finding.get("detector"):
        lines.append(f"- Detector: {finding.get('detector')}\n")
    if finding.get("status") is not None:
        lines.append(f"- HTTP status observed: {finding.get('status')}\n")
    if finding.get("response_time") is not None:
        lines.append(f"- Response time (s): {finding.get('response_time')}\n")
    lines.append("\n")

    # Attachments
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

    # Build duplicate map and normalise/enrich
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
    # Create individual H1 .md for ALL findings (not only high)
    for idx, r in enumerate(results):
        k = key_for(r)
        r2 = dict(r)
        r2["is_duplicate"] = counts[k] > 1
        r2["severity"] = (r2.get("severity") or "low").lower()
        r2["confidence"] = (r2.get("confidence") or "low").lower()

        # prepare safe filename for per-finding H1
        title_hint = (r2.get("type") or r2.get("url") or "")[:80]
        base = _safe_filename(title_hint)
        short = hashlib.sha1((r2.get("url","") + base + str(idx)).encode("utf-8")).hexdigest()[:8]
        fname = f"h1_{idx+1}_{base}_{short}.md"
        path = os.path.join(h1_dir, fname)

        # always write per-finding H1 markdown (for all severities)
        r2["h1_md_path"] = os.path.join("hackerone", fname).replace("\\", "/")
        md = _h1_markdown_fields(r2, idx, metadata or {})
        header = f"<!-- Generated by scanner {metadata.get('scanner_version') if metadata else 'N/A'} on {datetime.now().isoformat()} -->\n\n"
        try:
            with open(path, "w", encoding="utf-8") as mf:
                mf.write(header)
                mf.write(md)
        except Exception:
            # keep path even if write failed
            r2["h1_md_path"] = r2.get("h1_md_path")

        # ensure headers are printable in HTML details (stringify)
        r2["request_headers"] = json.dumps(r2.get("request_headers", {}), ensure_ascii=False, indent=2)
        r2["response_headers"] = json.dumps(r2.get("response_headers", {}), ensure_ascii=False, indent=2)

        enriched.append(r2)

    # Aggregated all-findings file
    agg_all_path = os.path.join(h1_dir, "hackerone_all_findings.md")
    try:
        with open(agg_all_path, "w", encoding="utf-8") as af:
            af.write(f"# All findings — aggregated {datetime.now().isoformat()}\n\n")
            if not enriched:
                af.write("No findings.\n")
            for i, f in enumerate(enriched):
                per = os.path.join(os.path.dirname(output_path), f.get("h1_md_path", ""))
                if os.path.isfile(per):
                    af.write(f"<!-- Included from {f.get('h1_md_path')} -->\n\n")
                    with open(per, "r", encoding="utf-8") as pf:
                        af.write(pf.read())
                        af.write("\n\n---\n\n")
                else:
                    af.write(_h1_markdown_fields(f, i, metadata or {}))
    except Exception:
        pass

    # also save JSON report (useful)
    json_path = os.path.splitext(output_path)[0] + ".json"
    with open(json_path, "w", encoding="utf-8") as jf:
        json.dump({"date": datetime.now().isoformat(), "metadata": metadata or {}, "results": enriched}, jf, ensure_ascii=False, indent=2)

    # HTML template with metadata and direct links to MD files (escape user-provided text)
    template_str = """
    <!DOCTYPE html>
    <html lang="bg">
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
      </style>
    </head>
    <body>
      <h1>Safe Bug Bounty Scanner — Отчет</h1>
      <div class="meta">
        <p><b>Дата:</b> {{ date }}</p>
        <p><b>Findings:</b> {{ enriched|length }} — <a href="{{ agg_all_rel }}">Download aggregated .md (all findings)</a></p>
        {% if metadata %}
          <h4>Run metadata</h4>
          <ul>
            <li>Triggered by: {{ metadata.triggered_by }}</li>
            <li>Scanner version: {{ metadata.scanner_version }}</li>
            <li>Start: {{ metadata.start_time }}</li>
            <li>End: {{ metadata.end_time }}</li>
            <li>Duration (s): {{ metadata.duration }}</li>
            <li>Scan options: {{ metadata.scan_options }}</li>
            <li>Used public DNS: {{ metadata.used_public_dns }}</li>
            {% if metadata.skipped_unresolved %}<li>Skipped unresolved: {{ metadata.skipped_unresolved|length }}</li>{% endif %}
            {% if metadata.skipped_unreachable %}<li>Skipped unreachable: {{ metadata.skipped_unreachable|length }}</li>{% endif %}
          </ul>
        {% endif %}
      </div>

      <h2>All findings</h2>
      {% for f in enriched %}
        <div class="finding">
          <h3>{{ loop.index }}. {{ f.type|e }}
            <span class="badge {% if f.severity == 'critical' or f.severity=='high' %}badge-high{% elif f.severity=='medium' %}badge-medium{% else %}badge-low{% endif %}">
              {{ (f.severity or 'low')|upper }}
            </span>
            <span class="small-meta">Confidence: {{ (f.confidence or 'low')|upper }}</span>
            {% if f.h1_md_path %}
              <a class="h1-link" href="{{ f.h1_md_path }}" download>Download H1 .md</a>
            {% endif %}
          </h3>
          <p><b>URL:</b> <a href="{{ f.url|e }}">{{ f.url|e }}</a></p>
          <p><b>Description:</b> {{ f.description|e }}</p>
          <p><b>Evidence:</b> {{ f.evidence|e }}</p>
          <p><b>How found:</b> {{ f.how_found|e }}</p>

          <details>
            <summary>Details & raw data</summary>
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

    </body>
    </html>
    """

    agg_all_rel = os.path.join("hackerone", os.path.basename(agg_all_path)).replace("\\", "/")
    html = Template(template_str).render(
        enriched=enriched,
        date=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        agg_all_rel=agg_all_rel,
        metadata=metadata or {}
    )

    with open(output_path, "w", encoding="utf-8") as f:
        f.write(html)

    return output_path, json_path