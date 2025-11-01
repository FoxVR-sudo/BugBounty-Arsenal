# detectors/open_redirect_detector.py
# Active detector for open-redirect candidates (safe, uses allow_redirects=False).
from urllib.parse import urlparse, parse_qs, urlencode
import logging

from detectors.registry import register_active, await_host_token

logger = logging.getLogger(__name__)


@register_active
async def open_redirect_detector(session, url, context):
    findings = []
    if not url:
        return findings

    per_host_rate = context.get("per_host_rate", None)
    try:
        parsed = urlparse(url)
        host = parsed.netloc.lower()
        qs = parse_qs(parsed.query, keep_blank_values=True)
        candidate_params = list(qs.keys())
        if not candidate_params:
            return findings

        for param in candidate_params:
            # craft redirect payload to external domain (non-malicious)
            payload = "https://example.com/"
            new_qs = dict(qs)
            new_qs[param] = [payload]
            new_query = urlencode(new_qs, doseq=True)
            test_url = parsed._replace(query=new_query).geturl()

            await await_host_token(host, per_host_rate)
            try:
                async with session.get(test_url, allow_redirects=False) as resp:
                    loc = resp.headers.get("Location") or resp.headers.get("location")
                    if resp.status in (301, 302, 303, 307, 308) and loc and loc.startswith("https://example.com"):
                        findings.append({
                            "type": "Open Redirect Candidate",
                            "evidence": f"Parameter '{param}' leads to external Location header: {loc}",
                            "how_found": f"Sent redirect payload in param '{param}' and received redirect",
                            "severity": "medium",
                            "payload": f"{param}={payload}",
                            "evidence_url": test_url,
                            "evidence_body": "",
                            "evidence_headers": dict(resp.headers),
                            "evidence_status": resp.status,
                        })
            except Exception as e:
                logger.debug("Open redirect request failed for %s: %s", test_url, e)
    except Exception:
        pass

    return findings