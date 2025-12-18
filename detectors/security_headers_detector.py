# detectors/security_headers_detector.py
# Active detector: checks for missing important security headers via a HEAD/GET request.
import logging

from detectors.registry import register_active, await_host_token

logger = logging.getLogger(__name__)


@register_active
async def security_headers_detector(session, url, context):
    findings = []
    if not url:
        return findings

    per_host_rate = context.get("per_host_rate", None)
    
    try:
        parsed_host = url.split("/")[2] if "//" in url else None
        host = parsed_host or ""
        await await_host_token(host, per_host_rate)
        try:
            # Use GET (some servers don't respond to HEAD consistently)
            async with session.get(url, allow_redirects=True) as resp:
                headers = dict(resp.headers)
                status = resp.status
        except Exception as e:
            logger.debug("Security headers request failed for %s: %s", url, e)
            return findings

        missing = []
        required = {
            "x-frame-options": "X-Frame-Options",
            "content-security-policy": "Content-Security-Policy",
            "x-content-type-options": "X-Content-Type-Options",
            "strict-transport-security": "Strict-Transport-Security",
            "referrer-policy": "Referrer-Policy"
        }
        low_headers = {k.lower(): v for k, v in headers.items()}
        for key, nice in required.items():
            if key not in low_headers:
                missing.append(nice)

        if missing:
            findings.append({
                "type": "Missing Security Headers",
                "evidence": f"Missing headers: {', '.join(missing)}",
                "how_found": "Performed request and inspected response headers",
                "severity": "low",
                "payload": None,
                "evidence_url": url,
                "evidence_body": "",
                "evidence_headers": headers,
                "evidence_status": status,
            })
    except Exception:
        pass

    return findings