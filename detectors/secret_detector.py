# detectors/secret_detector.py
# Passive detector: scans response text for API key patterns and returns masked findings.
import re
import html
import os
from detectors.registry import register_passive

# Conservative regexes (non-exhaustive).
PATTERNS = {
    "AWS Access Key ID": re.compile(r"\b(AKIA[0-9A-Z]{16})\b"),
    "GCP API Key": re.compile(r"\b(AIza[0-9A-Za-z\-_]{35})\b"),
    "JWT": re.compile(r"\b(eyJ[A-Za-z0-9_\-\.]+=*)\b"),
    "AWS Secret (heuristic)": re.compile(r"\b([A-Za-z0-9/+=]{40})\b"),
    # Slack tokens: xoxp-, xoxb-, xoxa-, xoxr-
    "Slack Token": re.compile(r"\b(xox[pabo]-?[A-Za-z0-9-]{8,})\b"),
    # Stripe secret keys: sk_live_..., sk_test_...
    "Stripe Secret Key": re.compile(r"\b(sk_live|sk_test)_[0-9a-zA-Z]{24,}\b"),
    # Azure: AccountKey=... (connection string) or SAS-like param indicators (heuristic)
    "Azure AccountKey": re.compile(r"AccountKey=([A-Za-z0-9\+\/=]+)"),
    "Azure SAS / Token (heuristic)": re.compile(r"(sv=[^&\s]+)"),
    # Generic long token (fallback)
    "Generic long token": re.compile(r"\b([A-Za-z0-9\-_\/+=]{32,128})\b"),
}

# Basic whitelist/blacklist terms to reduce false positives. Can be overridden via env/context.
DEFAULT_WHITELIST = ("http", "https", "www", ".com", ".org", "localhost")
DEFAULT_BLACKLIST = ()  # if non-empty then token must contain one of blacklisted substrings to be reported

def _mask_token(token: str) -> str:
    if not token:
        return token
    n = len(token)
    if n <= 8:
        return token[0] + "*" * max(0, n-2) + token[-1] if n > 2 else "*" * n
    return token[:4] + "*" * (n-8) + token[-4:]

def _get_config_from_context(context):
    # context may include "secret_whitelist" and "secret_blacklist" as iterables
    env_wh = os.getenv("SECRET_WHITELIST", "")
    env_bl = os.getenv("SECRET_BLACKLIST", "")
    wl = list(DEFAULT_WHITELIST)
    bl = list(DEFAULT_BLACKLIST)
    if env_wh:
        wl = [x.strip() for x in env_wh.split(",") if x.strip()]
    if env_bl:
        bl = [x.strip() for x in env_bl.split(",") if x.strip()]
    if isinstance(context, dict):
        cw = context.get("secret_whitelist")
        cb = context.get("secret_blacklist")
        if isinstance(cw, (list, tuple)):
            wl = list(cw)
        if isinstance(cb, (list, tuple)):
            bl = list(cb)
    return wl, bl

@register_passive
def detect_secrets_from_text(text, context):
    """
    Passive detector scanning response text for API key patterns.
    Returns list[dict] with masked evidence (fields: type,evidence,how_found,severity,payload,evidence_details).
    context may contain 'secret_whitelist' and 'secret_blacklist' (iterables of substrings).
    """
    findings = []
    if not text:
        return findings

    # config
    ctx = context.get("context") if isinstance(context, dict) and "context" in context else (context or {})
    whitelist, blacklist = _get_config_from_context(ctx)

    # Use a limited snippet to avoid huge processing; keep full for context building if small
    snippet = text if len(text) <= 200000 else text[:200000]

    for name, rx in PATTERNS.items():
        for m in rx.finditer(snippet):
            token = m.group(1) if m.groups() else m.group(0)
            if not token:
                continue
            lowtoken = token.lower()
            # whitelist filter: skip if token looks like a URL/hostname (reduce false positives)
            if any(w.lower() in lowtoken for w in whitelist):
                continue
            # blacklist behavior: if blacklist configured, require token to contain one of blacklist substrings
            if blacklist and not any(b.lower() in lowtoken for b in blacklist):
                continue
            masked = _mask_token(token)
            # Build small HTML excerpt around match and highlight masked token
            start = max(0, m.start() - 80)
            end = min(len(snippet), m.end() + 80)
            before = html.escape(snippet[start:m.start()])
            after = html.escape(snippet[m.end():end])
            excerpt_html = f"{before}<b>{html.escape(masked)}</b>{after}"
            findings.append({
                "type": "Potential Secret",
                "evidence": f"{name}: {masked}",
                "how_found": f"Passive pattern match for {name}",
                "severity": "high" if name in ("AWS Access Key ID", "GCP API Key", "AWS Secret (heuristic)", "Stripe Secret Key") else "medium",
                "payload": None,
                "evidence_details": excerpt_html,
            })
    return findings