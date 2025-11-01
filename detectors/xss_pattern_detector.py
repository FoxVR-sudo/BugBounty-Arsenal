# detectors/xss_pattern_detector.py
# Passive detector: търси потенциални XSS индикатори в текста.
from detectors.registry import register_passive

@register_passive
def detect_xss_from_text(text, context):
    findings = []
    if not text:
        return findings

    low_text = text.lower()
    if "<script" in low_text or "javascript:" in low_text:
        findings.append({
            "type": "XSS Indicator",
            "evidence": "<script> or javascript: found",
            "how_found": "Passive scan found script tag or javascript: in response",
            "severity": "medium",
            "payload": None
        })
    if "onerror=" in low_text or "onload=" in low_text:
        findings.append({
            "type": "XSS Attribute",
            "evidence": "onerror/onload attribute",
            "how_found": "Passive scan found potentially dangerous attributes",
            "severity": "low",
            "payload": None
        })
    return findings