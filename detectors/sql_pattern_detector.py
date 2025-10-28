# -*- coding: utf-8 -*-

import aiohttp

async def detect_sql_patterns(url):
    """
    Безопасно проверява за SQL грешки в отговора.
    Не изпраща SQL заявки, само гледа текстови индикатори.
    """
    def detect_sql_issues(content):
    """
    Открива базови SQL injection индикатори в HTML или response текст.
    Връща списък с откритите уязвимости (ако има такива).
    """
    patterns = [
        r"you have an error in your sql syntax",
        r"warning: mysql",
        r"unclosed quotation mark after the character string",
        r"quoted string not properly terminated",
        r"pg_query\(",
        r"SQLSTATE\[HY000\]",
        r"sqlite error",
    ]

    found = []
    for p in patterns:
        if re.search(p, content, re.IGNORECASE):
            found.append(f"Възможен SQL injection индикатор: '{p}'")

    return found
