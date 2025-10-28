# -*- coding: utf-8 -*-

import aiohttp

async def detect_xss_patterns(url):
    """
    Проверява дали HTML съдържа отразени тагове или опасни атрибути.
    Безопасно, без изпълнение на JS.
    """
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(url, timeout=10) as resp:
                text = await resp.text()
                indicators = []
                if "<script" in text.lower():
                    indicators.append({"tag": "<script>"})
                if "onerror=" in text.lower():
                    indicators.append({"attr": "onerror"})
                return indicators
    except Exception:
        return []
