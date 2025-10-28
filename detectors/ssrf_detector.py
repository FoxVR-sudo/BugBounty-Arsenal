# -*- coding: utf-8 -*-

import aiohttp
import asyncio

async def detect_ssrf(targets):
    findings = []

    async with aiohttp.ClientSession() as session:
        for url in targets:
            try:
                async with session.get(url) as resp:
                    text = await resp.text()

                    if "http://" in text or "https://" in text:
                        findings.append({
                            "url": url,
                            "type": "Potential SSRF Behavior",
                            "severity": "Medium",
                            "description": "The server response includes user-supplied URLs, which might indicate SSRF-like behavior.",
                            "how_found": "During SSRF scan, scanner looked for reflected URLs inside server responses.",
                            "evidence": "Response body contained URL-like patterns."
                        })

            except Exception as e:
                print(f"[!] Error scanning {url}: {e}")
                continue

    return findings

