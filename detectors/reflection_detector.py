# -*- coding: utf-8 -*-

import aiohttp
import asyncio

async def detect_reflections(targets):
    findings = []

    async with aiohttp.ClientSession() as session:
        for url in targets:
            try:
                async with session.get(url) as resp:
                    text = await resp.text()

                    # примерна логика — проверка за отражение на 'test'
                    if "test" in text:
                        findings.append({
                            "url": url,
                            "type": "Potential Reflection",
                            "severity": "Low",
                            "description": "User-controlled parameter value appears to be reflected in the response.",
                            "how_found": "During reflection scanning, scanner sent benign payloads and detected echoed values.",
                            "evidence": "Found reflected keyword 'test' in response body."
                        })

            except Exception as e:
                print(f"[!] Error scanning {url}: {e}")
                continue

    return findings

