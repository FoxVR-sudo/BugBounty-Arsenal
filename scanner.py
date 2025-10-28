import asyncio
import aiohttp
from tqdm import tqdm
import time

from detectors.reflection_detector import detect_reflections
from detectors.sql_pattern_detector import detect_sql_issues
from detectors.ssrf_detector import detect_ssrf_indicators


async def scan_single_url(session, url):
    """Сканира единичен URL и събира резултати от всички детектори."""
    # Ако случайно е подаден списък (от CSV)
    if isinstance(url, list):
        url = url[0]

    result = {"url": url, "issues": []}

    try:
        reflections = await detect_reflections(session, url)
        if reflections:
            result["issues"].append({
                "type": "Reflected Input",
                "description": "Възможно отражение на потребителски вход (потенциална XSS).",
                "details": reflections
            })

        sql = await detect_sql_issues(session, url)
        if sql:
            result["issues"].append({
                "type": "Potential SQL Reflection",
                "description": "Открити са признаци на SQL injection (unsafe параметри).",
                "details": sql
            })

        ssrf = await detect_ssrf_indicators(session, url)
        if ssrf:
            result["issues"].append({
                "type": "Potential SSRF Endpoint",
                "description": "Открити са подозрителни параметри, които може да извършват сървърни заявки.",
                "details": ssrf
            })

    except Exception as e:
        result["error"] = str(e)

    return result


async def async_run(targets):
    """Асинхронно стартира сканирането за всички URL."""
    results = []
    start_time = time.time()

    async with aiohttp.ClientSession() as session:
        for target in tqdm(targets, desc="🔍 Scanning", unit="url"):
            # Поправка – ако е списък в списък, взимаме само първия елемент
            if isinstance(target, list):
                target = target[0]

            scan_result = await scan_single_url(session, target)
            results.append(scan_result)

    elapsed = time.time() - start_time
    print(f"\n⏱ Сканирането завърши за {elapsed:.2f} секунди.")
    return results


def run_scan(targets):
    """Стартира асинхронното сканиране."""
    try:
        return asyncio.run(async_run(targets))
    except Exception as e:
        print(f"[!] Грешка при изпълнение: {e}")
        return []
