# scanner.py
import asyncio
import aiohttp
from tqdm import tqdm
import time
import logging
import os
import json
import hashlib
import getpass
from urllib.parse import urlparse
from typing import Dict, Tuple, List
from aiohttp.client_exceptions import ClientConnectorDNSError, ClientConnectorError

# Ensure detectors modules register themselves
import detectors.reflection_detector
import detectors.sql_pattern_detector
import detectors.ssrf_detector
import detectors.xss_pattern_detector
import detectors.injector
import detectors.open_redirect_detector
import detectors.security_headers_detector
import detectors.dir_listing_detector
import detectors.csrf_detector
import detectors.fuzz_detector
import detectors.lfi_detector
import detectors.header_injection_detector
import detectors.secret_detector
import detectors.idor_detector
import detectors.command_injection_detector
import detectors.jwt_vulnerability_scanner
import detectors.nosql_injection_detector
import detectors.xxe_detector
import detectors.ssti_detector
import detectors.race_condition_detector
import detectors.graphql_injection_detector
import detectors.prototype_pollution_detector
# import detectors.api_security_detector  # DISABLED - causes scanner hang, needs more investigation

from detectors.registry import ACTIVE_DETECTORS, PASSIVE_DETECTORS
import crawler
import payloads
# Logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)

SCANNER_VERSION = "1.0"


def _get_host(url: str) -> str:
    try:
        parsed = urlparse(url)
        return parsed.netloc.lower()
    except Exception:
        return url


def _save_raw_response(output_dir: str, host: str, url: str, status: int, headers: dict, body) -> str:
    os.makedirs(output_dir, exist_ok=True)
    h = hashlib.sha256(url.encode()).hexdigest()[:12]
    fname = f"{h}.txt"
    path = os.path.join(output_dir, fname)
    meta = {"url": url, "status": status, "headers": headers}
    with open(path, "wb") as f:
        f.write(json.dumps(meta, ensure_ascii=False).encode("utf-8"))
        f.write(b"\n\n")
        if isinstance(body, str):
            f.write(body.encode("utf-8", errors="replace"))
        else:
            f.write(body)
    return path


def classify_severity(finding: dict, confidence: str) -> str:
    """
    Map detector severity + confidence -> final level in {low, medium, high, critical}.
    """
    det_sev = (finding.get("severity") or "").lower()
    ftype = (finding.get("type") or "").lower()

    if confidence == "high":
        if "sql" in ftype:
            return "critical"
        if "ssrf" in ftype:
            return "critical"

    if det_sev in ("low", "medium", "high"):
        return det_sev
    return "low"


def _assess_confidence_and_repro(finding: dict) -> Tuple[str, str]:
    score = 0
    how = (finding.get("how_found") or "").lower()
    desc = (finding.get("description") or "").lower()
    evidence = finding.get("evidence") or ""

    if "confirm" in how or "confirmed" in how or "confirmed" in desc:
        score += 3
    if finding.get("evidence_path") or evidence:
        score += 2
    if finding.get("payload") or finding.get("test_param"):
        score += 1
    sev = (finding.get("severity") or "").lower()
    if sev in ("high", "critical"):
        score += 1

    if score >= 5:
        confidence = "high"
    elif score >= 3:
        confidence = "medium"
    else:
        confidence = "low"

    url = finding.get("evidence_url") or finding.get("url")
    repro = f'curl -i "{url}"' if url else None
    return confidence, repro


async def _secondary_check_presence(session: aiohttp.ClientSession, finding: dict, timeout: int = 10) -> bool:
    url = finding.get("evidence_url") or finding.get("url")
    if not url:
        return False
    evidence = finding.get("evidence")
    if not evidence:
        return False
    try:
        t = aiohttp.ClientTimeout(total=timeout)
        async with session.get(url, timeout=t, allow_redirects=True) as resp:
            try:
                body = await resp.text()
            except Exception:
                body = ""
            return evidence in (body or "")
    except Exception:
        return False


async def _wait_for_token(host_state: Dict, host: str, rate: float, capacity: float = 1.0):
    if not rate or rate <= 0:
        return
    now = time.time()
    hs = host_state.setdefault(host, {"tokens": capacity, "last": now})
    elapsed = now - hs["last"]
    refill = elapsed * rate
    hs["tokens"] = min(capacity, hs["tokens"] + refill)
    hs["last"] = now
    if hs["tokens"] >= 1.0:
        hs["tokens"] -= 1.0
        return
    need = (1.0 - hs["tokens"]) / rate
    await asyncio.sleep(need)
    hs["tokens"] = 0.0
    hs["last"] = time.time()


async def _fetch_with_timeout(session: aiohttp.ClientSession, url: str, timeout: int, proxy: str = None):
    t = aiohttp.ClientTimeout(total=timeout)
    async with session.get(url, timeout=t, allow_redirects=True, proxy=proxy) as resp:
        try:
            text = await resp.text()
        except Exception:
            text = ""
        return resp.status, text, dict(resp.headers)


async def scan_single_url(
    session: aiohttp.ClientSession,
    url: str,
    output_dir: str,
    allow_destructive: bool = False,
    per_host_rate: float = 1.0,
    scope_matcher=None,
    timeout: int = 15,
    proxy: str = None,
    secret_whitelist: List[str] = None,
    secret_blacklist: List[str] = None,
) -> dict:
    if isinstance(url, list):
        url = url[0]
    original_url = url
    result = {"url": url, "issues": [], "discovered_in_scope": [], "discovered_out_of_scope": []}

    try:
        parsed_try = urlparse(url)
        if not parsed_try.scheme:
            url = "https://" + url
            parsed_try = urlparse(url)

        # perform timed fetch (measure response_time)
        try:
            t0 = time.time()
            status, text, headers = await _fetch_with_timeout(session, url, timeout, proxy=proxy)
            resp_time = time.time() - t0
        except ClientConnectorDNSError as e:
            host = parsed_try.netloc or parsed_try.path
            logger.error("DNS lookup failed for host %s: %s", host, e)
            result["error"] = f"DNS lookup failed for host {host}: {e}"
            return result
        except ClientConnectorError as e:
            logger.warning("Connection failed for %s: %s", url, e)
            resp_time = None
            if parsed_try.scheme == "https":
                try:
                    fallback_url = parsed_try._replace(scheme="http").geturl()
                    logger.info("Trying HTTP fallback for %s -> %s", url, fallback_url)
                    t0 = time.time()
                    status, text, headers = await _fetch_with_timeout(session, fallback_url, timeout, proxy=proxy)
                    resp_time = time.time() - t0
                    url = fallback_url
                except Exception as e2:
                    logger.warning("HTTP fallback failed for %s: %s", fallback_url, type(e2).__name__)
                    result["error"] = f"Connection error: {e}; fallback error: {e2}"
                    return result
            else:
                result["error"] = f"Connection error: {e}"
                return result
        except Exception as e:
            logger.exception("Unexpected error fetching %s: %s", url, e)
            result["error"] = str(e)
            return result

        # crawler discovery
        context = {}
        try:
            context = await crawler.discover_params(session, url)
        except Exception:
            context = {}

        # classify discovered links by scope
        links = context.get("links", []) or []
        in_links: List[str] = []
        out_links: List[str] = []
        if scope_matcher:
            for l in links:
                try:
                    if scope_matcher(l):
                        in_links.append(l)
                    else:
                        out_links.append(l)
                except Exception:
                    out_links.append(l)
        else:
            in_links = list(links)

        result["discovered_in_scope"] = in_links
        result["discovered_out_of_scope"] = out_links

        # enrich context for detectors
        context["allow_destructive"] = allow_destructive
        context["output_dir"] = output_dir
        context["per_host_rate"] = per_host_rate
        context["in_scope_links"] = in_links
        # pass secret whitelist/blacklist into detector context
        context["secret_whitelist"] = secret_whitelist
        context["secret_blacklist"] = secret_blacklist

        # build some per-request metadata available to detectors
        request_headers = dict(session.headers) if getattr(session, "headers", None) else {}

        # Active detectors
        for det in ACTIVE_DETECTORS:
            detector_name = getattr(det, "__name__", str(det))
            try:
                findings = await det(session, url, context)
            except Exception as e:
                logger.exception("Active detector %s error for %s: %s", detector_name, url, e)
                findings = []
            for f in findings:
                f_record = {
                    "url": url,
                    "type": f.get("type", "Finding"),
                    "description": f.get("evidence", ""),
                    "evidence": f.get("evidence", ""),
                    "how_found": f.get("how_found", ""),
                    "payload": f.get("payload"),
                    "severity": f.get("severity", "low"),
                    "evidence_path": None,
                    "test_param": f.get("test_param"),
                    "test_payload_template": f.get("test_payload_template"),
                    "evidence_url": f.get("evidence_url"),
                    "evidence_body": f.get("evidence_body"),
                    "evidence_headers": f.get("evidence_headers"),
                    "evidence_status": f.get("evidence_status"),
                    # extended metadata
                    "detector": detector_name,
                    "request_headers": request_headers,
                    "response_headers": f.get("evidence_headers") or headers,
                    "status": f.get("evidence_status") or status,
                    "response_time": resp_time,
                }

                e_body = f_record.get("evidence_body") or text
                e_headers = f_record.get("response_headers") or headers
                e_status = f_record.get("status") or status
                e_url_for_evidence = f_record.get("evidence_url") or url

                try:
                    path = _save_raw_response(
                        os.path.join(output_dir or "raw_responses", _get_host(e_url_for_evidence)),
                        e_url_for_evidence,
                        e_url_for_evidence,
                        e_status,
                        e_headers,
                        e_body,
                    )
                    f_record["evidence_path"] = path
                except Exception:
                    pass

                result["issues"].append(f_record)

        # Passive detectors
        for det in PASSIVE_DETECTORS:
            detector_name = getattr(det, "__name__", str(det))
            try:
                findings = det(text, {"url": url, "context": context})
            except Exception as e:
                logger.exception("Passive detector %s error for %s: %s", detector_name, url, e)
                findings = []
            for f in findings:
                f_record = {
                    "url": url,
                    "type": f.get("type", "Finding"),
                    "description": f.get("evidence", ""),
                    "evidence": f.get("evidence", ""),
                    "how_found": f.get("how_found", ""),
                    "payload": f.get("payload"),
                    "severity": f.get("severity", "low"),
                    "evidence_path": None,
                    # extended metadata
                    "detector": detector_name,
                    "request_headers": request_headers,
                    "response_headers": headers,
                    "status": status,
                    "response_time": resp_time,
                }
                if f_record["evidence"]:
                    try:
                        path = _save_raw_response(os.path.join(output_dir or "raw_responses", _get_host(url)),
                                                  url, status, headers, text)
                        f_record["evidence_path"] = path
                    except Exception:
                        pass

                result["issues"].append(f_record)

    except Exception as e:
        logger.exception("Scan error for %s: %s", original_url, e)
        result["error"] = str(e)

    return result


async def _bounded_scan_with_retries(
    sem,
    session,
    target,
    retries,
    host_state_tokens,
    per_host_rate,
    output_dir,
    allow_destructive,
    scope_matcher,
    proxy: str = None,
    secret_whitelist: List[str] = None,
    secret_blacklist: List[str] = None,
):
    attempt = 0
    last_exc = None
    host = _get_host(target if not isinstance(target, list) else target[0])

    while attempt < retries:
        try:
            async with sem:
                await _wait_for_token(host_state_tokens, host, per_host_rate)
                return await scan_single_url(
                    session,
                    target,
                    output_dir,
                    allow_destructive=allow_destructive,
                    per_host_rate=per_host_rate,
                    scope_matcher=scope_matcher,
                    proxy=proxy,
                    secret_whitelist=secret_whitelist,
                    secret_blacklist=secret_blacklist,
                )
        except Exception as e:
            last_exc = e
            wait = 2 ** attempt
            logger.warning(
                "Attempt %d for %s failed (%s). Waiting %ds before retry %d.",
                attempt + 1,
                target,
                e,
                wait,
                attempt + 2,
            )
            await asyncio.sleep(wait)
            attempt += 1

    logger.error("All %d attempts for %s failed. Last error: %s", retries, target, last_exc)
    return {"url": target if not isinstance(target, list) else target[0], "issues": [], "error": str(last_exc)}


async def async_run(
    targets,
    *,
    concurrency: int = 10,
    timeout: int = 15,
    retries: int = 3,
    headers=None,
    per_host_rate: float = 1.0,
    allow_destructive: bool = False,
    output_dir: str = "raw_responses",
    auto_confirm: bool = False,
    scope_matcher=None,
    proxy: str = None,
    scan_both: bool = False,
    use_public_dns: bool = True,  # automatic fallback enabled
    secret_whitelist: List[str] = None,
    secret_blacklist: List[str] = None,
):
    results = []
    start_time = time.time()

    connector = aiohttp.TCPConnector(limit=concurrency)
    timeout_obj = aiohttp.ClientTimeout(total=timeout)

    host_state_tokens = {}

    metadata = {
        "auto_confirm": bool(auto_confirm),
        "triggered_by": getpass.getuser(),
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
        "start_time": time.strftime("%Y-%m-%dT%H:%M:%S%z", time.localtime(start_time)),
        "concurrency": concurrency,
        "per_host_rate": per_host_rate,
        "proxy": proxy,
        "scan_both": bool(scan_both),
        "network_note": None,
        "skipped_unresolved": [],
        "skipped_unreachable": [],
        "resolved_via_public_dns": [],
        "used_public_dns": False,
        "scan_options": {"concurrency": concurrency, "timeout": timeout, "retries": retries, "scan_both": scan_both},
        "scanner_version": SCANNER_VERSION,
        "secret_whitelist": secret_whitelist,
        "secret_blacklist": secret_blacklist,
    }

    async with aiohttp.ClientSession(connector=connector, timeout=timeout_obj, headers=headers) as session:
        sem = asyncio.Semaphore(concurrency)

        # normalize targets: create list; if scan_both True create both https and http variants
        normalized_targets = []
        seen = set()
        for t in targets:
            entry = t[0] if isinstance(t, list) and t else (t if not isinstance(t, list) else "")
            if not entry:
                continue
            if "*" in entry:
                logger.info("Skipping wildcard scope entry from direct scan (used only for matching): %s", entry)
                continue

            if '://' in entry:
                if entry not in seen:
                    normalized_targets.append(entry)
                    seen.add(entry)
                if scan_both:
                    parsed = urlparse(entry)
                    alt = parsed._replace(scheme=("http" if parsed.scheme == "https" else "https")).geturl()
                    if alt not in seen:
                        normalized_targets.append(alt)
                        seen.add(alt)
            else:
                https_u = "https://" + entry
                http_u = "http://" + entry
                if scan_both:
                    for u in (https_u, http_u):
                        if u not in seen:
                            normalized_targets.append(u)
                            seen.add(u)
                else:
                    if https_u not in seen:
                        normalized_targets.append(https_u)
                        seen.add(https_u)

        processed_candidates = normalized_targets

        # DNS pre-check: skip targets whose hostnames do not resolve from this environment
        loop = asyncio.get_running_loop()
        resolvable = []
        skipped_unresolved = []
        for tgt in processed_candidates:
            try:
                parsed = urlparse(tgt)
                host = parsed.hostname or parsed.netloc or parsed.path
                if not host:
                    skipped_unresolved.append(tgt)
                    logger.info("Skipping target with no hostname: %s", tgt)
                    continue
                try:
                    # getaddrinfo will throw if the host cannot be resolved locally
                    await loop.getaddrinfo(host, None)
                    resolvable.append(tgt)
                except Exception:
                    skipped_unresolved.append(tgt)
                    logger.info("Skipping unresolved host (DNS lookup failed): %s", host)
            except Exception:
                skipped_unresolved.append(tgt)
                logger.info("Skipping invalid target (parse error): %s", tgt)

        # Automatic fallback: try public DNS resolver for hosts that did not resolve locally
        resolved_via_public = set()
        if skipped_unresolved and use_public_dns:
            try:
                from aiohttp import AsyncResolver
                public_resolver = AsyncResolver(nameservers=["8.8.8.8", "1.1.1.1"])
                metadata["used_public_dns"] = True
                # try to resolve each unique host from skipped_unresolved
                unique_hosts = {}
                for tgt in skipped_unresolved:
                    parsed = urlparse(tgt)
                    host = parsed.hostname or parsed.netloc or parsed.path
                    if host:
                        unique_hosts.setdefault(host, []).append(tgt)

                for host, tgts in unique_hosts.items():
                    try:
                        addrs = await public_resolver.resolve(host)
                        if addrs:
                            # mark resolved; add corresponding targets back to resolvable
                            for t in tgts:
                                if t not in resolvable:
                                    resolvable.append(t)
                            resolved_via_public.add(host)
                            logger.info("Resolved via public DNS: %s", host)
                    except Exception as e:
                        logger.debug("Public resolver couldn't resolve %s: %s", host, e)
            except Exception as e:
                logger.warning("Public DNS fallback failed to initialize: %s", e)

        # update skipped_unresolved after attempting public DNS
        still_skipped = []
        for tgt in skipped_unresolved:
            parsed = urlparse(tgt)
            host = parsed.hostname or parsed.netloc or parsed.path
            if host and host in resolved_via_public:
                continue
            still_skipped.append(tgt)

        metadata["skipped_unresolved"] = still_skipped
        metadata["resolved_via_public_dns"] = sorted(list(resolved_via_public))

        processed_targets = resolvable

        tasks = [
            asyncio.create_task(
                _bounded_scan_with_retries(
                    sem,
                    session,
                    target,
                    retries,
                    host_state_tokens,
                    per_host_rate,
                    output_dir,
                    allow_destructive,
                    scope_matcher,
                    proxy=proxy,
                    secret_whitelist=secret_whitelist,
                    secret_blacklist=secret_blacklist,
                )
            )
            for target in processed_targets
        ]

        pbar = tqdm(total=len(tasks), desc="🔍 Scanning", unit="url")

        collected_findings = []
        for coro in asyncio.as_completed(tasks):
            try:
                scan_result = await coro
            except Exception as e:
                logger.exception("Unhandled task error: %s", e)
                scan_result = {"url": "unknown", "issues": [], "error": str(e)}

            for issue in scan_result.get("issues", []):
                issue.setdefault("url", scan_result.get("url"))
                collected_findings.append(issue)

            if "error" in scan_result:
                collected_findings.append(
                    {
                        "url": scan_result.get("url", ""),
                        "type": "Scan Error",
                        "description": scan_result.get("error", ""),
                        "evidence": scan_result.get("error", ""),
                        "how_found": "error",
                        "payload": None,
                        "evidence_path": None,
                        "severity": "low",
                        "detector": "scanner",
                        "request_headers": dict(session.headers) if getattr(session, "headers", None) else {},
                        "response_headers": {},
                        "status": None,
                        "response_time": None,
                    }
                )

            pbar.update(1)

        pbar.close()

        # Derive skipped_unreachable from scan errors (timeouts/connection failures)
        skipped_unreachable_hosts = set()
        for f in collected_findings:
            if f.get("type") == "Scan Error":
                desc = (f.get("description") or "").lower()
                if any(k in desc for k in ("timeout", "timed out", "cancelled", "connection error", "cannot connect", "refused", "no route", "connreset")):
                    try:
                        parsed = urlparse(f.get("url") or "")
                        host = parsed.hostname or parsed.netloc or f.get("url")
                        if host:
                            skipped_unreachable_hosts.add(host)
                    except Exception:
                        pass
        metadata["skipped_unreachable"] = sorted(skipped_unreachable_hosts)

        # parallel auto-confirm of medium findings
        if auto_confirm and collected_findings:
            to_confirm = []
            for idx, f in enumerate(collected_findings):
                conf, _ = _assess_confidence_and_repro(f)
                if conf == "medium":
                    to_confirm.append((idx, f))

            if to_confirm:
                confirm_concurrency = min(20, max(2, concurrency))
                sem_confirm = asyncio.Semaphore(confirm_concurrency)

                async def _confirm_worker(idx_f):
                    idx, finding = idx_f
                    async with sem_confirm:
                        try:
                            ok = await _secondary_check_presence(session, finding)
                            return idx, ok
                        except Exception:
                            return idx, False

                confirm_tasks = [asyncio.create_task(_confirm_worker(pair)) for pair in to_confirm]
                confirm_results = await asyncio.gather(*confirm_tasks)

                for idx, confirmed in confirm_results:
                    if confirmed:
                        f = collected_findings[idx]
                        f["how_found"] = (f.get("how_found") or "") + " (auto-confirmed)"

        # final assembly: keep extended fields; compute confidence + final severity
        for issue in collected_findings:
            confidence, repro = _assess_confidence_and_repro(issue)
            final_severity = classify_severity(issue, confidence)
            issue["confidence"] = confidence
            issue["severity"] = final_severity
            issue["repro_command"] = repro
            # ensure canonical keys exist
            issue.setdefault("request_headers", {})
            issue.setdefault("response_headers", {})
            issue.setdefault("status", None)
            issue.setdefault("response_time", None)
            results.append(issue)

    elapsed = time.time() - start_time
    metadata["end_time"] = time.strftime("%Y-%m-%dT%H:%M:%S%z")
    metadata["duration"] = elapsed
    logger.info("Scan finished in %.2f seconds", elapsed)
    return results, metadata


def run_scan(
    targets,
    *,
    concurrency: int = 10,
    timeout: int = 15,
    retries: int = 3,
    headers=None,
    per_host_rate: float = 1.0,
    allow_destructive: bool = False,
    output_dir: str = "raw_responses",
    auto_confirm: bool = False,
    scope_matcher=None,
    proxy: str = None,
    scan_both: bool = False,
    use_public_dns: bool = True,
    secret_whitelist: List[str] = None,
    secret_blacklist: List[str] = None,
):
    try:
        return asyncio.run(
            async_run(
                targets,
                concurrency=concurrency,
                timeout=timeout,
                retries=retries,
                headers=headers,
                per_host_rate=per_host_rate,
                allow_destructive=allow_destructive,
                output_dir=output_dir,
                auto_confirm=auto_confirm,
                scope_matcher=scope_matcher,
                proxy=proxy,
                scan_both=scan_both,
                use_public_dns=use_public_dns,
                secret_whitelist=secret_whitelist,
                secret_blacklist=secret_blacklist,
            )
        )
    except Exception as e:
        logger.exception("run_scan execution error: %s", e)
        return [], {
            "auto_confirm": bool(auto_confirm),
            "triggered_by": getpass.getuser(),
            "proxy": proxy,
            "scan_both": bool(scan_both),
            "network_note": None,
        }