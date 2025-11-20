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
from typing import Dict, Tuple, List, Optional, Any
from aiohttp.client_exceptions import ClientConnectorDNSError, ClientConnectorError
from yarl import URL

# Ensure detectors modules register themselves
import detectors.reflection_detector
import detectors.sql_pattern_detector
import detectors.ssrf_detector
import detectors.advanced_ssrf_detector  # Real SSRF exploitation tests
import detectors.ssrf_oob_detector  # DNS callback verification for SSRF
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
import detectors.graphql_detector  # Phase 4: High-value GraphQL vulnerability detection
import detectors.jwt_detector  # Phase 4: JWT/Token manipulation (account takeover)
import detectors.file_upload_detector  # Phase 4: File upload bypass (RCE potential)
import detectors.subdomain_takeover_detector  # Phase 4: Subdomain takeover (easy wins)
import detectors.cors_detector  # Phase 4: CORS misconfiguration
import detectors.oauth_detector  # Phase 4: OAuth/SSO bypass (account takeover)
import detectors.cache_poisoning_detector  # Phase 4: Cache poisoning (XSS, defacement)
import detectors.prototype_pollution_detector  # Phase 4: Prototype pollution (RCE potential)
import detectors.nosql_injection_detector  # Phase 4: NoSQL injection (auth bypass)
import detectors.api_security_detector  # Phase 4: API security issues
import detectors.auth_bypass_detector  # Phase 3: Authentication bypass detection
import detectors.rate_limit_bypass_detector  # Phase 3: Rate limit bypass detection
import detectors.brute_force_detector  # Phase 3: Credential testing (SAFE mode)
import detectors.idor_detector
import detectors.command_injection_detector
import detectors.jwt_vulnerability_scanner
import detectors.nosql_injection_detector
import detectors.xxe_detector
import detectors.ssti_detector
import detectors.race_condition_detector
import detectors.graphql_injection_detector
import detectors.simple_file_list_detector
## Note: avoid duplicate imports - detectors are expected to register themselves once
## import detectors.api_security_detector  # DISABLED - causes scanner hang, needs more investigation

from detectors.registry import ACTIVE_DETECTORS, PASSIVE_DETECTORS
import crawler
import payloads
from utils.cloudflare_bypass import CloudflareBypass, get_bypass_config
from utils.cloudflare_solver import CloudflareSolver
# Logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)

SCANNER_VERSION = "2.0"  # Phase 2: External tool integrations (Subfinder, HTTPX, Nuclei)


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
    repro = f'curl -i "{url}"' if url else ""
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


async def _fetch_with_timeout(
    session: aiohttp.ClientSession,
    url: str,
    timeout: int,
    proxy: Optional[str] = None,
    *,
    method: str = "GET",
    headers_override: Optional[Dict[str, str]] = None,
    data: Optional[str] = None,
):
    t = aiohttp.ClientTimeout(total=timeout)
    start = time.time()
    async with session.request(
        method,
        url,
        timeout=t,
        allow_redirects=True,
        proxy=proxy,
        headers=headers_override,
        data=data,
    ) as resp:
        try:
            text = await resp.text()
        except Exception:
            text = ""
        response_time = time.time() - start
        return resp.status, text, dict(resp.headers), response_time


def _build_forbidden_probe_playbook(url: str) -> List[Dict[str, Any]]:
    """Prepare a sequence of lightweight 403-bypass heuristics."""
    parsed = urlparse(url)
    path = parsed.path or "/"
    if not path.startswith("/"):
        path = "/" + path

    trimmed = path.rstrip("/") if path not in ("", "/") else path
    path_variants: List[str] = []

    if path and not path.endswith("/"):
        path_variants.append(path + "/")
        path_variants.append(path + ";/")
        path_variants.append(path + "%2f")
        path_variants.append(path + "%3b/")
    if trimmed and trimmed not in ("", "/"):
        path_variants.append(trimmed + "/.")
        path_variants.append(trimmed + "/..;/")
        path_variants.append(trimmed + "/.%2e/")
        path_variants.append(trimmed + "/%2e/")
        path_variants.append(trimmed + "/../")
        path_variants.append(trimmed + "%20/")
    leading = path.lstrip("/")
    path_variants.append("/." + leading)
    path_variants.append("//" + leading)
    path_variants.append("/..;/" + leading)
    path_variants.append("/%2e" + leading)
    path_variants.append("/%2e/" + leading)
    path_variants.append("/" + leading + "/../")
    path_variants.append(path + "?/.;/")
    path_variants.append(path + "?/../")

    # Deduplicate while preserving order
    seen_variants = set()
    unique_variants: List[str] = []
    for variant in path_variants:
        if not variant.startswith("/"):
            variant = "/" + variant
        if variant not in seen_variants:
            seen_variants.add(variant)
            unique_variants.append(variant)

    playbook: List[Dict[str, Any]] = []

    # Method variations first
    playbook.append({"label": "method-head", "method": "HEAD"})
    playbook.append({"label": "method-post", "method": "POST", "data": ""})

    for variant in unique_variants:
        mutated_url = parsed._replace(path=variant).geturl()
        playbook.append({"label": f"path-variant:{variant}", "url": mutated_url})

    header_sets: List[Tuple[str, Dict[str, str]]] = [
        (
            "x-original-url",
            {
                "X-Original-URL": path,
                "X-Rewrite-URL": path,
            },
        ),
        (
            "x-forwarded-for",
            {
                "X-Forwarded-For": "127.0.0.1",
                "X-Client-IP": "127.0.0.1",
                "X-Forwarded-Host": parsed.netloc,
            },
        ),
        (
            "x-custom-ip-authorization",
            {
                "X-Custom-IP-Authorization": "127.0.0.1",
            },
        ),
        (
            "x-referer",
            {
                "Referer": f"{parsed.scheme or 'https'}://{parsed.netloc}{path}",
            },
        ),
        (
            "forwarded-standard",
            {
                "Forwarded": f"for=127.0.0.1;host={parsed.netloc};proto={parsed.scheme or 'https'}",
            },
        ),
        (
            "true-client-ip",
            {
                "True-Client-IP": "127.0.0.1",
                "X-Originating-IP": "127.0.0.1",
                "X-Remote-IP": "127.0.0.1",
                "X-Remote-Addr": "127.0.0.1",
            },
        ),
        (
            "via-proxy",
            {
                "Via": "1.1 127.0.0.1",
                "X-Forwarded-Proto": parsed.scheme or "https",
                "X-Forwarded-Port": "443",
                "X-Forwarded-Server": parsed.netloc,
            },
        ),
        (
            "x-host",
            {
                "X-Host": parsed.netloc,
                "X-Forwarded-Server": parsed.netloc,
                "Host": parsed.netloc,
            },
        ),
        (
            "authorization-test",
            {
                "Authorization": "Basic dGVzdDp0ZXN0",
            },
        ),
    ]

    for label, headers in header_sets:
        playbook.append({"label": label, "headers": headers})

    return playbook


async def _attempt_forbidden_probe(
    session: aiohttp.ClientSession,
    url: str,
    timeout: int,
    proxy: Optional[str] = None,
) -> Dict[str, Any]:
    playbook = _build_forbidden_probe_playbook(url)
    attempts: List[Dict[str, Any]] = []

    for strategy in playbook:
        label = strategy.get("label", "unknown")
        target_url = strategy.get("url", url)
        method = strategy.get("method", "GET")
        headers_override = strategy.get("headers")
        data = strategy.get("data")

        try:
            status, body, headers, response_time = await _fetch_with_timeout(
                session,
                target_url,
                timeout,
                proxy=proxy,
                method=method,
                headers_override=headers_override,
                data=data,
            )
        except Exception as exc:
            attempts.append({
                "strategy": label,
                "url": target_url,
                "error": str(exc),
            })
            continue

        if status != 403:
            return {
                "bypassed": True,
                "strategy": label,
                "url": target_url,
                "status": status,
                "body": body,
                "headers": headers,
                "response_time": response_time,
                "method": method,
                "applied_headers": headers_override or {},
                "attempts": attempts,
            }

        attempts.append({
            "strategy": label,
            "url": target_url,
            "status": status,
            "response_time": response_time,
        })

    return {"bypassed": False, "attempts": attempts}


async def scan_single_url(
    session: aiohttp.ClientSession,
    url: str,
    context: Dict,
    proxy: Optional[str] = None,
    secret_whitelist: Optional[List[str]] = None,
    secret_blacklist: Optional[List[str]] = None,
    bypass: Optional[CloudflareBypass] = None,
):
    if isinstance(url, list):
        url = url[0]
    original_url = url
    result = {"url": url, "issues": [], "discovered_in_scope": [], "discovered_out_of_scope": []}
    
    # Apply Cloudflare bypass delay if configured
    if bypass:
        await bypass.delay()

    try:
        parsed_try = urlparse(url)
        if not parsed_try.scheme:
            url = "https://" + url
            parsed_try = urlparse(url)

        # perform timed fetch (measure response_time)
        try:
            timeout = context.get('timeout', 15)  # type: ignore
            status, text, headers, resp_time = await _fetch_with_timeout(
                session,
                url,
                timeout,
                proxy=proxy,
            )
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
                    status, text, headers, resp_time = await _fetch_with_timeout(
                        session,
                        fallback_url,
                        timeout,
                        proxy=proxy,
                    )
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
        output_dir = context.get('output_dir', 'raw_responses')  # type: ignore
        cloudflare_solver_enabled = bool(context.get("enable_cf_solver"))
        cloudflare_solver: Optional[CloudflareSolver] = context.get("cloudflare_solver")
        solver_summary: Optional[Dict[str, Any]] = None
        recent_403 = status == 403
        cloudflare_challenge_detected = False

        # Optional 403 probing
        forbidden_probe_enabled = bool(context.get("enable_403_probe"))
        probe_summary: Optional[Dict[str, Any]] = None
        if status == 403 and forbidden_probe_enabled:
            probe_summary = await _attempt_forbidden_probe(session, url, timeout, proxy=proxy)
            if probe_summary.get("bypassed"):
                result["forbidden_probe"] = {
                    "attempted": True,
                    "bypassed": True,
                    "strategy": probe_summary.get("strategy"),
                    "alt_url": probe_summary.get("url"),
                    "status": probe_summary.get("status"),
                    "attempt_count": len(probe_summary.get("attempts", [])) + 1,
                    "attempt_statuses": [
                        a.get("status") for a in probe_summary.get("attempts", []) if "status" in a
                    ],
                }
                bypass_headers = probe_summary.get("applied_headers", {})
                bypass_method = probe_summary.get("method", "GET")
                bypass_url = probe_summary.get("url", url)
                bypass_status = probe_summary.get("status", status)

                logger.info(
                    "403 bypass succeeded for %s → %s using strategy %s (status %s)",
                    original_url,
                    bypass_url,
                    probe_summary.get("strategy"),
                    bypass_status,
                )

                # Update working response with bypassed content
                url = bypass_url
                result["url"] = url
                status = bypass_status
                text = probe_summary.get("body", text)
                headers = probe_summary.get("headers", headers)
                resp_time = probe_summary.get("response_time", resp_time)

                base_req_headers = dict(session.headers) if getattr(session, "headers", None) else {}
                base_req_headers.update(bypass_headers)

                try:
                    evidence_path = _save_raw_response(
                        os.path.join(output_dir or "raw_responses", _get_host(url)),
                        url,
                        url,
                        status,
                        headers,
                        text,
                    )
                except Exception:
                    evidence_path = None

                result["issues"].append(
                    {
                        "url": url,
                        "type": "403 Bypass",
                        "description": f"403 bypassed via strategy '{probe_summary.get('strategy')}' (status {status})",
                        "evidence": f"Received HTTP {status} using {bypass_method}",
                        "how_found": "automatic 403 probe",
                        "payload": probe_summary.get("strategy"),
                        "severity": "medium",
                        "evidence_path": evidence_path,
                        "detector": "scanner.forbidden_probe",
                        "request_headers": base_req_headers,
                        "response_headers": headers,
                        "status": status,
                        "response_time": resp_time,
                    }
                )
            else:
                result["forbidden_probe"] = {
                    "attempted": True,
                    "bypassed": False,
                    "attempt_count": len(probe_summary.get("attempts", [])),
                    "attempt_statuses": [
                        a.get("status") for a in probe_summary.get("attempts", []) if "status" in a
                    ],
                }

        # Check if we hit a Cloudflare challenge and optionally solve it
        if CloudflareBypass.is_cloudflare_challenge(text, headers):
            logger.warning("⚠️  Cloudflare challenge detected for %s", url)
            result["cloudflare_challenge"] = True
            cloudflare_challenge_detected = True

            if cloudflare_solver_enabled:
                if cloudflare_solver is None:
                    solver_summary = {"success": False, "error": "solver_unavailable"}
                else:
                    solver_summary = await cloudflare_solver.solve(url, proxy=proxy)

                if solver_summary:
                    result["cloudflare_solver"] = solver_summary

                if solver_summary and solver_summary.get("success"):
                    cookies = solver_summary.get("cookies") or {}
                    if cookies:
                        try:
                            session.cookie_jar.update_cookies(cookies, response_url=URL(url))
                        except Exception as exc:
                            logger.debug("Failed to update cookies from Cloudflare solver for %s: %s", url, exc)

                    solver_headers = solver_summary.get("headers") or {}
                    try:
                        status, text, headers, resp_time = await _fetch_with_timeout(
                            session,
                            url,
                            timeout,
                            proxy=proxy,
                            headers_override=solver_headers if solver_headers else None,
                        )
                        solver_summary["refetch_status"] = status
                        solver_summary["resolved"] = not CloudflareBypass.is_cloudflare_challenge(text, headers)
                        solver_summary["cookies_used"] = list((cookies or {}).keys())
                    except Exception as exc:
                        solver_summary["refetch_error"] = str(exc)

        # crawler discovery - merge discovered params with the existing context
        try:
            discovered = await crawler.discover_params(session, url)
        except Exception:
            discovered = {}

        # Do NOT overwrite caller's context; merge discovered fields into it
        if isinstance(context, dict):
            # keep a copy to avoid mutating caller-supplied dict
            merged_context = dict(context)
        else:
            merged_context = {}

        # Merge discovered keys (forms, links, etc.) but do not clobber explicit keys
        for k, v in (discovered or {}).items():
            # if key already present, skip to preserve caller intent
            if k not in merged_context:
                merged_context[k] = v

        context = merged_context

        if recent_403:
            context["recent_403"] = True
        if cloudflare_challenge_detected:
            context["cloudflare_challenge_detected"] = True
            context["cloudflare_solver_attempted"] = bool(cloudflare_solver_enabled)
            context["cloudflare_solver_success"] = bool(solver_summary and solver_summary.get("success"))
        if probe_summary:
            context["forbidden_probe_meta"] = {
                "attempted": True,
                "bypassed": bool(probe_summary.get("bypassed")),
                "strategy": probe_summary.get("strategy"),
            }

        # classify discovered links by scope
        links = context.get("links", []) or []
        in_links: List[str] = []
        out_links: List[str] = []
        scope_matcher = context.get('scope_matcher')  # Get before use
        if scope_matcher:  # type: ignore
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

        # Get values from context (these should already be set by caller)
        allow_destructive = context.get('allow_destructive', False)  # type: ignore
        per_host_rate = context.get('per_host_rate', 0.0)  # type: ignore
        scope_matcher = context.get('scope_matcher')  # type: ignore
        context["in_scope_links"] = in_links
        # pass secret whitelist/blacklist into detector context
        context["secret_whitelist"] = secret_whitelist
        context["secret_blacklist"] = secret_blacklist

        # build some per-request metadata available to detectors
        request_headers = dict(session.headers) if getattr(session, "headers", None) else {}
        if result.get("forbidden_probe", {}).get("bypassed") and probe_summary:
            # Include any additional headers used during bypass in detector context
            probe_headers = probe_summary.get("applied_headers", {})
            request_headers.update(probe_headers)
        if solver_summary and solver_summary.get("success"):
            solver_headers = solver_summary.get("headers") or {}
            for key, value in solver_headers.items():
                if value:
                    request_headers[key] = value

        # Active detectors
        scan_mode = str(context.get('scan_mode','normal')).lower()
        # Detector filtering based on scan_mode
        brute_only = {"brute_force_detector", "rate_limit_bypass_detector", "auth_bypass_detector", "fuzz_detector", "race_condition_detector"}
        high_risk = {"command_injection_detector"}
        filtered_active = []
        for det in ACTIVE_DETECTORS:
            name = getattr(det, "__name__", "")
            if scan_mode == "safe" and (name in brute_only or name in high_risk):
                continue
            if scan_mode == "normal" and name in brute_only:
                continue
            filtered_active.append(det)
        for det in filtered_active:
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
                        path = _save_raw_response(
                            os.path.join(output_dir or "raw_responses", _get_host(url)),
                            _get_host(url),
                            url, status, headers, text
                        )
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
    timeout,
    enable_forbidden_probe,
    cloudflare_solver,
    enable_cloudflare_solver,
    scan_mode,
    proxy: Optional[str] = None,
    secret_whitelist: Optional[List[str]] = None,
    secret_blacklist: Optional[List[str]] = None,
    bypass: Optional[CloudflareBypass] = None,
):
    attempt = 0
    last_exc = None
    # Normalize target to string
    target_url = target if not isinstance(target, list) else target[0]
    host = _get_host(target_url)

    while attempt < retries:
        try:
            async with sem:
                await _wait_for_token(host_state_tokens, host, per_host_rate)
                # Build context dict for scan_single_url
                context = {
                    'timeout': timeout,
                    'allow_destructive': allow_destructive,
                    'output_dir': output_dir,
                    'per_host_rate': per_host_rate,
                    'scope_matcher': scope_matcher,
                    'enable_403_probe': enable_forbidden_probe,
                    'enable_cf_solver': enable_cloudflare_solver,
                    'cloudflare_solver': cloudflare_solver,
                    'scan_mode': scan_mode,
                }
                return await scan_single_url(
                    session,
                    target_url,
                    context,
                    proxy=proxy,
                    secret_whitelist=secret_whitelist,
                    secret_blacklist=secret_blacklist,
                    bypass=bypass,
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

    logger.error("All %d attempts for %s failed. Last error: %s", retries, target_url, last_exc)
    return {"url": target_url, "issues": [], "error": str(last_exc)}


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
    proxy: Optional[str] = None,
    scan_both: bool = False,
    use_public_dns: bool = True,  # automatic fallback enabled
    secret_whitelist: Optional[List[str]] = None,
    secret_blacklist: Optional[List[str]] = None,
    bypass_cloudflare: bool = False,  # Enable Cloudflare bypass
    bypass_delay_min: float = 1.0,  # Minimum delay between requests
    bypass_delay_max: float = 3.0,  # Maximum delay between requests
        enable_forbidden_probe: bool = False,
        enable_cloudflare_solver: bool = False,
    scan_mode: str = "normal",
):
    results = []
    start_time = time.time()
    
    # Initialize Cloudflare bypass if enabled
    bypass = get_bypass_config(
        enable_bypass=bypass_cloudflare,
        delay_min=bypass_delay_min,
        delay_max=bypass_delay_max,
        rotate_ua=True
    ) if bypass_cloudflare else None

    # Use bypass headers if configured, otherwise use provided headers
    if bypass:
        headers = bypass.get_headers()
        logger.info("🛡️  Cloudflare bypass enabled: User-Agent rotation, realistic headers, delays %.1f-%.1fs", 
                   bypass_delay_min, bypass_delay_max)

    # Use overall connection limit and also a per-host limit to avoid overwhelming single hosts
    try:
        connector = aiohttp.TCPConnector(limit=concurrency, limit_per_host=max(1, concurrency // 2))
    except TypeError:
        # Older aiohttp versions may not support limit_per_host parameter
        connector = aiohttp.TCPConnector(limit=concurrency)
    timeout_obj = aiohttp.ClientTimeout(total=timeout)

    host_state_tokens = {}

    cloudflare_solver: Optional[CloudflareSolver] = None
    if enable_cloudflare_solver:
        cloudflare_solver = CloudflareSolver()

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
        "scan_mode": scan_mode,
        "scan_options": {
            "concurrency": concurrency,
            "timeout": timeout,
            "retries": retries,
            "scan_both": scan_both,
            "allow_destructive": allow_destructive,
            "bypass_cloudflare": bypass_cloudflare,
            "enable_403_probe": bool(enable_forbidden_probe),
            "enable_cloudflare_solver": bool(enable_cloudflare_solver),
            "scan_mode": scan_mode,
        },
        "scanner_version": SCANNER_VERSION,
        "secret_whitelist": secret_whitelist,
        "secret_blacklist": secret_blacklist,
        "bypass_cloudflare": bypass_cloudflare,
        "bypass_delay_range": (bypass_delay_min, bypass_delay_max) if bypass_cloudflare else None,
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
        metadata["targets_considered"] = list(processed_candidates)

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
        metadata["targets_scanned"] = list(processed_targets)
        metadata["total_targets_considered"] = len(processed_candidates)
        metadata["total_targets_scanned"] = len(processed_targets)

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
                    timeout,
                    enable_forbidden_probe,
                    cloudflare_solver,
                    enable_cloudflare_solver,
                    scan_mode,
                    proxy=proxy,
                    secret_whitelist=secret_whitelist,
                    secret_blacklist=secret_blacklist,
                    bypass=bypass,
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

    if enable_forbidden_probe:
        metadata["forbidden_probe_summary"] = {
            "enabled": True,
            "bypass_findings": sum(1 for issue in results if issue.get("type") == "403 Bypass"),
        }

    if cloudflare_solver:
        metadata["cloudflare_solver_stats"] = cloudflare_solver.get_stats()

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
    proxy: Optional[str] = None,
    scan_both: bool = False,
    use_public_dns: bool = True,
    secret_whitelist: Optional[List[str]] = None,
    secret_blacklist: Optional[List[str]] = None,
    bypass_cloudflare: bool = False,
    bypass_delay_min: float = 1.0,
    bypass_delay_max: float = 3.0,
    enable_forbidden_probe: bool = False,
    enable_cloudflare_solver: bool = False,
    scan_mode: str = "normal",
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
                bypass_cloudflare=bypass_cloudflare,
                bypass_delay_min=bypass_delay_min,
                bypass_delay_max=bypass_delay_max,
                enable_forbidden_probe=enable_forbidden_probe,
                enable_cloudflare_solver=enable_cloudflare_solver,
                scan_mode=scan_mode,
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