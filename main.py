import sys
# On Windows use the selector event loop policy to avoid "Event loop is closed"
# errors from Proactor transports during interpreter shutdown.
if sys.platform.startswith("win"):
    try:
        import asyncio
        from asyncio import WindowsSelectorEventLoopPolicy  # type: ignore
        asyncio.set_event_loop_policy(WindowsSelectorEventLoopPolicy())
    except Exception:
        # if unavailable, continue with default policy
        pass

import os
import argparse
import subprocess
from datetime import datetime
from scope_parser import parse_scope, build_scope_matcher
from scanner import run_scan
from report_generator import generate_html_report

def _create_scan_directory(base_dir: str = "reports", scan_name: str = "") -> tuple:
    """
    Create a timestamped directory for scan results.
    Returns: (scan_dir, output_html_path, raw_responses_dir)
    """
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    
    if scan_name:
        # Clean scan_name for filesystem
        safe_name = "".join(c if c.isalnum() or c in ('-', '_', '.') else '_' for c in scan_name)
        scan_dir = os.path.join(base_dir, f"{timestamp}_{safe_name}")
    else:
        scan_dir = os.path.join(base_dir, f"scan_{timestamp}")
    
    raw_responses_dir = os.path.join(scan_dir, "raw_responses")
    os.makedirs(raw_responses_dir, exist_ok=True)
    
    output_html = os.path.join(scan_dir, "report.html")
    
    return scan_dir, output_html, raw_responses_dir

def _split_list_arg(s: str):
    if not s:
        return None
    return [x.strip() for x in s.split(",") if x.strip()]

def _run_tool(script_name, args=None):
    script = os.path.join(os.path.dirname(__file__), "tools", script_name)
    if not os.path.exists(script):
        print(f"[!] Tool not found: {script_name} — skipping")
        return False
    cmd = [sys.executable, script]
    if args:
        cmd.extend(args)
    try:
        subprocess.run(cmd, check=True)
        print(f"[+] Tool finished: {script_name}")
        return True
    except subprocess.CalledProcessError as e:
        print(f"[!] Tool {script_name} failed: {e}")
        return False

def main():
    parser = argparse.ArgumentParser(description="Safe Bug Bounty Scanner v2.0")
    
    # Mode selection
    parser.add_argument("--recon", metavar="DOMAIN", help="🚀 [V2.0] Full recon mode: Subfinder → HTTPX → Scanner → Nuclei")
    
    # Standard scanning mode
    parser.add_argument("--scope", "-s", help="CSV file with URL,Status (required for standard mode)")
    parser.add_argument("--concurrency", "-c", type=int, default=10)
    parser.add_argument("--per-host-rate", "-r", type=float, default=1.0, help="requests per second per host")
    parser.add_argument("--timeout", "-t", type=int, default=15)
    parser.add_argument("--retries", type=int, default=3)
    parser.add_argument("--output", "-o", default="reports/report.html")
    parser.add_argument("--consent", action="store_true", help="I have written permission to scan these targets")
    parser.add_argument("--allow-destructive", action="store_true", help="Allow destructive tests (disabled by default)")
    parser.add_argument("--auto-confirm", action="store_true", help="Automatically perform secondary confirmation checks for medium-confidence findings")
    parser.add_argument("--proxy", help="Optional HTTP proxy URL to use for requests (e.g. http://proxy:8080)")
    parser.add_argument("--scan-both", action="store_true", help="Try both https:// and http:// for each target (will double requests)")
    parser.add_argument("--secret-whitelist", help="Comma-separated whitelist substrings to ignore in secret detector (e.g. example,internal)")
    parser.add_argument("--secret-blacklist", help="Comma-separated blacklist substrings to require-match in secret detector")
    parser.add_argument(
        "--enable-403-probing",
        action="store_true",
        help="Attempt automatic 403 bypass heuristics when forbidden responses are encountered",
    )
    parser.add_argument("--no-auto-reports", action="store_true", help="Do not automatically generate masked/correlated/combined reports after scan")
    
    # Cloudflare/CDN bypass options
    parser.add_argument("--bypass-cloudflare", action="store_true", help="🛡️  Enable Cloudflare/CDN bypass (User-Agent rotation, realistic headers, delays)")
    parser.add_argument("--bypass-delay-min", type=float, default=1.0, help="Minimum delay between requests (seconds) for bypass mode (default: 1.0)")
    parser.add_argument("--bypass-delay-max", type=float, default=3.0, help="Maximum delay between requests (seconds) for bypass mode (default: 3.0)")
    
    # Recon mode options
    parser.add_argument("--recon-output", default="recon_output", help="Output directory for recon mode")
    parser.add_argument("--skip-scanner", action="store_true", help="Skip custom scanner in recon mode")
    parser.add_argument("--skip-nuclei", action="store_true", help="Skip Nuclei in recon mode")
    parser.add_argument("--nuclei-severity", help="Nuclei severity filter (comma-separated: info,low,medium,high,critical)")
    parser.add_argument("--recursive-subs", action="store_true", help="Use recursive subdomain enumeration")
    parser.add_argument(
        "--enable-dom-playwright",
        action="store_true",
        help="Run Playwright DOM audit stage for client-side issues (recon & standard modes)",
    )
    parser.add_argument(
        "--enable-exploit-validation",
        action="store_true",
        help="Run Exploit-DB backed exploit validation stage after primary scanner"
    )
    parser.add_argument(
        "--enable-cloudflare-solver",
        action="store_true",
        help="Use Playwright to automatically solve Cloudflare browser challenges when encountered",
    )
    
    args = parser.parse_args()

    # V2.0: Recon mode (Subfinder → HTTPX → Scanner → Nuclei)
    if args.recon:
        if not args.consent:
            print("You must provide --consent to confirm you have permission to scan the target.")
            sys.exit(1)
        
        # Create timestamped recon directory
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        domain_safe = "".join(c if c.isalnum() or c in ('-', '_', '.') else '_' for c in args.recon)
        recon_dir = os.path.join(args.recon_output, f"{timestamp}_{domain_safe}")
        
        print(f"\n{'='*70}")
        print(f"🚀 BUG BOUNTY ARSENAL v2.0 - FULL RECON MODE")
        print(f"{'='*70}\n")
        print(f"Target domain: {args.recon}")
        print(f"Pipeline: Subfinder → HTTPX → Scanner (22+ detectors) → Nuclei")
        print(f"Output directory: {recon_dir}\n")
        
        # Import and run recon orchestrator
        from tools.recon_orchestrator import run_recon_pipeline
        
        nuclei_sev = _split_list_arg(args.nuclei_severity) if args.nuclei_severity else None
        
        results = run_recon_pipeline(
            domain=args.recon,
            output_dir=recon_dir,
            skip_scanner=args.skip_scanner,
            skip_nuclei=args.skip_nuclei,
            nuclei_severity=nuclei_sev,
            scanner_concurrency=args.concurrency,
            recursive_subs=args.recursive_subs,
            allow_destructive=args.allow_destructive,
            bypass_cloudflare=args.bypass_cloudflare,
            bypass_delay_min=args.bypass_delay_min,
            bypass_delay_max=args.bypass_delay_max,
            enable_dom_playwright=args.enable_dom_playwright,
            enable_exploit_validation=args.enable_exploit_validation,
            enable_cloudflare_solver=args.enable_cloudflare_solver,
            enable_403_probe=args.enable_403_probing,
        )
        
        if "error" in results:
            print(f"\n[!] Recon failed: {results['error']}")
            sys.exit(1)
        
        print(f"\n{'='*70}")
        print(f"✅ Full recon completed successfully!")
        print(f"{'='*70}")
        print(f"📁 Output directory: {results.get('output_directory')}")
        print(f"{'='*70}\n")
        sys.exit(0)

    # Standard scanning mode (requires --scope)
    if not args.scope:
        print("[!] Either --recon DOMAIN or --scope FILE is required")
        print("    Use --recon for full reconnaissance pipeline")
        print("    Use --scope for targeted scanning")
        sys.exit(1)

    if not args.consent:
        print("You must provide --consent to confirm you have permission to scan the targets.")
        sys.exit(1)

    if not os.path.exists(args.scope):
        print(f"[!] Scope file '{args.scope}' not found.")
        sys.exit(1)

    in_scope, out_scope = parse_scope(args.scope)
    print(f"[+] In-scope: {len(in_scope)} | Out-of-scope: {len(out_scope)}")

    # build scope matcher and pass to scanner so discovered links are classified and out-of-scope aren't touched
    scope_matcher = build_scope_matcher(in_scope)

    secret_whitelist = _split_list_arg(args.secret_whitelist)
    secret_blacklist = _split_list_arg(args.secret_blacklist)

    # Create timestamped scan directory
    # Extract scan name from scope file (e.g., "vulnweb" from "test_vulnweb.csv")
    scope_basename = os.path.splitext(os.path.basename(args.scope))[0]
    scan_dir, output_html, raw_responses_dir = _create_scan_directory(
        base_dir="reports",
        scan_name=scope_basename
    )
    
    print(f"[+] Scan directory: {scan_dir}")
    print(f"[+] Raw responses: {raw_responses_dir}")

    results, metadata = run_scan(
        in_scope,
        concurrency=args.concurrency,
        timeout=args.timeout,
        retries=args.retries,
        per_host_rate=args.per_host_rate,
        allow_destructive=args.allow_destructive,
        output_dir=raw_responses_dir,  # Use timestamped directory
        auto_confirm=args.auto_confirm,
        scope_matcher=scope_matcher,
        proxy=args.proxy,
        scan_both=args.scan_both,
        secret_whitelist=secret_whitelist or [],
        secret_blacklist=secret_blacklist or [],
        bypass_cloudflare=args.bypass_cloudflare,
        bypass_delay_min=args.bypass_delay_min,
        bypass_delay_max=args.bypass_delay_max,
        enable_forbidden_probe=args.enable_403_probing,
        enable_cloudflare_solver=args.enable_cloudflare_solver,
    )

    dom_playwright_summary = None
    if args.enable_dom_playwright:
        dom_targets = metadata.get("targets_scanned") or metadata.get("targets_considered") or []
        dom_targets = [t for t in dom_targets if isinstance(t, str) and t]
        if not dom_targets:
            print("[!] No scanned targets available for DOM audit; skipping Playwright stage.")
            dom_playwright_summary = {"skipped": "no_targets"}
        else:
            # Deduplicate while preserving order
            deduped_targets = list(dict.fromkeys(dom_targets))
            dom_stage_dir = os.path.join(scan_dir, "dom_playwright")
            print(f"[+] Running Playwright DOM audit on {len(deduped_targets)} URLs...")
            try:
                from tools.dom_playwright_scanner import run_dom_playwright_scan

                dom_playwright_summary = run_dom_playwright_scan(deduped_targets, dom_stage_dir)
                if dom_playwright_summary.get("error") == "playwright_missing":
                    print("[!] Playwright is not installed. Skipping DOM audit stage.")
                elif dom_playwright_summary.get("error"):
                    print(f"[!] DOM audit failed: {dom_playwright_summary['error']}")
                else:
                    issues = dom_playwright_summary.get("potential_issues", 0)
                    print(f"[+] DOM audit complete. Potential issues flagged: {issues}")
            except Exception as exc:
                print(f"[!] DOM audit encountered an exception: {exc}")
                dom_playwright_summary = {"error": str(exc)}

    if dom_playwright_summary is not None:
        metadata["dom_playwright_summary"] = dom_playwright_summary

    generate_html_report(results, output_html, duration_seconds=metadata.get("duration", 0.0), metadata=metadata)
    
    # Also save JSON report
    import json
    json_path = os.path.join(scan_dir, "report.json")
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump({"results": results, "metadata": metadata}, f, indent=2, ensure_ascii=False)
    
    print(f"\n{'='*70}")
    print(f"✅ Scan completed!")
    print(f"{'='*70}")
    print(f"📁 Scan directory: {scan_dir}")
    print(f"📄 HTML report:    {output_html}")
    print(f"📄 JSON report:    {json_path}")
    print(f"📂 Raw responses:  {raw_responses_dir}")
    print(f"{'='*70}\n")

    # Auto-generate auxiliary reports (masked evidence, correlation, combined) unless disabled
    if not args.no_auto_reports:
        print("Generating auxiliary reports (masked evidence, correlation, combined)...")
        # 1) masked evidence (pass whitelist/blacklist)
        mask_args = []
        if secret_whitelist:
            mask_args.extend(["--whitelist", ",".join(secret_whitelist)])
        if secret_blacklist:
            mask_args.extend(["--blacklist", ",".join(secret_blacklist)])
        _run_tool("mask_and_extract_evidence.py", mask_args)

        # 2) correlate reports (produces correlated_report.json)
        _run_tool("correlate_reports.py", None)

        # 3) combined side-by-side HTML
        _run_tool("generate_combined_evidence.py", None)

        print("Auxiliary report generation complete. Check reports/ directory.")

if __name__ == "__main__":
    main()