import sys
# On Windows use the selector event loop policy to avoid "Event loop is closed"
# errors from Proactor transports during interpreter shutdown.
if sys.platform.startswith("win"):
    try:
        import asyncio
        from asyncio import WindowsSelectorEventLoopPolicy
        asyncio.set_event_loop_policy(WindowsSelectorEventLoopPolicy())
    except Exception:
        # if unavailable, continue with default policy
        pass

import os
import argparse
import subprocess
from scope_parser import parse_scope, build_scope_matcher
from scanner import run_scan
from report_generator import generate_html_report

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
    parser = argparse.ArgumentParser(description="Safe Bug Bounty Scanner")
    parser.add_argument("--scope", "-s", required=True, help="CSV file with URL,Status")
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
    # new: auto-generate all auxiliary reports by default; add flag to disable
    parser.add_argument("--no-auto-reports", action="store_true", help="Do not automatically generate masked/correlated/combined reports after scan")
    args = parser.parse_args()

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

    results, metadata = run_scan(
        in_scope,
        concurrency=args.concurrency,
        timeout=args.timeout,
        retries=args.retries,
        per_host_rate=args.per_host_rate,
        allow_destructive=args.allow_destructive,
        output_dir=os.path.dirname(args.output),
        auto_confirm=args.auto_confirm,
        scope_matcher=scope_matcher,
        proxy=args.proxy,
        scan_both=args.scan_both,
        secret_whitelist=secret_whitelist,
        secret_blacklist=secret_blacklist,
    )

    os.makedirs(os.path.dirname(args.output), exist_ok=True)
    generate_html_report(results, args.output, duration_seconds=0.0, metadata=metadata)
    print(f"Report written to {args.output}")

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