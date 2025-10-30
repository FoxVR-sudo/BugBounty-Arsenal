import os
import argparse
import sys
from scope_parser import parse_scope, build_scope_matcher
from scanner import run_scan
from report_generator import generate_html_report

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
        scan_both=args.scan_both
    )

    os.makedirs(os.path.dirname(args.output), exist_ok=True)
    generate_html_report(results, args.output, duration_seconds=0.0, metadata=metadata)
    print(f"Report written to {args.output}")

if __name__ == "__main__":
    main()