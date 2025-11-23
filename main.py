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

# ANSI color helper
class Color:
    HEADER = "\033[1;36m"  # Cyan bold blocks
    INFO = "\033[36m"      # Cyan regular info
    SUCCESS = "\033[1;32m"  # Green success
    WARN = "\033[1;33m"     # Yellow warning
    ERROR = "\033[1;31m"    # Red errors
    MODE = "\033[1;35m"     # Magenta mode banner
    RESET = "\033[0m"

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
    parser.add_argument("--with-recon", dest="with_recon", action="store_true", help="Стартирай recon pipeline (Subfinder, HTTPX, Nuclei) преди сканиране")
    parser.add_argument("--no-recon", dest="with_recon", action="store_false", help="Не стартирай recon pipeline преди сканиране")
    parser.set_defaults(with_recon=True)
    
    # Mode selection
    parser.add_argument("--recon", metavar="DOMAIN", help="🚀 [V2.0] Full recon mode: Subfinder → HTTPX → Scanner → Nuclei")
    
    # Standard scanning mode
    parser.add_argument("--scope", "-s", help="CSV file with URL,Status (required for standard mode). If omitted, interactive menu launches.")
    parser.add_argument("--scan-mode", choices=["safe","normal","brute"], default="normal", help="Scanning intensity preset (safe, normal, brute). Brute uses full payload sets without DoS.")
    parser.add_argument("--url", help="Scan a single URL (overrides --scope if provided). Creates temporary scope file internally.")
    parser.add_argument("--auto-suite", action="store_true", help="Run full automated suite (safe → normal → brute) and generate comparative summary.")
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

    def print_logo():
        logo = (
            "\n"
            "┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓\n"
            "┃  BUG BOUNTY ░ ARSENAL ░ SCANNER v2.0 ┃\n"
            "┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛\n"
            "    fast • modular • permission-aware\n"
        )
        # Cyan bold for the frame, normal for tagline
        print("\033[1;36m" + "\n".join(logo.splitlines()[:3]) + "\033[0m")
        print("\033[36m" + "\n".join(logo.splitlines()[3:]) + "\033[0m")

    def interactive_menu():
        print_logo()
        print(Color.MODE + "=== ИНТЕРАКТИВЕН РЕЖИМ ===" + Color.RESET)
        print(Color.INFO + "Изберете scope файл (.csv или .txt). .txt ще бъде конвертиран към CSV (URL,200)." + Color.RESET)
        single_url = input("[0] Единичен URL (Enter ако ще ползваш файл): ").strip()
        scope_path = input("[1] Път до scope файл (default targets.csv): ").strip() or "targets.csv"
        single_url_temp_csv = None
        if single_url:
            if not single_url.startswith("http"):
                single_url = "https://" + single_url
            single_url_temp_csv = f"_single_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
            with open(single_url_temp_csv, 'w', encoding='utf-8') as sf:
                sf.write(f"{single_url},200\n")
            scope_path = single_url_temp_csv
            print(Color.SUCCESS + f"[+] Единичен URL записан → {single_url_temp_csv}" + Color.RESET)
        if not os.path.exists(scope_path):
            print(Color.ERROR + f"[!] Файлът {scope_path} не съществува." + Color.RESET)
            sys.exit(1)
        if scope_path.lower().endswith('.txt'):
            tmp_csv = f"_auto_scope_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
            with open(scope_path, 'r', encoding='utf-8', errors='ignore') as src, open(tmp_csv, 'w', encoding='utf-8') as dst:
                for line in src:
                    line = line.strip()
                    if not line or line.startswith('#'):
                        continue
                    dst.write(f"{line},200\n")
            print(Color.SUCCESS + f"[+] TXT конвертиран → {tmp_csv}" + Color.RESET)
            scope_path = tmp_csv
        print(Color.MODE + "\nРежим на сканиране:" + Color.RESET)
        print(Color.INFO + "  1) safe   - минимални нискорискови (без brute/auth/command)" + Color.RESET)
        print(Color.INFO + "  2) normal - пълен стандартен набор" + Color.RESET)
        print(Color.INFO + "  3) brute  - всички детектори + разширени payload-и (ограничено натоварване)" + Color.RESET)
        choice = input("[2] Избор (1/2/3) [default 2]: ").strip() or "2"
        mapping = {"1":"safe","2":"normal","3":"brute"}
        scan_mode = mapping.get(choice, "normal")
        # Допълнителни опции
        enable_403 = input(Color.WARN + "[3] Включи 403 bypass? (y/N): " + Color.RESET).strip().lower() == 'y'
        enable_cf_bypass = input(Color.WARN + "[4] Включи Cloudflare bypass headers? (y/N): " + Color.RESET).strip().lower() == 'y'
        enable_cf_solver = input(Color.WARN + "[5] Включи Cloudflare solver (Playwright)? (y/N): " + Color.RESET).strip().lower() == 'y'
        allow_destructive = input(Color.ERROR + "[6] Позволи destructive payload-и? (n/Y - внимателно): " + Color.RESET).strip().lower() == 'y'
        try:
            concurrency = int(input(Color.MODE + "[7] Concurrency (default 10): " + Color.RESET).strip() or 10)
        except ValueError:
            concurrency = 10
        try:
            per_host_rate = float(input(Color.MODE + "[8] Per-host rate (req/sec, default 1.0): " + Color.RESET).strip() or 1.0)
        except ValueError:
            per_host_rate = 1.0
        recon_choice = input(Color.INFO + "[9] Стартирай recon pipeline (Subfinder, HTTPX, Nuclei) преди сканиране? (Y/n): " + Color.RESET).strip().lower()
        with_recon = not (recon_choice == 'n')
        return {
            'scope_path': scope_path,
            'scan_mode': scan_mode,
            'enable_403_probing': enable_403,
            'bypass_cloudflare': enable_cf_bypass,
            'enable_cloudflare_solver': enable_cf_solver,
            'allow_destructive': allow_destructive,
            'concurrency': concurrency,
            'per_host_rate': per_host_rate,
            'single_url_temp_csv': single_url_temp_csv,
            'with_recon': with_recon,
        }

    # If single URL provided via CLI, synthesize scope CSV early
    if args.url and not args.scope:
        single = args.url.strip()
        if single and not single.startswith("http"):
            single = "https://" + single
        tmp_single_csv = f"_single_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
        with open(tmp_single_csv, 'w', encoding='utf-8') as ftmp:
            ftmp.write(f"{single},in\n")
        args.scope = tmp_single_csv
        print(Color.INFO + f"[+] Създаден временен scope за единичен URL: {tmp_single_csv}" + Color.RESET)

    # Launch interactive if no recon and no scope provided
    if not args.recon and not args.scope:
        menu = interactive_menu()
        args.scope = menu['scope_path']
        args.scan_mode = menu['scan_mode']
        if menu.get('single_url_temp_csv'):
            print(Color.INFO + f"[+] Единичен URL добавен като scope: {menu['single_url_temp_csv']}" + Color.RESET)
        # Override selected runtime tuning & flags if user chose interactive values
        args.enable_403_probing = menu['enable_403_probing'] or args.enable_403_probing
        args.bypass_cloudflare = menu['bypass_cloudflare'] or args.bypass_cloudflare
        args.enable_cloudflare_solver = menu['enable_cloudflare_solver'] or args.enable_cloudflare_solver
        args.allow_destructive = menu['allow_destructive'] or args.allow_destructive
        args.concurrency = menu['concurrency']
        args.per_host_rate = menu['per_host_rate']
        args.with_recon = menu.get('with_recon', True)

    # V2.0: Recon mode (Subfinder → HTTPX → Scanner → Nuclei)
    if args.recon:
        if not args.consent:
            print("You must provide --consent to confirm you have permission to scan the target.")
            sys.exit(1)
        
        # Create timestamped recon directory
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        domain_safe = "".join(c if c.isalnum() or c in ('-', '_', '.') else '_' for c in args.recon)
        recon_dir = os.path.join(args.recon_output, f"{timestamp}_{domain_safe}")
        
        print(Color.HEADER + f"\n{'='*70}" + Color.RESET)
        print(Color.MODE + "🚀 BUG BOUNTY ARSENAL v2.0 - FULL RECON MODE" + Color.RESET)
        print(Color.HEADER + f"{'='*70}\n" + Color.RESET)
        print(Color.INFO + f"Target domain: {args.recon}" + Color.RESET)
        print(Color.INFO + "Pipeline: Subfinder → HTTPX → Scanner (22+ detectors) → Nuclei" + Color.RESET)
        print(Color.INFO + f"Output directory: {recon_dir}\n" + Color.RESET)
        
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
        
        print(Color.HEADER + f"\n{'='*70}" + Color.RESET)
        print(Color.SUCCESS + "✅ Full recon completed successfully!" + Color.RESET)
        print(Color.HEADER + f"{'='*70}" + Color.RESET)
        print(Color.INFO + f"📁 Output directory: {results.get('output_directory')}" + Color.RESET)
        print(Color.HEADER + f"{'='*70}\n" + Color.RESET)
        sys.exit(0)


    # Standard scanning mode (requires --scope)
    if not args.scope:
        print("[!] Either --recon DOMAIN or --scope FILE is required (interactive attempted).")
        sys.exit(1)

    # --- Recon pipeline integration ---
    if args.with_recon and not args.recon:
        import csv
        from urllib.parse import urlparse
        scope_file = args.scope
        with open(scope_file, encoding='utf-8') as f:
            reader = csv.reader(f)
            for row in reader:
                if not row or row[0].startswith('#'):
                    continue
                url = row[0]
                parsed = urlparse(url)
                domain = parsed.hostname or url
                break
            else:
                print(Color.ERROR + "[!] Не може да се извлече домейн за recon pipeline." + Color.RESET)
                domain = None
        if domain:
            print(Color.INFO + f"[RECON] Стартиране на recon pipeline за {domain}..." + Color.RESET)
            from tools.recon_orchestrator import run_recon_pipeline
            recon_dir = args.recon_output if hasattr(args, 'recon_output') else "recon_output"
            recon_results = run_recon_pipeline(
                domain=domain,
                output_dir=recon_dir,
                skip_scanner=True,  # ще стартираме скенера след recon
                skip_nuclei=False,
                nuclei_severity=None,
                scanner_concurrency=args.concurrency,
                recursive_subs=getattr(args, 'recursive_subs', False),
                allow_destructive=args.allow_destructive,
                bypass_cloudflare=args.bypass_cloudflare,
                bypass_delay_min=args.bypass_delay_min,
                bypass_delay_max=args.bypass_delay_max,
                enable_dom_playwright=getattr(args, 'enable_dom_playwright', False),
                enable_exploit_validation=getattr(args, 'enable_exploit_validation', False),
                enable_403_probe=args.enable_403_probing,
                enable_cloudflare_solver=args.enable_cloudflare_solver,
            )
            # Използвай live_urls от recon pipeline, ако има
            live_urls = None
            try:
                phases = recon_results.get('phases', {})
                httpx_phase = phases.get('http_probing', {})
                live_file = httpx_phase.get('output_file')
                if live_file and os.path.exists(live_file):
                    with open(live_file, encoding='utf-8') as lf:
                        import json
                        live_hosts = json.load(lf)
                        live_urls = [h.get('url') for h in live_hosts if h.get('url')]
            except Exception as e:
                print(Color.ERROR + f"[!] Неуспешно извличане на live URLs от recon: {e}" + Color.RESET)
            if live_urls:
                # Създай нов временен scope файл с live URLs
                recon_scope = f"_recon_scope_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
                with open(recon_scope, 'w', encoding='utf-8') as rf:
                    for url in live_urls:
                        rf.write(f"{url},in\n")
                print(Color.SUCCESS + f"[RECON] Използвам {len(live_urls)} live URLs като нов scope: {recon_scope}" + Color.RESET)
                args.scope = recon_scope
            else:
                print(Color.WARN + "[RECON] Няма live URLs от recon, използвам оригиналния scope." + Color.RESET)
        else:
            print(Color.ERROR + "[!] Пропуснат recon pipeline (няма домейн)." + Color.RESET)

    # ------------------------------------------------------------
    # Automated suite (safe → normal → brute)
    # ------------------------------------------------------------
    if args.auto_suite:
        if not args.consent:
            print("[!] --consent required for automated suite.")
            sys.exit(1)
        if not os.path.exists(args.scope):
            print(f"[!] Scope file '{args.scope}' not found for suite.")
            sys.exit(1)

        def _mode_params(mode: str):
            # Apply the same limiting logic as interactive brute adjustments
            base_conc = args.concurrency
            base_rate = args.per_host_rate
            if mode == 'brute':
                return min(base_conc, 5), min(base_rate, 2.0)
            if mode == 'safe':
                # slightly lower default to keep footprint minimal
                return min(base_conc, 6), min(base_rate, 1.0)
            return base_conc, base_rate

        from scanner import run_scan as _suite_run_scan  # local import safety
        in_scope, out_scope = parse_scope(args.scope)
        scope_matcher = build_scope_matcher(in_scope)
        suite_root = os.path.join("reports", datetime.now().strftime("suite_%Y%m%d_%H%M%S"))
        os.makedirs(suite_root, exist_ok=True)
        print(Color.HEADER + f"[+] Автоматизиран пакет стартиран → {suite_root}" + Color.RESET)

        summary = {"modes": [], "scope_file": args.scope, "total_in_scope": len(in_scope)}
        for mode in ["safe", "normal", "brute"]:
            conc, rate = _mode_params(mode)
            mode_dir = os.path.join(suite_root, mode)
            raw_dir = os.path.join(mode_dir, "raw_responses")
            os.makedirs(raw_dir, exist_ok=True)
            print(Color.MODE + f"\n=== MODE: {mode.upper()} (concurrency={conc}, rate={rate}) ===" + Color.RESET)
            results, metadata = _suite_run_scan(
                in_scope,
                concurrency=conc,
                timeout=args.timeout,
                retries=args.retries,
                per_host_rate=rate,
                allow_destructive=args.allow_destructive,
                output_dir=raw_dir,
                auto_confirm=args.auto_confirm,
                scope_matcher=scope_matcher,
                proxy=args.proxy,
                scan_both=args.scan_both,
                secret_whitelist=None,
                secret_blacklist=None,
                bypass_cloudflare=args.bypass_cloudflare,
                bypass_delay_min=args.bypass_delay_min,
                bypass_delay_max=args.bypass_delay_max,
                enable_forbidden_probe=args.enable_403_probing,
                enable_cloudflare_solver=args.enable_cloudflare_solver,
                scan_mode=mode,
            )
            # Generate mode-specific HTML & JSON
            html_path = os.path.join(mode_dir, "report.html")
            json_path = os.path.join(mode_dir, "report.json")
            generate_html_report(results, html_path, duration_seconds=metadata.get("duration", 0.0), metadata=metadata)
            import json as _json
            with open(json_path, "w", encoding="utf-8") as jf:
                _json.dump({"results": results, "metadata": metadata}, jf, indent=2, ensure_ascii=False)
            # Summarize counts
            counts = {"total": len(results), "critical": 0, "high": 0, "medium": 0, "low": 0}
            for r in results:
                sev = (r.get("severity") or "").lower()
                if sev in counts:
                    counts[sev] += 1
            summary["modes"].append({
                "mode": mode,
                "counts": counts,
                "duration": metadata.get("duration"),
                "directory": mode_dir,
            })

        # Write suite summary JSON
        import json as _json2
        suite_json = os.path.join(suite_root, "suite_summary.json")
        with open(suite_json, "w", encoding="utf-8") as sf:
            _json2.dump(summary, sf, indent=2, ensure_ascii=False)
        # Simple HTML summary
        suite_html = os.path.join(suite_root, "suite_summary.html")
        with open(suite_html, "w", encoding="utf-8") as hf:
            hf.write("<html><head><title>Suite Summary</title><style>body{font-family:Arial}table{border-collapse:collapse}td,th{border:1px solid #ccc;padding:4px}</style></head><body>")
            hf.write(f"<h1>Automated Suite Summary</h1><p>Scope: {args.scope}</p>")
            hf.write("<table><tr><th>Mode</th><th>Total</th><th>Critical</th><th>High</th><th>Medium</th><th>Low</th><th>Duration (s)</th></tr>")
            for m in summary["modes"]:
                c = m["counts"]
                hf.write(f"<tr><td>{m['mode']}</td><td>{c['total']}</td><td>{c['critical']}</td><td>{c['high']}</td><td>{c['medium']}</td><td>{c['low']}</td><td>{m['duration']:.2f}</td></tr>")
            hf.write("</table></body></html>")
        print(Color.HEADER + "\n==================================================" + Color.RESET)
        print(Color.SUCCESS + "✅ Автоматизиран пакет завършен" + Color.RESET)
        print(Color.HEADER + "==================================================" + Color.RESET)
        print(Color.INFO + f"📁 Root: {suite_root}" + Color.RESET)
        print(Color.INFO + f"📄 Summary JSON: {suite_json}" + Color.RESET)
        print(Color.INFO + f"📄 Summary HTML: {suite_html}\n" + Color.RESET)
        sys.exit(0)

    if not args.consent:
        print("You must provide --consent to confirm you have permission to scan the targets.")
        sys.exit(1)

    if not os.path.exists(args.scope):
        print(f"[!] Scope file '{args.scope}' not found.")
        sys.exit(1)

    in_scope, out_scope = parse_scope(args.scope)
    print(Color.INFO + f"[+] In-scope: {len(in_scope)} | Out-of-scope: {len(out_scope)}" + Color.RESET)

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
    
    print(Color.INFO + f"[+] Scan directory: {scan_dir}" + Color.RESET)
    print(Color.INFO + f"[+] Raw responses: {raw_responses_dir}" + Color.RESET)

    # Adjust concurrency / rate for brute mode to avoid DoS
    eff_concurrency = args.concurrency
    eff_rate = args.per_host_rate
    if args.scan_mode == 'brute':
        eff_concurrency = min(eff_concurrency, 5)
        eff_rate = min(eff_rate, 2.0)
        print(Color.WARN + f"[!] Brute mode активен → ограничаване concurrency={eff_concurrency}, per_host_rate={eff_rate}" + Color.RESET)

    # Detect if this is a single URL scan (by temp CSV name pattern)
    single_url_scan = False
    if args.url or (hasattr(args, 'scope') and str(args.scope).startswith('_single_')):
        single_url_scan = True

    results, metadata = run_scan(
        in_scope,
        concurrency=eff_concurrency,
        timeout=args.timeout,
        retries=args.retries,
        per_host_rate=eff_rate,
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
        scan_mode=args.scan_mode,
        extra_context={"single_url_scan": single_url_scan},
    )

    dom_playwright_summary = None
    if args.enable_dom_playwright:
        dom_targets = metadata.get("targets_scanned") or metadata.get("targets_considered") or []
        dom_targets = [t for t in dom_targets if isinstance(t, str) and t]
        if not dom_targets:
            print(Color.WARN + "[!] No scanned targets available for DOM audit; skipping Playwright stage." + Color.RESET)
            dom_playwright_summary = {"skipped": "no_targets"}
        else:
            # Deduplicate while preserving order
            deduped_targets = list(dict.fromkeys(dom_targets))
            dom_stage_dir = os.path.join(scan_dir, "dom_playwright")
            print(Color.MODE + f"[+] Running Playwright DOM audit on {len(deduped_targets)} URLs..." + Color.RESET)
            try:
                from tools.dom_playwright_scanner import run_dom_playwright_scan

                dom_playwright_summary = run_dom_playwright_scan(deduped_targets, dom_stage_dir)
                if dom_playwright_summary.get("error") == "playwright_missing":
                    print(Color.WARN + "[!] Playwright is not installed. Skipping DOM audit stage." + Color.RESET)
                elif dom_playwright_summary.get("error"):
                    print(Color.ERROR + f"[!] DOM audit failed: {dom_playwright_summary['error']}" + Color.RESET)
                else:
                    issues = dom_playwright_summary.get("potential_issues", 0)
                    print(Color.SUCCESS + f"[+] DOM audit complete. Potential issues flagged: {issues}" + Color.RESET)
            except Exception as exc:
                print(Color.ERROR + f"[!] DOM audit encountered an exception: {exc}" + Color.RESET)
                dom_playwright_summary = {"error": str(exc)}

    if dom_playwright_summary is not None:
        metadata["dom_playwright_summary"] = dom_playwright_summary

    generate_html_report(results, output_html, duration_seconds=metadata.get("duration", 0.0), metadata=metadata)
    
    # Also save JSON report
    import json
    json_path = os.path.join(scan_dir, "report.json")
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump({"results": results, "metadata": metadata}, f, indent=2, ensure_ascii=False)
    
    print(Color.HEADER + f"\n{'='*70}" + Color.RESET)
    print(Color.SUCCESS + "✅ Scan completed!" + Color.RESET)
    print(Color.HEADER + f"{'='*70}" + Color.RESET)
    print(Color.INFO + f"📁 Scan directory: {scan_dir}" + Color.RESET)
    print(Color.MODE + f"🔧 Scan mode:     {args.scan_mode}" + Color.RESET)
    print(Color.INFO + f"📄 HTML report:    {output_html}" + Color.RESET)
    print(Color.INFO + f"📄 JSON report:    {json_path}" + Color.RESET)
    print(Color.INFO + f"📂 Raw responses:  {raw_responses_dir}" + Color.RESET)
    print(Color.HEADER + f"{'='*70}\n" + Color.RESET)

    # Auto-generate auxiliary reports (masked evidence, correlation, combined) unless disabled
    if not args.no_auto_reports:
        print(Color.MODE + "Generating auxiliary reports (masked evidence, correlation, combined)..." + Color.RESET)
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

        print(Color.SUCCESS + "Auxiliary report generation complete. Check reports/ directory." + Color.RESET)

if __name__ == "__main__":
    main()