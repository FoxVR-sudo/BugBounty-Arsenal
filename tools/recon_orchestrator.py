"""
Recon orchestrator - coordinates Subfinder, HTTPX, Scanner, and Nuclei.

Pipeline:
1. Subfinder: Enumerate subdomains
2. HTTPX: Probe live web servers
3. Scanner: Deep vulnerability scanning (22+ detectors)
4. Nuclei: Template-based vulnerability scanning
"""
import logging
import json
import time
from pathlib import Path
from typing import List, Dict, Optional, Any
from datetime import datetime

from tools.external_tools import (
    SubfinderWrapper,
    HTTPXWrapper,
    NucleiWrapper,
    check_tool_installation,
    print_installation_instructions
)

logger = logging.getLogger(__name__)


class ReconOrchestrator:
    """Orchestrates the full reconnaissance and scanning pipeline."""
    
    def __init__(self, output_dir: str = "recon_output"):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(exist_ok=True, parents=True)
        
        # Initialize tool wrappers
        self.subfinder = SubfinderWrapper()
        self.httpx = HTTPXWrapper()
        self.nuclei = NucleiWrapper()
        
        # Check tool installation
        self.tools_status = check_tool_installation()
        
    def check_prerequisites(self) -> bool:
        """
        Check if all required tools are installed.
        
        Returns:
            True if all tools are available, False otherwise
        """
        all_installed = all(self.tools_status.values())
        
        if not all_installed:
            missing = [name for name, installed in self.tools_status.items() if not installed]
            logger.error(f"Missing tools: {', '.join(missing)}")
            print_installation_instructions()
            return False
        
        logger.info("✓ All recon tools are installed and ready")
        return True
    
    def run_full_recon(
        self,
        domain: str,
        run_scanner: bool = True,
        run_nuclei: bool = True,
        nuclei_severity: Optional[List[str]] = None,
        scanner_concurrency: int = 10,
        nuclei_rate_limit: int = 150,
        recursive_subs: bool = False,
        bypass_cloudflare: bool = False,
        bypass_delay_min: float = 1.0,
        bypass_delay_max: float = 3.0
    ) -> Dict[str, Any]:
        """
        Run the full reconnaissance pipeline.
        
        Args:
            domain: Target domain (e.g., "example.com")
            run_scanner: Whether to run the custom scanner
            run_nuclei: Whether to run Nuclei
            nuclei_severity: Filter Nuclei by severity (e.g., ["high", "critical"])
            scanner_concurrency: Concurrency for custom scanner
            nuclei_rate_limit: Rate limit for Nuclei
            recursive_subs: Use recursive subdomain enumeration
            bypass_cloudflare: Enable Cloudflare/CDN bypass
            bypass_delay_min: Minimum delay between requests (seconds)
            bypass_delay_max: Maximum delay between requests (seconds)
            
        Returns:
            Dictionary with all findings and metadata
        """
        if not self.check_prerequisites():
            return {"error": "Missing required tools"}
        
        start_time = time.time()
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        
        # Create domain-specific output directory
        domain_output = self.output_dir / domain / timestamp
        domain_output.mkdir(parents=True, exist_ok=True)
        
        results = {
            "domain": domain,
            "timestamp": datetime.now().isoformat(),
            "phases": {}
        }
        
        # Phase 1: Subdomain Enumeration
        logger.info(f"[Phase 1/4] Enumerating subdomains for {domain}...")
        phase1_start = time.time()
        
        subdomains = self.subfinder.enumerate_subdomains(
            domain,
            recursive=recursive_subs,
            timeout=600  # Increased from 300s to 600s for large targets like GitHub
        )
        
        if not subdomains:
            logger.warning(f"No subdomains found for {domain}")
            return {"error": "No subdomains discovered"}
        
        # Save subdomains
        subs_file = domain_output / "01_subdomains.txt"
        subs_file.write_text("\n".join(subdomains))
        
        results["phases"]["subdomain_enumeration"] = {
            "duration": time.time() - phase1_start,
            "subdomains_found": len(subdomains),
            "output_file": str(subs_file)
        }
        
        logger.info(f"✓ Found {len(subdomains)} subdomains in {time.time() - phase1_start:.1f}s")
        
        # Phase 2: HTTP Probing
        logger.info(f"[Phase 2/4] Probing {len(subdomains)} hosts with HTTPX...")
        phase2_start = time.time()
        
        live_hosts = self.httpx.probe_hosts(
            subdomains,
            threads=50,
            timeout=10
        )
        
        if not live_hosts:
            logger.warning("No live hosts found")
            return results
        
        # Save live hosts
        live_file = domain_output / "02_live_hosts.json"
        live_file.write_text(json.dumps(live_hosts, indent=2))
        
        # Extract URLs for scanning
        live_urls = [h["url"] for h in live_hosts if h.get("url")]
        
        results["phases"]["http_probing"] = {
            "duration": time.time() - phase2_start,
            "hosts_probed": len(subdomains),
            "live_hosts": len(live_hosts),
            "output_file": str(live_file)
        }
        
        logger.info(f"✓ Found {len(live_hosts)} live hosts in {time.time() - phase2_start:.1f}s")
        
        # Phase 3: Custom Scanner (our 22+ detectors)
        if run_scanner and live_urls:
            logger.info(f"[Phase 3/4] Running custom scanner on {len(live_urls)} URLs...")
            phase3_start = time.time()
            
            try:
                # Import scanner module
                import scanner
                
                # Prepare targets for scanner
                scanner_results, scanner_meta = scanner.run_scan(
                    live_urls,
                    concurrency=scanner_concurrency,
                    timeout=15,
                    output_dir=str(domain_output / "scanner_responses"),
                    per_host_rate=1.0,
                    bypass_cloudflare=bypass_cloudflare,
                    bypass_delay_min=bypass_delay_min,
                    bypass_delay_max=bypass_delay_max
                )
                
                # Save scanner results
                scanner_file = domain_output / "03_scanner_findings.json"
                scanner_output = {
                    "results": scanner_results,
                    "metadata": scanner_meta
                }
                scanner_file.write_text(json.dumps(scanner_output, indent=2))
                
                # Summarize by severity
                severity_counts = {}
                for finding in scanner_results:
                    sev = finding.get("severity", "unknown")
                    severity_counts[sev] = severity_counts.get(sev, 0) + 1
                
                results["phases"]["custom_scanner"] = {
                    "duration": time.time() - phase3_start,
                    "urls_scanned": len(live_urls),
                    "findings": len(scanner_results),
                    "by_severity": severity_counts,
                    "output_file": str(scanner_file)
                }
                
                logger.info(
                    f"✓ Scanner found {len(scanner_results)} issues in {time.time() - phase3_start:.1f}s"
                )
                
            except Exception as e:
                logger.error(f"Scanner phase failed: {e}")
                results["phases"]["custom_scanner"] = {"error": str(e)}
        else:
            logger.info("[Phase 3/4] Skipping custom scanner")
        
        # Phase 4: Nuclei Scanning
        if run_nuclei and live_urls:
            logger.info(f"[Phase 4/4] Running Nuclei on {len(live_urls)} URLs...")
            phase4_start = time.time()
            
            try:
                nuclei_findings = self.nuclei.scan_targets(
                    live_urls,
                    severity=nuclei_severity or ["low", "medium", "high", "critical"],
                    rate_limit=nuclei_rate_limit,
                    timeout=600
                )
                
                # Save Nuclei results
                nuclei_file = domain_output / "04_nuclei_findings.json"
                nuclei_file.write_text(json.dumps(nuclei_findings, indent=2))
                
                # Summarize by severity
                nuclei_severity_counts = {}
                for finding in nuclei_findings:
                    sev = finding.get("severity", "unknown")
                    nuclei_severity_counts[sev] = nuclei_severity_counts.get(sev, 0) + 1
                
                results["phases"]["nuclei"] = {
                    "duration": time.time() - phase4_start,
                    "urls_scanned": len(live_urls),
                    "findings": len(nuclei_findings),
                    "by_severity": nuclei_severity_counts,
                    "output_file": str(nuclei_file)
                }
                
                logger.info(
                    f"✓ Nuclei found {len(nuclei_findings)} issues in {time.time() - phase4_start:.1f}s"
                )
                
            except Exception as e:
                logger.error(f"Nuclei phase failed: {e}")
                results["phases"]["nuclei"] = {"error": str(e)}
        else:
            logger.info("[Phase 4/4] Skipping Nuclei")
        
        # Save final results
        results["total_duration"] = time.time() - start_time
        results["output_directory"] = str(domain_output)
        
        summary_file = domain_output / "00_recon_summary.json"
        summary_file.write_text(json.dumps(results, indent=2))
        
        logger.info(f"\n{'='*70}")
        logger.info(f"✓ Full recon completed in {results['total_duration']:.1f}s")
        logger.info(f"✓ Output directory: {domain_output}")
        logger.info(f"{'='*70}\n")
        
        # Print summary
        self._print_summary(results)
        
        return results
    
    def _print_summary(self, results: Dict[str, Any]):
        """Print a formatted summary of the recon results."""
        print("\n" + "="*70)
        print(f"RECON SUMMARY: {results['domain']}")
        print("="*70)
        
        phases = results.get("phases", {})
        
        # Subdomain enumeration
        if "subdomain_enumeration" in phases:
            sub_data = phases["subdomain_enumeration"]
            print(f"\n📡 Subdomain Enumeration:")
            print(f"   Found: {sub_data.get('subdomains_found', 0)} subdomains")
            print(f"   Time: {sub_data.get('duration', 0):.1f}s")
        
        # HTTP probing
        if "http_probing" in phases:
            http_data = phases["http_probing"]
            print(f"\n🌐 HTTP Probing:")
            print(f"   Probed: {http_data.get('hosts_probed', 0)} hosts")
            print(f"   Live: {http_data.get('live_hosts', 0)} hosts")
            print(f"   Time: {http_data.get('duration', 0):.1f}s")
        
        # Custom scanner
        if "custom_scanner" in phases:
            scanner_data = phases["custom_scanner"]
            if "error" not in scanner_data:
                print(f"\n🔍 Custom Scanner (22+ detectors):")
                print(f"   Scanned: {scanner_data.get('urls_scanned', 0)} URLs")
                print(f"   Findings: {scanner_data.get('findings', 0)}")
                
                sev_counts = scanner_data.get("by_severity", {})
                if sev_counts:
                    print(f"   Severity breakdown:")
                    for sev in ["critical", "high", "medium", "low"]:
                        if sev in sev_counts:
                            print(f"      {sev.capitalize()}: {sev_counts[sev]}")
                
                print(f"   Time: {scanner_data.get('duration', 0):.1f}s")
        
        # Nuclei
        if "nuclei" in phases:
            nuclei_data = phases["nuclei"]
            if "error" not in nuclei_data:
                print(f"\n⚡ Nuclei Scanner:")
                print(f"   Scanned: {nuclei_data.get('urls_scanned', 0)} URLs")
                print(f"   Findings: {nuclei_data.get('findings', 0)}")
                
                sev_counts = nuclei_data.get("by_severity", {})
                if sev_counts:
                    print(f"   Severity breakdown:")
                    for sev in ["critical", "high", "medium", "low", "info"]:
                        if sev in sev_counts:
                            print(f"      {sev.capitalize()}: {sev_counts[sev]}")
                
                print(f"   Time: {nuclei_data.get('duration', 0):.1f}s")
        
        print(f"\n⏱️  Total Time: {results.get('total_duration', 0):.1f}s")
        print(f"📁 Output: {results.get('output_directory', 'N/A')}")
        print("="*70 + "\n")


def run_recon_pipeline(
    domain: str,
    output_dir: str = "recon_output",
    skip_scanner: bool = False,
    skip_nuclei: bool = False,
    nuclei_severity: Optional[List[str]] = None,
    scanner_concurrency: int = 10,
    nuclei_rate_limit: int = 150,
    recursive_subs: bool = False,
    bypass_cloudflare: bool = False,
    bypass_delay_min: float = 1.0,
    bypass_delay_max: float = 3.0
) -> Dict[str, Any]:
    """
    Convenience function to run the full recon pipeline.
    
    Args:
        domain: Target domain
        output_dir: Output directory for results
        skip_scanner: Skip custom scanner phase
        skip_nuclei: Skip Nuclei phase
        nuclei_severity: Filter Nuclei by severity
        scanner_concurrency: Scanner concurrency level
        nuclei_rate_limit: Nuclei rate limit
        recursive_subs: Use recursive subdomain enumeration
        bypass_cloudflare: Enable Cloudflare/CDN bypass
        bypass_delay_min: Minimum delay between requests (seconds)
        bypass_delay_max: Maximum delay between requests (seconds)
        
    Returns:
        Recon results dictionary
    """
    orchestrator = ReconOrchestrator(output_dir=output_dir)
    
    return orchestrator.run_full_recon(
        domain=domain,
        run_scanner=not skip_scanner,
        run_nuclei=not skip_nuclei,
        nuclei_severity=nuclei_severity,
        scanner_concurrency=scanner_concurrency,
        nuclei_rate_limit=nuclei_rate_limit,
        recursive_subs=recursive_subs,
        bypass_cloudflare=bypass_cloudflare,
        bypass_delay_min=bypass_delay_min,
        bypass_delay_max=bypass_delay_max
    )
