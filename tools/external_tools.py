"""
External tool integration wrappers for Subfinder, HTTPX, and Nuclei.
"""
import subprocess
import json
import logging
import shutil
from pathlib import Path
from typing import List, Dict, Optional, Any

logger = logging.getLogger(__name__)


class ExternalToolError(Exception):
    """Raised when external tool execution fails."""
    pass


class ExternalTool:
    """Base class for external tool wrappers."""
    
    def __init__(self, tool_name: str):
        self.tool_name = tool_name
        self.binary_path = shutil.which(tool_name)
        
    def is_installed(self) -> bool:
        """Check if the tool is installed and available in PATH."""
        return self.binary_path is not None
    
    def _run_command(self, args: List[str], timeout: int = 300) -> str:
        """
        Execute tool command and return stdout.
        
        Args:
            args: Command arguments (tool name will be prepended)
            timeout: Command timeout in seconds
            
        Returns:
            Command stdout as string
            
        Raises:
            ExternalToolError: If command fails or times out
        """
        if not self.binary_path:
            raise ExternalToolError(
                f"{self.tool_name} is not installed. "
                f"Install with: go install -v {self._get_install_command()}"
            )
        
        cmd = [self.binary_path] + args
        # Filter out None values and ensure all are strings
        cmd = [str(arg) for arg in cmd if arg is not None]
        logger.info(f"Running: {' '.join(cmd)}")
        
        try:
            result = subprocess.run(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=timeout,
                text=True,
                check=False
            )
            
            if result.returncode != 0:
                logger.warning(
                    f"{self.tool_name} exited with code {result.returncode}. "
                    f"stderr: {result.stderr[:500]}"
                )
            
            return result.stdout
            
        except subprocess.TimeoutExpired:
            raise ExternalToolError(f"{self.tool_name} command timed out after {timeout}s")
        except Exception as e:
            raise ExternalToolError(f"Failed to run {self.tool_name}: {e}")
    
    def _get_install_command(self) -> str:
        """Return the go install command for this tool."""
        raise NotImplementedError


class SubfinderWrapper(ExternalTool):
    """Wrapper for Subfinder subdomain enumeration tool."""
    
    def __init__(self):
        super().__init__("subfinder")
    
    def _get_install_command(self) -> str:
        return "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
    
    def enumerate_subdomains(
        self,
        domain: str,
        silent: bool = True,
        recursive: bool = False,
        timeout: int = 60
    ) -> List[str]:
        """
        Enumerate subdomains for a given domain.
        
        Args:
            domain: Target domain (e.g., "example.com")
            silent: Only show subdomains in output
            recursive: Use recursive subdomain enumeration
            timeout: Command timeout in seconds (default: 60s)
            
        Returns:
            List of discovered subdomains
        """
        args = ["-d", domain, "-json"]
        
        if silent:
            args.append("-silent")
        if recursive:
            args.append("-recursive")
        
        # Add explicit timeout to subfinder itself (30s max per source)
        args.extend(["-timeout", "30"])
        
        try:
            output = self._run_command(args, timeout=timeout)
            
            subdomains = []
            for line in output.strip().split('\n'):
                if not line:
                    continue
                try:
                    data = json.loads(line)
                    host = data.get("host", "")
                    if host and host not in subdomains:
                        subdomains.append(host)
                except json.JSONDecodeError:
                    # Fallback for non-JSON output
                    if line and not line.startswith('['):
                        subdomains.append(line.strip())
            
            logger.info(f"Subfinder found {len(subdomains)} subdomains for {domain}")
            return subdomains
            
        except ExternalToolError as e:
            logger.error(f"Subfinder enumeration failed: {e}")
            return []


class HTTPXWrapper(ExternalTool):
    """Wrapper for HTTPX HTTP probing tool."""
    
    def __init__(self):
        super().__init__("httpx")
    
    def _get_install_command(self) -> str:
        return "github.com/projectdiscovery/httpx/cmd/httpx@latest"
    
    def probe_hosts(
        self,
        hosts: List[str],
        silent: bool = True,
        follow_redirects: bool = True,
        timeout: int = 10,
        threads: int = 50
    ) -> List[Dict[str, Any]]:
        """
        Probe hosts to find live web servers.
        
        Args:
            hosts: List of hosts/URLs to probe
            silent: Display only results
            follow_redirects: Follow HTTP redirects
            timeout: Request timeout in seconds
            threads: Number of concurrent threads
            
        Returns:
            List of probe results with URL, status, title, tech, etc.
        """
        if not hosts:
            return []
        
        args = [
            "-json",
            "-status-code",
            "-title",
            "-tech-detect",
            "-content-length",
            "-timeout", str(timeout),
            "-threads", str(threads)
        ]
        
        if silent:
            args.append("-silent")
        if follow_redirects:
            args.append("-follow-redirects")
        
        # Write hosts to temp file for input
        import tempfile
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.txt') as f:
            for host in hosts:
                f.write(f"{host}\n")
            temp_file = f.name
        
        args.extend(["-list", temp_file])
        
        try:
            output = self._run_command(args, timeout=len(hosts) * 2 + 60)
            
            results = []
            for line in output.strip().split('\n'):
                if not line:
                    continue
                try:
                    data = json.loads(line)
                    results.append({
                        "url": data.get("url", ""),
                        "status_code": data.get("status_code", 0),
                        "title": data.get("title", ""),
                        "content_length": data.get("content_length", 0),
                        "technologies": data.get("technologies", []),
                        "webserver": data.get("webserver", ""),
                        "host": data.get("host", ""),
                        "scheme": data.get("scheme", "https")
                    })
                except json.JSONDecodeError:
                    continue
            
            logger.info(f"HTTPX probed {len(hosts)} hosts, found {len(results)} live")
            return results
            
        except ExternalToolError as e:
            logger.error(f"HTTPX probing failed: {e}")
            return []
        finally:
            # Clean up temp file
            try:
                Path(temp_file).unlink()
            except Exception:
                pass


class NucleiWrapper(ExternalTool):
    """Wrapper for Nuclei vulnerability scanner."""
    
    def __init__(self):
        super().__init__("nuclei")
    
    def _get_install_command(self) -> str:
        return "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"
    
    def scan_targets(
        self,
        targets: List[str],
        templates: Optional[List[str]] = None,
        severity: Optional[List[str]] = None,
        tags: Optional[List[str]] = None,
        silent: bool = True,
        rate_limit: int = 150,
        timeout: int = 600
    ) -> List[Dict[str, Any]]:
        """
        Scan targets with Nuclei vulnerability templates.
        
        Args:
            targets: List of URLs to scan
            templates: Specific template paths/IDs to use
            severity: Filter by severity (info, low, medium, high, critical)
            tags: Filter by template tags
            silent: Display only results
            rate_limit: Maximum requests per second
            timeout: Command timeout in seconds
            
        Returns:
            List of findings with template info, severity, matched URL, etc.
        """
        if not targets:
            return []
        
        args = [
            "-json",
            "-rate-limit", str(rate_limit),
            "-timeout", "10"
        ]
        
        if silent:
            args.append("-silent")
        
        if templates:
            for template in templates:
                args.extend(["-t", template])
        else:
            # Use default templates
            args.extend(["-t", "~/.local/nuclei-templates/"])
        
        if severity:
            args.extend(["-severity", ",".join(severity)])
        
        if tags:
            args.extend(["-tags", ",".join(tags)])
        
        # Write targets to temp file
        import tempfile
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.txt') as f:
            for target in targets:
                f.write(f"{target}\n")
            temp_file = f.name
        
        args.extend(["-list", temp_file])
        
        try:
            output = self._run_command(args, timeout=timeout)
            
            findings = []
            for line in output.strip().split('\n'):
                if not line:
                    continue
                try:
                    data = json.loads(line)
                    findings.append({
                        "template_id": data.get("template-id", ""),
                        "template_name": data.get("info", {}).get("name", ""),
                        "severity": data.get("info", {}).get("severity", "info"),
                        "type": data.get("type", ""),
                        "host": data.get("host", ""),
                        "matched_at": data.get("matched-at", ""),
                        "extracted_results": data.get("extracted-results", []),
                        "matcher_name": data.get("matcher-name", ""),
                        "description": data.get("info", {}).get("description", ""),
                        "reference": data.get("info", {}).get("reference", []),
                        "tags": data.get("info", {}).get("tags", []),
                        "cvss_score": data.get("info", {}).get("classification", {}).get("cvss-score", 0)
                    })
                except json.JSONDecodeError:
                    continue
            
            logger.info(f"Nuclei scanned {len(targets)} targets, found {len(findings)} issues")
            return findings
            
        except ExternalToolError as e:
            logger.error(f"Nuclei scan failed: {e}")
            return []
        finally:
            # Clean up temp file
            try:
                Path(temp_file).unlink()
            except Exception:
                pass
    
    def update_templates(self) -> bool:
        """Update Nuclei templates to latest version."""
        try:
            args = ["-update-templates"]
            self._run_command(args, timeout=120)
            logger.info("Nuclei templates updated successfully")
            return True
        except ExternalToolError as e:
            logger.error(f"Failed to update Nuclei templates: {e}")
            return False


def check_tool_installation() -> Dict[str, bool]:
    """
    Check which external tools are installed.
    
    Returns:
        Dictionary mapping tool name to installation status
    """
    tools = {
        "subfinder": SubfinderWrapper(),
        "httpx": HTTPXWrapper(),
        "nuclei": NucleiWrapper()
    }
    
    status = {}
    for name, tool in tools.items():
        installed = tool.is_installed()
        status[name] = installed
        if installed:
            logger.info(f"✓ {name} is installed at {tool.binary_path}")
        else:
            logger.warning(
                f"✗ {name} is not installed. "
                f"Install with: go install -v {tool._get_install_command()}"
            )
    
    return status


def print_installation_instructions():
    """Print installation instructions for missing tools."""
    print("\n" + "="*70)
    print("EXTERNAL TOOL INSTALLATION INSTRUCTIONS")
    print("="*70)
    print("\nPhase 2 tools require Go to be installed: https://go.dev/doc/install")
    print("\nInstall all tools with these commands:\n")
    
    tools = [
        ("Subfinder", "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"),
        ("HTTPX", "github.com/projectdiscovery/httpx/cmd/httpx@latest"),
        ("Nuclei", "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest")
    ]
    
    for name, path in tools:
        print(f"# {name}")
        print(f"go install -v {path}\n")
    
    print("After installation, update Nuclei templates:")
    print("nuclei -update-templates\n")
    print("="*70 + "\n")
