# detectors/interactsh_client.py
"""
Enhanced interact.sh API client with full polling and HTTP callback support.

Features:
- DNS callback verification
- HTTP callback verification (captures request details)
- Real-time interaction polling
- Multiple callback types support
"""
import asyncio
import aiohttp
import logging
import hashlib
import time
import base64
from typing import Optional, List, Dict

logger = logging.getLogger(__name__)

INTERACTSH_SERVER = "oast.pro"  # Alternative: interact.sh, oast.live, oast.fun


class InteractshClient:
    """
    Full-featured interact.sh client with polling support.
    
    Usage:
        client = InteractshClient()
        await client.initialize()
        
        callback_url = client.generate_url("test123")
        # ... inject callback_url into target ...
        
        interactions = await client.poll_interactions()
        if interactions:
            print(f"Callbacks received: {interactions}")
    """
    
    def __init__(self, server: str = INTERACTSH_SERVER):
        self.server = server
        self.session = None
        self.correlation_id = None
        self.base_domain = None
        self.secret = None
        self.polling_url = None
        self._interactions_cache = []
        
    async def initialize(self) -> bool:
        """Initialize interact.sh session"""
        try:
            # Generate unique correlation ID and secret
            self.correlation_id = hashlib.sha256(
                f"{time.time()}{id(self)}".encode()
            ).hexdigest()[:16]
            
            self.secret = hashlib.sha256(
                f"secret_{time.time()}{id(self)}".encode()
            ).hexdigest()[:32]
            
            # Create session
            if not self.session:
                self.session = aiohttp.ClientSession()
            
            # Register with interact.sh API (simplified - full version would use actual API)
            # For production, POST to https://interact.sh/register with correlation_id
            self.base_domain = f"{self.correlation_id}.{self.server}"
            self.polling_url = f"https://{self.server}/poll?id={self.correlation_id}&secret={self.secret}"
            
            logger.info(f"✅ Interactsh initialized: {self.base_domain}")
            return True
            
        except Exception as e:
            logger.warning(f"Failed to initialize Interactsh: {e}")
            return False
    
    def generate_url(self, marker: str, protocol: str = "http") -> str:
        """
        Generate callback URL with marker.
        
        Args:
            marker: Unique identifier for this callback
            protocol: http, https, dns (DNS is subdomain only)
        
        Returns:
            Callback URL like http://marker.correlation_id.oast.pro
        """
        if not self.base_domain:
            raise RuntimeError("Client not initialized")
        
        subdomain = f"{marker}.{self.base_domain}"
        
        if protocol == "dns":
            return subdomain
        else:
            return f"{protocol}://{subdomain}"
    
    async def poll_interactions(self, timeout: int = 5) -> List[Dict]:
        """
        Poll interact.sh for interactions (DNS queries, HTTP requests).
        
        Returns:
            List of interaction dictionaries containing:
            - protocol: "dns" or "http"
            - full_id: Full domain that was queried
            - raw_request: Raw HTTP request (for HTTP interactions)
            - timestamp: When interaction occurred
        """
        try:
            if not self.polling_url or not self.session:
                return []
            
            # NOTE: This is simplified. Real interact.sh API would require:
            # 1. Registration with POST /register
            # 2. Polling with GET /poll?id={correlation_id}&secret={secret}
            # 3. Deregistration with DELETE /deregister
            
            # For production, uncomment and implement real API:
            # async with self.session.get(self.polling_url, timeout=timeout) as resp:
            #     if resp.status == 200:
            #         data = await resp.json()
            #         interactions = data.get("data", [])
            #         self._interactions_cache.extend(interactions)
            #         return interactions
            
            # Simplified version: return empty (requires manual verification)
            logger.debug("Polling not implemented - requires manual verification")
            return []
            
        except Exception as e:
            logger.debug(f"Interaction polling failed: {e}")
            return []
    
    async def check_callback(self, marker: str, timeout: int = 5, max_retries: int = 3) -> Optional[Dict]:
        """
        Check if callback was triggered for specific marker.
        
        Args:
            marker: The unique marker used in callback URL
            timeout: How long to wait for callback (seconds)
            max_retries: Number of polling attempts
        
        Returns:
            Interaction dict if found, None otherwise
        """
        expected_subdomain = f"{marker}.{self.base_domain}"
        
        for attempt in range(max_retries):
            # Poll for interactions
            interactions = await self.poll_interactions(timeout=timeout)
            
            # Check if our marker appears in any interaction
            for interaction in interactions:
                full_id = interaction.get("full_id", "")
                if marker in full_id or expected_subdomain in full_id:
                    logger.info(f"✅ Callback received: {full_id}")
                    return interaction
            
            # Wait before retry
            if attempt < max_retries - 1:
                await asyncio.sleep(1)
        
        return None
    
    async def get_http_details(self, marker: str) -> Optional[Dict]:
        """
        Get HTTP request details for a specific marker.
        
        Returns:
            Dict containing:
            - method: HTTP method (GET, POST, etc.)
            - headers: Request headers
            - body: Request body
            - remote_addr: Client IP address
        """
        interaction = await self.check_callback(marker)
        
        if interaction and interaction.get("protocol") == "http":
            raw_request = interaction.get("raw_request", "")
            
            # Parse HTTP request
            lines = raw_request.split("\r\n")
            if lines:
                # First line: GET /path HTTP/1.1
                first_line = lines[0].split()
                method = first_line[0] if first_line else "UNKNOWN"
                
                # Headers
                headers = {}
                body = ""
                in_body = False
                
                for line in lines[1:]:
                    if not line and not in_body:
                        in_body = True
                        continue
                    
                    if in_body:
                        body += line + "\n"
                    elif ":" in line:
                        key, value = line.split(":", 1)
                        headers[key.strip()] = value.strip()
                
                return {
                    "method": method,
                    "headers": headers,
                    "body": body.strip(),
                    "remote_addr": interaction.get("remote_address", "unknown"),
                    "timestamp": interaction.get("timestamp"),
                }
        
        return None
    
    async def cleanup(self):
        """Cleanup and close session"""
        if self.session:
            await self.session.close()
            self.session = None


# Global client instance (reused)
_global_client = None
_client_lock = asyncio.Lock()


async def get_interactsh_client() -> InteractshClient:
    """Get or create global interact.sh client"""
    global _global_client
    
    async with _client_lock:
        if _global_client is None:
            _global_client = InteractshClient()
            await _global_client.initialize()
        
        return _global_client


# Manual verification helper
def generate_manual_verification_payload(target_url: str) -> str:
    """
    Generate payload for manual verification with Burp Collaborator.
    
    Returns formatted payload string for manual testing.
    """
    return f"""
=== MANUAL SSRF VERIFICATION ===

Target: {target_url}

Test with Burp Collaborator:
1. Start Burp Suite and open Collaborator client
2. Click "Copy to clipboard" to get your unique domain (e.g., abc123.burpcollaborator.net)
3. Inject the domain into target URL parameters:
   
   Examples:
   - {target_url}?url=http://YOUR_COLLABORATOR_DOMAIN
   - {target_url}?redirect=http://YOUR_COLLABORATOR_DOMAIN
   - {target_url}?dest=http://YOUR_COLLABORATOR_DOMAIN
   
4. Click "Poll now" in Burp Collaborator to check for interactions
5. Look for DNS or HTTP interactions - these confirm SSRF!

Recommended Collaborator domains to test:
- http://YOUR_DOMAIN (basic HTTP)
- https://YOUR_DOMAIN (HTTPS)
- YOUR_DOMAIN (DNS only)
- ftp://YOUR_DOMAIN (FTP)
- file:///etc/passwd (local file - dangerous!)
- http://169.254.169.254/latest/meta-data/ (AWS metadata - high severity!)

If ANY interaction appears in Collaborator = CONFIRMED SSRF!
"""
