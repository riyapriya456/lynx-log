import asyncio
import urllib.parse
from .base import BaseScanner
from common import TestingZone, event_manager


class SSRFScanner(BaseScanner):
    """
    Server-Side Request Forgery (SSRF) Scanner.
    
    Detects SSRF vulnerabilities by injecting internal/localhost URLs
    into parameters and checking for differences in response behavior.
    """
    
    def __init__(self, context):
        super().__init__(context)
        self.zone = TestingZone.ZONE_A
        self.name = "SSRFScanner"
        
        # SSRF payloads targeting internal resources
        self.payloads = [
            # Localhost variations
            "http://127.0.0.1",
            "http://localhost",
            "http://127.0.0.1:80",
            "http://127.0.0.1:443",
            "http://127.0.0.1:8080",
            "http://127.0.0.1:22",
            "http://0.0.0.0",
            "http://[::1]",
            
            # Internal IP ranges
            "http://10.0.0.1",
            "http://172.16.0.1",
            "http://192.168.0.1",
            "http://192.168.1.1",
            
            # AWS metadata endpoints
            "http://169.254.169.254/latest/meta-data/",
            "http://169.254.169.254/latest/user-data/",
            "http://169.254.169.254/latest/api/token",
            
            # Google Cloud metadata
            "http://metadata.google.internal/computeMetadata/v1/",
            
            # Azure metadata
            "http://169.254.169.254/metadata/instance",
            
            # Protocol smuggling
            "file:///etc/passwd",
            "file:///c:/windows/win.ini",
            "dict://127.0.0.1:11211/stats",
            "gopher://127.0.0.1:25/",
            
            # URL encoding bypass
            "http://127.1",
            "http://0177.0.0.1",  # Octal
            "http://2130706433",   # Decimal
            "http://0x7f.0x0.0x0.0x1",  # Hex
            
            # DNS rebinding
            "http://spoofed.burpcollaborator.net",
        ]
        
        # Signatures indicating successful SSRF
        self.signatures = [
            # Linux files
            "root:x:0:0",
            "/bin/bash",
            "/bin/sh",
            
            # Windows files
            "[extensions]",
            "[fonts]",
            
            # AWS metadata
            "ami-id",
            "instance-id",
            "security-credentials",
            "iam/info",
            
            # Internal services
            "STAT items",  # Memcached
            "SSH-",        # SSH banner
            "220 ",        # SMTP/FTP banner
            
            # Error messages indicating SSRF attempt
            "Connection refused",
            "No route to host",
            "Network is unreachable",
        ]
        
        # URL parameters commonly vulnerable to SSRF
        self.ssrf_params = ["url", "uri", "path", "dest", "redirect", "next", 
                           "data", "load", "page", "file", "document", "folder",
                           "root", "img", "image", "pic", "picture", "src",
                           "feed", "href", "site", "html", "ref", "link"]

    async def run(self):
        await event_manager.emit("log", f"[{self.name}] Starting SSRF scan...")
        
        urls_to_scan = self.context.crawled_urls if self.context.crawled_urls else {self.context.target}
        tasks = []
        
        for url in urls_to_scan:
            # Check existing parameters
            parsed = urllib.parse.urlparse(url)
            params = urllib.parse.parse_qs(parsed.query)
            
            for param in params:
                # Only test parameters that look like they might handle URLs
                param_lower = param.lower()
                if any(ssrf_p in param_lower for ssrf_p in self.ssrf_params) or "?" in url:
                    for payload in self.payloads[:15]:  # Limit to avoid too many requests
                        tasks.append(self.check_ssrf(url, param, payload))
            
            # Also try adding common SSRF parameters
            if not params:
                for ssrf_param in self.ssrf_params[:5]:
                    for payload in self.payloads[:10]:
                        test_url = f"{url}?{ssrf_param}={urllib.parse.quote(payload)}"
                        tasks.append(self.check_ssrf_direct(test_url, payload))
        
        # Process in chunks
        chunk_size = 10
        for i in range(0, len(tasks), chunk_size):
            await asyncio.gather(*tasks[i:i+chunk_size])
        
        await event_manager.emit("log", f"[{self.name}] Scan complete.")

    async def check_ssrf(self, original_url, param, payload):
        """Check for SSRF by replacing a parameter value with the payload."""
        try:
            parsed = urllib.parse.urlparse(original_url)
            params = urllib.parse.parse_qs(parsed.query)
            params[param] = [payload]
            new_query = urllib.parse.urlencode(params, doseq=True)
            test_url = urllib.parse.urlunparse((
                parsed.scheme, parsed.netloc, parsed.path,
                parsed.params, new_query, parsed.fragment
            ))
            
            await self.check_ssrf_direct(test_url, payload)
        except Exception:
            pass

    async def check_ssrf_direct(self, url, payload):
        """Make request and check for SSRF indicators."""
        try:
            async with self.context.session.get(url, timeout=10) as response:
                text = await response.text()
                
                # Check for SSRF signatures
                for sig in self.signatures:
                    if sig.lower() in text.lower():
                        await self.emit_vulnerability(
                            "Potential SSRF",
                            f"SSRF indicator found: '{sig}'\nPayload: {payload}",
                            severity="P3",
                            remediation="Validate and sanitize all user-supplied URLs. Use allowlists for permitted domains. Block internal IP ranges.",
                            url=url,
                            payload=payload,
                            confidence=0.62,
                            observed_behavior=f"Response body contained SSRF-related marker: {sig}.",
                            verification="heuristic",
                            reproduction_steps=[
                                "Submit the reported payload to the URL parameter.",
                                "Compare the response against a safe external URL baseline.",
                                "Confirm the marker is an actual remote fetch result before escalating.",
                            ],
                        )
                        return
                
                # Check for timing-based SSRF (response time differences)
                # If internal resource, response might be faster or slower
                if response.status == 200 and ("127.0.0.1" in payload or "localhost" in payload):
                    # Could indicate SSRF if content changed significantly
                    if len(text) > 0 and any(x in text.lower() for x in ["error", "failed", "denied"]):
                        pass  # Likely blocked, not vulnerable
                        
        except asyncio.TimeoutError:
            # Timeout might indicate SSRF to slow internal service
            pass
        except Exception:
            pass
