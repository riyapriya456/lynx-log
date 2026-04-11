import asyncio
import urllib.parse
from .base import BaseScanner
from common import TestingZone, event_manager


class Bypass403Scanner(BaseScanner):
    """
    403 Bypass Scanner.
    
    Tests various techniques to bypass 403 Forbidden responses:
    - Header manipulation (X-Forwarded-For, X-Original-URL, etc.)
    - URL encoding tricks and path manipulation
    - HTTP method override
    - Case manipulation
    """
    
    def __init__(self, context):
        super().__init__(context)
        self.zone = TestingZone.ZONE_A
        self.name = "Bypass403Scanner"
        
        # Load payloads from files
        self.bypass_headers = []
        self.url_payloads = []
        
    async def run(self):
        await event_manager.emit("log", f"[{self.name}] Starting 403 Bypass scan...")
        
        # Load payloads
        self.bypass_headers = self.load_payloads("403_bypass/headers.txt")
        self.url_payloads = self.load_payloads("403_bypass/url_payloads.txt", limit=50)
        
        if not self.bypass_headers:
            self.bypass_headers = [
                "X-Forwarded-For", "X-Forwarded-Host", "X-Original-URL",
                "X-Rewrite-URL", "X-Custom-IP-Authorization", "X-Real-IP"
            ]
        
        if not self.url_payloads:
            self.url_payloads = ["/", "//", "/..", "/./", "%2f", "%2e%2e"]
        
        # Get the target URL
        target_url = self.context.target.rstrip('/')
        
        # Check if target itself returns 403
        original_status, original_length = await self._check_response(target_url)
        
        await event_manager.emit("log", f"[{self.name}] Target status: {original_status}, Content-Length: {original_length}")
        
        # Only proceed if we have a 403/401 to bypass
        if original_status not in [403, 401]:
            await event_manager.emit("log", f"[{self.name}] Target does not return 403/401 (got {original_status}). Testing admin paths...")
            
            # Test common admin paths
            admin_paths = ["/admin", "/administrator", "/admin.php", "/wp-admin", 
                          "/manager", "/console", "/dashboard", "/panel", "/.htaccess",
                          "/config", "/backup", "/.git", "/.env"]
            
            forbidden_found = False
            for path in admin_paths:
                test_url = f"{target_url}{path}"
                status, length = await self._check_response(test_url)
                if status in [403, 401]:
                    await event_manager.emit("log", f"[{self.name}] Found 403 at: {test_url}")
                    await self._test_all_bypasses(test_url, status, length)
                    forbidden_found = True
            
            if not forbidden_found:
                await event_manager.emit("log", f"[{self.name}] No 403/401 pages found to test. Scan complete.")
        else:
            # Target itself is 403, test bypasses
            await event_manager.emit("log", f"[{self.name}] Target returns {original_status}. Testing bypass techniques...")
            await self._test_all_bypasses(target_url, original_status, original_length)
        
        await event_manager.emit("log", f"[{self.name}] Scan complete.")
    
    async def _check_response(self, url):
        """Check the HTTP status code and content length of a URL."""
        try:
            async with self.context.session.get(url, allow_redirects=False, timeout=10) as response:
                content = await response.read()
                return response.status, len(content)
        except Exception:
            return None, 0
    
    async def _test_all_bypasses(self, url, original_status, original_length):
        """Test all bypass techniques on a confirmed 403/401 URL."""
        # Header-based bypasses
        await self.test_header_bypass(url, original_status, original_length)
        # URL-based bypasses
        await self.test_url_bypass(url, original_status, original_length)
        # Method override bypass
        await self.test_method_bypass(url, original_status, original_length)
        # Case manipulation
        await self.test_case_bypass(url, original_status, original_length)
    
    async def test_header_bypass(self, url, original_status, original_length):
        """Test header-based 403 bypass techniques."""
        header_values = ["127.0.0.1", "localhost", "10.0.0.1", "192.168.1.1"]
        
        for header in self.bypass_headers[:15]:
            for value in header_values[:2]:
                try:
                    headers = {header: value}
                    async with self.context.session.get(url, headers=headers, 
                                                       allow_redirects=False, timeout=10) as response:
                        content = await response.read()
                        new_length = len(content)
                        
                        # Verify it's a TRUE bypass: status changed from 403/401 to 200
                        # AND content is significantly different (not just an error page)
                        if response.status == 200 and self._is_real_bypass(original_length, new_length, content):
                            payload_used = f"{header}: {value}"
                            await self.emit_vulnerability(
                                "403 Bypass",
                                f"403 Forbidden bypassed using header manipulation.\n"
                                f"Original Status: {original_status}\n"
                                f"Bypassed Status: 200\n"
                                f"Header: {payload_used}\n"
                                f"Content Length Change: {original_length} → {new_length}",
                                severity="P2",
                                remediation="Implement proper access controls that cannot be bypassed via headers. Don't trust X-Forwarded-* headers for authorization.",
                                url=url,
                                payload=payload_used,
                                confidence=0.9,
                                observed_behavior="Restricted endpoint returned 200 with materially different content after header manipulation.",
                                verification="direct",
                                reproduction_steps=[
                                    f"Request {url} without spoofed headers and confirm the 401/403 response.",
                                    f"Repeat the request with {payload_used}.",
                                    "Confirm the access boundary changes only when the bypass header is accepted.",
                                ]
                            )
                            await event_manager.emit("log", f"[{self.name}] ✓ BYPASS FOUND: {payload_used}")
                            return
                except Exception:
                    pass
    
    async def test_url_bypass(self, url, original_status, original_length):
        """Test URL manipulation bypass techniques."""
        parsed = urllib.parse.urlparse(url)
        path = parsed.path
        
        for payload in self.url_payloads[:25]:
            test_paths = [
                f"{path}{payload}",
                f"{path}/{payload}",
            ]
            
            for test_path in test_paths:
                try:
                    test_url = urllib.parse.urlunparse((
                        parsed.scheme, parsed.netloc, test_path,
                        parsed.params, parsed.query, parsed.fragment
                    ))
                    async with self.context.session.get(test_url, allow_redirects=False, 
                                                       timeout=10) as response:
                        content = await response.read()
                        new_length = len(content)
                        
                        if response.status == 200 and self._is_real_bypass(original_length, new_length, content):
                            await self.emit_vulnerability(
                                "403 Bypass",
                                f"403 Forbidden bypassed using URL manipulation.\n"
                                f"Original: {url} (Status: {original_status})\n"
                                f"Bypassed: {test_url} (Status: 200)\n"
                                f"Payload: {payload}",
                                severity="P2",
                                remediation="Normalize URLs before access control checks. Use strict path matching.",
                                url=url,
                                payload=f"URL: {test_url}",
                                confidence=0.88,
                                observed_behavior="Path normalization altered the authorization outcome.",
                                verification="direct",
                                reproduction_steps=[
                                    f"Request the restricted URL {url} and confirm the 401/403 baseline.",
                                    f"Request the manipulated path {test_url}.",
                                    "Verify the bypassed response is not just a generic error page.",
                                ]
                            )
                            await event_manager.emit("log", f"[{self.name}] ✓ BYPASS FOUND: {payload}")
                            return
                except Exception:
                    pass
    
    async def test_method_bypass(self, url, original_status, original_length):
        """Test HTTP method override bypass."""
        methods = ["POST", "PUT", "PATCH", "OPTIONS"]
        
        for method in methods:
            try:
                async with self.context.session.request(method, url, allow_redirects=False, 
                                                       timeout=10) as response:
                    content = await response.read()
                    new_length = len(content)
                    
                    if response.status == 200 and self._is_real_bypass(original_length, new_length, content):
                        payload_used = f"HTTP Method: {method}"
                        await self.emit_vulnerability(
                            "403 Bypass",
                            f"403 Forbidden bypassed using HTTP method change.\n"
                            f"Original: GET (Status: {original_status})\n"
                            f"Bypassed: {method} (Status: 200)\n"
                            f"Content Length Change: {original_length} → {new_length}",
                            severity="P2",
                            remediation="Implement access controls that check all HTTP methods consistently.",
                            url=url,
                            payload=payload_used,
                            confidence=0.84,
                            observed_behavior="Alternative HTTP method returned authorized content.",
                            verification="direct",
                            reproduction_steps=[
                                f"Request {url} with GET and confirm the forbidden response.",
                                f"Repeat the same path with method {method}.",
                                "Confirm the response body is actually protected content and not a generic page.",
                            ]
                        )
                        await event_manager.emit("log", f"[{self.name}] ✓ BYPASS FOUND: {method}")
                        return
            except Exception:
                pass
        
        # Test method override headers
        override_headers = [
            ("X-HTTP-Method-Override", "GET"),
            ("X-Method-Override", "GET"),
        ]
        
        for header, value in override_headers:
            try:
                headers = {header: value}
                async with self.context.session.post(url, headers=headers, 
                                                    allow_redirects=False, timeout=10) as response:
                    content = await response.read()
                    new_length = len(content)
                    
                    if response.status == 200 and self._is_real_bypass(original_length, new_length, content):
                        payload_used = f"{header}: {value}"
                        await self.emit_vulnerability(
                            "403 Bypass",
                            f"403 Forbidden bypassed using method override header.\n"
                            f"Header: {payload_used}",
                            severity="P2",
                            remediation="Disable or properly handle HTTP method override headers.",
                            url=url,
                            payload=payload_used,
                            confidence=0.8,
                            observed_behavior="Method override header changed the authorization result.",
                            verification="direct",
                        )
                        return
            except Exception:
                pass
    
    async def test_case_bypass(self, url, original_status, original_length):
        """Test case manipulation bypass."""
        parsed = urllib.parse.urlparse(url)
        path = parsed.path
        
        variations = [
            path.upper(),
            path.lower(),
            path.swapcase(),
        ]
        
        for var_path in variations:
            if var_path == path:
                continue
            try:
                test_url = urllib.parse.urlunparse((
                    parsed.scheme, parsed.netloc, var_path,
                    parsed.params, parsed.query, parsed.fragment
                ))
                async with self.context.session.get(test_url, allow_redirects=False, 
                                                   timeout=10) as response:
                    content = await response.read()
                    new_length = len(content)
                    
                    if response.status == 200 and self._is_real_bypass(original_length, new_length, content):
                        await self.emit_vulnerability(
                            "403 Bypass",
                            f"403 Forbidden bypassed using case manipulation.\n"
                            f"Original: {url} (Status: {original_status})\n"
                            f"Bypassed: {test_url} (Status: 200)",
                            severity="P2",
                            remediation="Use case-insensitive URL matching for access controls.",
                            url=url,
                            payload=f"Case variant: {var_path}",
                            confidence=0.82,
                            observed_behavior="Path case normalization changed access control behavior.",
                            verification="direct",
                        )
                        return
            except Exception:
                pass
    
    def _is_real_bypass(self, original_length, new_length, content):
        """
        Verify if this is a real bypass by checking:
        1. Content length is significantly different (not just different error page)
        2. Content doesn't look like a generic error/forbidden page
        """
        # If the new content is much larger, it's likely a real page
        if new_length > original_length * 1.5 and new_length > 500:
            return True
        
        # Check if content looks like forbidden/error page
        content_str = content.decode('utf-8', errors='ignore').lower()
        error_indicators = ['forbidden', 'access denied', '403', '401', 'not authorized', 
                           'permission denied', 'you are not allowed', 'error']
        
        # If it contains error indicators, it's probably not a real bypass
        if any(indicator in content_str for indicator in error_indicators):
            return False
        
        # If we got meaningful content (> 200 bytes, no error words), consider it a bypass
        if new_length > 200:
            return True
        
        return False

