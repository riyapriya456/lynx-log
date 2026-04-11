import asyncio
import random
from .base import BaseScanner
from common import TestingZone, event_manager


class RateLimitBypassScanner(BaseScanner):
    """
    Rate Limit Bypass Scanner.
    
    Tests various techniques to bypass rate limiting:
    - IP spoofing via headers (X-Forwarded-For, etc.)
    - Null character injection
    - Case variation in endpoints
    - Session rotation simulation
    """
    
    def __init__(self, context):
        super().__init__(context)
        self.zone = TestingZone.ZONE_B
        self.name = "RateLimitBypassScanner"
        
    async def run(self):
        await event_manager.emit("log", f"[{self.name}] Starting Rate Limit Bypass scan...")
        
        # Load payloads
        bypass_headers = self.load_payloads("rate_limit/headers.txt")
        null_chars = self.load_payloads("rate_limit/null_chars.txt")
        
        if not bypass_headers:
            bypass_headers = [
                "X-Forwarded-For", "X-Client-IP", "X-Remote-IP",
                "X-Originating-IP", "X-Real-IP", "True-Client-IP"
            ]
        
        if not null_chars:
            null_chars = ["%00", "%0d%0a", "%09", "%20"]
        
        # Identify rate-limited endpoints (login, password reset, signup, etc.)
        base_url = self.context.target.rstrip('/')
        rate_limit_endpoints = [
            "/login", "/signin", "/auth/login", "/api/login",
            "/password/reset", "/forgot-password", "/api/reset-password",
            "/signup", "/register", "/api/register",
            "/api/auth", "/api/token", "/oauth/token"
        ]
        
        tasks = []
        for endpoint in rate_limit_endpoints:
            test_url = f"{base_url}{endpoint}"
            # Check if endpoint exists
            exists = await self._endpoint_exists(test_url)
            if exists:
                tasks.append(self.test_header_bypass(test_url, bypass_headers))
                tasks.append(self.test_null_char_bypass(test_url, null_chars))
        
        if tasks:
            await asyncio.gather(*tasks)
        else:
            await event_manager.emit("log", f"[{self.name}] No rate-limited endpoints found.")
        
        await event_manager.emit("log", f"[{self.name}] Scan complete.")
    
    async def _endpoint_exists(self, url):
        """Check if an endpoint exists (returns non-404)."""
        try:
            async with self.context.session.get(url, allow_redirects=True, timeout=10) as response:
                return response.status != 404
        except Exception:
            return False
    
    async def test_header_bypass(self, url, headers):
        """Test if rate limiting can be bypassed via IP spoofing headers."""
        # Generate random IPs
        random_ips = [
            f"{random.randint(1,254)}.{random.randint(1,254)}.{random.randint(1,254)}.{random.randint(1,254)}"
            for _ in range(5)
        ]
        
        # First, establish a baseline by making requests without spoofed headers
        baseline_responses = []
        for _ in range(3):
            try:
                async with self.context.session.get(url, timeout=10) as response:
                    baseline_responses.append(response.status)
            except Exception:
                pass
        
        if not baseline_responses:
            return
        
        # Test with spoofed headers
        for header in headers[:5]:
            success_count = 0
            for ip in random_ips[:3]:
                try:
                    test_headers = {header: ip}
                    async with self.context.session.get(url, headers=test_headers, timeout=10) as response:
                        if response.status in [200, 302, 401]:  # Normal responses
                            success_count += 1
                except Exception:
                    pass
            
            # If we can successfully make requests with different IPs, rate limit may be bypassable
            if success_count >= 2:
                await self.emit_vulnerability(
                    "Rate Limit Bypass",
                    f"Rate limiting may be bypassable via {header} header.\nEndpoint: {url}\nEach request with a different IP in {header} was accepted.",
                    severity="P4",
                    remediation="Implement rate limiting based on authenticated user sessions, not just IP. Don't trust X-Forwarded-For for rate limiting.",
                    url=url,
                    payload=f"{header}: <random_ip>",
                    confidence=0.55,
                    observed_behavior="Requests with spoofed IP headers were accepted, but explicit limiting behavior was not confirmed.",
                    verification="heuristic",
                    reproduction_steps=[
                        "Send a baseline burst without spoofed headers.",
                        f"Repeat the requests with {header} set to different IP values.",
                        "Confirm whether the server actually enforces a 429/403 threshold before treating this as bypassable.",
                    ],
                )
                return
    
    async def test_null_char_bypass(self, url, null_chars):
        """Test if null characters can bypass rate limiting."""
        # This is more of an informational check
        for char in null_chars[:3]:
            try:
                # Append null char to URL
                test_url = f"{url}{char}"
                async with self.context.session.get(test_url, timeout=10) as response:
                    # If request succeeds, the server might process it differently
                    if response.status == 200:
                        await self.emit_vulnerability(
                            "Rate Limit Bypass",
                            f"Endpoint accepts URLs with special characters.\nURL: {test_url}\nThis may bypass URL-based rate limiting.",
                            severity="P4",
                            remediation="Normalize URLs before applying rate limits. Strip null bytes and special characters.",
                            url=url,
                            payload=char,
                            confidence=0.45,
                            observed_behavior="Special-character URL variant returned 200, but bypass impact was not demonstrated.",
                            verification="heuristic",
                        )
                        return
            except Exception:
                pass
