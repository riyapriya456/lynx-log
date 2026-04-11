import asyncio
import re
import urllib.parse
from bs4 import BeautifulSoup
from .base import BaseScanner
from common import TestingZone, event_manager


class TwoFABypassScanner(BaseScanner):
    """
    2FA Bypass Scanner.
    
    Tests various techniques to bypass Two-Factor Authentication:
    - Token leakage in response
    - Response manipulation detection
    - Session/referrer bypass checks
    - Rate limiting on 2FA endpoints
    - Token validation checks
    """
    
    def __init__(self, context):
        super().__init__(context)
        self.zone = TestingZone.ZONE_A
        self.name = "TwoFABypassScanner"
        
    async def run(self):
        await event_manager.emit("log", f"[{self.name}] Starting 2FA Bypass scan...")
        
        # Identify 2FA endpoints
        base_url = self.context.target.rstrip('/')
        twofa_endpoints = [
            "/2fa", "/mfa", "/otp", "/verify", "/verification",
            "/two-factor", "/second-factor", "/auth/verify",
            "/login/verify", "/api/verify-otp", "/api/2fa",
            "/account/security/2fa", "/settings/2fa"
        ]
        
        found_endpoints = []
        for endpoint in twofa_endpoints:
            test_url = f"{base_url}{endpoint}"
            if await self._endpoint_exists(test_url):
                found_endpoints.append(test_url)
        
        if not found_endpoints:
            # Check crawled URLs for 2FA patterns
            urls_to_scan = self.context.crawled_urls if self.context.crawled_urls else set()
            for url in urls_to_scan:
                if any(pattern in url.lower() for pattern in ['2fa', 'mfa', 'otp', 'verify', 'two-factor']):
                    found_endpoints.append(url)
        
        if not found_endpoints:
            await event_manager.emit("log", f"[{self.name}] No 2FA endpoints identified. Scan complete.")
            return
        
        await event_manager.emit("log", f"[{self.name}] Found {len(found_endpoints)} potential 2FA endpoints.")
        
        for endpoint in found_endpoints[:5]:
            await self.check_token_leakage(endpoint)
            await self.check_response_manipulation(endpoint)
            await self.check_rate_limiting(endpoint)
            await self.check_direct_access_bypass(endpoint)
        
        await event_manager.emit("log", f"[{self.name}] Scan complete.")
    
    async def _endpoint_exists(self, url):
        """Check if an endpoint exists."""
        try:
            async with self.context.session.get(url, allow_redirects=True, timeout=10) as response:
                return response.status in [200, 302, 401, 403]
        except Exception:
            return False
    
    async def check_token_leakage(self, url):
        """Check if 2FA token is leaked in the response."""
        try:
            async with self.context.session.get(url, timeout=15) as response:
                text = await response.text()
                headers = dict(response.headers)
                
                # Check response body for token patterns
                token_patterns = [
                    (r'otp["\s:=]+["\']?(\d{4,8})["\']?', "OTP in response body"),
                    (r'code["\s:=]+["\']?(\d{4,8})["\']?', "Code in response body"),
                    (r'token["\s:=]+["\']?([a-zA-Z0-9]{6,})["\']?', "Token in response body"),
                    (r'verification[-_]?code["\s:=]+["\']?(\d{4,8})["\']?', "Verification code in response"),
                ]
                
                for pattern, description in token_patterns:
                    match = re.search(pattern, text, re.IGNORECASE)
                    if match:
                        await self.emit_vulnerability(
                            "2FA Bypass",
                            f"2FA token potentially leaked in response.\n{description}\nMatch: {match.group(0)[:50]}...",
                            severity="P1",
                            remediation="Never include 2FA tokens or OTPs in HTTP responses. Tokens should only be sent via secure side channels (SMS, email, authenticator app).",
                            url=url,
                            payload=description
                        )
                        return
                
                # Check response headers for token leakage
                sensitive_headers = ['x-otp', 'x-code', 'x-token', 'x-verification']
                for header in headers:
                    if any(sh in header.lower() for sh in sensitive_headers):
                        await self.emit_vulnerability(
                            "2FA Bypass",
                            f"2FA token leaked in response header.\nHeader: {header}: {headers[header][:20]}...",
                            severity="P1",
                            remediation="Never expose 2FA tokens in HTTP headers.",
                            url=url,
                            payload=f"{header} header"
                        )
                        return
        except Exception:
            pass
    
    async def check_response_manipulation(self, url):
        """Check for response manipulation vulnerabilities."""
        try:
            # Submit a fake 2FA code
            async with self.context.session.post(
                url, 
                data={"code": "000000", "otp": "000000", "token": "000000"},
                timeout=15
            ) as response:
                text = await response.text()
                
                # Look for boolean responses that could be manipulated
                manipulation_patterns = [
                    (r'"success"\s*:\s*false', "success: false -> true"),
                    (r'"verified"\s*:\s*false', "verified: false -> true"),
                    (r'"valid"\s*:\s*false', "valid: false -> true"),
                    (r'"passed"\s*:\s*false', "passed: false -> true"),
                ]
                
                for pattern, description in manipulation_patterns:
                    if re.search(pattern, text, re.IGNORECASE):
                        await self.emit_vulnerability(
                            "2FA Bypass",
                            f"2FA response contains manipulatable field.\nPattern: {description}\nIf client-side validation is used, this could be bypassed.",
                            severity="P2",
                            remediation="Always validate 2FA server-side. Never trust client responses for security decisions.",
                            url=url,
                            payload=description
                        )
                        return
                
                # Check for status code manipulation vulnerability
                if response.status in [401, 403]:
                    await self.emit_vulnerability(
                        "2FA Bypass",
                        f"2FA endpoint returns {response.status} status.\nIf only status code is checked client-side, manipulation to 200 may bypass 2FA.",
                        severity="P3",
                        remediation="Don't rely solely on HTTP status codes for 2FA validation.",
                        url=url,
                        payload=f"Status: {response.status}"
                    )
        except Exception:
            pass
    
    async def check_rate_limiting(self, url):
        """Check if 2FA endpoint has rate limiting."""
        success_count = 0
        
        for _ in range(10):
            try:
                async with self.context.session.post(
                    url,
                    data={"code": "123456", "otp": "123456"},
                    timeout=10
                ) as response:
                    if response.status not in [429, 503]:
                        success_count += 1
            except Exception:
                pass
        
        if success_count >= 8:
            await self.emit_vulnerability(
                "2FA Bypass",
                f"2FA endpoint lacks rate limiting.\n{success_count}/10 requests succeeded without throttling.\nThis allows brute-forcing of 2FA codes.",
                severity="P2",
                remediation="Implement strict rate limiting on 2FA endpoints. Lock accounts after multiple failed attempts.",
                url=url,
                payload=f"{success_count}/10 requests accepted"
            )
    
    async def check_direct_access_bypass(self, url):
        """Check if post-2FA pages are directly accessible."""
        base_url = self.context.target.rstrip('/')
        
        # Common pages that should require 2FA
        protected_pages = [
            "/dashboard", "/account", "/settings", "/profile",
            "/admin", "/home", "/my-account"
        ]
        
        for page in protected_pages:
            test_url = f"{base_url}{page}"
            try:
                async with self.context.session.get(test_url, timeout=10) as response:
                    if response.status == 200:
                        text = await response.text()
                        # Check if it looks like an authenticated page
                        auth_indicators = ['logout', 'my account', 'settings', 'profile', 'dashboard']
                        if any(ind in text.lower() for ind in auth_indicators):
                            await self.emit_vulnerability(
                                "2FA Bypass",
                                f"Post-authentication page accessible without completing 2FA.\nURL: {test_url}",
                                severity="P1",
                                remediation="Ensure all protected pages verify 2FA completion server-side before rendering.",
                                url=test_url,
                                payload="Direct access bypass"
                            )
                            return
            except Exception:
                pass
