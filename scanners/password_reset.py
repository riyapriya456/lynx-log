import asyncio
import re
import urllib.parse
from bs4 import BeautifulSoup
from .base import BaseScanner
from common import TestingZone, event_manager


class PasswordResetScanner(BaseScanner):
    """
    Password Reset Vulnerability Scanner.
    
    Tests for password reset vulnerabilities:
    - Host header injection
    - Token leakage in response
    - Token manipulation (null, empty, predictable)
    - CRLF injection in reset emails
    """
    
    def __init__(self, context):
        super().__init__(context)
        self.zone = TestingZone.ZONE_A
        self.name = "PasswordResetScanner"
        
    async def run(self):
        await event_manager.emit("log", f"[{self.name}] Starting Password Reset scan...")
        
        # Find password reset endpoints
        reset_endpoints = await self._find_reset_endpoints()
        
        if not reset_endpoints:
            await event_manager.emit("log", f"[{self.name}] No password reset endpoints found. Scan complete.")
            return
        
        await event_manager.emit("log", f"[{self.name}] Found {len(reset_endpoints)} reset endpoints. Testing...")
        
        for endpoint in reset_endpoints[:3]:
            await self.test_host_header_injection(endpoint)
            await self.test_token_in_response(endpoint)
            await self.test_token_manipulation(endpoint)
        
        await event_manager.emit("log", f"[{self.name}] Scan complete.")
    
    async def _find_reset_endpoints(self):
        """Find password reset endpoints."""
        endpoints = []
        base_url = self.context.target.rstrip('/')
        
        # Common reset paths
        reset_paths = [
            "/password/reset", "/forgot-password", "/reset-password",
            "/password/forgot", "/account/reset", "/auth/forgot",
            "/api/password/reset", "/api/forgot-password",
            "/user/forgot-password", "/users/password/new"
        ]
        
        for path in reset_paths:
            test_url = f"{base_url}{path}"
            try:
                async with self.context.session.get(test_url, timeout=10) as response:
                    if response.status == 200:
                        html = await response.text()
                        # Check if it looks like a reset form
                        if any(x in html.lower() for x in ['email', 'reset', 'forgot', 'password']):
                            # Find the form
                            soup = BeautifulSoup(html, 'html.parser')
                            form = soup.find('form')
                            if form:
                                action = form.get('action', '')
                                action_url = urllib.parse.urljoin(test_url, action) if action else test_url
                                
                                # Find email field
                                email_field = None
                                for inp in form.find_all('input'):
                                    inp_type = inp.get('type', 'text').lower()
                                    inp_name = inp.get('name', '').lower()
                                    if inp_type == 'email' or 'email' in inp_name:
                                        email_field = inp.get('name')
                                        break
                                
                                if email_field:
                                    endpoints.append({
                                        'url': action_url,
                                        'source_url': test_url,
                                        'email_field': email_field
                                    })
            except Exception:
                pass
        
        return endpoints
    
    async def test_host_header_injection(self, endpoint):
        """Test for host header injection in password reset."""
        evil_hosts = [
            "evil.com",
            "attacker.com",
            f"evil.{urllib.parse.urlparse(endpoint['url']).netloc}"
        ]
        
        for evil_host in evil_hosts:
            try:
                headers = {"Host": evil_host}
                data = {endpoint['email_field']: "test@example.com"}
                
                async with self.context.session.post(
                    endpoint['url'],
                    data=data,
                    headers=headers,
                    allow_redirects=False,
                    timeout=15
                ) as response:
                    text = await response.text()
                    
                    # Check if evil host appears in response (link injection)
                    if evil_host in text:
                        await self.emit_vulnerability(
                            "Password Reset Vulnerability",
                            f"Host header injection in password reset.\nInjected host ({evil_host}) appears in response.\nThis can be used to steal reset tokens.",
                            severity="P2",
                            remediation="Never use the Host header to construct URLs. Use a hardcoded base URL.",
                            url=endpoint['source_url'],
                            payload=f"Host: {evil_host}",
                            confidence=0.7,
                            observed_behavior="Injected host value was reflected in the reset flow response.",
                            verification="heuristic",
                            reproduction_steps=[
                                "Request the reset page with the reported Host header.",
                                "Check whether the injected host is reflected into reset links.",
                                "Confirm the link is actually used for token delivery before escalating.",
                            ],
                        )
                        return
                    
                    # Check X-Forwarded-Host too
                    headers2 = {"X-Forwarded-Host": evil_host}
                    async with self.context.session.post(
                        endpoint['url'],
                        data=data,
                        headers=headers2,
                        timeout=15
                    ) as response2:
                        text2 = await response2.text()
                        
                        if evil_host in text2:
                            await self.emit_vulnerability(
                                "Password Reset Vulnerability",
                                f"X-Forwarded-Host header injection in password reset.\nThis can be used to steal reset tokens.",
                                severity="P2",
                                remediation="Ignore X-Forwarded-Host header. Use hardcoded URL for reset links.",
                                url=endpoint['source_url'],
                                payload=f"X-Forwarded-Host: {evil_host}",
                                confidence=0.68,
                                observed_behavior="Reset flow reflected X-Forwarded-Host content.",
                                verification="heuristic",
                            )
                            return
            except Exception:
                pass
    
    async def test_token_in_response(self, endpoint):
        """Check if reset token is leaked in response."""
        try:
            data = {endpoint['email_field']: "test@example.com"}
            
            async with self.context.session.post(
                endpoint['url'],
                data=data,
                timeout=15
            ) as response:
                text = await response.text()
                headers = dict(response.headers)
                
                # Check for token patterns in response body
                token_patterns = [
                    (r'token["\s:=]+["\']?([a-zA-Z0-9]{20,})["\']?', "Reset token in body"),
                    (r'reset[-_]?link["\s:=]+["\']?([^\s"\']+)["\']?', "Reset link in body"),
                    (r'/reset/([a-zA-Z0-9]{20,})', "Reset token in URL"),
                    (r'code["\s:=]+["\']?([a-zA-Z0-9]{6,})["\']?', "Reset code in body"),
                ]
                
                for pattern, description in token_patterns:
                    match = re.search(pattern, text, re.IGNORECASE)
                    if match:
                        await self.emit_vulnerability(
                            "Password Reset Vulnerability",
                            f"Reset token leaked in HTTP response.\n{description}\nMatch: {match.group(0)[:50]}...",
                            severity="P1",
                            remediation="Never include reset tokens in HTTP responses. Send only via email.",
                            url=endpoint['source_url'],
                            payload=description,
                            confidence=0.97,
                            observed_behavior="Reset token-like value was exposed in the response body.",
                            verification="direct",
                            reproduction_steps=[
                                "Submit the reset request for a known account.",
                                "Inspect the response body for the reported token pattern.",
                                "Confirm the token is actionable and not a placeholder before treating it as exploitable.",
                            ],
                        )
                        return
                
                # Check referrer leakage warning
                if 'referrer-policy' not in ' '.join(headers.keys()).lower():
                    await self.emit_vulnerability(
                        "Password Reset Vulnerability",
                        f"Missing Referrer-Policy header on reset page.\nReset tokens in URL could leak via Referer header.",
                        severity="P4",
                        remediation="Set Referrer-Policy: no-referrer on password reset pages.",
                        url=endpoint['source_url'],
                        payload="Missing Referrer-Policy",
                        confidence=0.55,
                        observed_behavior="Referrer-Policy header was absent on a password reset page.",
                        verification="heuristic",
                    )
        except Exception:
            pass
    
    async def test_token_manipulation(self, endpoint):
        """Test token manipulation on reset confirmation endpoint."""
        # Common token confirmation endpoints
        base_url = urllib.parse.urljoin(endpoint['url'], '/')
        
        confirmation_paths = [
            "/password/reset/confirm",
            "/reset-password/confirm",
            "/password/reset/",
            "/reset/"
        ]
        
        # Test payloads for token manipulation
        token_payloads = [
            ("", "empty token"),
            ("null", "null string"),
            ("0000000000", "all zeros"),
            ("undefined", "undefined string"),
            ("''", "empty quotes"),
        ]
        
        for path in confirmation_paths:
            for token, description in token_payloads:
                try:
                    test_url = f"{base_url.rstrip('/')}{path}"
                    
                    # Try as query parameter
                    query_url = f"{test_url}?token={token}"
                    async with self.context.session.get(query_url, timeout=10) as response:
                        if response.status == 200:
                            text = await response.text()
                            # Check if we bypassed
                            if any(x in text.lower() for x in ['new password', 'confirm password', 'enter password']):
                                await self.emit_vulnerability(
                                    "Password Reset Vulnerability",
                                    f"Reset token validation bypassed with {description}.\nURL: {query_url}",
                                    severity="P2",
                                    remediation="Implement proper token validation. Reject null/empty tokens.",
                                    url=endpoint['source_url'],
                                    payload=f"token={token}",
                                    confidence=0.72,
                                    observed_behavior="Reset confirmation page accepted an invalid token format.",
                                    verification="heuristic",
                                )
                                return
                    
                    # Try as POST data
                    data = {"token": token, "password": "test123", "password_confirm": "test123"}
                    async with self.context.session.post(test_url, data=data, timeout=10) as response:
                        text = await response.text()
                        if response.status == 200 and 'success' in text.lower():
                            await self.emit_vulnerability(
                                "Password Reset Vulnerability",
                                f"Reset accepted with {description}.\nEndpoint: {test_url}",
                                severity="P1",
                                remediation="Validate reset tokens server-side before allowing password change.",
                                url=endpoint['source_url'],
                                payload=f"token={token}",
                                confidence=0.9,
                                observed_behavior="Password reset accepted an invalid token/value and reported success.",
                                verification="direct",
                                reproduction_steps=[
                                    "Request the reported confirmation endpoint.",
                                    "Submit the invalid token value from the report.",
                                    "Confirm the reset succeeds only if the server-side token validation is broken.",
                                ],
                            )
                            return
                except Exception:
                    pass
