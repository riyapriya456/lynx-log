import asyncio
import re
from .base import BaseScanner
from common import TestingZone, event_manager


class CookieAttackScanner(BaseScanner):
    """
    Cookie Attack Scanner.
    
    Tests for cookie-related vulnerabilities:
    - Sensitive data in cookies
    - SQL injection via cookies
    - Privilege escalation via cookie manipulation
    - Session security issues
    """
    
    def __init__(self, context):
        super().__init__(context)
        self.zone = TestingZone.ZONE_B
        self.name = "CookieAttackScanner"
        
    async def run(self):
        await event_manager.emit("log", f"[{self.name}] Starting Cookie Attack scan...")
        
        # Load payloads
        attack_payloads = self.load_payloads("cookie/attacks.txt", limit=20)
        
        if not attack_payloads:
            attack_payloads = [
                "' OR 1=1--", "admin=true", "role=admin", "isAdmin=1"
            ]
        
        urls_to_scan = self.context.crawled_urls if self.context.crawled_urls else {self.context.target}
        
        # Check cookies from main target first
        await self.analyze_cookies(self.context.target)
        
        # Test cookie injection on sample URLs
        for url in list(urls_to_scan)[:10]:
            await self.test_cookie_sqli(url, attack_payloads)
            await self.test_privilege_escalation(url)
        
        await event_manager.emit("log", f"[{self.name}] Scan complete.")
    
    async def analyze_cookies(self, url):
        """Analyze cookies for sensitive data and security issues."""
        try:
            async with self.context.session.get(url, timeout=15) as response:
                # Get Set-Cookie headers
                set_cookies = response.headers.getall('Set-Cookie', [])
                
                for cookie_header in set_cookies:
                    await self._check_cookie_security(url, cookie_header)
                    await self._check_sensitive_data(url, cookie_header)
                    
        except Exception:
            pass
    
    async def _check_cookie_security(self, url, cookie_header):
        """Check cookie security attributes."""
        cookie_lower = cookie_header.lower()
        
        # Check for missing HttpOnly on session cookies
        if any(x in cookie_lower for x in ['session', 'auth', 'token', 'jwt']):
            if 'httponly' not in cookie_lower:
                await self.emit_vulnerability(
                    "Cookie Security",
                    f"Session cookie missing HttpOnly flag.\nCookie: {cookie_header[:100]}...",
                    severity="P4",
                    remediation="Set HttpOnly flag on all session cookies to prevent XSS-based theft.",
                    url=url,
                    payload="Missing HttpOnly",
                    confidence=0.68,
                    observed_behavior="Session-like cookie is readable by client-side script.",
                    verification="heuristic",
                    reproduction_steps=[
                        "Inspect the Set-Cookie header for the affected response.",
                        "Confirm the cookie is session-related and missing HttpOnly.",
                        "Retest after enabling HttpOnly and verify the warning no longer appears.",
                    ],
                )
            
            if 'secure' not in cookie_lower:
                await self.emit_vulnerability(
                    "Cookie Security",
                    f"Session cookie missing Secure flag.\nCookie: {cookie_header[:100]}...",
                    severity="P4",
                    remediation="Set Secure flag on all session cookies to prevent transmission over HTTP.",
                    url=url,
                    payload="Missing Secure",
                    confidence=0.7,
                    observed_behavior="Session-like cookie can be transmitted without TLS-only protection.",
                    verification="direct",
                    reproduction_steps=[
                        "Inspect the Set-Cookie header for the affected response.",
                        "Confirm the cookie is session-related and missing Secure.",
                        "Retest over HTTPS after enabling Secure and confirm the header is fixed.",
                    ],
                )
    
    async def _check_sensitive_data(self, url, cookie_header):
        """Check for sensitive data in cookies."""
        # Extract cookie value
        cookie_match = re.match(r'^([^=]+)=([^;]*)', cookie_header)
        if not cookie_match:
            return
        
        cookie_name = cookie_match.group(1)
        cookie_value = cookie_match.group(2)
        
        # Check for sensitive patterns
        sensitive_patterns = [
            (r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b', "Email address"),
            (r'\b\d{3}[-.]?\d{3}[-.]?\d{4}\b', "Phone number"),
            (r'\b\d{9}\b', "Potential SSN"),
            (r'\b(?:password|passwd|pwd)\s*[=:]\s*\S+', "Password"),
            (r'eyJ[A-Za-z0-9_-]*\.eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*', "JWT Token"),
        ]
        
        for pattern, description in sensitive_patterns:
            if re.search(pattern, cookie_value, re.IGNORECASE):
                await self.emit_vulnerability(
                    "Cookie Attack",
                    f"Sensitive data found in cookie.\nCookie: {cookie_name}\nData type: {description}",
                    severity="P2",
                    remediation="Never store sensitive data in cookies. Use server-side sessions.",
                    url=url,
                    payload=f"{cookie_name}: {description}",
                    confidence=0.9,
                    observed_behavior=f"Cookie value matches {description.lower()} pattern.",
                    verification="direct",
                    reproduction_steps=[
                        "Inspect the cookie value in the response headers.",
                        "Confirm the sensitive pattern is present in cleartext.",
                        "Rotate any exposed credentials or identifiers if applicable.",
                    ],
                )
                return
        
        # Check for overly long cookies (potential buffer overflow)
        if len(cookie_value) > 4000:
            await self.emit_vulnerability(
                "Cookie Attack",
                f"Unusually large cookie detected.\nCookie: {cookie_name}\nLength: {len(cookie_value)} bytes",
                severity="P4",
                remediation="Limit cookie sizes. Consider using server-side sessions.",
                url=url,
                payload=f"{cookie_name}: {len(cookie_value)} bytes",
                confidence=0.55,
                observed_behavior="Cookie size is unusually large but not inherently exploitable.",
                verification="heuristic",
            )
    
    async def test_cookie_sqli(self, url, payloads):
        """Test for SQL injection via cookie values."""
        sql_errors = [
            "sql syntax", "mysql_fetch", "ORA-", "postgresql", 
            "sqlite", "syntax error", "unclosed quotation"
        ]
        
        for payload in payloads[:10]:
            if not any(x in payload for x in ["'", '"', "--", "OR"]):
                continue  # Skip non-SQLi payloads
            
            try:
                # Set malicious cookie
                cookies = {"test": payload, "session": payload}
                async with self.context.session.get(
                    url, cookies=cookies, timeout=10
                ) as response:
                    text = await response.text()
                    
                    if any(err.lower() in text.lower() for err in sql_errors):
                        await self.emit_vulnerability(
                            "SQL Injection",
                            f"SQL injection via cookie parameter.\nPayload: {payload}",
                            severity="P1",
                            remediation="Validate and sanitize cookie values. Use parameterized queries.",
                            url=url,
                            payload=f"Cookie: {payload}",
                            confidence=0.95,
                            observed_behavior="Database error markers returned after cookie payload injection.",
                            verification="direct",
                            reproduction_steps=[
                                "Send the request with the recorded cookie payload.",
                                "Confirm the response contains SQL error markers.",
                                "Retest against a clean cookie baseline.",
                            ],
                        )
                        return
            except Exception:
                pass
    
    async def test_privilege_escalation(self, url):
        """Test for privilege escalation via cookie manipulation."""
        escalation_cookies = [
            {"admin": "1"},
            {"admin": "true"},
            {"role": "admin"},
            {"isAdmin": "true"},
            {"user_type": "administrator"},
            {"access_level": "admin"},
            {"privileges": "admin"},
        ]
        
        # First, get baseline response
        try:
            async with self.context.session.get(url, timeout=10) as response:
                baseline_text = await response.text()
                baseline_status = response.status
        except Exception:
            return
        
        for cookies in escalation_cookies:
            try:
                async with self.context.session.get(
                    url, cookies=cookies, timeout=10
                ) as response:
                    text = await response.text()
                    
                    # Check if response changed to include admin content
                    admin_indicators = [
                        'admin panel', 'administrator', 'manage users',
                        'admin dashboard', 'delete user', 'user management'
                    ]
                    
                    # Check if new admin content appeared
                    for indicator in admin_indicators:
                        if indicator in text.lower() and indicator not in baseline_text.lower():
                            cookie_str = ', '.join(f"{k}={v}" for k, v in cookies.items())
                            await self.emit_vulnerability(
                                "Cookie Attack",
                                f"Cookie manipulation grants elevated access.\nCookie: {cookie_str}\nAdmin content appeared in response.",
                                severity="P2",
                                remediation="Never trust cookie values for authorization. Implement server-side session validation.",
                                url=url,
                                payload=cookie_str,
                                confidence=0.72,
                                observed_behavior="Admin-like content appears after cookie tampering.",
                                verification="heuristic",
                                reproduction_steps=[
                                    "Load the page with a normal session and capture baseline content.",
                                    "Replay the request with the modified cookie values.",
                                    "Confirm only privileged content appears after server-side validation is fixed.",
                                ],
                            )
                            return
            except Exception:
                pass
