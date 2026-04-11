import asyncio
import re
from .base import BaseScanner
from common import TestingZone, event_manager


class CSRFScanner(BaseScanner):
    """
    Cross-Site Request Forgery (CSRF) Scanner.
    
    Detects CSRF vulnerabilities by analyzing forms for missing tokens,
    checking cookie security attributes, and validating anti-CSRF measures.
    """
    
    def __init__(self, context):
        super().__init__(context)
        self.zone = TestingZone.ZONE_B
        self.name = "CSRFScanner"
        
        # Common CSRF token field names
        self.csrf_token_names = [
            "csrf", "csrf_token", "csrftoken", "_csrf", "_token",
            "authenticity_token", "token", "xsrf", "xsrf_token",
            "__RequestVerificationToken", "anti-csrf-token",
            "csrf-param", "csrf_name", "csrf_value", "_csrftoken"
        ]
        
        # Form actions that are security-sensitive
        self.sensitive_actions = [
            "login", "logout", "register", "signup", "password",
            "profile", "settings", "account", "admin", "delete",
            "update", "edit", "submit", "transfer", "payment",
            "checkout", "order", "cart", "api"
        ]

    async def run(self):
        await event_manager.emit("log", f"[{self.name}] Starting CSRF scan...")
        
        urls_to_scan = self.context.crawled_urls if self.context.crawled_urls else {self.context.target}
        tasks = []
        
        for url in urls_to_scan:
            tasks.append(self.check_csrf(url))
        
        # Also check the main target
        if self.context.target not in urls_to_scan:
            tasks.append(self.check_csrf(self.context.target))
        
        # Process in chunks
        chunk_size = 10
        for i in range(0, len(tasks), chunk_size):
            await asyncio.gather(*tasks[i:i+chunk_size])
        
        await event_manager.emit("log", f"[{self.name}] Scan complete.")

    async def check_csrf(self, url):
        """Check a URL for CSRF vulnerabilities."""
        try:
            async with self.context.session.get(url, timeout=15) as response:
                text = await response.text()
                cookies = response.cookies
                
                # Check for forms without CSRF tokens
                await self.check_forms_for_csrf(url, text)
                
                # Check cookie security attributes
                await self.check_cookie_security(url, response.headers)
                
        except asyncio.TimeoutError:
            pass
        except Exception:
            pass

    async def check_forms_for_csrf(self, url, html_content):
        """Analyze forms for missing CSRF tokens."""
        # Find all forms
        form_pattern = r'<form[^>]*>(.*?)</form>'
        forms = re.findall(form_pattern, html_content, re.IGNORECASE | re.DOTALL)
        
        for form in forms:
            # Check if form method is POST (CSRF mainly affects POST)
            method_match = re.search(r'method\s*=\s*["\']?(post)["\']?', form, re.IGNORECASE)
            if not method_match:
                # Also check the opening form tag
                form_tag_match = re.search(r'<form[^>]*method\s*=\s*["\']?(post)["\']?', 
                                          html_content, re.IGNORECASE)
                if not form_tag_match:
                    continue  # Skip GET forms
            
            # Check if form action is security-sensitive
            action_match = re.search(r'action\s*=\s*["\']?([^"\'>\s]+)', form, re.IGNORECASE)
            action = action_match.group(1) if action_match else ""
            
            is_sensitive = any(sens in action.lower() or sens in url.lower() 
                             for sens in self.sensitive_actions)
            
            # Look for CSRF token in hidden inputs
            has_csrf_token = False
            for token_name in self.csrf_token_names:
                token_pattern = rf'name\s*=\s*["\']?{re.escape(token_name)}["\']?'
                if re.search(token_pattern, form, re.IGNORECASE):
                    has_csrf_token = True
                    break
            
            # Also check for token in input type="hidden"
            if not has_csrf_token:
                hidden_inputs = re.findall(
                    r'<input[^>]*type\s*=\s*["\']?hidden["\']?[^>]*>',
                    form, re.IGNORECASE
                )
                for hidden in hidden_inputs:
                    for token_name in self.csrf_token_names:
                        if token_name.lower() in hidden.lower():
                            has_csrf_token = True
                            break
            
            # Report if no CSRF token found on sensitive form
            if not has_csrf_token and is_sensitive:
                await self.emit_vulnerability(
                    "CSRF Missing",
                    f"POST form missing CSRF token. Form action: {action or 'current page'}",
                    severity="P2",
                    remediation="Implement anti-CSRF tokens in all state-changing forms. Use SameSite cookie attribute.",
                    url=url,
                    payload="Missing CSRF token in form",
                    confidence=0.82,
                    observed_behavior="Sensitive POST form has no obvious anti-CSRF token.",
                    verification="heuristic",
                    reproduction_steps=[
                        "Open the affected POST form.",
                        "Inspect the form HTML for a CSRF token field.",
                        "Submit the form from a third-party origin and confirm the request is rejected after remediation.",
                    ],
                )

    async def check_cookie_security(self, url, headers):
        """Check if cookies have proper security attributes for CSRF protection."""
        set_cookie = headers.get('Set-Cookie', '')
        
        if set_cookie:
            # Check for session cookies without SameSite
            if 'session' in set_cookie.lower() or 'auth' in set_cookie.lower():
                # Check SameSite attribute
                if 'samesite' not in set_cookie.lower():
                    await self.emit_vulnerability(
                        "Cookie Security",
                        "Session cookie missing SameSite attribute (CSRF protection)",
                        severity="P4",
                        remediation="Set SameSite=Strict or SameSite=Lax for session cookies.",
                        url=url,
                        payload="Missing SameSite cookie attribute",
                        confidence=0.68,
                        observed_behavior="Session-like cookie lacks SameSite protection.",
                        verification="heuristic",
                        reproduction_steps=[
                            "Load the page and inspect Set-Cookie headers.",
                            "Confirm the session cookie lacks SameSite.",
                            "Verify the cookie is sent in a cross-site request after remediation testing.",
                        ],
                    )
                elif 'samesite=none' in set_cookie.lower():
                    # SameSite=None requires Secure
                    if 'secure' not in set_cookie.lower():
                        await self.emit_vulnerability(
                            "Cookie Security",
                            "Cookie has SameSite=None without Secure attribute",
                            severity="P4",
                            remediation="When using SameSite=None, the Secure attribute must also be set.",
                            url=url,
                            payload="SameSite=None without Secure",
                            confidence=0.7,
                            observed_behavior="Cookie explicitly allows cross-site use without transport protection.",
                            verification="direct",
                            reproduction_steps=[
                                "Inspect Set-Cookie on the affected response.",
                                "Verify SameSite=None is present without Secure.",
                                "Retest after setting Secure and confirm the warning disappears.",
                            ],
                        )
