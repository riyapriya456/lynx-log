import asyncio
import os
import urllib.parse
from .base import BaseScanner
from common import TestingZone, event_manager


class OpenRedirectScanner(BaseScanner):
    """
    Open Redirect Vulnerability Scanner.
    
    Detects open redirect vulnerabilities by:
    1. Injecting google.com URLs into redirect parameters
    2. Checking for redirect response (301/302/303/307/308)
    3. Verifying with Selenium that redirect actually works
    """
    
    def __init__(self, context):
        super().__init__(context)
        self.zone = TestingZone.ZONE_A
        self.name = "OpenRedirectScanner"
        self.selenium_driver = None
        
        # Parameters commonly used for redirects
        self.redirect_params = [
            "url", "redirect", "next", "target", "rurl", "dest",
            "destination", "redir", "redirect_uri", "redirect_url",
            "return", "return_url", "returnurl", "go", "goto", "out",
            "continue", "forward", "to", "uri", "link"
        ]
        
        # Use google.com as verifiable redirect target
        self.payloads = [
            "https://www.google.com",
            "https://google.com",
            "//google.com",
            "///google.com",
            "////google.com",
            "https://www.google.com/",
            "//www.google.com",
            "https://google.com%00",
            "https://google.com%0d%0a",
            "https://legitimate.com@google.com",
            "https://google.com\\legitimate.com",
            "https%3A%2F%2Fgoogle.com",
            "//google.com/%2f..",
        ]
        
        # Potential redirect vulnerabilities found (to verify with Selenium)
        self.potential_redirects = []

    async def run(self):
        await event_manager.emit("log", f"[{self.name}] Starting Open Redirect scan...")
        
        urls_to_scan = self.context.crawled_urls if self.context.crawled_urls else {self.context.target}
        tasks = []
        
        for url in urls_to_scan:
            parsed = urllib.parse.urlparse(url)
            params = urllib.parse.parse_qs(parsed.query)
            
            # Check existing parameters that look like redirect params
            for param in params:
                if param.lower() in self.redirect_params:
                    for payload in self.payloads[:8]:
                        tasks.append(self.check_redirect(url, param, payload))
            
            # Also try adding common redirect parameters if none found
            if not any(p.lower() in self.redirect_params for p in params):
                for redirect_param in self.redirect_params[:3]:
                    for payload in self.payloads[:5]:
                        test_url = f"{url}{'&' if '?' in url else '?'}{redirect_param}={urllib.parse.quote(payload)}"
                        tasks.append(self.check_redirect_direct(test_url, payload))
        
        # Process in chunks
        chunk_size = 6
        for i in range(0, len(tasks), chunk_size):
            await asyncio.gather(*tasks[i:i+chunk_size])
        
        # Verify potential redirects with Selenium
        if self.potential_redirects:
            await event_manager.emit("log", f"[{self.name}] Verifying {len(self.potential_redirects)} potential redirects with Selenium...")
            await self.verify_with_selenium()
        
        await event_manager.emit("log", f"[{self.name}] Scan complete.")

    async def check_redirect(self, original_url, param, payload):
        """Check for open redirect by replacing a parameter value."""
        try:
            parsed = urllib.parse.urlparse(original_url)
            params = urllib.parse.parse_qs(parsed.query)
            params[param] = [payload]
            new_query = urllib.parse.urlencode(params, doseq=True)
            test_url = urllib.parse.urlunparse((
                parsed.scheme, parsed.netloc, parsed.path,
                parsed.params, new_query, parsed.fragment
            ))
            
            await self.check_redirect_direct(test_url, payload)
        except Exception:
            pass

    async def check_redirect_direct(self, url, payload):
        """Make request and check for redirect behavior."""
        try:
            async with self.context.session.get(url, allow_redirects=False, timeout=10) as response:
                status = response.status
                location = response.headers.get('Location', '')
                
                # Check for redirect status codes
                if status in [301, 302, 303, 307, 308]:
                    if self._is_google_redirect(location):
                        # Store for Selenium verification
                        self.potential_redirects.append({
                            'url': url,
                            'payload': payload,
                            'location': location,
                            'status': status
                        })
                        await event_manager.emit("log", f"[{self.name}] Potential redirect found: {url[:60]}...")
                        return
                
                # Check for meta refresh or JavaScript redirects
                if status == 200:
                    text = await response.text()
                    text_lower = text.lower()
                    
                    # Check meta refresh
                    if 'google.com' in text_lower and ('http-equiv="refresh"' in text_lower or 'meta refresh' in text_lower):
                        self.potential_redirects.append({
                            'url': url,
                            'payload': payload,
                            'location': 'meta-refresh',
                            'status': 200
                        })
                    
                    # Check JavaScript redirects
                    elif 'google.com' in text_lower and ('location.href' in text_lower or 'window.location' in text_lower):
                        self.potential_redirects.append({
                            'url': url,
                            'payload': payload,
                            'location': 'javascript',
                            'status': 200
                        })
                        
        except asyncio.TimeoutError:
            pass
        except Exception:
            pass

    def _is_google_redirect(self, location):
        """Check if the redirect location points to google.com."""
        if not location:
            return False
        
        location_lower = location.lower()
        
        # Check for google.com in various forms
        google_patterns = ['google.com', 'www.google.com', '//google.com']
        return any(pattern in location_lower for pattern in google_patterns)

    async def verify_with_selenium(self):
        """Verify potential redirects using Selenium."""
        try:
            from selenium import webdriver
            from selenium.webdriver.chrome.options import Options
            from selenium.webdriver.chrome.service import Service
            from selenium.webdriver.support.ui import WebDriverWait
            from selenium.webdriver.support import expected_conditions as EC
            
            # Setup headless Chrome
            options = Options()
            options.add_argument("--headless=new")
            options.add_argument("--no-sandbox")
            options.add_argument("--disable-dev-shm-usage")
            options.add_argument("--disable-gpu")
            options.add_argument("--window-size=1280,720")
            options.add_argument("--ignore-certificate-errors")
            
            try:
                driver = webdriver.Chrome(options=options)
                driver.set_page_load_timeout(15)
            except Exception as e:
                await event_manager.emit("log", f"[{self.name}] Selenium not available, skipping verification: {e}")
                # Report without Selenium verification but note it's unverified
                for redirect in self.potential_redirects[:3]:
                    await self.emit_vulnerability(
                        "Open Redirect",
                        f"Potential open redirect detected (unverified).\n"
                        f"Status: {redirect['status']}\n"
                        f"Location: {redirect['location']}\n"
                        f"Note: Selenium verification failed, manual testing recommended.",
                        severity="P3",
                        remediation="Validate redirect URLs against an allowlist. Use relative URLs for redirects.",
                        url=redirect['url'],
                        payload=redirect['payload'],
                        confidence=0.58,
                        observed_behavior=f"Redirect response status {redirect['status']} with location {redirect['location']}",
                        reproduction_steps=[
                            f"Request {redirect['url']} with payload `{redirect['payload']}`.",
                            "Observe the Location header or meta refresh target.",
                            "Confirm the destination is not restricted to an allowlisted internal path.",
                        ],
                    )
                return
            
            verified_count = 0
            
            for redirect in self.potential_redirects[:5]:  # Limit Selenium checks
                try:
                    url = redirect['url']
                    await event_manager.emit("log", f"[{self.name}] Selenium verifying: {url[:50]}...")
                    
                    driver.get(url)
                    await asyncio.sleep(3)  # Wait for redirect without blocking the event loop
                    
                    current_url = driver.current_url.lower()
                    
                    # Check if we actually ended up at google.com
                    if 'google.com' in current_url:
                        verified_count += 1
                        await self.emit_vulnerability(
                            "Open Redirect",
                            f"VERIFIED: Browser redirected to Google.com\n"
                            f"Original Status: {redirect['status']}\n"
                            f"Final URL: {driver.current_url}",
                            severity="P2",  # Higher severity since verified
                            remediation="Validate redirect URLs against an allowlist. Use relative URLs for redirects.",
                            url=redirect['url'],
                            payload=redirect['payload'],
                            confidence=0.94,
                            observed_behavior=f"Browser navigated to {driver.current_url}",
                            reproduction_steps=[
                                f"Open {redirect['url']} with payload `{redirect['payload']}`.",
                                "Follow the redirect chain in a browser.",
                                "Confirm the browser lands on the attacker-controlled destination.",
                            ],
                        )
                        await event_manager.emit("log", f"[{self.name}] ✓ VERIFIED redirect to google.com")
                    else:
                        await event_manager.emit("log", f"[{self.name}] ✗ Redirect did not go to google.com (went to: {current_url[:50]})")
                        
                except Exception as e:
                    await event_manager.emit("log", f"[{self.name}] Selenium error: {e}")
            
            driver.quit()
            
            if verified_count == 0 and self.potential_redirects:
                await event_manager.emit("log", f"[{self.name}] No redirects verified by Selenium (false positives filtered)")
                
        except ImportError:
            await event_manager.emit("log", f"[{self.name}] Selenium not installed, reporting potential redirects as unverified")
            for redirect in self.potential_redirects[:3]:
                    await self.emit_vulnerability(
                        "Open Redirect",
                        f"Potential open redirect (unverified - Selenium not available).\n"
                        f"Status: {redirect['status']}\n"
                        f"Location: {redirect['location']}",
                        severity="P4",  # Lower severity since unverified
                        remediation="Validate redirect URLs against an allowlist.",
                        url=redirect['url'],
                        payload=redirect['payload'],
                        confidence=0.55,
                        observed_behavior=f"Redirect path {redirect['location']} returned status {redirect['status']}",
                    )
        except Exception as e:
            await event_manager.emit("log", f"[{self.name}] Selenium verification failed: {e}")

