import asyncio
import json
import urllib.parse
from bs4 import BeautifulSoup
from .base import BaseScanner
from common import TestingZone, event_manager


class MassAssignmentScanner(BaseScanner):
    """
    Mass Assignment Vulnerability Scanner.
    
    Tests for mass assignment/parameter binding vulnerabilities:
    - Adding admin/role parameters to registration
    - Privilege escalation via hidden parameters
    - Organization access escalation
    """
    
    def __init__(self, context):
        super().__init__(context)
        self.zone = TestingZone.ZONE_A
        self.name = "MassAssignmentScanner"
        
    async def run(self):
        await event_manager.emit("log", f"[{self.name}] Starting Mass Assignment scan...")
        
        # Load payloads
        params = self.load_payloads("mass_assignment/params.txt")
        values = self.load_payloads("mass_assignment/values.txt")
        
        if not params:
            params = ["admin", "isAdmin", "role", "user_type", "privilege", "permissions"]
        if not values:
            values = ["true", "1", "admin", "administrator"]
        
        # Find registration/update forms
        forms = await self._find_update_forms()
        
        if not forms:
            await event_manager.emit("log", f"[{self.name}] No registration/update forms found. Scan complete.")
            return
        
        await event_manager.emit("log", f"[{self.name}] Found {len(forms)} forms. Testing mass assignment...")
        
        for form in forms[:5]:
            await self.test_form_mass_assignment(form, params, values)
            await self.test_json_mass_assignment(form, params, values)
        
        await event_manager.emit("log", f"[{self.name}] Scan complete.")
    
    async def _find_update_forms(self):
        """Find registration, profile update, and similar forms."""
        forms = []
        urls_to_scan = self.context.crawled_urls if self.context.crawled_urls else {self.context.target}
        
        # Add common paths
        base_url = self.context.target.rstrip('/')
        additional_paths = [
            "/register", "/signup", "/create-account",
            "/profile", "/settings", "/account", "/update-profile",
            "/api/register", "/api/user", "/api/profile"
        ]
        
        for path in additional_paths:
            urls_to_scan.add(f"{base_url}{path}")
        
        for url in list(urls_to_scan)[:30]:
            try:
                async with self.context.session.get(url, timeout=15) as response:
                    if response.status != 200:
                        continue
                    
                    html = await response.text()
                    soup = BeautifulSoup(html, 'html.parser')
                    
                    for form in soup.find_all('form'):
                        action = form.get('action', '')
                        method = form.get('method', 'post').lower()
                        action_url = urllib.parse.urljoin(url, action) if action else url
                        
                        # Check if it looks like a registration/profile form
                        form_html = str(form).lower()
                        if any(x in form_html for x in ['register', 'signup', 'profile', 'update', 'account', 'user']):
                            inputs = form.find_all(['input', 'textarea', 'select'])
                            fields = {}
                            for inp in inputs:
                                name = inp.get('name')
                                if name:
                                    fields[name] = inp.get('value', 'test')
                            
                            if fields:
                                forms.append({
                                    'url': action_url,
                                    'source_url': url,
                                    'method': method,
                                    'fields': fields
                                })
            except Exception:
                pass
        
        return forms
    
    async def test_form_mass_assignment(self, form, params, values):
        """Test form-based mass assignment."""
        url = form['url']
        
        for param in params[:10]:
            for value in values[:3]:
                # Add the parameter to the form data
                data = form['fields'].copy()
                data[param] = value
                
                try:
                    if form['method'] == 'post':
                        async with self.context.session.post(
                            url, data=data, allow_redirects=True, timeout=15
                        ) as response:
                            text = await response.text()
                            
                            # Check if the parameter was accepted
                            if response.status in [200, 201, 302]:
                                # Look for indications that it worked
                                if self._check_escalation_indicators(text, param, value):
                                    await self.emit_vulnerability(
                                        "Mass Assignment",
                                        f"Server accepted privilege escalation parameter.\nParameter: {param}={value}",
                                        severity="P1",
                                        remediation="Whitelist allowed parameters. Never auto-bind user input to data models.",
                                        url=form['source_url'],
                                        payload=f"{param}={value}"
                                    )
                                    return
                except Exception:
                    pass
    
    async def test_json_mass_assignment(self, form, params, values):
        """Test JSON-based mass assignment."""
        url = form['url']
        headers = {"Content-Type": "application/json"}
        
        # Convert form fields to JSON
        base_json = {k: 'test' for k in form['fields'].keys()}
        
        for param in params[:10]:
            for value in values[:3]:
                # Add the parameter to JSON
                payload = base_json.copy()
                payload[param] = value if value not in ['true', 'false'] else (value == 'true')
                
                try:
                    async with self.context.session.post(
                        url, json=payload, headers=headers, timeout=15
                    ) as response:
                        text = await response.text()
                        
                        if response.status in [200, 201]:
                            try:
                                resp_json = json.loads(text)
                                resp_str = json.dumps(resp_json).lower()
                                
                                # Check if our parameter appears in response
                                if param.lower() in resp_str:
                                    await self.emit_vulnerability(
                                        "Mass Assignment",
                                        f"JSON API accepted privilege parameter.\nParameter: {param}",
                                        severity="P1",
                                        remediation="Use DTOs or explicit field mapping. Never auto-bind JSON to models.",
                                        url=form['source_url'],
                                        payload=json.dumps({param: value})
                                    )
                                    return
                            except json.JSONDecodeError:
                                pass
                except Exception:
                    pass
    
    def _check_escalation_indicators(self, text, param, value):
        """Check if response indicates privilege escalation."""
        text_lower = text.lower()
        param_lower = param.lower()
        value_lower = str(value).lower()
        
        # Check if parameter appears in response
        if param_lower in text_lower and value_lower in text_lower:
            return True
        
        # Check for admin-related content
        admin_indicators = ['admin dashboard', 'administrator', 'full access', 'elevated privileges']
        if any(ind in text_lower for ind in admin_indicators):
            return True
        
        return False
