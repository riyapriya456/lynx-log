import asyncio
import json
import re
from .base import BaseScanner
from common import TestingZone, event_manager


class JSONAttackScanner(BaseScanner):
    """
    JSON Attack Scanner.
    
    Tests various JSON-based attack techniques:
    - Type confusion (array, object, null, boolean)
    - JSON injection
    - Mass assignment via JSON
    - Authentication bypass via JSON manipulation
    """
    
    def __init__(self, context):
        super().__init__(context)
        self.zone = TestingZone.ZONE_A
        self.name = "JSONAttackScanner"
        
    async def run(self):
        await event_manager.emit("log", f"[{self.name}] Starting JSON Attack scan...")
        
        # Find JSON endpoints
        json_endpoints = await self._find_json_endpoints()
        
        if not json_endpoints:
            await event_manager.emit("log", f"[{self.name}] No JSON endpoints found. Scan complete.")
            return
        
        await event_manager.emit("log", f"[{self.name}] Found {len(json_endpoints)} JSON endpoints. Testing...")
        
        for endpoint in json_endpoints[:10]:
            await self.test_type_confusion(endpoint)
            await self.test_json_injection(endpoint)
            await self.test_mass_assignment(endpoint)
        
        await event_manager.emit("log", f"[{self.name}] Scan complete.")
    
    async def _find_json_endpoints(self):
        """Find endpoints that accept JSON."""
        endpoints = []
        base_url = self.context.target.rstrip('/')
        
        # Common API/JSON endpoints
        api_paths = [
            "/api/login", "/api/auth", "/api/user", "/api/register",
            "/api/v1/login", "/api/v1/auth", "/auth/login",
            "/login", "/signin", "/register", "/signup"
        ]
        
        for path in api_paths:
            test_url = f"{base_url}{path}"
            try:
                # Test if endpoint accepts JSON
                headers = {"Content-Type": "application/json"}
                async with self.context.session.post(
                    test_url, 
                    json={"test": "test"},
                    headers=headers,
                    timeout=10
                ) as response:
                    if response.status in [200, 201, 400, 401, 403, 422]:
                        content_type = response.headers.get('Content-Type', '')
                        text = await response.text()
                        
                        # Check if response is JSON
                        if 'json' in content_type.lower() or text.startswith('{') or text.startswith('['):
                            endpoints.append({
                                'url': test_url,
                                'accepts_json': True
                            })
            except Exception:
                pass
        
        # Also check crawled URLs
        urls_to_scan = self.context.crawled_urls if self.context.crawled_urls else set()
        for url in list(urls_to_scan)[:20]:
            if any(pattern in url.lower() for pattern in ['/api/', '.json', 'graphql']):
                endpoints.append({'url': url, 'accepts_json': True})
        
        return endpoints
    
    async def test_type_confusion(self, endpoint):
        """Test type confusion attacks."""
        url = endpoint['url']
        headers = {"Content-Type": "application/json"}
        
        # Type confusion payloads
        payloads = [
            # Null values
            ({"login": None, "password": None}, "null values"),
            # Boolean values
            ({"login": True, "password": True}, "boolean true"),
            ({"login": False, "password": False}, "boolean false"),
            # Array values
            ({"login": ["admin"], "password": ["password"]}, "array values"),
            # Nested objects
            ({"login": {"value": "admin"}, "password": {"value": "password"}}, "nested objects"),
            # Empty values
            ({"login": "", "password": ""}, "empty strings"),
            # Numeric values
            ({"login": 1, "password": 1}, "numeric values"),
            # Array wrapping
            ({"login": [["admin"]], "password": [["password"]]}, "nested arrays"),
        ]
        
        for payload, description in payloads:
            try:
                async with self.context.session.post(
                    url, json=payload, headers=headers, timeout=10
                ) as response:
                    text = await response.text()
                    
                    # Check for interesting responses
                    if response.status == 200:
                        # Successful login? Critical!
                        if any(ind in text.lower() for ind in ['success', 'token', 'authenticated', 'welcome']):
                            await self.emit_vulnerability(
                                "JSON Injection",
                                f"Type confusion may bypass authentication.\nPayload: {description}\nEndpoint returned success indicator.",
                                severity="P2",
                                remediation="Implement strict type validation on all JSON inputs. Reject unexpected types.",
                                url=url,
                                payload=json.dumps(payload),
                                confidence=0.66,
                                observed_behavior="JSON payload changed the response into a success-like state, but full auth bypass was not proven.",
                                verification="heuristic",
                                reproduction_steps=[
                                    "Send the reported JSON payload to the endpoint.",
                                    "Compare the response with a clean baseline request.",
                                    "Only escalate if the application actually grants access or issues a valid session.",
                                ],
                            )
                            return
                    
                    # Check for SQL errors (type confusion to SQLi)
                    sql_errors = ["sql", "syntax", "query", "mysql", "postgresql", "oracle"]
                    if any(err in text.lower() for err in sql_errors):
                        await self.emit_vulnerability(
                            "JSON Injection",
                            f"Type confusion causes SQL error.\nPayload: {description}",
                            severity="P3",
                            remediation="Validate JSON types before using in database queries.",
                            url=url,
                            payload=json.dumps(payload),
                            confidence=0.6,
                            observed_behavior="Server returned SQL error markers after type confusion input.",
                            verification="heuristic",
                        )
                        return
                        
            except Exception:
                pass
    
    async def test_json_injection(self, endpoint):
        """Test JSON injection attacks."""
        url = endpoint['url']
        headers = {"Content-Type": "application/json"}
        
        # JSON injection payloads
        payloads = [
            # SQL injection in JSON
            ({"login": "admin' OR '1'='1", "password": "x"}, "SQL injection in JSON"),
            ({"login": "admin\"--", "password": "x"}, "SQL injection with double quote"),
            # XSS in JSON
            ({"login": "<script>alert(1)</script>", "password": "x"}, "XSS in JSON"),
            # Command injection
            ({"login": "; ls", "password": "x"}, "Command injection in JSON"),
            # Template injection
            ({"login": "{{7*7}}", "password": "x"}, "Template injection"),
            ({"login": "${7*7}", "password": "x"}, "Expression language injection"),
        ]
        
        for payload, description in payloads:
            try:
                async with self.context.session.post(
                    url, json=payload, headers=headers, timeout=10
                ) as response:
                    text = await response.text()
                    
                    # SQL error detection
                    if any(err in text.lower() for err in ['sql', 'syntax', 'query error']):
                        await self.emit_vulnerability(
                            "SQL Injection",
                            f"SQL injection via JSON parameter.\nPayload: {description}",
                            severity="P1",
                            remediation="Use parameterized queries. Sanitize JSON inputs.",
                            url=url,
                            payload=json.dumps(payload),
                            confidence=0.93,
                            observed_behavior="Database error markers returned after JSON SQLi payload.",
                            verification="direct",
                        )
                        return
                    
                    # XSS reflection
                    if '<script>' in text and 'alert' in text:
                        await self.emit_vulnerability(
                            "Reflected XSS",
                            f"XSS payload reflected in JSON response.\nPayload: {description}",
                            severity="P3",
                            remediation="Encode output. Set proper Content-Type headers.",
                            url=url,
                            payload=json.dumps(payload),
                            confidence=0.7,
                            observed_behavior="XSS marker reflected in the JSON response body.",
                            verification="heuristic",
                            reproduction_steps=[
                                "Send the JSON payload to the endpoint.",
                                "Inspect the response body for the reflected script marker.",
                                "Verify whether the reflection is encoded before treating it as exploitable.",
                            ],
                        )
                        return
                    
                    # Template injection (check for 49 from 7*7)
                    if '49' in text and ('{{' in str(payload) or '${' in str(payload)):
                        await self.emit_vulnerability(
                            "Command Injection",
                            f"Template injection executed.\nPayload: {description}",
                            severity="P1",
                            remediation="Never pass user input directly to template engines.",
                            url=url,
                            payload=json.dumps(payload),
                            confidence=0.85,
                            observed_behavior="Template marker evaluated to 49 in the response.",
                            verification="direct",
                        )
                        return
                        
            except Exception:
                pass
    
    async def test_mass_assignment(self, endpoint):
        """Test mass assignment via JSON."""
        url = endpoint['url']
        headers = {"Content-Type": "application/json"}
        
        # Mass assignment payloads (add admin privileges)
        payloads = [
            ({"username": "test", "password": "test", "admin": True}, "admin: true"),
            ({"username": "test", "password": "test", "role": "admin"}, "role: admin"),
            ({"username": "test", "password": "test", "isAdmin": True}, "isAdmin: true"),
            ({"username": "test", "password": "test", "user_type": "administrator"}, "user_type: administrator"),
            ({"username": "test", "password": "test", "privilege": "admin"}, "privilege: admin"),
            ({"username": "test", "password": "test", "permissions": ["admin", "write", "read"]}, "permissions array"),
        ]
        
        for payload, description in payloads:
            try:
                async with self.context.session.post(
                    url, json=payload, headers=headers, timeout=10
                ) as response:
                    text = await response.text()
                    
                    # Check if the extra parameter was accepted
                    if response.status in [200, 201]:
                        try:
                            resp_json = json.loads(text)
                            # Check if admin field is in response
                            resp_str = json.dumps(resp_json).lower()
                            if any(x in resp_str for x in ['admin', 'role', 'privilege', 'permission']):
                                await self.emit_vulnerability(
                                    "Mass Assignment",
                                    f"Server accepts extra parameters that may escalate privileges.\nPayload: {description}",
                                    severity="P3",
                                    remediation="Whitelist allowed parameters. Never auto-bind user input to models.",
                                    url=url,
                                    payload=json.dumps(payload),
                                    confidence=0.58,
                                    observed_behavior="Extra JSON field was accepted, but privilege impact was not confirmed.",
                                    verification="heuristic",
                                )
                                return
                        except json.JSONDecodeError:
                            pass
                            
            except Exception:
                pass
