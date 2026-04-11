import asyncio
import urllib.parse
import re
from .base import BaseScanner
from common import TestingZone, event_manager


class IDORScanner(BaseScanner):
    """
    Insecure Direct Object Reference (IDOR) Scanner.
    
    Detects IDOR vulnerabilities by manipulating numeric and string IDs
    in URL parameters and checking for unauthorized data access.
    """
    
    def __init__(self, context):
        super().__init__(context)
        self.zone = TestingZone.ZONE_B
        self.name = "IDORScanner"
        
        # Parameters commonly vulnerable to IDOR
        self.idor_params = [
            "id", "user_id", "userid", "uid", "account", "account_id",
            "doc", "document", "file", "order", "order_id", "profile",
            "report", "invoice", "item", "product", "record", "ticket",
            "message", "msg", "comment", "review", "post", "article",
            "no", "number", "ref", "reference", "key", "token"
        ]
        
        # Indicators of sensitive data exposure
        self.sensitive_patterns = [
            r"email[\"\']?\s*[:=]\s*[\"\']?[\w\.-]+@[\w\.-]+",
            r"password[\"\']?\s*[:=]",
            r"ssn[\"\']?\s*[:=]",
            r"credit[_\s]?card",
            r"phone[\"\']?\s*[:=]\s*[\"\']?[\d\-\+\(\)\s]+",
            r"address[\"\']?\s*[:=]",
            r"dob[\"\']?\s*[:=]",
            r"birth[\"\']?\s*[:=]",
            r"salary[\"\']?\s*[:=]",
            r"bank[\"\']?\s*[:=]",
            r"api[_\s]?key",
            r"secret",
            r"token[\"\']?\s*[:=]",
        ]

    async def run(self):
        await event_manager.emit("log", f"[{self.name}] Starting IDOR scan...")
        
        urls_to_scan = self.context.crawled_urls if self.context.crawled_urls else {self.context.target}
        tasks = []
        
        for url in urls_to_scan:
            parsed = urllib.parse.urlparse(url)
            params = urllib.parse.parse_qs(parsed.query)
            
            for param, values in params.items():
                param_lower = param.lower()
                
                # Check if parameter looks like an ID
                if any(idor_p in param_lower for idor_p in self.idor_params):
                    original_value = values[0] if values else ""
                    
                    # Generate IDOR test values
                    test_values = self.generate_idor_values(original_value)
                    
                    for test_value in test_values:
                        tasks.append(self.check_idor(url, param, original_value, test_value))
                
                # Also check numeric values even if param name doesn't match
                elif values and values[0].isdigit():
                    original_value = values[0]
                    test_values = self.generate_idor_values(original_value)
                    
                    for test_value in test_values:
                        tasks.append(self.check_idor(url, param, original_value, test_value))
        
        # Process in chunks
        chunk_size = 5
        for i in range(0, len(tasks), chunk_size):
            await asyncio.gather(*tasks[i:i+chunk_size])
        
        await event_manager.emit("log", f"[{self.name}] Scan complete.")

    def generate_idor_values(self, original_value):
        """Generate test values for IDOR testing."""
        test_values = []
        
        if original_value.isdigit():
            num = int(original_value)
            # Adjacent values
            test_values.extend([str(num + 1), str(num - 1)])
            # Common IDs
            test_values.extend(["1", "2", "0", "100", "1000", "999"])
            # Negative
            test_values.append("-1")
        else:
            # For string IDs, try common admin/test values
            test_values.extend(["admin", "root", "test", "user", "1", "0"])
            # Try parent directory traversal for file-like IDs
            if "/" in original_value or "\\" in original_value:
                test_values.append("../../../etc/passwd")
                test_values.append("..\\..\\..\\windows\\win.ini")
        
        return test_values

    async def check_idor(self, original_url, param, original_value, test_value):
        """Check for IDOR by comparing responses with different ID values."""
        try:
            # Get original response first
            async with self.context.session.get(original_url, timeout=10) as original_response:
                original_text = await original_response.text()
                original_status = original_response.status
            
            # Build test URL with modified parameter
            parsed = urllib.parse.urlparse(original_url)
            params = urllib.parse.parse_qs(parsed.query)
            params[param] = [test_value]
            new_query = urllib.parse.urlencode(params, doseq=True)
            test_url = urllib.parse.urlunparse((
                parsed.scheme, parsed.netloc, parsed.path,
                parsed.params, new_query, parsed.fragment
            ))
            
            async with self.context.session.get(test_url, timeout=10) as test_response:
                test_text = await test_response.text()
                test_status = test_response.status
            
            # Analyze for potential IDOR
            if test_status == 200 and original_status == 200:
                # Check if we got different content (potential data leakage)
                if test_text != original_text and len(test_text) > 100:
                    # Check for sensitive data patterns in the response
                    for pattern in self.sensitive_patterns:
                        if re.search(pattern, test_text, re.IGNORECASE):
                            await self.emit_vulnerability(
                                "Potential IDOR",
                                f"Different data returned for ID={test_value} vs ID={original_value}. Sensitive pattern detected.",
                                severity="P2",
                                remediation="Implement proper authorization checks. Verify user ownership of requested resources. Use indirect references.",
                                url=test_url,
                                payload=f"{param}={test_value}",
                                confidence=0.76,
                                observed_behavior="Changing the object reference altered the response content and exposed sensitive-looking data.",
                                verification="heuristic",
                                reproduction_steps=[
                                    f"Request the original object using {param}={original_value}.",
                                    f"Repeat with {param}={test_value}.",
                                    "Confirm the response includes data from another account before treating it as a confirmed IDOR.",
                                ],
                            )
                            return
                    
                    # Even without sensitive patterns, report if content differs significantly
                    len_diff = abs(len(test_text) - len(original_text))
                    if len_diff > 500 or (len_diff > 100 and test_value in ["1", "2", "admin"]):
                        await self.emit_vulnerability(
                            "Potential IDOR",
                            f"Response content differs significantly when accessing {param}={test_value}",
                            severity="P3",
                            remediation="Implement proper authorization checks. Verify user ownership of requested resources.",
                            url=test_url,
                            payload=f"{param}={test_value}",
                            confidence=0.55,
                            observed_behavior="Response length changed significantly after ID mutation, but sensitive data was not confirmed.",
                            verification="heuristic",
                        )
                        
        except asyncio.TimeoutError:
            pass
        except Exception:
            pass
