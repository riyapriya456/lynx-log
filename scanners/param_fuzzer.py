"""
Lynx VAPT - Parameter Fuzzing Engine

Discovers hidden parameters, JSON keys, and attack surfaces:
- Hidden form fields detection
- JSON keys discovery
- Nested objects fuzzing
- URL path variables detection
- Cookie values fuzzing
- Param Miner-style discovery

Author: Lynx Team
"""

import asyncio
import re
import json
from typing import Dict, List, Optional, Any, Set, Tuple
from dataclasses import dataclass, field
from urllib.parse import urljoin, urlparse, parse_qs, urlencode, urlunparse
from itertools import combinations

from scanners.base import BaseScanner
from common import event_manager, TestingZone


@dataclass
class DiscoveredParam:
    """A discovered parameter."""
    name: str
    source: str  # 'form', 'json', 'url', 'cookie', 'header'
    url: str
    original_value: Optional[str] = None
    discovered_via: str = ""
    is_sensitive: bool = False
    affects_response: bool = False


class ParamFuzzer(BaseScanner):
    """
    Parameter Fuzzing Engine.
    
    Discovers hidden parameters and attack surfaces using:
    - Common parameter wordlist
    - Response differential analysis
    - JSON structure fuzzing
    - Form field discovery
    - Cookie manipulation
    """
    
    # Common hidden parameters (Param Miner style)
    COMMON_PARAMS = [
        # Debug/development
        "debug", "test", "dev", "development", "staging", "prod",
        "verbose", "trace", "log", "logging", "profiler",
        
        # Authentication/Authorization
        "admin", "user", "role", "is_admin", "isAdmin", "privileged",
        "auth", "token", "api_key", "apikey", "access_token",
        "session", "sid", "uid", "user_id", "userId",
        
        # Common functionality
        "callback", "jsonp", "cb", "redirect", "url", "next", "return",
        "redir", "destination", "dest", "continue", "target",
        
        # Format/output
        "format", "output", "type", "mode", "action", "method",
        "template", "view", "page", "layout", "theme",
        
        # Filtering/sorting
        "sort", "order", "orderby", "sortby", "filter", "where",
        "limit", "offset", "page", "per_page", "pagesize",
        
        # SSRF/file related
        "file", "path", "include", "src", "source", "ref",
        "load", "read", "fetch", "get", "post",
        
        # Misc dangerous
        "exec", "execute", "cmd", "command", "run", "eval",
        "code", "data", "input", "query", "sql",
        "xml", "json", "config", "settings",
        "_", "__", "___",
        
        # Framework specific
        "_method", "__proto__", "constructor", "prototype",
        "class", "cls", "__class__",
    ]
    
    # Values to test for response differential
    TEST_VALUES = [
        "1", "true", "false", "null", "undefined",
        "admin", "root", "test", "debug",
        "../", "..\\", "${7*7}", "{{7*7}}",
        "<script>", "' OR '1'='1",
    ]
    
    # Sensitive parameter patterns
    SENSITIVE_PATTERNS = [
        r'password', r'passwd', r'pwd', r'secret', r'token',
        r'api[_-]?key', r'auth', r'credential', r'private',
        r'ssn', r'credit', r'card', r'account',
    ]
    
    def __init__(self, context):
        super().__init__(context)
        self.name = "ParamFuzzer"
        self.zone = TestingZone.ZONE_A
        self.discovered: List[DiscoveredParam] = []
        self.baseline_responses: Dict[str, Tuple[int, int]] = {}
    
    async def run(self):
        """Run parameter fuzzing."""
        await event_manager.emit("log", f"[{self.name}] Starting parameter discovery...")
        
        urls_to_test = list(self.context.crawled_urls)
        if not urls_to_test:
            urls_to_test = [self.context.target]
        
        # Test each URL
        for url in urls_to_test[:15]:
            await self._discover_hidden_params(url)
            await self._discover_json_keys(url)
            await self._fuzz_path_variables(url)
        
        # Test cookie parameters
        await self._fuzz_cookies()
        
        # Report findings
        if self.discovered:
            await self._report_findings()
    
    async def _get_baseline(self, url: str) -> Tuple[int, int]:
        """Get baseline response for differential analysis."""
        if url in self.baseline_responses:
            return self.baseline_responses[url]
        
        try:
            async with self.context.session.get(url, timeout=10) as response:
                body = await response.text()
                baseline = (response.status, len(body))
                self.baseline_responses[url] = baseline
                return baseline
        except Exception:
            return (0, 0)
    
    async def _discover_hidden_params(self, url: str):
        """Discover hidden URL parameters."""
        parsed = urlparse(url)
        base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
        existing_params = parse_qs(parsed.query)
        
        baseline_status, baseline_len = await self._get_baseline(url)
        if baseline_status == 0:
            return
        
        # Test each common parameter
        for param in self.COMMON_PARAMS:
            if param in existing_params:
                continue
            
            for test_value in self.TEST_VALUES[:3]:  # Limit test values
                test_params = dict(existing_params)
                test_params[param] = [test_value]
                
                test_query = urlencode(test_params, doseq=True)
                test_url = urlunparse((
                    parsed.scheme, parsed.netloc, parsed.path,
                    parsed.params, test_query, parsed.fragment
                ))
                
                try:
                    async with self.context.session.get(test_url, timeout=5) as response:
                        body = await response.text()
                        
                        # Check if response changed significantly
                        len_diff = abs(len(body) - baseline_len)
                        status_changed = response.status != baseline_status
                        
                        if status_changed or len_diff > 50:
                            is_sensitive = any(
                                re.search(p, param, re.I)
                                for p in self.SENSITIVE_PATTERNS
                            )
                            
                            self.discovered.append(DiscoveredParam(
                                name=param,
                                source='url',
                                url=url,
                                original_value=test_value,
                                discovered_via='response_differential',
                                is_sensitive=is_sensitive,
                                affects_response=True
                            ))
                            
                            await event_manager.emit("log",
                                f"[{self.name}] Found param: {param}={test_value} "
                                f"(status: {response.status}, len_diff: {len_diff})")
                            break  # Found this param, move to next
                            
                except Exception:
                    continue
                
                await asyncio.sleep(0.1)  # Rate limiting
    
    async def _discover_json_keys(self, url: str):
        """Discover hidden JSON keys in POST bodies."""
        # Try common JSON endpoints
        json_endpoints = [url]
        if not url.endswith('/'):
            json_endpoints.append(url + '/')
        
        headers = {'Content-Type': 'application/json'}
        
        for endpoint in json_endpoints:
            # Get baseline with empty JSON
            try:
                async with self.context.session.post(
                    endpoint,
                    json={},
                    headers=headers,
                    timeout=5
                ) as response:
                    if response.status >= 500:
                        continue
                    baseline_body = await response.text()
                    baseline_len = len(baseline_body)
            except Exception:
                continue
            
            # Test each common parameter as JSON key
            for param in self.COMMON_PARAMS[:30]:  # Limit for JSON
                test_bodies = [
                    {param: "1"},
                    {param: True},
                    {param: "admin"},
                ]
                
                for test_body in test_bodies:
                    try:
                        async with self.context.session.post(
                            endpoint,
                            json=test_body,
                            headers=headers,
                            timeout=5
                        ) as response:
                            body = await response.text()
                            len_diff = abs(len(body) - baseline_len)
                            
                            if len_diff > 20 or response.status != 200:
                                self.discovered.append(DiscoveredParam(
                                    name=param,
                                    source='json',
                                    url=endpoint,
                                    original_value=str(test_body[param]),
                                    discovered_via='json_differential',
                                    affects_response=True
                                ))
                                break
                                
                    except Exception:
                        continue
                
                await asyncio.sleep(0.05)
    
    async def _fuzz_path_variables(self, url: str):
        """Discover path variable injection points."""
        parsed = urlparse(url)
        path_parts = parsed.path.strip('/').split('/')
        
        if len(path_parts) < 2:
            return
        
        # Look for ID-like patterns
        id_patterns = [
            r'^\d+$',  # Numeric IDs
            r'^[a-f0-9]{8,}$',  # Hex IDs
            r'^[a-zA-Z0-9_-]{10,}$',  # Base64-like
        ]
        
        for i, part in enumerate(path_parts):
            for pattern in id_patterns:
                if re.match(pattern, part):
                    # This looks like an ID, try IDOR
                    test_values = ['1', '2', '0', '-1', 'admin', '../']
                    
                    for test_val in test_values:
                        new_parts = path_parts.copy()
                        new_parts[i] = test_val
                        new_path = '/' + '/'.join(new_parts)
                        
                        test_url = urlunparse((
                            parsed.scheme, parsed.netloc, new_path,
                            parsed.params, parsed.query, parsed.fragment
                        ))
                        
                        try:
                            async with self.context.session.get(test_url, timeout=5) as response:
                                if response.status == 200:
                                    self.discovered.append(DiscoveredParam(
                                        name=f"path[{i}]",
                                        source='url_path',
                                        url=url,
                                        original_value=part,
                                        discovered_via='path_variable',
                                        affects_response=True
                                    ))
                                    break
                        except Exception:
                            continue
                    
                    break  # Found pattern, move to next part
    
    async def _fuzz_cookies(self):
        """Discover cookie manipulation opportunities."""
        target = self.context.target
        
        try:
            async with self.context.session.get(target) as response:
                cookies = response.cookies
                
                for cookie_name in cookies:
                    cookie_value = cookies[cookie_name].value
                    
                    # Check for sensitive cookie names
                    is_sensitive = any(
                        re.search(p, cookie_name, re.I)
                        for p in self.SENSITIVE_PATTERNS
                    )
                    
                    # Check for manipulable values
                    manipulable = (
                        cookie_value.isdigit() or
                        cookie_value in ['true', 'false', '0', '1'] or
                        re.match(r'^[a-zA-Z0-9_-]+$', cookie_value)
                    )
                    
                    if is_sensitive or manipulable:
                        self.discovered.append(DiscoveredParam(
                            name=cookie_name,
                            source='cookie',
                            url=target,
                            original_value=cookie_value,
                            discovered_via='cookie_analysis',
                            is_sensitive=is_sensitive
                        ))
                        
        except Exception:
            pass
    
    async def _report_findings(self):
        """Report discovered parameters."""
        # Group by source
        by_source: Dict[str, List[DiscoveredParam]] = {}
        for param in self.discovered:
            if param.source not in by_source:
                by_source[param.source] = []
            by_source[param.source].append(param)
        
        # Report sensitive parameters
        sensitive = [p for p in self.discovered if p.is_sensitive]
        if sensitive:
            param_list = "\n".join(
                f"  - {p.name} ({p.source}) at {p.url[:50]}"
                for p in sensitive[:10]
            )
            
            await self.emit_vulnerability(
                "Sensitive Hidden Parameters Discovered",
                f"Found {len(sensitive)} sensitive hidden parameters:\n{param_list}",
                severity="P3",
                remediation="Review these parameters for authorization bypass or information disclosure.",
                url=self.context.target,
                payload=", ".join(p.name for p in sensitive[:5])
            )
        
        # Report response-affecting parameters
        affecting = [p for p in self.discovered if p.affects_response and not p.is_sensitive]
        if affecting:
            param_list = "\n".join(
                f"  - {p.name}={p.original_value} ({p.source})"
                for p in affecting[:10]
            )
            
            await self.emit_vulnerability(
                "Hidden Parameters Affecting Response",
                f"Found {len(affecting)} hidden parameters that affect server response:\n{param_list}",
                severity="P4",
                remediation="Test these parameters for injection vulnerabilities.",
                url=self.context.target,
                payload=", ".join(p.name for p in affecting[:5])
            )
    
    def cleanup(self):
        self.discovered.clear()
        self.baseline_responses.clear()
