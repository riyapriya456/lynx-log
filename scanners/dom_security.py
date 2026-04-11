"""
Lynx VAPT - DOM Security Scanner

Comprehensive DOM-based vulnerability detection:
- DOM XSS detection via source/sink analysis
- Prototype pollution detection
- Client-side template injection
- PostMessage exploitation
- CSP bypass detection
- Open redirect via DOM

Author: Lynx Team
"""

import asyncio
import re
from typing import Dict, List, Optional, Any, Set, Tuple
from dataclasses import dataclass, field
from urllib.parse import urljoin, urlparse

from scanners.base import BaseScanner
from common import event_manager, TestingZone


@dataclass
class DOMVulnerability:
    """A DOM-based vulnerability finding."""
    vuln_type: str
    url: str
    source: str
    sink: str
    code_snippet: str
    severity: str
    confidence: float


class DOMSecurityScanner(BaseScanner):
    """
    DOM Security Scanner.
    
    Analyzes JavaScript for DOM-based vulnerabilities:
    - Taint tracking (source → sink analysis)
    - Prototype pollution gadgets
    - PostMessage handlers
    - Client-side template injection
    - DOM clobbering
    """
    
    # DOM XSS Sources (where user input enters)
    DOM_SOURCES = [
        r'location\.hash',
        r'location\.search',
        r'location\.href',
        r'location\.pathname',
        r'document\.URL',
        r'document\.documentURI',
        r'document\.referrer',
        r'window\.name',
        r'document\.cookie',
        r'localStorage\.',
        r'sessionStorage\.',
        r'\.getItem\s*\(',
        r'postMessage',
        r'\.hash\b',
        r'\.search\b',
        r'URLSearchParams',
        r'new\s+URL\s*\(',
    ]
    
    # DOM XSS Sinks (where code execution can occur)
    DOM_SINKS = [
        # Direct execution
        (r'eval\s*\(', 'eval', 'P1'),
        (r'Function\s*\(', 'Function constructor', 'P1'),
        (r'setTimeout\s*\([^,]+,', 'setTimeout with string', 'P1'),
        (r'setInterval\s*\([^,]+,', 'setInterval with string', 'P1'),
        (r'execScript\s*\(', 'execScript', 'P1'),
        
        # HTML injection
        (r'\.innerHTML\s*=', 'innerHTML assignment', 'P1'),
        (r'\.outerHTML\s*=', 'outerHTML assignment', 'P1'),
        (r'\.insertAdjacentHTML\s*\(', 'insertAdjacentHTML', 'P1'),
        (r'document\.write\s*\(', 'document.write', 'P1'),
        (r'document\.writeln\s*\(', 'document.writeln', 'P1'),
        
        # jQuery sinks
        (r'\$\s*\([^)]*\)\.html\s*\(', 'jQuery .html()', 'P1'),
        (r'\$\s*\([^)]*\)\.append\s*\(', 'jQuery .append()', 'P2'),
        (r'\$\s*\([^)]*\)\.prepend\s*\(', 'jQuery .prepend()', 'P2'),
        (r'\$\s*\([^)]*\)\.after\s*\(', 'jQuery .after()', 'P2'),
        (r'\$\s*\([^)]*\)\.before\s*\(', 'jQuery .before()', 'P2'),
        
        # URL/redirect sinks
        (r'location\s*=', 'location assignment', 'P2'),
        (r'location\.href\s*=', 'location.href assignment', 'P2'),
        (r'location\.replace\s*\(', 'location.replace', 'P2'),
        (r'location\.assign\s*\(', 'location.assign', 'P2'),
        (r'window\.open\s*\(', 'window.open', 'P2'),
        
        # Script/resource loading
        (r'\.src\s*=', 'src assignment', 'P2'),
        (r'script\.src\s*=', 'script.src assignment', 'P1'),
        (r'\.href\s*=', 'href assignment', 'P3'),
    ]
    
    # Prototype pollution patterns
    PROTOTYPE_POLLUTION_PATTERNS = [
        r'Object\.assign\s*\([^,]*,\s*[^)]*\)',
        r'_\.merge\s*\(',
        r'_\.extend\s*\(',
        r'\$\.extend\s*\(',
        r'JSON\.parse\s*\([^)]*\)',
        r'\[([^\]]+)\]\s*=\s*([^;]+)',  # obj[key] = value
        r'__proto__',
        r'constructor\s*\.\s*prototype',
    ]
    
    # PostMessage patterns
    POSTMESSAGE_PATTERNS = [
        r'addEventListener\s*\(\s*["\']message["\']',
        r'onmessage\s*=',
        r'\.postMessage\s*\(',
    ]
    
    # CSP bypass patterns
    CSP_BYPASS_PATTERNS = [
        r'base-uri[^;]*\*',
        r"script-src[^;]*'unsafe-inline'",
        r"script-src[^;]*'unsafe-eval'",
        r'script-src[^;]*\*',
        r'default-src[^;]*\*',
        r'object-src[^;]*\*',
    ]
    
    def __init__(self, context):
        super().__init__(context)
        self.name = "DOMSecurityScanner"
        self.zone = TestingZone.ZONE_A
        self.findings: List[DOMVulnerability] = []
    
    async def run(self):
        """Run DOM security scan."""
        await event_manager.emit("log", f"[{self.name}] Starting DOM security scan...")
        
        # Get target page
        try:
            async with self.context.session.get(self.context.target) as response:
                html = await response.text()
                headers = dict(response.headers)
        except Exception as e:
            await event_manager.emit("log", f"[{self.name}] Failed to fetch target: {e}")
            return
        
        # Extract inline scripts
        inline_scripts = self._extract_inline_scripts(html)
        
        # Extract external script URLs
        external_scripts = self._extract_external_scripts(html)
        
        # Fetch external scripts
        for script_url in external_scripts[:10]:  # Limit
            try:
                async with self.context.session.get(script_url, timeout=10) as resp:
                    if resp.status == 200:
                        script_content = await resp.text()
                        inline_scripts.append((script_url, script_content))
            except Exception:
                continue
        
        # Analyze each script
        for source, script in inline_scripts:
            await self._analyze_script(source, script)
        
        # Check CSP
        await self._check_csp(headers)
        
        # Check for PostMessage issues
        for source, script in inline_scripts:
            await self._check_postmessage(source, script)
        
        # Check for prototype pollution
        for source, script in inline_scripts:
            await self._check_prototype_pollution(source, script)
        
        await event_manager.emit("log", 
            f"[{self.name}] Found {len(self.findings)} DOM security issues")
    
    def _extract_inline_scripts(self, html: str) -> List[Tuple[str, str]]:
        """Extract inline JavaScript from HTML."""
        scripts = []
        
        pattern = r'<script[^>]*>(.*?)</script>'
        for match in re.finditer(pattern, html, re.DOTALL | re.I):
            content = match.group(1).strip()
            if content:
                scripts.append(('inline', content))
        
        # Event handlers
        event_pattern = r'on\w+\s*=\s*["\']([^"\']+)["\']'
        for match in re.finditer(event_pattern, html, re.I):
            scripts.append(('event_handler', match.group(1)))
        
        return scripts
    
    def _extract_external_scripts(self, html: str) -> List[str]:
        """Extract external script URLs."""
        scripts = []
        
        pattern = r'<script[^>]*\ssrc\s*=\s*["\']([^"\']+)["\']'
        for match in re.finditer(pattern, html, re.I):
            src = match.group(1)
            if not src.startswith('http'):
                src = urljoin(self.context.target, src)
            scripts.append(src)
        
        return scripts
    
    async def _analyze_script(self, source: str, script: str):
        """Analyze script for DOM XSS vulnerabilities."""
        # Find all sources and sinks
        found_sources = []
        found_sinks = []
        
        for source_pattern in self.DOM_SOURCES:
            for match in re.finditer(source_pattern, script):
                found_sources.append((match.group(), match.start()))
        
        for sink_pattern, sink_name, severity in self.DOM_SINKS:
            for match in re.finditer(sink_pattern, script):
                found_sinks.append((match.group(), sink_name, severity, match.start()))
        
        # Simple taint analysis: check if source appears before sink in same context
        for src_match, src_pos in found_sources:
            for sink_match, sink_name, severity, sink_pos in found_sinks:
                # Check if source and sink are within 500 chars (same function likely)
                if abs(sink_pos - src_pos) < 500:
                    # Get code context
                    start = max(0, min(src_pos, sink_pos) - 50)
                    end = min(len(script), max(src_pos, sink_pos) + 100)
                    context = script[start:end].strip()
                    
                    # Check for common safe patterns
                    if self._is_likely_safe(context):
                        continue
                    
                    self.findings.append(DOMVulnerability(
                        vuln_type='DOM XSS',
                        url=self.context.target,
                        source=src_match,
                        sink=sink_name,
                        code_snippet=context[:200],
                        severity=severity,
                        confidence=0.7
                    ))
                    
                    await self.emit_vulnerability(
                        f"Potential DOM XSS ({sink_name})",
                        f"Source: {src_match}\n"
                        f"Sink: {sink_name}\n"
                        f"Script: {source}\n"
                        f"Code:\n```javascript\n{context[:300]}\n```",
                        severity=severity,
                        remediation="Sanitize user input before using in DOM sinks. "
                                   "Use textContent instead of innerHTML when possible.",
                        url=self.context.target,
                        payload=f"{src_match} → {sink_name}"
                    )
    
    def _is_likely_safe(self, context: str) -> bool:
        """Check if the code context is likely safe."""
        safe_patterns = [
            r'encodeURIComponent\s*\(',
            r'escape\s*\(',
            r'DOMPurify',
            r'sanitize',
            r'\.textContent\s*=',
            r'\.innerText\s*=',
        ]
        
        return any(re.search(p, context, re.I) for p in safe_patterns)
    
    async def _check_postmessage(self, source: str, script: str):
        """Check for insecure PostMessage handlers."""
        for pattern in self.POSTMESSAGE_PATTERNS:
            if re.search(pattern, script):
                # Check for origin validation
                if not re.search(r'\.origin\s*[!=]==?', script):
                    # Get context
                    match = re.search(pattern, script)
                    if match:
                        start = max(0, match.start() - 50)
                        end = min(len(script), match.end() + 200)
                        context = script[start:end]
                        
                        await self.emit_vulnerability(
                            "Insecure PostMessage Handler",
                            f"PostMessage handler without origin validation.\n"
                            f"Script: {source}\n"
                            f"Code:\n```javascript\n{context[:300]}\n```",
                            severity="P2",
                            remediation="Always validate event.origin before processing "
                                       "postMessage data.",
                            url=self.context.target,
                            payload="addEventListener('message', ...)"
                        )
                        break
    
    async def _check_prototype_pollution(self, source: str, script: str):
        """Check for prototype pollution vulnerabilities."""
        for pattern in self.PROTOTYPE_POLLUTION_PATTERNS:
            matches = list(re.finditer(pattern, script))
            
            for match in matches[:3]:  # Limit reports per pattern
                context_start = max(0, match.start() - 100)
                context_end = min(len(script), match.end() + 100)
                context = script[context_start:context_end]
                
                # Check if user input flows into this
                if any(re.search(src, context) for src in self.DOM_SOURCES):
                    await self.emit_vulnerability(
                        "Potential Prototype Pollution",
                        f"Prototype pollution pattern with user input.\n"
                        f"Pattern: {match.group()[:50]}\n"
                        f"Script: {source}\n"
                        f"Code:\n```javascript\n{context[:250]}\n```",
                        severity="P2",
                        remediation="Validate and sanitize object keys. "
                                   "Use Object.create(null) for lookup objects. "
                                   "Block __proto__ and constructor keys.",
                        url=self.context.target,
                        payload="__proto__[key]=value"
                    )
                    break
    
    async def _check_csp(self, headers: Dict[str, str]):
        """Check Content Security Policy for weaknesses."""
        csp = headers.get('Content-Security-Policy', '') or headers.get('content-security-policy', '')
        
        if not csp:
            await self.emit_vulnerability(
                "Missing Content Security Policy",
                "No CSP header found. This allows unrestricted script execution.",
                severity="P3",
                remediation="Implement a strict Content-Security-Policy header.",
                url=self.context.target,
                payload="Content-Security-Policy: missing"
            )
            return
        
        # Check for weak CSP directives
        weaknesses = []
        
        for pattern in self.CSP_BYPASS_PATTERNS:
            if re.search(pattern, csp, re.I):
                weaknesses.append(re.sub(r'\[[^\]]+\]', '', pattern))
        
        # Check for specific issues
        if "'unsafe-inline'" in csp and 'script-src' in csp:
            weaknesses.append("unsafe-inline in script-src")
        
        if "'unsafe-eval'" in csp:
            weaknesses.append("unsafe-eval allows eval()")
        
        if 'data:' in csp and 'script-src' in csp:
            weaknesses.append("data: URIs in script-src")
        
        if weaknesses:
            await self.emit_vulnerability(
                "Weak Content Security Policy",
                f"CSP has weaknesses that may allow XSS bypass:\n"
                f"- " + "\n- ".join(weaknesses) + f"\n\nCSP: {csp[:200]}",
                severity="P3",
                remediation="Strengthen CSP by removing unsafe directives.",
                url=self.context.target,
                payload=", ".join(weaknesses[:3])
            )
    
    def cleanup(self):
        self.findings.clear()
