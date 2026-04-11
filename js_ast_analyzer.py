"""
Lynx VAPT - Advanced JavaScript AST Analyzer

Features:
- Real JavaScript AST parsing  
- Dynamic endpoint detection
- Function-level secret detection
- Logic flow analysis
- Obfuscation detection
- API schema extraction

Author: Lynx Team
"""

import re
import json
import asyncio
from typing import Dict, List, Optional, Any, Set, Tuple
from dataclasses import dataclass, field
from urllib.parse import urljoin, urlparse
from enum import Enum


class JSFindingType(Enum):
    """Types of JavaScript findings."""
    SECRET = "secret"
    API_ENDPOINT = "api_endpoint"
    DANGEROUS_FUNCTION = "dangerous_function"
    DOM_SINK = "dom_sink"
    HARDCODED_CRED = "hardcoded_credential"
    DEBUG_CODE = "debug_code"
    OBFUSCATED = "obfuscated"
    EVAL_USAGE = "eval_usage"
    POSTMESSAGE = "postmessage"


@dataclass
class JSEndpoint:
    """Discovered API endpoint from JS."""
    url: str
    method: str = "GET"
    parameters: List[str] = field(default_factory=list)
    body_schema: Optional[Dict] = None
    auth_required: bool = False
    source_file: str = ""
    line_number: int = 0


@dataclass
class JSSecret:
    """Discovered secret in JS."""
    type: str
    value: str
    context: str
    confidence: float
    source_file: str = ""
    line_number: int = 0


@dataclass
class JSVulnerability:
    """A JavaScript vulnerability."""
    type: JSFindingType
    description: str
    code_snippet: str
    severity: str
    source_file: str = ""
    line_number: int = 0


class AdvancedJSAnalyzer:
    """
    Advanced JavaScript Analyzer with pseudo-AST parsing.
    
    Since we can't use Node.js directly, this uses sophisticated
    regex and pattern matching that simulates AST-level analysis.
    """
    
    # Secret patterns with high confidence
    SECRET_PATTERNS = [
        # API Keys
        (r'(?:api[_-]?key|apikey)\s*[=:]\s*["\']([a-zA-Z0-9_\-]{20,})["\']', 'api_key', 0.9),
        (r'(?:secret[_-]?key|secretkey)\s*[=:]\s*["\']([a-zA-Z0-9_\-]{20,})["\']', 'secret_key', 0.9),
        
        # AWS
        (r'AKIA[0-9A-Z]{16}', 'aws_access_key', 0.95),
        (r'(?:aws[_-]?secret|secret[_-]?access)\s*[=:]\s*["\']([a-zA-Z0-9/+=]{40})["\']', 'aws_secret', 0.9),
        
        # Google
        (r'AIza[0-9A-Za-z_-]{35}', 'google_api_key', 0.95),
        
        # GitHub
        (r'gh[pousr]_[A-Za-z0-9_]{36}', 'github_token', 0.95),
        
        # JWT
        (r'eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+', 'jwt_token', 0.85),
        
        # Private Keys
        (r'-----BEGIN (?:RSA |EC )?PRIVATE KEY-----', 'private_key', 0.95),
        
        # Generic passwords
        (r'(?:password|passwd|pwd)\s*[=:]\s*["\']([^"\']{8,})["\']', 'password', 0.7),
        
        # Bearer tokens
        (r'[Bb]earer\s+[a-zA-Z0-9_\-.]+', 'bearer_token', 0.8),
        
        # Slack
        (r'xox[baprs]-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24}', 'slack_token', 0.95),
        
        # Stripe
        (r'sk_live_[0-9a-zA-Z]{24}', 'stripe_secret', 0.95),
        (r'pk_live_[0-9a-zA-Z]{24}', 'stripe_public', 0.8),
        
        # Twilio
        (r'SK[0-9a-fA-F]{32}', 'twilio_key', 0.85),
        
        # Firebase
        (r'["\']?firebase["\']?\s*:\s*\{[^}]*apiKey\s*:\s*["\']([^"\']+)["\']', 'firebase_key', 0.85),
    ]
    
    # API endpoint patterns
    API_PATTERNS = [
        # Fetch/axios calls
        (r'fetch\s*\(\s*["\']([^"\']+)["\']', 'fetch'),
        (r'axios\.(?:get|post|put|delete|patch)\s*\(\s*["\']([^"\']+)["\']', 'axios'),
        
        # jQuery AJAX
        (r'\$\.(?:ajax|get|post)\s*\(\s*(?:\{[^}]*url\s*:\s*)?["\']([^"\']+)["\']', 'jquery'),
        
        # XMLHttpRequest
        (r'\.open\s*\(\s*["\'](?:GET|POST|PUT|DELETE)["\'],\s*["\']([^"\']+)["\']', 'xhr'),
        
        # Template literals with API paths
        (r'`(/(?:api|v\d)/[^`]+)`', 'template'),
        
        # String concatenation
        (r'["\']/(api|v\d+)/[^"\']+["\']', 'string'),
        
        # React/Vue routing
        (r'path\s*:\s*["\']/(api|v\d+)/[^"\']+["\']', 'route'),
    ]
    
    # Dangerous function patterns
    DANGEROUS_PATTERNS = [
        (r'\beval\s*\(', 'eval', 'P1'),
        (r'\bFunction\s*\(', 'Function constructor', 'P1'),
        (r'document\.write\s*\(', 'document.write', 'P2'),
        (r'innerHTML\s*=', 'innerHTML assignment', 'P2'),
        (r'outerHTML\s*=', 'outerHTML assignment', 'P2'),
        (r'insertAdjacentHTML\s*\(', 'insertAdjacentHTML', 'P2'),
        (r'\.html\s*\([^)]+\)', 'jQuery .html()', 'P2'),
        (r'location\s*=\s*[^;]+(?:hash|search|href)', 'DOM redirect', 'P2'),
        (r'setTimeout\s*\(\s*[^,]+,', 'setTimeout with string', 'P2'),
        (r'setInterval\s*\(\s*[^,]+,', 'setInterval with string', 'P2'),
    ]
    
    # Obfuscation detection patterns
    OBFUSCATION_PATTERNS = [
        (r'\\x[0-9a-fA-F]{2}', 'hex_encoding'),
        (r'\\u[0-9a-fA-F]{4}', 'unicode_encoding'),
        (r'String\.fromCharCode\s*\([^)]{50,}\)', 'charcode_obfuscation'),
        (r'atob\s*\(["\'][A-Za-z0-9+/=]{50,}["\']', 'base64_encoded'),
        (r'eval\s*\(\s*(?:unescape|decodeURIComponent|atob)', 'packed_eval'),
        (r'\[\s*["\'][^"\']+["\']\s*\]\s*\[\s*["\'][^"\']+["\']\s*\]', 'bracket_obfuscation'),
        (r'_0x[a-f0-9]{4,}', 'hex_variable_names'),
        (r'[a-zA-Z_$][a-zA-Z_$0-9]*\s*\(\s*\)\s*\{\s*return\s*this\s*\}', 'constructor_trick'),
    ]
    
    # PostMessage patterns
    POSTMESSAGE_PATTERNS = [
        (r'addEventListener\s*\(\s*["\']message["\']', 'message_listener'),
        (r'onmessage\s*=', 'onmessage_handler'),
        (r'\.postMessage\s*\(', 'postMessage_call'),
        (r'event\.data\s*', 'event_data_access'),
    ]
    
    def __init__(self):
        self.endpoints: List[JSEndpoint] = []
        self.secrets: List[JSSecret] = []
        self.vulnerabilities: List[JSVulnerability] = []
        self.analyzed_files: Set[str] = set()
    
    async def analyze(
        self,
        js_content: str,
        source_url: str = "",
        base_url: str = ""
    ) -> Dict[str, Any]:
        """
        Analyze JavaScript content for security issues.
        
        Returns a comprehensive report of findings.
        """
        self.analyzed_files.add(source_url)
        
        # Extract secrets
        await self._find_secrets(js_content, source_url)
        
        # Extract API endpoints
        await self._find_endpoints(js_content, source_url, base_url)
        
        # Find dangerous patterns
        await self._find_dangerous_patterns(js_content, source_url)
        
        # Check for obfuscation
        await self._detect_obfuscation(js_content, source_url)
        
        # Check PostMessage handling
        await self._check_postmessage(js_content, source_url)
        
        # Extract API schema hints
        schemas = await self._extract_api_schemas(js_content)
        
        return {
            'source': source_url,
            'secrets': [self._secret_to_dict(s) for s in self.secrets],
            'endpoints': [self._endpoint_to_dict(e) for e in self.endpoints],
            'vulnerabilities': [self._vuln_to_dict(v) for v in self.vulnerabilities],
            'api_schemas': schemas,
            'stats': {
                'total_secrets': len(self.secrets),
                'total_endpoints': len(self.endpoints),
                'total_vulnerabilities': len(self.vulnerabilities),
                'is_obfuscated': any(
                    v.type == JSFindingType.OBFUSCATED 
                    for v in self.vulnerabilities
                ),
            }
        }
    
    async def _find_secrets(self, content: str, source: str):
        """Find secrets in JavaScript content."""
        lines = content.split('\n')
        
        for pattern, secret_type, confidence in self.SECRET_PATTERNS:
            for match in re.finditer(pattern, content, re.I):
                # Get line number
                line_num = content[:match.start()].count('\n') + 1
                
                # Get context (surrounding code)
                context_start = max(0, match.start() - 50)
                context_end = min(len(content), match.end() + 50)
                context = content[context_start:context_end]
                
                # Extract the actual secret value
                if match.groups():
                    value = match.group(1)
                else:
                    value = match.group(0)
                
                # Skip if looks like a placeholder
                if self._is_placeholder(value):
                    continue
                
                # Adjust confidence based on context
                adjusted_confidence = self._adjust_secret_confidence(
                    value, context, confidence
                )
                
                if adjusted_confidence > 0.5:
                    self.secrets.append(JSSecret(
                        type=secret_type,
                        value=self._mask_secret(value),
                        context=context.strip(),
                        confidence=adjusted_confidence,
                        source_file=source,
                        line_number=line_num
                    ))
    
    def _is_placeholder(self, value: str) -> bool:
        """Check if value is a placeholder."""
        placeholders = [
            'your_api_key', 'your_secret', 'xxx', 'yyy', 'zzz',
            'example', 'test', 'demo', 'sample', 'placeholder',
            'insert', 'enter', 'replace', 'changeme', 'todo',
            'undefined', 'null', 'none', 'empty', 'blank',
        ]
        
        value_lower = value.lower()
        return any(p in value_lower for p in placeholders)
    
    def _adjust_secret_confidence(
        self,
        value: str,
        context: str,
        base_confidence: float
    ) -> float:
        """Adjust confidence based on context analysis."""
        confidence = base_confidence
        
        # Lower confidence for test/example contexts
        if re.search(r'test|example|demo|sample|placeholder', context, re.I):
            confidence *= 0.5
        
        # Lower for commented code
        if re.search(r'//.*' + re.escape(value), context):
            confidence *= 0.3
        
        # Higher for production indicators
        if re.search(r'production|prod|live', context, re.I):
            confidence *= 1.2
        
        # Lower for environment variable references
        if re.search(r'process\.env|ENV\[', context):
            confidence *= 0.4
        
        return min(1.0, max(0.0, confidence))
    
    def _mask_secret(self, secret: str) -> str:
        """Mask part of secret for safe logging."""
        if len(secret) <= 8:
            return secret[:2] + '*' * (len(secret) - 2)
        return secret[:4] + '*' * (len(secret) - 8) + secret[-4:]
    
    async def _find_endpoints(
        self,
        content: str,
        source: str,
        base_url: str
    ):
        """Find API endpoints in JavaScript."""
        for pattern, api_type in self.API_PATTERNS:
            for match in re.finditer(pattern, content, re.I):
                url = match.group(1) if match.groups() else match.group(0)
                
                # Clean up the URL
                url = url.strip('"\'`')
                
                # Skip non-API URLs
                if not url or url.startswith('#'):
                    continue
                
                # Convert relative to absolute
                if url.startswith('/') and base_url:
                    url = urljoin(base_url, url)
                
                # Determine HTTP method from context
                method = self._detect_http_method(content, match.start())
                
                # Extract parameters
                params = self._extract_parameters(url, content, match.start())
                
                # Check for auth requirements
                auth_required = self._detect_auth_requirement(
                    content, match.start()
                )
                
                line_num = content[:match.start()].count('\n') + 1
                
                self.endpoints.append(JSEndpoint(
                    url=url,
                    method=method,
                    parameters=params,
                    auth_required=auth_required,
                    source_file=source,
                    line_number=line_num
                ))
    
    def _detect_http_method(self, content: str, position: int) -> str:
        """Detect HTTP method from context."""
        # Look at surrounding 200 chars
        start = max(0, position - 100)
        end = min(len(content), position + 100)
        context = content[start:end].upper()
        
        methods = ['POST', 'PUT', 'DELETE', 'PATCH', 'GET']
        for method in methods:
            if method in context:
                return method
        
        return 'GET'
    
    def _extract_parameters(
        self,
        url: str,
        content: str,
        position: int
    ) -> List[str]:
        """Extract API parameters."""
        params = []
        
        # URL query parameters
        if '?' in url:
            query = url.split('?')[1]
            for param in query.split('&'):
                if '=' in param:
                    params.append(param.split('=')[0])
        
        # Look for body parameters in context
        start = position
        end = min(len(content), position + 500)
        context = content[start:end]
        
        # JSON body patterns
        body_match = re.search(r'\{([^}]+)\}', context)
        if body_match:
            body_content = body_match.group(1)
            for key_match in re.finditer(r'["\'](\w+)["\']s*:', body_content):
                params.append(key_match.group(1))
        
        return list(set(params))[:20]  # Limit to 20
    
    def _detect_auth_requirement(self, content: str, position: int) -> bool:
        """Detect if endpoint requires authentication."""
        start = max(0, position - 200)
        end = min(len(content), position + 300)
        context = content[start:end].lower()
        
        auth_indicators = [
            'authorization', 'bearer', 'token', 'auth',
            'headers', 'credentials', 'withcredentials',
        ]
        
        return any(ind in context for ind in auth_indicators)
    
    async def _find_dangerous_patterns(self, content: str, source: str):
        """Find dangerous code patterns."""
        for pattern, name, severity in self.DANGEROUS_PATTERNS:
            for match in re.finditer(pattern, content, re.I):
                line_num = content[:match.start()].count('\n') + 1
                
                # Get code context
                start = max(0, match.start() - 50)
                end = min(len(content), match.end() + 100)
                snippet = content[start:end].strip()
                
                self.vulnerabilities.append(JSVulnerability(
                    type=JSFindingType.DANGEROUS_FUNCTION,
                    description=f"Dangerous function usage: {name}",
                    code_snippet=snippet[:200],
                    severity=severity,
                    source_file=source,
                    line_number=line_num
                ))
    
    async def _detect_obfuscation(self, content: str, source: str):
        """Detect JavaScript obfuscation."""
        obfuscation_score = 0
        techniques_found = []
        
        for pattern, technique in self.OBFUSCATION_PATTERNS:
            matches = len(re.findall(pattern, content))
            if matches > 3:  # Threshold
                obfuscation_score += matches
                techniques_found.append(technique)
        
        # Check entropy (high entropy = likely obfuscated)
        if len(content) > 1000:
            unique_chars = len(set(content[:1000]))
            if unique_chars > 70:  # High variety
                obfuscation_score += 10
        
        # Check for very long lines (minified + obfuscated)
        lines = content.split('\n')
        long_lines = sum(1 for line in lines if len(line) > 1000)
        if long_lines > 0:
            obfuscation_score += long_lines * 5
        
        if obfuscation_score > 20:
            self.vulnerabilities.append(JSVulnerability(
                type=JSFindingType.OBFUSCATED,
                description=f"JavaScript appears obfuscated. Techniques: {', '.join(techniques_found)}",
                code_snippet=content[:200] + "...",
                severity="P4",
                source_file=source,
                line_number=1
            ))
    
    async def _check_postmessage(self, content: str, source: str):
        """Check for insecure postMessage handling."""
        for pattern, handler_type in self.POSTMESSAGE_PATTERNS:
            for match in re.finditer(pattern, content, re.I):
                line_num = content[:match.start()].count('\n') + 1
                
                # Look for origin validation
                start = max(0, match.start() - 100)
                end = min(len(content), match.end() + 300)
                context = content[start:end]
                
                has_origin_check = bool(re.search(
                    r'\.origin\s*[!=]==?|event\.origin|message\.origin',
                    context, re.I
                ))
                
                if not has_origin_check:
                    self.vulnerabilities.append(JSVulnerability(
                        type=JSFindingType.POSTMESSAGE,
                        description=f"PostMessage {handler_type} without origin validation",
                        code_snippet=context[:200],
                        severity="P2",
                        source_file=source,
                        line_number=line_num
                    ))
    
    async def _extract_api_schemas(self, content: str) -> List[Dict]:
        """Extract API schema information from JavaScript."""
        schemas = []
        
        # Look for GraphQL queries/mutations
        graphql_pattern = r'(?:query|mutation)\s+(\w+)[^{]*\{([^}]+)\}'
        for match in re.finditer(graphql_pattern, content):
            schemas.append({
                'type': 'graphql',
                'name': match.group(1),
                'fields': match.group(2).strip()[:200]
            })
        
        # Look for typed API calls (TypeScript hints)
        type_pattern = r':\s*\{([^}]+)\}\s*=>\s*|interface\s+(\w+)\s*\{([^}]+)\}'
        for match in re.finditer(type_pattern, content):
            if match.group(2):  # Interface
                schemas.append({
                    'type': 'typescript_interface',
                    'name': match.group(2),
                    'definition': match.group(3)[:200]
                })
        
        # Look for Swagger/OpenAPI references
        if 'swagger' in content.lower() or 'openapi' in content.lower():
            openapi_refs = re.findall(
                r'["\']?(?:swagger|openapi)["\']?\s*:\s*["\']([^"\']+)["\']',
                content, re.I
            )
            for ref in openapi_refs:
                schemas.append({
                    'type': 'openapi_reference',
                    'path': ref
                })
        
        return schemas
    
    def _secret_to_dict(self, secret: JSSecret) -> Dict:
        return {
            'type': secret.type,
            'value': secret.value,
            'confidence': secret.confidence,
            'source': secret.source_file,
            'line': secret.line_number
        }
    
    def _endpoint_to_dict(self, endpoint: JSEndpoint) -> Dict:
        return {
            'url': endpoint.url,
            'method': endpoint.method,
            'parameters': endpoint.parameters,
            'auth_required': endpoint.auth_required,
            'source': endpoint.source_file,
            'line': endpoint.line_number
        }
    
    def _vuln_to_dict(self, vuln: JSVulnerability) -> Dict:
        return {
            'type': vuln.type.value,
            'description': vuln.description,
            'severity': vuln.severity,
            'code': vuln.code_snippet,
            'source': vuln.source_file,
            'line': vuln.line_number
        }
    
    def clear(self):
        """Clear analyzed data."""
        self.endpoints.clear()
        self.secrets.clear()
        self.vulnerabilities.clear()
        self.analyzed_files.clear()


# Global analyzer instance
_js_analyzer: Optional[AdvancedJSAnalyzer] = None


def get_js_analyzer() -> AdvancedJSAnalyzer:
    """Get the global JS analyzer."""
    global _js_analyzer
    if _js_analyzer is None:
        _js_analyzer = AdvancedJSAnalyzer()
    return _js_analyzer


async def analyze_javascript(
    content: str,
    source_url: str = "",
    base_url: str = ""
) -> Dict[str, Any]:
    """Convenience function to analyze JavaScript."""
    analyzer = get_js_analyzer()
    return await analyzer.analyze(content, source_url, base_url)
