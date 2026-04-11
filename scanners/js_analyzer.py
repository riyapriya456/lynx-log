"""
JavaScript Analyzer Scanner for Lynx VAPT Tool

This scanner analyzes JavaScript files to extract:
- API Keys and Secrets
- URL Endpoints (REST, GraphQL, WebSocket)
- React-specific patterns (hooks, state, routing)
- Storage methods (localStorage, sessionStorage, cookies)
- Vulnerabilities (eval, innerHTML, prototype pollution)
- Request conditions and authentication logic
"""

import re
import asyncio
import urllib.parse
from typing import List, Dict, Set, Tuple, Optional
from dataclasses import dataclass, field
from bs4 import BeautifulSoup

from .base import BaseScanner
from common import event_manager, TestingZone


@dataclass
class JSFinding:
    """Represents a finding from JS analysis."""
    category: str
    finding_type: str
    value: str
    context: str
    line_hint: str = ""
    severity: str = "P4"
    remediation: str = ""
    reproducibility: str = ""


@dataclass 
class JSFileAnalysis:
    """Contains all analysis results for a single JS file."""
    url: str
    secrets: List[JSFinding] = field(default_factory=list)
    endpoints: List[JSFinding] = field(default_factory=list)
    storage_methods: List[JSFinding] = field(default_factory=list)
    react_patterns: List[JSFinding] = field(default_factory=list)
    vulnerabilities: List[JSFinding] = field(default_factory=list)
    request_conditions: List[JSFinding] = field(default_factory=list)
    

class JSAnalyzerScanner(BaseScanner):
    """
    Comprehensive JavaScript analyzer for security assessment.
    
    Features:
    - Auto-detects direct JS URL vs website for crawling
    - Extracts secrets, endpoints, storage patterns
    - Detects React-specific patterns
    - Identifies client-side vulnerabilities
    """
    
    def __init__(self, context):
        super().__init__(context)
        self.name = "JSAnalyzerScanner"
        self.zone = TestingZone.ZONE_C
        self.analyzed_files: Set[str] = set()
        self.js_files: Set[str] = set()
        
        # ============== SECRET PATTERNS ==============
        self.secret_patterns = {
            # Cloud Provider Keys
            "AWS Access Key": r'AKIA[0-9A-Z]{16}',
            "AWS Secret Key": r'(?i)aws(.{0,20})?(?-i)[\'"][0-9a-zA-Z\/+]{40}[\'"]',
            "Google API Key": r'AIza[0-9A-Za-z\-_]{35}',
            "Google OAuth": r'[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com',
            "Azure Storage": r'DefaultEndpointsProtocol=https;AccountName=[^;]+;AccountKey=[^;]+',
            
            # Version Control & CI/CD
            "GitHub Token": r'gh[pousr]_[0-9a-zA-Z]{36}',
            "GitHub OAuth": r'gho_[0-9a-zA-Z]{36}',
            "GitLab Token": r'glpat-[0-9a-zA-Z\-_]{20}',
            "Bitbucket Token": r'(?i)bitbucket(.{0,20})?[\'"][0-9a-zA-Z]{32}[\'"]',
            
            # Payment & Financial
            "Stripe API Key": r'sk_live_[0-9a-zA-Z]{24}',
            "Stripe Publishable": r'pk_live_[0-9a-zA-Z]{24}',
            "PayPal Client ID": r'(?i)paypal(.{0,20})?[\'"][A-Za-z0-9\-_]{20,}[\'"]',
            
            # Communication Services
            "Slack Token": r'xox[baprs]-[0-9]{10,13}-[0-9]{10,13}[a-zA-Z0-9-]*',
            "Slack Webhook": r'https://hooks\.slack\.com/services/T[a-zA-Z0-9_]+/B[a-zA-Z0-9_]+/[a-zA-Z0-9_]+',
            "Discord Webhook": r'https://discord(?:app)?\.com/api/webhooks/[0-9]+/[a-zA-Z0-9_-]+',
            "Twilio API Key": r'SK[0-9a-fA-F]{32}',
            "SendGrid API Key": r'SG\.[a-zA-Z0-9]{22}\.[a-zA-Z0-9\-_]{43}',
            "Mailgun API Key": r'key-[0-9a-zA-Z]{32}',
            
            # Firebase & Google Cloud
            "Firebase API Key": r'(?i)firebase(.{0,20})?[\'"][A-Za-z0-9\-_]{20,}[\'"]',
            "Firebase URL": r'https://[a-z0-9-]+\.firebaseio\.com',
            "GCP Service Account": r'"type":\s*"service_account"',
            
            # Database & Infrastructure  
            "MongoDB URI": r'mongodb(\+srv)?://[^\s\'"]+',
            "PostgreSQL URI": r'postgres(ql)?://[^\s\'"]+',
            "MySQL URI": r'mysql://[^\s\'"]+',
            "Redis URI": r'redis://[^\s\'"]+',
            
            # Authentication
            "JWT Token": r'eyJ[A-Za-z0-9-_]+\.eyJ[A-Za-z0-9-_]+\.[A-Za-z0-9-_.+/]*',
            "Bearer Token": r'(?i)bearer\s+[a-zA-Z0-9\-_\.]+',
            "Basic Auth": r'(?i)basic\s+[a-zA-Z0-9+/=]+',
            "Private Key": r'-----BEGIN\s+(RSA|EC|DSA|OPENSSH|PGP)\s+PRIVATE\s+KEY-----',
            
            # Generic Patterns
            "Generic API Key": r'(?i)(api[_-]?key|apikey|api_secret)["\']?\s*[:=]\s*["\'][a-zA-Z0-9\-_]{16,}["\']',
            "Generic Secret": r'(?i)(secret|password|passwd|pwd)["\']?\s*[:=]\s*["\'][^"\']{8,}["\']',
            "Generic Token": r'(?i)(token|access_token|auth_token)["\']?\s*[:=]\s*["\'][a-zA-Z0-9\-_\.]{16,}["\']',
            
            # Social Media & Analytics
            "Facebook Access Token": r'EAACEdEose0cBA[0-9A-Za-z]+',
            "Twitter API Key": r'(?i)twitter(.{0,20})?[\'"][0-9a-zA-Z]{18,25}[\'"]',
            "Heroku API Key": r'(?i)heroku(.{0,20})?[\'"][0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}[\'"]',
        }
        
        # ============== ENDPOINT PATTERNS ==============
        self.endpoint_patterns = {
            "REST API": r'["\']/(api|v[0-9]+)/[a-zA-Z0-9/_\-{}:]+["\']',
            "GraphQL": r'["\']/(graphql|gql)["\']',
            "WebSocket": r'wss?://[^\s\'"]+',
            "Fetch URL": r'fetch\s*\(\s*[`"\']([^`"\']+)[`"\']',
            "Axios URL": r'axios\.(get|post|put|patch|delete)\s*\(\s*[`"\']([^`"\']+)[`"\']',
            "XMLHttpRequest": r'\.open\s*\(\s*["\'][A-Z]+["\']\s*,\s*["\']([^"\']+)["\']',
            "jQuery AJAX": r'\$\.(ajax|get|post)\s*\(\s*[{"\'].*?url["\']?\s*:\s*["\']([^"\']+)["\']',
            "Template Literal URL": r'`[^`]*\$\{[^}]+\}[^`]*/[^`]+`',
            "Absolute URL": r'https?://[a-zA-Z0-9\-._~:/?#\[\]@!$&\'()*+,;=%]+',
            "Relative Path": r'["\']\/[a-zA-Z0-9/_\-]+\.(json|xml|php|asp|jsp)["\']',
        }
        
        # ============== REACT PATTERNS ==============
        self.react_patterns = {
            "useEffect API Call": r'useEffect\s*\(\s*(?:async\s*)?\(\s*\)\s*=>\s*\{[^}]*(?:fetch|axios)',
            "useState": r'(?:const|let|var)\s+\[([a-zA-Z0-9_]+),\s*set[A-Z][a-zA-Z0-9_]*\]\s*=\s*useState',
            "useContext": r'useContext\s*\(\s*([A-Z][a-zA-Z0-9_]*Context)\s*\)',
            "Redux Dispatch": r'dispatch\s*\(\s*([a-zA-Z0-9_]+)\s*\(',
            "Redux Connect": r'connect\s*\(\s*mapStateToProps',
            "React Router": r'(?:Route|Switch|Link|NavLink|useHistory|useParams|useLocation)',
            "Router Path": r'<Route[^>]*path\s*=\s*["\']([^"\']+)["\']',
            "Navigate": r'(?:history\.push|navigate)\s*\(\s*["\']([^"\']+)["\']',
            "Lazy Loading": r'React\.lazy\s*\(\s*\(\s*\)\s*=>\s*import',
            "Error Boundary": r'componentDidCatch|ErrorBoundary',
            "Context Provider": r'<([A-Z][a-zA-Z0-9_]*Context)\.Provider',
            "Custom Hook": r'(?:function|const)\s+(use[A-Z][a-zA-Z0-9_]*)',
        }
        
        # ============== STORAGE PATTERNS ==============
        self.storage_patterns = {
            "localStorage Set": r'localStorage\.setItem\s*\(\s*["\']([^"\']+)["\']',
            "localStorage Get": r'localStorage\.getItem\s*\(\s*["\']([^"\']+)["\']',
            "localStorage Remove": r'localStorage\.removeItem\s*\(\s*["\']([^"\']+)["\']',
            "sessionStorage Set": r'sessionStorage\.setItem\s*\(\s*["\']([^"\']+)["\']',
            "sessionStorage Get": r'sessionStorage\.getItem\s*\(\s*["\']([^"\']+)["\']',
            "Cookie Set": r'document\.cookie\s*=\s*["\']?([^;"\'\n]+)',
            "Cookie Library": r'(?:js-cookie|Cookies)\.(set|get|remove)\s*\(\s*["\']([^"\']+)["\']',
            "IndexedDB": r'indexedDB\.open\s*\(\s*["\']([^"\']+)["\']',
        }
        
        # ============== VULNERABILITY PATTERNS ==============
        self.vuln_patterns = {
            # Code Execution
            "eval Usage": (r'\beval\s*\([^)]+\)', "P1", "eval() can execute arbitrary code. Use safer alternatives like JSON.parse()."),
            "Function Constructor": (r'new\s+Function\s*\([^)]+\)', "P2", "Function constructor can execute arbitrary code. Avoid dynamic code execution."),
            "setTimeout String": (r'setTimeout\s*\(\s*["\'][^"\']+["\']', "P2", "setTimeout with string argument acts like eval. Use function reference instead."),
            "setInterval String": (r'setInterval\s*\(\s*["\'][^"\']+["\']', "P2", "setInterval with string argument acts like eval. Use function reference instead."),
            
            # DOM Manipulation
            "innerHTML Assignment": (r'\.innerHTML\s*=\s*[^;]+', "P2", "innerHTML can lead to XSS. Use textContent or sanitize input."),
            "outerHTML Assignment": (r'\.outerHTML\s*=\s*[^;]+', "P2", "outerHTML can lead to XSS. Sanitize input before use."),
            "document.write": (r'document\.write\s*\([^)]+\)', "P2", "document.write can be exploited for XSS. Use DOM methods instead."),
            "insertAdjacentHTML": (r'\.insertAdjacentHTML\s*\([^)]+\)', "P2", "insertAdjacentHTML can lead to XSS if input is unsanitized."),
            
            # Prototype Pollution
            "Proto Access": (r'__proto__', "P2", "Direct __proto__ access can lead to prototype pollution. Use Object.create() or Object.getPrototypeOf()."),
            "Constructor Prototype": (r'constructor\[?["\']?prototype', "P2", "Prototype manipulation can lead to prototype pollution attacks."),
            "Object Assign Deep": (r'Object\.assign\s*\([^)]*\.\.\.[^)]+\)', "P3", "Deep object merging without validation can lead to prototype pollution."),
            
            # Postmessage Issues
            "Postmessage No Origin": (r'addEventListener\s*\(\s*["\']message["\'][^}]+(?!origin)[^}]+\}', "P2", "postMessage handler should verify event.origin to prevent cross-origin attacks."),
            "Postmessage Wildcard": (r'postMessage\s*\([^)]+,\s*["\*"]["\']', "P2", "postMessage with wildcard origin can leak data. Specify exact origin."),
            
            # Security Issues
            "Insecure Randomness": (r'Math\.random\s*\(\s*\)', "P3", "Math.random() is not cryptographically secure. Use crypto.getRandomValues() for security."),
            "HTTP URL": (r'["\']http://[^"\']+["\']', "P3", "HTTP URLs transmit data unencrypted. Use HTTPS."),
            "Hardcoded Password": (r'(?i)(password|passwd|pwd)\s*[:=]\s*["\'][^"\']{4,}["\']', "P1", "Hardcoded passwords should be removed and stored securely."),
            
            # Debug/Development Code
            "Console Log": (r'console\.(log|debug|info|warn|error)\s*\(', "P4", "Remove console statements in production code."),
            "Debugger Statement": (r'\bdebugger\b', "P3", "Debugger statements should be removed in production."),
            "Alert/Confirm/Prompt": (r'\b(alert|confirm|prompt)\s*\(', "P4", "Native dialogs may indicate debug code or poor UX."),
            "TODO/FIXME Comments": (r'(?://|/\*)\s*(?:TODO|FIXME|HACK|XXX|BUG)[:\s]', "P4", "Unresolved TODO/FIXME comments may indicate incomplete implementation."),
            
            # Open Redirect Patterns
            "Location Assignment": (r'(?:location\.href|location\.replace|window\.location)\s*=\s*[^;]*(?:params|query|search|url)', "P3", "URL parameters in location assignments can lead to open redirect."),
            "Window Open": (r'window\.open\s*\(\s*[^)]*(?:params|query|url)', "P3", "URL parameters in window.open can lead to open redirect."),
            
            # CORS Issues
            "CORS Wildcard": (r'Access-Control-Allow-Origin["\']?\s*:\s*["\']?\*', "P3", "Wildcard CORS allows any origin to access resources."),
            "Credentials Include": (r'credentials\s*:\s*["\']include["\']', "P4", "credentials: 'include' sends cookies cross-origin. Ensure CORS is properly configured."),
        }
        
        # ============== REQUEST CONDITION PATTERNS ==============
        self.request_condition_patterns = {
            "Auth Token Check": r'if\s*\(\s*(?:token|accessToken|authToken|jwt)',
            "Role Based Access": r'if\s*\(\s*(?:role|userRole|isAdmin|permissions)',
            "Feature Flag": r'if\s*\(\s*(?:feature|flag|isEnabled|config)\.',
            "Environment Check": r'(?:process\.env|import\.meta\.env)\.[A-Z_]+',
            "Rate Limit Logic": r'(?:rateLimit|throttle|debounce)',
            "Retry Logic": r'(?:retry|attempts|maxRetries)',
            "Conditional Endpoint": r'(?:baseUrl|apiUrl|endpoint)\s*=\s*[^;]*\?[^;]*:',
        }

    async def run(self):
        """Main entry point for the scanner."""
        await event_manager.emit("log", f"[{self.name}] Starting JavaScript analysis...")
        
        target = self.context.target
        
        # Determine if target is a direct JS file or needs crawling
        if self._is_js_url(target):
            await event_manager.emit("log", f"[{self.name}] Direct JS file detected: {target}")
            self.js_files.add(target)
        else:
            # Crawl for JS files
            await event_manager.emit("log", f"[{self.name}] Crawling for JavaScript files...")
            await self._discover_js_files(target)
            
            # Also check crawled URLs
            for url in self.context.crawled_urls:
                if self._is_js_url(url):
                    self.js_files.add(url)
        
        if not self.js_files:
            await event_manager.emit("log", f"[{self.name}] No JavaScript files found to analyze.")
            return
        
        await event_manager.emit("log", f"[{self.name}] Found {len(self.js_files)} JavaScript file(s) to analyze.")
        
        # Analyze each JS file
        for js_url in self.js_files:
            if js_url not in self.analyzed_files:
                await self._analyze_js_file(js_url)
                self.analyzed_files.add(js_url)
        
        await event_manager.emit("log", f"[{self.name}] JavaScript analysis complete.")

    def _is_js_url(self, url: str) -> bool:
        """Check if URL points to a JavaScript file."""
        parsed = urllib.parse.urlparse(url)
        path = parsed.path.lower()
        
        # Check common JS extensions and patterns
        js_extensions = ['.js', '.mjs', '.jsx', '.ts', '.tsx']
        js_patterns = ['bundle', 'chunk', 'vendor', 'main', 'app', 'runtime']
        
        for ext in js_extensions:
            if path.endswith(ext):
                return True
        
        # Check for bundled JS files (often without extension in path)
        for pattern in js_patterns:
            if pattern in path and '/api/' not in path:
                return True
        
        return False

    async def _discover_js_files(self, target_url: str):
        """Crawl target page to discover JavaScript files."""
        try:
            async with self.context.session.get(target_url) as response:
                if response.status != 200:
                    return
                
                html = await response.text()
                soup = BeautifulSoup(html, 'html.parser')
                
                # Get base URL for resolving relative paths
                parsed = urllib.parse.urlparse(target_url)
                base_url = f"{parsed.scheme}://{parsed.netloc}"
                
                # Find script tags
                for script in soup.find_all('script'):
                    src = script.get('src')
                    if src:
                        # Resolve relative URLs
                        if src.startswith('//'):
                            full_url = f"{parsed.scheme}:{src}"
                        elif src.startswith('/'):
                            full_url = f"{base_url}{src}"
                        elif src.startswith('http'):
                            full_url = src
                        else:
                            full_url = f"{target_url.rsplit('/', 1)[0]}/{src}"
                        
                        # Filter external CDNs optionally (but include them for analysis)
                        self.js_files.add(full_url)
                        await event_manager.emit("log", f"[{self.name}] Found JS: {full_url}")
                    
                    # Also analyze inline scripts
                    if script.string and len(script.string) > 100:
                        # Store inline script with special marker
                        inline_key = f"{target_url}#inline-{hash(script.string) & 0xFFFFFFFF}"
                        self.js_files.add(inline_key)
                
        except Exception as e:
            await event_manager.emit("log", f"[{self.name}] Error discovering JS files: {e}")

    async def _analyze_js_file(self, js_url: str):
        """Analyze a single JavaScript file."""
        try:
            # Handle inline scripts
            if '#inline-' in js_url:
                # For inline scripts, we'd need to store the content separately
                # This is a simplified approach
                return
            
            await event_manager.emit("log", f"[{self.name}] Analyzing: {js_url}")
            
            async with self.context.session.get(js_url) as response:
                if response.status != 200:
                    await event_manager.emit("log", f"[{self.name}] Failed to fetch {js_url}: {response.status}")
                    return
                
                content = await response.text()
                
                if not content or len(content) < 50:
                    return
                
                analysis = JSFileAnalysis(url=js_url)
                
                # Run all analyzers
                await self._find_secrets(content, analysis)
                await self._find_endpoints(content, analysis)
                await self._find_storage_methods(content, analysis)
                await self._find_react_patterns(content, analysis)
                await self._find_vulnerabilities(content, analysis)
                await self._find_request_conditions(content, analysis)
                
                # Emit findings
                await self._emit_findings(analysis)
                
        except Exception as e:
            await event_manager.emit("log", f"[{self.name}] Error analyzing {js_url}: {e}")

    def _get_line_hint(self, content: str, match_start: int) -> str:
        """Get approximate line number for a match."""
        lines_before = content[:match_start].count('\n') + 1
        return f"~Line {lines_before}"

    def _get_context(self, content: str, match_start: int, match_end: int, context_chars: int = 100) -> str:
        """Get surrounding context for a match."""
        start = max(0, match_start - context_chars)
        end = min(len(content), match_end + context_chars)
        
        context = content[start:end]
        # Clean up the context
        context = ' '.join(context.split())
        
        if start > 0:
            context = '...' + context
        if end < len(content):
            context = context + '...'
        
        return context[:300]  # Limit context length

    async def _find_secrets(self, content: str, analysis: JSFileAnalysis):
        """Find secrets and API keys in JavaScript content."""
        for secret_type, pattern in self.secret_patterns.items():
            try:
                for match in re.finditer(pattern, content, re.IGNORECASE | re.MULTILINE):
                    value = match.group(0)
                    
                    # Skip false positives
                    if self._is_false_positive_secret(value, secret_type):
                        continue
                    
                    finding = JSFinding(
                        category="Secrets",
                        finding_type=secret_type,
                        value=value[:100] + ('...' if len(value) > 100 else ''),
                        context=self._get_context(content, match.start(), match.end()),
                        line_hint=self._get_line_hint(content, match.start()),
                        severity="P1",
                        remediation=f"Remove hardcoded {secret_type}. Use environment variables or a secrets manager.",
                        reproducibility=f"Search for '{value[:30]}...' in the JS file."
                    )
                    analysis.secrets.append(finding)
            except re.error:
                continue

    def _is_false_positive_secret(self, value: str, secret_type: str) -> bool:
        """Filter out common false positives."""
        # Skip placeholder values
        placeholder_patterns = [
            r'your[_-]?api[_-]?key',
            r'xxx+',
            r'placeholder',
            r'example',
            r'test',
            r'dummy',
            r'sample',
            r'\*{3,}',
        ]
        
        value_lower = value.lower()
        for pattern in placeholder_patterns:
            if re.search(pattern, value_lower):
                return True
        
        return False

    async def _find_endpoints(self, content: str, analysis: JSFileAnalysis):
        """Find API endpoints and URLs in JavaScript content."""
        seen_endpoints = set()
        
        for endpoint_type, pattern in self.endpoint_patterns.items():
            try:
                for match in re.finditer(pattern, content, re.IGNORECASE | re.MULTILINE):
                    # Extract the URL from the match
                    groups = match.groups()
                    value = groups[-1] if groups else match.group(0)
                    
                    # Clean up the value
                    value = value.strip('"\'` ')
                    
                    # Skip duplicates and invalid URLs
                    if value in seen_endpoints or len(value) < 3:
                        continue
                    
                    # Skip common false positives
                    if self._is_false_positive_endpoint(value):
                        continue
                    
                    seen_endpoints.add(value)
                    
                    finding = JSFinding(
                        category="Endpoints",
                        finding_type=endpoint_type,
                        value=value,
                        context=self._get_context(content, match.start(), match.end()),
                        line_hint=self._get_line_hint(content, match.start()),
                        severity="P4",
                        remediation="Review endpoint for proper authentication and authorization.",
                        reproducibility=f"Access endpoint: {value}"
                    )
                    analysis.endpoints.append(finding)
            except re.error:
                continue

    def _is_false_positive_endpoint(self, value: str) -> bool:
        """Filter out common false positive endpoints."""
        skip_patterns = [
            r'^/$',
            r'^/\.\*',
            r'googleapis\.com',
            r'fonts\.google',
            r'cdnjs\.cloudflare',
            r'unpkg\.com',
            r'jsdelivr\.net',
            r'^#',
            r'^javascript:',
            r'\.css$',
            r'\.png$',
            r'\.jpg$',
            r'\.svg$',
            r'\.woff',
        ]
        
        for pattern in skip_patterns:
            if re.search(pattern, value, re.IGNORECASE):
                return True
        
        return False

    async def _find_storage_methods(self, content: str, analysis: JSFileAnalysis):
        """Find storage method usage in JavaScript content."""
        for storage_type, pattern in self.storage_patterns.items():
            try:
                for match in re.finditer(pattern, content, re.MULTILINE):
                    groups = match.groups()
                    value = groups[0] if groups else match.group(0)
                    
                    finding = JSFinding(
                        category="Storage",
                        finding_type=storage_type,
                        value=value,
                        context=self._get_context(content, match.start(), match.end()),
                        line_hint=self._get_line_hint(content, match.start()),
                        severity="P4",
                        remediation="Ensure sensitive data is not stored in client-side storage without encryption.",
                        reproducibility=f"Check browser DevTools > Application > Storage for key: {value}"
                    )
                    analysis.storage_methods.append(finding)
            except re.error:
                continue

    async def _find_react_patterns(self, content: str, analysis: JSFileAnalysis):
        """Find React-specific patterns in JavaScript content."""
        for pattern_type, pattern in self.react_patterns.items():
            try:
                for match in re.finditer(pattern, content, re.MULTILINE):
                    groups = match.groups()
                    value = groups[0] if groups else match.group(0)
                    
                    finding = JSFinding(
                        category="React",
                        finding_type=pattern_type,
                        value=value[:100] if len(value) > 100 else value,
                        context=self._get_context(content, match.start(), match.end()),
                        line_hint=self._get_line_hint(content, match.start()),
                        severity="P4",
                        remediation="Review React patterns for security implications.",
                        reproducibility=f"Search for {pattern_type} pattern in component."
                    )
                    analysis.react_patterns.append(finding)
            except re.error:
                continue

    async def _find_vulnerabilities(self, content: str, analysis: JSFileAnalysis):
        """Find potential vulnerabilities in JavaScript content."""
        for vuln_type, (pattern, severity, remediation) in self.vuln_patterns.items():
            try:
                for match in re.finditer(pattern, content, re.IGNORECASE | re.MULTILINE):
                    value = match.group(0)
                    
                    finding = JSFinding(
                        category="Vulnerability",
                        finding_type=vuln_type,
                        value=value[:100] if len(value) > 100 else value,
                        context=self._get_context(content, match.start(), match.end()),
                        line_hint=self._get_line_hint(content, match.start()),
                        severity=severity,
                        remediation=remediation,
                        reproducibility=f"Locate {vuln_type} at {self._get_line_hint(content, match.start())} and verify exploitability."
                    )
                    analysis.vulnerabilities.append(finding)
            except re.error:
                continue

    async def _find_request_conditions(self, content: str, analysis: JSFileAnalysis):
        """Find request condition patterns in JavaScript content."""
        for condition_type, pattern in self.request_condition_patterns.items():
            try:
                for match in re.finditer(pattern, content, re.MULTILINE):
                    value = match.group(0)
                    
                    finding = JSFinding(
                        category="Request Conditions",
                        finding_type=condition_type,
                        value=value,
                        context=self._get_context(content, match.start(), match.end()),
                        line_hint=self._get_line_hint(content, match.start()),
                        severity="P4",
                        remediation="Review client-side access control logic for bypass opportunities.",
                        reproducibility=f"Analyze {condition_type} logic for potential bypass."
                    )
                    analysis.request_conditions.append(finding)
            except re.error:
                continue

    async def _emit_findings(self, analysis: JSFileAnalysis):
        """Emit all findings as vulnerabilities with clean formatting."""
        
        # Emit secrets (High Priority) - these use payload since they are actual secrets
        for finding in analysis.secrets:
            await self.emit_vulnerability(
                vuln_type="Secret Leaked",
                details=f"**{finding.finding_type}** found in JavaScript file.\n\n"
                       f"**Secret Value:** `{finding.value}`\n\n"
                       f"**Location:** {finding.line_hint}\n\n"
                       f"**Code Context:**\n```javascript\n{finding.context}\n```\n\n"
                       f"**How to Reproduce:** {finding.reproducibility}",
                severity=finding.severity,
                remediation=finding.remediation,
                url=analysis.url,
                payload=f"[{finding.finding_type}] {finding.value[:50]}..."  # Short identifier
            )
        
        # Emit vulnerabilities (Variable Priority)
        for finding in analysis.vulnerabilities:
            # Skip low-priority findings in production to reduce noise
            if finding.severity in ["P1", "P2", "P3"]:
                await self.emit_vulnerability(
                    vuln_type=f"JS Vulnerability: {finding.finding_type}",
                    details=f"**Issue:** {finding.finding_type}\n\n"
                           f"**Vulnerable Code:**\n```javascript\n{finding.value}\n```\n\n"
                           f"**Location:** {finding.line_hint}\n\n"
                           f"**Context:**\n```javascript\n{finding.context}\n```\n\n"
                           f"**How to Reproduce:** {finding.reproducibility}",
                    severity=finding.severity,
                    remediation=finding.remediation,
                    url=analysis.url,
                    payload=f"[{finding.finding_type}]"  # Just the type, not the code
                )
        
        # Emit endpoint summary (Info) - NO payload, just details
        if analysis.endpoints:
            # Format endpoints nicely
            endpoint_list = []
            for e in analysis.endpoints[:25]:
                endpoint_list.append(f"  • {e.value}")
            
            endpoints_formatted = "\n".join(endpoint_list)
            more_text = f"\n  ... and {len(analysis.endpoints) - 25} more endpoints" if len(analysis.endpoints) > 25 else ""
            
            await self.emit_vulnerability(
                vuln_type="API Endpoint Found",
                details=f"**{len(analysis.endpoints)} API endpoint(s) discovered in JavaScript:**\n\n"
                       f"```\n{endpoints_formatted}{more_text}\n```\n\n"
                       f"**How to Test:**\n"
                       f"1. Review each endpoint for authentication requirements\n"
                       f"2. Test with different HTTP methods (GET, POST, PUT, DELETE)\n"
                       f"3. Check for authorization bypass by accessing without credentials\n"
                       f"4. Look for IDOR vulnerabilities with parameter manipulation",
                severity="P4",
                remediation="Ensure all discovered endpoints have proper authentication and authorization. Implement rate limiting and input validation.",
                url=analysis.url,
                payload=None  # No payload for informational findings
            )
        
        # Emit storage summary (Info) - NO payload
        if analysis.storage_methods:
            storage_list = []
            for s in analysis.storage_methods[:20]:
                storage_list.append(f"  • [{s.finding_type}] {s.value}")
            
            storage_formatted = "\n".join(storage_list)
            
            await self.emit_vulnerability(
                vuln_type="Client Storage Usage",
                details=f"**{len(analysis.storage_methods)} storage operation(s) detected:**\n\n"
                       f"```\n{storage_formatted}\n```\n\n"
                       f"**Security Implications:**\n"
                       f"• Data in localStorage persists across sessions\n"
                       f"• sessionStorage is cleared when tab closes\n"
                       f"• Both are accessible via XSS attacks\n"
                       f"• Cookies may lack httpOnly protection\n\n"
                       f"**How to Verify:**\n"
                       f"Open DevTools → Application → Storage to view stored values",
                severity="P4",
                remediation="Avoid storing sensitive data (tokens, PII) in client-side storage. Use httpOnly cookies for session tokens.",
                url=analysis.url,
                payload=None
            )
        
        # Emit React patterns summary (Info) - NO payload  
        if analysis.react_patterns:
            react_list = []
            for r in analysis.react_patterns[:15]:
                react_list.append(f"  • {r.finding_type}: {r.value}")
            
            react_formatted = "\n".join(react_list)
            
            await self.emit_vulnerability(
                vuln_type="React Application Analysis",
                details=f"**React patterns detected ({len(analysis.react_patterns)} total):**\n\n"
                       f"```\n{react_formatted}\n```\n\n"
                       f"**Security Review Points:**\n"
                       f"• Check useEffect hooks for unvalidated API calls\n"
                       f"• Review Router paths for hidden admin routes\n"
                       f"• Ensure sensitive data isn't stored in React state\n"
                       f"• Verify Redux actions don't expose sensitive logic",
                severity="P4",
                remediation="Review React patterns for state management security. Ensure sensitive logic is server-side.",
                url=analysis.url,
                payload=None
            )
        
        # Emit request conditions (Info) - NO payload
        if analysis.request_conditions:
            conditions_list = []
            for c in analysis.request_conditions[:10]:
                conditions_list.append(f"  • {c.finding_type}")
            
            conditions_formatted = "\n".join(conditions_list)
            
            await self.emit_vulnerability(
                vuln_type="Client-Side Access Control",
                details=f"**Access control logic detected ({len(analysis.request_conditions)} patterns):**\n\n"
                       f"```\n{conditions_formatted}\n```\n\n"
                       f"**⚠️ WARNING:** Client-side access controls can be bypassed!\n\n"
                       f"**Bypass Techniques:**\n"
                       f"• Modify JavaScript variables in DevTools console\n"
                       f"• Edit localStorage/sessionStorage values\n"
                       f"• Intercept and modify requests with Burp Suite\n"
                       f"• Disable JavaScript and access routes directly\n\n"
                       f"**How to Test:**\n"
                       f"1. Identify role/permission checks in the code\n"
                       f"2. Set localStorage.isAdmin = true in console\n"
                       f"3. Navigate to restricted routes\n"
                       f"4. Verify server-side validation exists",
                severity="P4",
                remediation="Never rely solely on client-side access control. Always implement server-side authorization.",
                url=analysis.url,
                payload=None
            )

