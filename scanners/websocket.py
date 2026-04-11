"""
Lynx VAPT - WebSocket Security Scanner

Comprehensive WebSocket security testing:
- WebSocket endpoint discovery
- Connection and frame capture
- Sensitive operation identification
- Message fuzzing
- JWT/session leakage detection
- CSWSH (Cross-Site WebSocket Hijacking)
- Origin validation bypass

Author: Lynx Team
"""

import asyncio
import re
import json
from typing import Dict, List, Optional, Any, Set
from dataclasses import dataclass, field
from urllib.parse import urljoin, urlparse, urlencode

from scanners.base import BaseScanner
from common import event_manager, TestingZone


@dataclass
class WebSocketEndpoint:
    """Discovered WebSocket endpoint information."""
    url: str
    protocol: str = "wss"
    connected: bool = False
    messages_received: List[str] = field(default_factory=list)
    messages_sent: List[str] = field(default_factory=list)
    origin_required: bool = True
    subprotocols: List[str] = field(default_factory=list)


@dataclass
class WebSocketMessage:
    """A WebSocket message."""
    direction: str  # 'sent' or 'received'
    content: str
    timestamp: float = 0.0
    is_sensitive: bool = False
    sensitive_data: List[str] = field(default_factory=list)


class WebSocketScanner(BaseScanner):
    """
    WebSocket Security Scanner.
    
    Tests for:
    - WebSocket endpoint discovery
    - Origin validation bypass (CSWSH)
    - Message injection/fuzzing
    - Sensitive data leakage
    - Authentication bypass
    - Session hijacking potential
    """
    
    # Common WebSocket endpoint patterns
    WS_PATTERNS = [
        r'wss?://[^\s"\'<>]+',
        r'["\'](/ws[^\s"\'<>]*)["\']',
        r'["\'](/socket[^\s"\'<>]*)["\']',
        r'["\'](/websocket[^\s"\'<>]*)["\']',
        r'new\s+WebSocket\s*\(\s*["\']([^"\']+)["\']',
        r'socket\.io',
        r'Socket\.IO',
        r'io\s*\(',
    ]
    
    # Common WebSocket paths
    WS_PATHS = [
        "/ws",
        "/wss",
        "/websocket",
        "/socket.io",
        "/socket.io/",
        "/realtime",
        "/live",
        "/push",
        "/stream",
        "/api/ws",
        "/api/websocket",
        "/chat",
        "/notifications",
        "/events",
    ]
    
    # Sensitive data patterns
    SENSITIVE_PATTERNS = [
        (r'(?:password|passwd|pwd)[\s:="\']+([^\s\'"]+)', "password"),
        (r'(?:token|auth|jwt)[\s:="\']+([^\s\'"]{20,})', "token"),
        (r'(?:api[_-]?key|apikey)[\s:="\']+([^\s\'"]+)', "api_key"),
        (r'(?:secret)[\s:="\']+([^\s\'"]+)', "secret"),
        (r'(?:session[_-]?id)[\s:="\']+([^\s\'"]+)', "session_id"),
        (r'(?:credit.?card|cc.?num)[\s:="\']+(\d{13,19})', "credit_card"),
        (r'eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+', "jwt"),
    ]
    
    # Injection payloads for WebSocket fuzzing
    INJECTION_PAYLOADS = [
        '{"type":"admin","action":"getUsers"}',
        '{"__proto__":{"admin":true}}',
        '<script>alert(1)</script>',
        '{"$where":"1==1"}',
        '{"id":"1 OR 1=1"}',
        '../../../etc/passwd',
        '{"role":"admin"}',
        '{"isAdmin":true}',
    ]
    
    def __init__(self, context):
        super().__init__(context)
        self.name = "WebSocketScanner"
        self.zone = TestingZone.ZONE_D  # API Security
        self.endpoints: List[WebSocketEndpoint] = []
        self._ws_available = False
        
        # Check if websockets library is available
        try:
            import websockets
            self._ws_available = True
        except ImportError:
            pass
    
    async def run(self):
        """Run WebSocket security scan."""
        await event_manager.emit("log", f"[{self.name}] Starting WebSocket security scan...")
        
        if not self._ws_available:
            await event_manager.emit("log", 
                f"[{self.name}] websockets library not available, using HTTP-based detection only")
        
        # Discover WebSocket endpoints
        await self._discover_endpoints()
        
        if not self.endpoints:
            await event_manager.emit("log", f"[{self.name}] No WebSocket endpoints discovered")
            return
        
        await event_manager.emit("log", 
            f"[{self.name}] Found {len(self.endpoints)} WebSocket endpoint(s)")
        
        # Test each endpoint
        for endpoint in self.endpoints:
            await self._test_endpoint(endpoint)
    
    async def _discover_endpoints(self):
        """Discover WebSocket endpoints."""
        # Method 1: Parse pages for WebSocket URLs
        await self._discover_from_pages()
        
        # Method 2: Try common WebSocket paths
        await self._discover_common_paths()
    
    async def _discover_from_pages(self):
        """Discover WebSocket endpoints from page content."""
        urls_to_check = list(self.context.crawled_urls)
        if not urls_to_check:
            urls_to_check = [self.context.target]
        
        for url in urls_to_check[:20]:
            try:
                async with self.context.session.get(url, timeout=10) as response:
                    if response.status != 200:
                        continue
                    
                    text = await response.text()
                    
                    for pattern in self.WS_PATTERNS:
                        for match in re.finditer(pattern, text, re.I):
                            ws_url = match.group(1) if match.lastindex else match.group(0)
                            
                            # Convert relative URLs to absolute
                            if ws_url.startswith('/'):
                                parsed = urlparse(url)
                                protocol = 'wss' if parsed.scheme == 'https' else 'ws'
                                ws_url = f"{protocol}://{parsed.netloc}{ws_url}"
                            
                            # Skip if not a WebSocket URL
                            if not ws_url.startswith('ws://') and not ws_url.startswith('wss://'):
                                continue
                            
                            # Check if already found
                            if not any(e.url == ws_url for e in self.endpoints):
                                self.endpoints.append(WebSocketEndpoint(
                                    url=ws_url,
                                    protocol='wss' if ws_url.startswith('wss://') else 'ws'
                                ))
                                
            except Exception:
                continue
    
    async def _discover_common_paths(self):
        """Try common WebSocket paths."""
        parsed = urlparse(self.context.target)
        base_netloc = parsed.netloc
        
        for protocol in ['wss', 'ws']:
            for path in self.WS_PATHS:
                ws_url = f"{protocol}://{base_netloc}{path}"
                
                # Check if already found
                if any(e.url == ws_url for e in self.endpoints):
                    continue
                
                # Try to detect if endpoint exists
                if await self._check_ws_endpoint(ws_url):
                    self.endpoints.append(WebSocketEndpoint(
                        url=ws_url,
                        protocol=protocol
                    ))
    
    async def _check_ws_endpoint(self, ws_url: str) -> bool:
        """Check if a WebSocket endpoint exists."""
        # Convert ws:// to http:// for HTTP upgrade check
        http_url = ws_url.replace('wss://', 'https://').replace('ws://', 'http://')
        
        try:
            headers = {
                'Upgrade': 'websocket',
                'Connection': 'Upgrade',
                'Sec-WebSocket-Key': 'dGhlIHNhbXBsZSBub25jZQ==',
                'Sec-WebSocket-Version': '13'
            }
            
            async with self.context.session.get(
                http_url,
                headers=headers,
                timeout=5
            ) as response:
                # 101 = Switching Protocols (success)
                # 400/426 with specific headers = WS endpoint but upgrade needed
                if response.status == 101:
                    return True
                if response.status in [400, 426]:
                    if 'upgrade' in response.headers.get('Connection', '').lower():
                        return True
                        
        except Exception:
            pass
        
        return False
    
    async def _test_endpoint(self, endpoint: WebSocketEndpoint):
        """Run all tests on a WebSocket endpoint."""
        await self._test_origin_bypass(endpoint)
        await self._test_sensitive_leakage(endpoint)
        
        if self._ws_available:
            await self._test_message_injection(endpoint)
            await self._test_auth_bypass(endpoint)
    
    async def _test_origin_bypass(self, endpoint: WebSocketEndpoint):
        """Test for Cross-Site WebSocket Hijacking (CSWSH)."""
        # This is tested by checking if connection works without/with different Origin
        
        # Try HTTP upgrade with different origins
        http_url = endpoint.url.replace('wss://', 'https://').replace('ws://', 'http://')
        
        origins_to_test = [
            None,  # No origin
            "https://evil.com",
            "https://attacker.com",
            "null",
        ]
        
        for origin in origins_to_test:
            try:
                headers = {
                    'Upgrade': 'websocket',
                    'Connection': 'Upgrade',
                    'Sec-WebSocket-Key': 'dGhlIHNhbXBsZSBub25jZQ==',
                    'Sec-WebSocket-Version': '13'
                }
                
                if origin:
                    headers['Origin'] = origin
                
                async with self.context.session.get(
                    http_url,
                    headers=headers,
                    timeout=5
                ) as response:
                    if response.status == 101:
                        origin_str = origin or "None (missing)"
                        await self.emit_vulnerability(
                            "WebSocket Origin Bypass (CSWSH)",
                            f"WebSocket accepts connection with untrusted Origin.\n"
                            f"Endpoint: {endpoint.url}\n"
                            f"Origin used: {origin_str}\n"
                            f"This allows Cross-Site WebSocket Hijacking attacks.",
                            severity="P2",
                            remediation="Implement strict Origin header validation. Only allow trusted origins.",
                            url=endpoint.url,
                            payload=f"Origin: {origin_str}"
                        )
                        return
                        
            except Exception:
                continue
    
    async def _test_sensitive_leakage(self, endpoint: WebSocketEndpoint):
        """Check for sensitive data in WebSocket communications."""
        if not self._ws_available:
            return
        
        try:
            import websockets
            
            # Connect and listen for messages
            async with websockets.connect(
                endpoint.url,
                open_timeout=10,
                close_timeout=5
            ) as ws:
                endpoint.connected = True
                
                # Try to receive a few messages
                try:
                    for _ in range(5):
                        message = await asyncio.wait_for(ws.recv(), timeout=3)
                        endpoint.messages_received.append(message)
                        
                        # Check for sensitive data
                        sensitive_found = self._check_sensitive_data(message)
                        if sensitive_found:
                            await self.emit_vulnerability(
                                "WebSocket Sensitive Data Leakage",
                                f"Sensitive data detected in WebSocket message.\n"
                                f"Endpoint: {endpoint.url}\n"
                                f"Data types found: {', '.join(sensitive_found)}\n"
                                f"Message preview: {message[:200]}...",
                                severity="P2",
                                remediation="Encrypt sensitive data. Implement proper authorization for data access.",
                                url=endpoint.url,
                                payload=message[:100]
                            )
                            return
                            
                except asyncio.TimeoutError:
                    pass  # No messages within timeout
                    
        except Exception as e:
            await event_manager.emit("log", f"[{self.name}] WebSocket connection error: {e}")
    
    def _check_sensitive_data(self, message: str) -> List[str]:
        """Check message for sensitive data patterns."""
        found = []
        
        for pattern, data_type in self.SENSITIVE_PATTERNS:
            if re.search(pattern, message, re.I):
                found.append(data_type)
        
        return found
    
    async def _test_message_injection(self, endpoint: WebSocketEndpoint):
        """Test WebSocket message injection."""
        if not self._ws_available:
            return
        
        try:
            import websockets
            
            async with websockets.connect(
                endpoint.url,
                open_timeout=10,
                close_timeout=5
            ) as ws:
                for payload in self.INJECTION_PAYLOADS:
                    try:
                        await ws.send(payload)
                        
                        # Wait for response
                        try:
                            response = await asyncio.wait_for(ws.recv(), timeout=2)
                            
                            # Check if injection had effect
                            response_lower = response.lower()
                            
                            # Check for error disclosure
                            if any(ind in response_lower for ind in [
                                'sql', 'syntax error', 'exception', 'stack trace',
                                'error', 'admin', 'authorized'
                            ]):
                                await self.emit_vulnerability(
                                    "WebSocket Injection Vulnerability",
                                    f"WebSocket responds to injection payload.\n"
                                    f"Endpoint: {endpoint.url}\n"
                                    f"Payload: {payload}\n"
                                    f"Response: {response[:200]}",
                                    severity="P2",
                                    remediation="Validate and sanitize all WebSocket messages. Implement proper authorization.",
                                    url=endpoint.url,
                                    payload=payload
                                )
                                return
                                
                        except asyncio.TimeoutError:
                            continue
                            
                    except Exception:
                        continue
                        
        except Exception as e:
            await event_manager.emit("log", f"[{self.name}] Injection test error: {e}")
    
    async def _test_auth_bypass(self, endpoint: WebSocketEndpoint):
        """Test WebSocket authentication bypass."""
        if not self._ws_available:
            return
        
        # Try connecting without any authentication
        try:
            import websockets
            
            async with websockets.connect(
                endpoint.url,
                open_timeout=10,
                close_timeout=5
                # No auth headers/cookies
            ) as ws:
                # Send a request for privileged data
                admin_requests = [
                    '{"action":"getUsers"}',
                    '{"type":"admin","command":"list"}',
                    '{"request":"userData","all":true}',
                    '{"method":"admin.getAll"}',
                ]
                
                for request in admin_requests:
                    try:
                        await ws.send(request)
                        
                        try:
                            response = await asyncio.wait_for(ws.recv(), timeout=2)
                            
                            # Check if we got data (not an auth error)
                            response_lower = response.lower()
                            
                            if any(ind in response_lower for ind in [
                                'users', 'data', 'email', 'username', 'id'
                            ]) and not any(err in response_lower for err in [
                                'unauthorized', 'forbidden', 'authentication', 'login required'
                            ]):
                                await self.emit_vulnerability(
                                    "WebSocket Authentication Bypass",
                                    f"WebSocket allows unauthenticated access to data.\n"
                                    f"Endpoint: {endpoint.url}\n"
                                    f"Request: {request}\n"
                                    f"Response: {response[:200]}",
                                    severity="P1",
                                    remediation="Implement authentication for WebSocket connections. Validate session on every message.",
                                    url=endpoint.url,
                                    payload=request
                                )
                                return
                                
                        except asyncio.TimeoutError:
                            continue
                            
                    except Exception:
                        continue
                        
        except Exception as e:
            await event_manager.emit("log", f"[{self.name}] Auth bypass test error: {e}")
    
    def cleanup(self):
        """Cleanup scanner resources."""
        self.endpoints.clear()
