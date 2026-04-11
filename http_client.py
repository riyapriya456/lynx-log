"""
Lynx VAPT - Enhanced HTTP Client Module

Features:
- Adaptive concurrency control (auto-adjust based on server response)
- Intelligent rate limiting (429/503 detection, WAF evasion)
- Connection pooling with persistent connections
- Random jitter delays to avoid pattern detection
- WAF signature detection and bypass strategies

Author: Lynx Team
"""

import asyncio
import aiohttp
import random
import time
import hashlib
import ssl
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Callable, Any
from collections import deque
from enum import Enum

from common import event_manager


class WAFStatus(Enum):
    """WAF detection status."""
    NONE = "none"
    SUSPECTED = "suspected"
    CONFIRMED = "confirmed"
    BLOCKING = "blocking"


@dataclass
class ResponseMetrics:
    """Metrics collected from HTTP responses."""
    url: str
    status_code: int
    response_time: float
    content_length: int
    timestamp: float = field(default_factory=time.time)
    is_cached: bool = False
    waf_detected: bool = False


class AdaptiveConcurrencyController:
    """
    Dynamically adjusts concurrency based on server response times and errors.
    
    Strategy:
    - Start at initial concurrency (default: 15)
    - Increase when responses are fast and successful
    - Decrease when seeing throttling (429), errors (5xx), or slow responses
    - Respect min/max bounds
    """
    
    def __init__(
        self,
        initial: int = 15,
        min_concurrency: int = 3,
        max_concurrency: int = 50,
        window_size: int = 50,
        target_latency_ms: float = 500.0,
        max_latency_ms: float = 2000.0
    ):
        self.current = initial
        self.min_concurrency = min_concurrency
        self.max_concurrency = max_concurrency
        self.window_size = window_size
        self.target_latency_ms = target_latency_ms
        self.max_latency_ms = max_latency_ms
        
        # Sliding window for metrics
        self.latencies: deque = deque(maxlen=window_size)
        self.error_counts: deque = deque(maxlen=window_size)
        
        # Semaphore for concurrency control
        self._semaphore: Optional[asyncio.Semaphore] = None
        self._lock = asyncio.Lock()
        
        # Adjustment tracking
        self.last_adjustment = time.time()
        self.adjustment_cooldown = 2.0  # seconds
    
    @property
    def semaphore(self) -> asyncio.Semaphore:
        """Get or create the semaphore with current concurrency."""
        if self._semaphore is None:
            self._semaphore = asyncio.Semaphore(self.current)
        return self._semaphore
    
    async def record_response(self, metrics: ResponseMetrics):
        """Record response metrics and potentially adjust concurrency."""
        self.latencies.append(metrics.response_time * 1000)  # Convert to ms
        
        # Track errors
        is_error = metrics.status_code >= 500 or metrics.status_code == 429
        self.error_counts.append(1 if is_error else 0)
        
        # Adjust if cooldown passed
        if time.time() - self.last_adjustment > self.adjustment_cooldown:
            await self._adjust_concurrency()
    
    async def _adjust_concurrency(self):
        """Adjust concurrency based on collected metrics."""
        if len(self.latencies) < 10:
            return  # Not enough data
        
        async with self._lock:
            avg_latency = sum(self.latencies) / len(self.latencies)
            error_rate = sum(self.error_counts) / len(self.error_counts)
            
            old_concurrency = self.current
            
            # High error rate - decrease aggressively
            if error_rate > 0.3:
                self.current = max(self.min_concurrency, int(self.current * 0.5))
                await event_manager.emit("log", f"[HTTP] High error rate ({error_rate:.1%}), reducing concurrency to {self.current}")
            
            # Very slow responses - decrease
            elif avg_latency > self.max_latency_ms:
                self.current = max(self.min_concurrency, int(self.current * 0.7))
                await event_manager.emit("log", f"[HTTP] Slow responses ({avg_latency:.0f}ms), reducing concurrency to {self.current}")
            
            # Moderate latency - hold steady
            elif avg_latency > self.target_latency_ms:
                pass  # Keep current
            
            # Fast responses and low error rate - increase
            elif avg_latency < self.target_latency_ms and error_rate < 0.05:
                self.current = min(self.max_concurrency, int(self.current * 1.2))
                if self.current != old_concurrency:
                    await event_manager.emit("log", f"[HTTP] Good performance, increasing concurrency to {self.current}")
            
            # Recreate semaphore if changed (for future requests)
            if self.current != old_concurrency:
                self._semaphore = asyncio.Semaphore(self.current)
                self.last_adjustment = time.time()
    
    def get_stats(self) -> Dict[str, Any]:
        """Get current performance statistics."""
        return {
            "current_concurrency": self.current,
            "avg_latency_ms": sum(self.latencies) / len(self.latencies) if self.latencies else 0,
            "error_rate": sum(self.error_counts) / len(self.error_counts) if self.error_counts else 0,
            "samples": len(self.latencies)
        }


class WAFDetector:
    """
    Detects Web Application Firewall presence and blocking.
    
    Detection methods:
    - Response patterns (403 with specific bodies)
    - Known WAF signatures in headers/body
    - Behavioral patterns (sudden blocks after payloads)
    """
    
    WAF_SIGNATURES = {
        "cloudflare": [
            "cloudflare", "cf-ray", "cf-request-id", "__cfduid",
            "attention required", "cloudflare ray id"
        ],
        "akamai": [
            "akamai", "ak_bmsc", "bm_sv", "akamaighost"
        ],
        "aws_waf": [
            "awswaf", "x-amzn-requestid", "x-amz-cf-id"
        ],
        "imperva": [
            "imperva", "incap_ses", "visid_incap", "incapsula"
        ],
        "f5_big_ip": [
            "bigip", "f5-", "ts=", "lastmrh_loc"
        ],
        "sucuri": [
            "sucuri", "x-sucuri-id", "x-sucuri-cache"
        ],
        "wordfence": [
            "wordfence", "wfwaf-authcookie"
        ],
        "modsecurity": [
            "mod_security", "modsecurity", "noyb"
        ],
    }
    
    BLOCK_PATTERNS = [
        "access denied", "forbidden", "blocked", "security",
        "not allowed", "threat detected", "suspicious activity",
        "rate limit", "too many requests", "captcha"
    ]
    
    def __init__(self):
        self.status = WAFStatus.NONE
        self.detected_waf: Optional[str] = None
        self.block_count = 0
        self.last_block_time: Optional[float] = None
    
    def analyze_response(
        self,
        status_code: int,
        headers: Dict[str, str],
        body: str
    ) -> WAFStatus:
        """Analyze response for WAF signatures."""
        headers_lower = {k.lower(): v.lower() for k, v in headers.items()}
        body_lower = body.lower()[:5000]  # Check first 5KB
        
        # Check for WAF signatures
        for waf_name, signatures in self.WAF_SIGNATURES.items():
            for sig in signatures:
                if any(sig in v for v in headers_lower.values()) or sig in body_lower:
                    self.detected_waf = waf_name
                    if status_code in [403, 406, 429, 503]:
                        self.status = WAFStatus.BLOCKING
                        self.block_count += 1
                        self.last_block_time = time.time()
                    else:
                        self.status = WAFStatus.CONFIRMED
                    return self.status
        
        # Check for generic blocking patterns
        if status_code in [403, 406, 429, 503]:
            for pattern in self.BLOCK_PATTERNS:
                if pattern in body_lower:
                    self.status = WAFStatus.SUSPECTED
                    self.block_count += 1
                    self.last_block_time = time.time()
                    return self.status
        
        return WAFStatus.NONE
    
    def should_backoff(self) -> bool:
        """Check if we should back off due to WAF blocking."""
        if self.status == WAFStatus.BLOCKING and self.block_count > 5:
            return True
        if self.last_block_time and time.time() - self.last_block_time < 30:
            return self.block_count > 10
        return False
    
    def get_recommended_delay(self) -> float:
        """Get recommended delay based on WAF status."""
        if self.status == WAFStatus.BLOCKING:
            return min(30.0, 2.0 ** min(self.block_count, 5))
        elif self.status == WAFStatus.CONFIRMED:
            return 1.0
        elif self.status == WAFStatus.SUSPECTED:
            return 0.5
        return 0.0


class IntelligentRateLimiter:
    """
    Dynamic rate limiting based on server responses.
    
    Features:
    - Exponential backoff on 429/503
    - Random jitter to avoid pattern detection
    - Per-host rate limiting
    - Recovery detection
    """
    
    def __init__(
        self,
        base_delay: float = 0.1,
        max_delay: float = 30.0,
        jitter_range: tuple = (0.1, 0.5)
    ):
        self.base_delay = base_delay
        self.max_delay = max_delay
        self.jitter_range = jitter_range
        
        # Per-host tracking
        self.host_delays: Dict[str, float] = {}
        self.host_errors: Dict[str, int] = {}
        self.host_last_request: Dict[str, float] = {}
        
        self._lock = asyncio.Lock()
    
    def _get_host(self, url: str) -> str:
        """Extract host from URL."""
        from urllib.parse import urlparse
        return urlparse(url).netloc
    
    async def wait_if_needed(self, url: str):
        """Wait before making request if rate limiting is needed."""
        host = self._get_host(url)
        
        async with self._lock:
            current_delay = self.host_delays.get(host, 0)
            last_request = self.host_last_request.get(host, 0)
            
            if current_delay > 0:
                elapsed = time.time() - last_request
                if elapsed < current_delay:
                    wait_time = current_delay - elapsed
                    # Add jitter
                    jitter = random.uniform(*self.jitter_range)
                    wait_time += jitter
                    
                    await event_manager.emit("log", f"[RateLimit] Waiting {wait_time:.2f}s for {host}")
                    await asyncio.sleep(wait_time)
            
            self.host_last_request[host] = time.time()
    
    async def record_response(self, url: str, status_code: int, response_time: float):
        """Update rate limiting based on response."""
        host = self._get_host(url)
        
        async with self._lock:
            if status_code == 429 or status_code == 503:
                # Exponential backoff
                current_errors = self.host_errors.get(host, 0) + 1
                self.host_errors[host] = current_errors
                
                new_delay = min(
                    self.max_delay,
                    self.base_delay * (2 ** current_errors)
                )
                self.host_delays[host] = new_delay
                
                await event_manager.emit("log", f"[RateLimit] {status_code} from {host}, backing off {new_delay:.1f}s")
            
            elif status_code < 400:
                # Successful response - gradually reduce delay
                if host in self.host_delays:
                    self.host_delays[host] = max(0, self.host_delays[host] * 0.8)
                if host in self.host_errors:
                    self.host_errors[host] = max(0, self.host_errors[host] - 1)
    
    def get_stats(self) -> Dict[str, Any]:
        """Get rate limiting statistics."""
        return {
            "hosts_with_delays": len([h for h, d in self.host_delays.items() if d > 0]),
            "total_hosts": len(self.host_delays),
            "max_current_delay": max(self.host_delays.values()) if self.host_delays else 0
        }


class EnhancedHTTPClient:
    """
    Enhanced HTTP client with all performance features integrated.
    
    Features:
    - Adaptive concurrency
    - Intelligent rate limiting
    - WAF detection
    - Response caching (via cache module)
    - Connection pooling
    """
    
    def __init__(
        self,
        concurrency_controller: Optional[AdaptiveConcurrencyController] = None,
        rate_limiter: Optional[IntelligentRateLimiter] = None,
        waf_detector: Optional[WAFDetector] = None,
        cache: Optional[Any] = None,  # ResponseCache from cache module
        timeout: float = 30.0,
        max_connections: int = 100,
        max_connections_per_host: int = 10
    ):
        self.concurrency = concurrency_controller or AdaptiveConcurrencyController()
        self.rate_limiter = rate_limiter or IntelligentRateLimiter()
        self.waf_detector = waf_detector or WAFDetector()
        self.cache = cache
        
        self.timeout = aiohttp.ClientTimeout(total=timeout, connect=10, sock_read=20)
        # Create strict SSL context for security
        self.ssl_context = ssl.create_default_context()
        self.ssl_context.check_hostname = True
        self.ssl_context.verify_mode = ssl.CERT_REQUIRED
        
        self.connector_config = {
            "limit": max_connections,
            "limit_per_host": max_connections_per_host,
            "ttl_dns_cache": 300,
            "force_close": False,
            "enable_cleanup_closed": True,
            "ssl": self.ssl_context  # Enforce SSL verification
        }
        
        self._session: Optional[aiohttp.ClientSession] = None
        self._trace_config: Optional[aiohttp.TraceConfig] = None
    
    async def get_session(self) -> aiohttp.ClientSession:
        """Get or create the HTTP session with strict SSL verification."""
        if self._session is None or self._session.closed:
            # Create trace config for request monitoring
            self._trace_config = aiohttp.TraceConfig()
            self._trace_config.on_request_start.append(self._on_request_start)
            self._trace_config.on_request_end.append(self._on_request_end)
            
            # Create connector with SSL context
            connector = aiohttp.TCPConnector(**self.connector_config)
            
            self._session = aiohttp.ClientSession(
                connector=connector,
                timeout=self.timeout,
                trace_configs=[self._trace_config]
            )
        return self._session
    
    async def _on_request_start(self, session, trace_config_ctx, params):
        """Track request start."""
        trace_config_ctx.start_time = time.time()
        await event_manager.emit("net_request_start", str(params.url))
    
    async def _on_request_end(self, session, trace_config_ctx, params):
        """Track request end and update metrics."""
        response_time = time.time() - trace_config_ctx.start_time
        
        metrics = ResponseMetrics(
            url=str(params.url),
            status_code=params.response.status,
            response_time=response_time,
            content_length=int(params.response.headers.get("content-length", 0))
        )
        
        await self.concurrency.record_response(metrics)
        await self.rate_limiter.record_response(
            str(params.url),
            params.response.status,
            response_time
        )
        
        await event_manager.emit("net_request_end", {
            "url": str(params.url),
            "status": params.response.status,
            "time": response_time
        })
    
    async def request(
        self,
        method: str,
        url: str,
        headers: Optional[Dict] = None,
        data: Optional[Any] = None,
        json: Optional[Dict] = None,
        allow_cache: bool = True,
        **kwargs
    ) -> Optional[aiohttp.ClientResponse]:
        """
        Make an HTTP request with intelligent concurrency, rate limiting, and WAF detection.
        
        Returns:
            Response object or None if failed
        """
        # Validate URL to prevent command injection
        if not url or not isinstance(url, str):
            await event_manager.emit("log", f"[ERROR] Invalid URL: {url}")
            return None
        
        # Check cache for GET requests
        if method.upper() == "GET" and allow_cache and self.cache:
            cached = await self.cache.get(url)
            if cached:
                return cached
        
        # Wait for rate limit
        await self.rate_limiter.wait_if_needed(url)
        
        # Check WAF status
        if self.waf_detector.should_backoff():
            delay = self.waf_detector.get_recommended_delay()
            await event_manager.emit("log", f"[WAF] Backing off {delay:.1f}s due to detected WAF blocking")
            await asyncio.sleep(delay)
        
        # Use concurrency semaphore
        async with self.concurrency.semaphore:
            try:
                session = await self.get_session()
                
                # Add explicit SSL verification to kwargs
                if 'ssl' not in kwargs:
                    kwargs['ssl'] = self.ssl_context
                
                async with session.request(
                    method,
                    url,
                    headers=headers,
                    data=data,
                    json=json,
                    **kwargs
                ) as response:
                    # Read body for WAF detection
                    body = await response.text()
                    
                    # Check for WAF
                    waf_status = self.waf_detector.analyze_response(
                        response.status,
                        dict(response.headers),
                        body
                    )
                    
                    if waf_status == WAFStatus.BLOCKING:
                        await event_manager.emit("log", f"[WAF] Detected blocking by {self.waf_detector.detected_waf or 'unknown WAF'}")
                    
                    # Cache successful GET responses
                    if method.upper() == "GET" and response.status == 200 and self.cache:
                        await self.cache.set(url, response, body)
                    
                    # Return a wrapper that includes the body
                    try:
                        response._cached_body = body
                    except AttributeError:
                        pass
                    return response
                    
            except aiohttp.ClientError as e:
                await event_manager.emit("net_request_error", {"url": url, "error": str(e)})
                return None
            except asyncio.TimeoutError:
                await event_manager.emit("net_request_error", {"url": url, "error": "Timeout"})
                return None
            except ssl.SSLError as e:
                await event_manager.emit("log", f"[red][SSL Error] {url}: {e}[/red]")
                await event_manager.emit("net_request_error", {"url": url, "error": f"SSL: {e}"})
                return None
            except Exception as e:
                await event_manager.emit("log", f"[red][ERROR] Unexpected error on {url}: {e}[/red]")
                await event_manager.emit("net_request_error", {"url": url, "error": str(e)})
                return None
    
    async def get(self, url: str, **kwargs):
        """Convenience method for GET requests."""
        return await self.request("GET", url, **kwargs)
    
    async def post(self, url: str, **kwargs):
        """Convenience method for POST requests."""
        return await self.request("POST", url, **kwargs)
    
    async def close(self):
        """Close the HTTP session."""
        if self._session and not self._session.closed:
            await self._session.close()
    
    def get_stats(self) -> Dict[str, Any]:
        """Get comprehensive client statistics."""
        return {
            "concurrency": self.concurrency.get_stats(),
            "rate_limiting": self.rate_limiter.get_stats(),
            "waf": {
                "status": self.waf_detector.status.value,
                "detected": self.waf_detector.detected_waf,
                "blocks": self.waf_detector.block_count
            }
        }


async def create_enhanced_session(
    initial_concurrency: int = 15,
    enable_cache: bool = True
) -> EnhancedHTTPClient:
    """
    Factory function to create an enhanced HTTP client.
    
    Args:
        initial_concurrency: Starting concurrency level
        enable_cache: Whether to enable response caching
    
    Returns:
        Configured EnhancedHTTPClient
    """
    concurrency = AdaptiveConcurrencyController(initial=initial_concurrency)
    rate_limiter = IntelligentRateLimiter()
    waf_detector = WAFDetector()
    
    cache = None
    if enable_cache:
        try:
            from cache import ResponseCache
            cache = ResponseCache()
        except ImportError:
            pass
    
    client = EnhancedHTTPClient(
        concurrency_controller=concurrency,
        rate_limiter=rate_limiter,
        waf_detector=waf_detector,
        cache=cache
    )
    
    return client
