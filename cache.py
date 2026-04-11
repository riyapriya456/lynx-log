"""
Lynx VAPT - Response Caching Module

Features:
- LRU cache for HTTP responses
- Similar endpoint detection and caching
- Static asset caching
- TTL-based and pattern-based invalidation
- Memory-efficient storage

Author: Lynx Team
"""

import asyncio
import hashlib
import time
import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any, Tuple
from collections import OrderedDict
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse


@dataclass
class CachedResponse:
    """Cached HTTP response data."""
    url: str
    status_code: int
    headers: Dict[str, str]
    body: str
    content_type: str
    timestamp: float = field(default_factory=time.time)
    hits: int = 0
    size_bytes: int = 0
    
    @property
    def age(self) -> float:
        """Get age of cached response in seconds."""
        return time.time() - self.timestamp
    
    @property
    def is_html(self) -> bool:
        """Check if response is HTML."""
        return "text/html" in self.content_type.lower()
    
    @property
    def is_json(self) -> bool:
        """Check if response is JSON."""
        return "application/json" in self.content_type.lower()
    
    @property
    def is_static(self) -> bool:
        """Check if response is a static asset."""
        static_types = [
            "image/", "video/", "audio/", "font/",
            "text/css", "application/javascript", "text/javascript"
        ]
        return any(t in self.content_type.lower() for t in static_types)


class ResponseCache:
    """
    LRU cache for HTTP responses with intelligent features.
    
    Features:
    - Size-limited LRU eviction
    - TTL expiration
    - Similar endpoint deduplication
    - Static asset long-term caching
    """
    
    # Static file extensions for long-term caching
    STATIC_EXTENSIONS = {
        '.js', '.css', '.png', '.jpg', '.jpeg', '.gif', '.svg',
        '.woff', '.woff2', '.ttf', '.eot', '.ico', '.webp', '.mp4',
        '.mp3', '.pdf', '.zip'
    }
    
    # Default TTL values (in seconds)
    DEFAULT_TTL = 300  # 5 minutes
    STATIC_TTL = 3600  # 1 hour
    HTML_TTL = 60  # 1 minute (HTML changes more often)
    
    def __init__(
        self,
        max_size: int = 1000,
        max_memory_mb: float = 100.0,
        default_ttl: float = 300.0
    ):
        self.max_size = max_size
        self.max_memory_bytes = int(max_memory_mb * 1024 * 1024)
        self.default_ttl = default_ttl
        
        # LRU cache (OrderedDict for O(1) LRU operations)
        self._cache: OrderedDict[str, CachedResponse] = OrderedDict()
        
        # Similar endpoint mapping
        self._similar_map: Dict[str, str] = {}
        
        # Stats
        self.hits = 0
        self.misses = 0
        self.evictions = 0
        self.memory_evictions = 0
        self.size_evictions = 0
        self.total_memory_used = 0
        self.peak_memory_used = 0
        
        self._lock = asyncio.Lock()
    
    def _get_cache_key(self, url: str) -> str:
        """Generate a cache key for URL."""
        # Normalize URL
        parsed = urlparse(url)
        
        # Sort query parameters for consistent keys
        params = parse_qs(parsed.query)
        sorted_params = sorted(params.items())
        normalized_query = urlencode(sorted_params, doseq=True)
        
        normalized_url = urlunparse((
            parsed.scheme,
            parsed.netloc,
            parsed.path,
            "",
            normalized_query,
            ""
        ))
        
        return hashlib.md5(normalized_url.encode()).hexdigest()
    
    def _get_similar_key(self, url: str) -> str:
        """
        Generate a key for similar endpoint grouping.
        
        Similar endpoints are URLs that differ only in parameter values,
        not in structure. E.g., /api/user/1 and /api/user/2 are similar.
        """
        parsed = urlparse(url)
        
        # Replace numeric path segments with placeholder
        path_parts = parsed.path.split('/')
        normalized_parts = []
        for part in path_parts:
            if part.isdigit():
                normalized_parts.append('{id}')
            elif re.match(r'^[a-f0-9]{32}$', part, re.I):  # MD5
                normalized_parts.append('{hash}')
            elif re.match(r'^[a-f0-9]{64}$', part, re.I):  # SHA256
                normalized_parts.append('{hash}')
            elif re.match(r'^[a-f0-9\-]{36}$', part, re.I):  # UUID
                normalized_parts.append('{uuid}')
            else:
                normalized_parts.append(part)
        
        normalized_path = '/'.join(normalized_parts)
        
        # Get parameter names (not values)
        params = parse_qs(parsed.query)
        param_names = sorted(params.keys())
        
        return f"{parsed.netloc}:{normalized_path}:{','.join(param_names)}"
    
    def _get_ttl(self, cached: CachedResponse) -> float:
        """Get appropriate TTL for a cached response."""
        if cached.is_static:
            return self.STATIC_TTL
        elif cached.is_html:
            return self.HTML_TTL
        return self.default_ttl
    
    def _is_expired(self, cached: CachedResponse) -> bool:
        """Check if cached response is expired."""
        ttl = self._get_ttl(cached)
        return cached.age > ttl
    
    def _current_memory_usage(self) -> int:
        """Get current memory usage of cache."""
        return sum(c.size_bytes for c in self._cache.values())
    
    def _calculate_entry_memory(self, body: str, headers: Dict[str, str]) -> int:
        """Calculate actual memory footprint of a cache entry."""
        # Base size: body + headers + overhead
        memory = len(body.encode('utf-8'))
        memory += sum(len(k) + len(v) for k, v in headers.items())
        memory += 200  # Approximate overhead for object structure
        
        return memory
    
    async def _evict_if_needed(self):
        """Evict entries if cache is over limits with memory tracking."""
        current_memory = self._current_memory_usage()
        self.total_memory_used = current_memory
        
        # Update peak memory
        if current_memory > self.peak_memory_used:
            self.peak_memory_used = current_memory
        
        # Evict by count (LRU)
        evicted_by_size = 0
        while len(self._cache) >= self.max_size:
            if not self._cache:
                break
            # Remove oldest (LRU)
            oldest_key = next(iter(self._cache))
            oldest_entry = self._cache[oldest_key]
            del self._cache[oldest_key]
            self.evictions += 1
            self.size_evictions += 1
            evicted_by_size += 1
        
        # Evict by memory (with safety limit)
        evicted_by_memory = 0
        max_memory_evictions = 50  # Prevent excessive eviction in one call
        
        while (self._current_memory_usage() > self.max_memory_bytes and 
               self._cache and 
               evicted_by_memory < max_memory_evictions):
            # Find entry with largest memory footprint first
            largest_key = None
            largest_size = 0
            
            for key, entry in self._cache.items():
                if entry.size_bytes > largest_size:
                    largest_size = entry.size_bytes
                    largest_key = key
            
            if largest_key:
                del self._cache[largest_key]
                self.evictions += 1
                self.memory_evictions += 1
                evicted_by_memory += 1
            else:
                # Fallback to LRU if no size info
                oldest_key = next(iter(self._cache))
                del self._cache[oldest_key]
                self.evictions += 1
                self.memory_evictions += 1
                evicted_by_memory += 1
        
        # Log if we're consistently hitting memory limits
        if evicted_by_memory > 0:
            try:
                from common import DEBUG_ENABLED, debug_log
                if DEBUG_ENABLED:
                    debug_log(f"[CACHE] Memory eviction: {evicted_by_memory} entries, {current_memory / (1024*1024):.2f}MB used")
            except Exception:
                pass
    
    async def get(self, url: str) -> Optional[CachedResponse]:
        """
        Get cached response for URL.
        
        Args:
            url: The URL to look up
        
        Returns:
            CachedResponse if found and not expired, else None
        """
        async with self._lock:
            cache_key = self._get_cache_key(url)
            
            if cache_key in self._cache:
                cached = self._cache[cache_key]
                
                if self._is_expired(cached):
                    # Expired - remove and return None
                    del self._cache[cache_key]
                    self.misses += 1
                    return None
                
                # Move to end (most recently used)
                self._cache.move_to_end(cache_key)
                cached.hits += 1
                self.hits += 1
                return cached
            
            # Check similar endpoints
            similar_key = self._get_similar_key(url)
            if similar_key in self._similar_map:
                original_cache_key = self._similar_map[similar_key]
                if original_cache_key in self._cache:
                    # We have a similar cached response
                    # This is useful for detecting redundant scans
                    pass
            
            self.misses += 1
            return None
    
    async def set(
        self,
        url: str,
        response: Any,  # aiohttp.ClientResponse or similar
        body: str
    ) -> bool:
        """
        Cache a response with memory tracking.
        
        Args:
            url: The URL
            response: The HTTP response object
            body: The response body text
        
        Returns:
            True if cached, False if skipped
        """
        # Skip caching large responses
        if len(body) > 5 * 1024 * 1024:  # 5MB limit
            return False
        
        # Skip caching error responses (except 404 which is useful)
        status = response.status if hasattr(response, 'status') else 200
        if status >= 400 and status != 404:
            return False
        
        async with self._lock:
            await self._evict_if_needed()
            
            cache_key = self._get_cache_key(url)
            content_type = ""
            headers = {}
            
            if hasattr(response, 'headers'):
                headers = dict(response.headers)
                content_type = headers.get('content-type', '')
            
            # Calculate actual memory footprint
            size_bytes = self._calculate_entry_memory(body, headers)
            
            # Additional safety check: skip if single entry is too large
            if size_bytes > self.max_memory_bytes * 0.5:  # Entry > 50% of cache
                return False
            
            cached = CachedResponse(
                url=url,
                status_code=status,
                headers=headers,
                body=body,
                content_type=content_type,
                size_bytes=size_bytes
            )
            
            self._cache[cache_key] = cached
            
            # Update memory tracking
            current_memory = self._current_memory_usage()
            self.total_memory_used = current_memory
            if current_memory > self.peak_memory_used:
                self.peak_memory_used = current_memory
            
            # Track similar endpoints
            similar_key = self._get_similar_key(url)
            if similar_key not in self._similar_map:
                self._similar_map[similar_key] = cache_key
            
            return True
    
    async def invalidate(self, url: str):
        """Invalidate a specific cached URL."""
        async with self._lock:
            cache_key = self._get_cache_key(url)
            if cache_key in self._cache:
                del self._cache[cache_key]
    
    async def invalidate_pattern(self, pattern: str):
        """Invalidate all URLs matching a regex pattern."""
        async with self._lock:
            regex = re.compile(pattern)
            to_remove = [
                key for key, cached in self._cache.items()
                if regex.search(cached.url)
            ]
            for key in to_remove:
                del self._cache[key]
    
    async def clear(self):
        """Clear entire cache."""
        async with self._lock:
            self._cache.clear()
            self._similar_map.clear()
    
    def get_stats(self) -> Dict[str, Any]:
        """Get cache statistics with memory tracking."""
        total_requests = self.hits + self.misses
        hit_rate = self.hits / total_requests if total_requests > 0 else 0
        current_memory = self._current_memory_usage()
        
        return {
            "entries": len(self._cache),
            "max_entries": self.max_size,
            "memory_mb": current_memory / (1024 * 1024),
            "max_memory_mb": self.max_memory_bytes / (1024 * 1024),
            "peak_memory_mb": self.peak_memory_used / (1024 * 1024),
            "total_memory_used_mb": self.total_memory_used / (1024 * 1024),
            "memory_utilization": f"{(current_memory / self.max_memory_bytes) * 100:.1f}%",
            "hits": self.hits,
            "misses": self.misses,
            "hit_rate": f"{hit_rate:.1%}",
            "evictions": self.evictions,
            "evictions_by_size": self.size_evictions,
            "evictions_by_memory": self.memory_evictions,
            "similar_endpoints": len(self._similar_map)
        }


class SimilarEndpointDetector:
    """
    Detect and track similar endpoints to avoid redundant scanning.
    
    This helps reduce noise from scanning the same endpoint pattern
    multiple times (e.g., /user/1, /user/2, /user/3).
    """
    
    def __init__(self, max_similar_scans: int = 3):
        self.max_similar_scans = max_similar_scans
        self._patterns: Dict[str, List[str]] = {}
        self._lock = asyncio.Lock()
    
    def _get_pattern(self, url: str) -> str:
        """Generate a pattern key for the URL."""
        parsed = urlparse(url)
        
        # Normalize path by replacing variable parts
        path = parsed.path
        
        # Replace numeric segments
        path = re.sub(r'/\d+', '/{num}', path)
        
        # Replace UUID-like segments
        path = re.sub(r'/[a-f0-9\-]{36}', '/{uuid}', path, flags=re.I)
        
        # Replace hash-like segments (32 or 64 hex chars)
        path = re.sub(r'/[a-f0-9]{32,64}', '/{hash}', path, flags=re.I)
        
        # Get query param structure
        params = parse_qs(parsed.query)
        param_keys = sorted(params.keys())
        
        return f"{parsed.netloc}:{path}:{','.join(param_keys)}"
    
    async def should_scan(self, url: str) -> Tuple[bool, str]:
        """
        Check if URL should be scanned based on similar endpoint tracking.
        
        Returns:
            (should_scan, reason): Tuple of boolean and explanation
        """
        async with self._lock:
            pattern = self._get_pattern(url)
            
            if pattern not in self._patterns:
                self._patterns[pattern] = [url]
                return True, "First occurrence of this endpoint pattern"
            
            similar_urls = self._patterns[pattern]
            
            if len(similar_urls) >= self.max_similar_scans:
                return False, f"Already scanned {len(similar_urls)} similar endpoints"
            
            similar_urls.append(url)
            return True, f"Scanning ({len(similar_urls)}/{self.max_similar_scans} similar)"
    
    async def get_similar_urls(self, url: str) -> List[str]:
        """Get all similar URLs that have been seen."""
        async with self._lock:
            pattern = self._get_pattern(url)
            return self._patterns.get(pattern, [])
    
    def get_stats(self) -> Dict[str, Any]:
        """Get detector statistics."""
        return {
            "unique_patterns": len(self._patterns),
            "total_urls": sum(len(urls) for urls in self._patterns.values()),
            "patterns_at_limit": sum(
                1 for urls in self._patterns.values()
                if len(urls) >= self.max_similar_scans
            )
        }


class StaticAssetFilter:
    """
    Filter out static assets that don't need security scanning.
    
    Static assets like images, fonts, and stylesheets rarely have
    security implications and can be skipped to save time.
    """
    
    STATIC_EXTENSIONS = {
        # Images
        '.png', '.jpg', '.jpeg', '.gif', '.svg', '.ico', '.webp', '.bmp', '.tiff',
        # Fonts
        '.woff', '.woff2', '.ttf', '.eot', '.otf',
        # Media
        '.mp4', '.mp3', '.webm', '.ogg', '.wav', '.avi', '.mov',
        # Documents (usually not injectable)
        '.pdf', '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx',
        # Archives
        '.zip', '.rar', '.7z', '.tar', '.gz',
        # Other
        '.map', '.wasm'
    }
    
    # CSS and JS are sometimes worth scanning (inline XSS, secrets)
    SEMI_STATIC_EXTENSIONS = {'.css', '.js'}
    
    # Paths that indicate static content
    STATIC_PATH_PATTERNS = [
        r'/static/',
        r'/assets/',
        r'/images/',
        r'/img/',
        r'/css/',
        r'/fonts/',
        r'/media/',
        r'/uploads/',  # Be careful - uploads might be exploitable
        r'/vendor/',
        r'/node_modules/',
        r'/bower_components/',
    ]
    
    def __init__(self, skip_semi_static: bool = False):
        self.skip_semi_static = skip_semi_static
        self._path_regex = re.compile('|'.join(self.STATIC_PATH_PATTERNS), re.I)
    
    def is_static(self, url: str) -> Tuple[bool, str]:
        """
        Check if URL points to a static asset.
        
        Returns:
            (is_static, reason): Tuple of boolean and explanation
        """
        parsed = urlparse(url)
        path = parsed.path.lower()
        
        # Check extension
        for ext in self.STATIC_EXTENSIONS:
            if path.endswith(ext):
                return True, f"Static asset extension: {ext}"
        
        # Check semi-static if configured
        if self.skip_semi_static:
            for ext in self.SEMI_STATIC_EXTENSIONS:
                if path.endswith(ext):
                    return True, f"Semi-static asset: {ext}"
        
        # Check path patterns
        if self._path_regex.search(path):
            match = self._path_regex.search(path)
            return True, f"Static path pattern: {match.group()}"
        
        return False, "Not a static asset"
    
    def filter_urls(self, urls: List[str]) -> Tuple[List[str], List[str]]:
        """
        Filter a list of URLs into dynamic and static categories.
        
        Returns:
            (dynamic_urls, static_urls): Two lists
        """
        dynamic = []
        static = []
        
        for url in urls:
            is_static, _ = self.is_static(url)
            if is_static:
                static.append(url)
            else:
                dynamic.append(url)
        
        return dynamic, static
