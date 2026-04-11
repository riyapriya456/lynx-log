"""
Lynx VAPT - Incremental Crawler

Batch-based crawling with scan integration:
- Crawl small batches → scan → continue fetch
- Prevent huge URL queues blocking core tasks
- Priority-based URL ordering
- Depth-first vs breadth-first options

Author: Lynx Team
"""

import asyncio
import re
from typing import Dict, List, Optional, Any, Set, Callable, AsyncIterator
from dataclasses import dataclass, field
from urllib.parse import urljoin, urlparse, urlunparse
from collections import deque
from enum import Enum
import time


class CrawlPriority(Enum):
    """URL priority for crawling."""
    HIGH = 1      # API endpoints, auth pages
    MEDIUM = 2    # Forms, dynamic pages
    LOW = 3       # Static content
    SKIP = 99     # Assets to skip


@dataclass
class CrawlItem:
    """A URL to crawl with metadata."""
    url: str
    depth: int = 0
    priority: CrawlPriority = CrawlPriority.MEDIUM
    parent_url: Optional[str] = None
    discovered_at: float = field(default_factory=time.time)
    
    def __lt__(self, other):
        return self.priority.value < other.priority.value


@dataclass 
class CrawlBatch:
    """A batch of crawled URLs ready for scanning."""
    urls: List[str]
    batch_number: int
    crawl_depth: int
    total_discovered: int


class IncrementalCrawler:
    """
    Incremental Crawler that yields batches for scanning.
    
    Features:
    - Batch-based crawling (process N URLs, yield, continue)
    - Priority queue (API endpoints first)
    - Depth limiting
    - Duplicate detection
    - Scope filtering
    - Integration with scanning pipeline
    """
    
    # High priority patterns (API, auth)
    HIGH_PRIORITY_PATTERNS = [
        r'/api/', r'/v\d+/', r'/graphql', r'/rest/',
        r'/auth', r'/login', r'/admin', r'/user',
        r'/account', r'/profile', r'/settings',
        r'/upload', r'/file', r'/download',
    ]
    
    # Skip patterns (static assets)
    SKIP_PATTERNS = [
        r'\.(css|js|png|jpg|jpeg|gif|ico|svg|woff|woff2|ttf|eot)(\?|$)',
        r'\.(pdf|doc|docx|xls|xlsx|zip|tar|gz)(\?|$)',
        r'/static/', r'/assets/', r'/images/', r'/fonts/',
        r'cdn\.', r'fonts\.googleapis', r'ajax\.googleapis',
    ]
    
    # Medium priority (forms, dynamic)
    MEDIUM_PRIORITY_PATTERNS = [
        r'\?', r'\.php', r'\.asp', r'\.jsp',
        r'/search', r'/query', r'/form',
    ]
    
    def __init__(
        self,
        session,
        base_url: str,
        max_depth: int = 3,
        batch_size: int = 10,
        max_urls: int = 500,
        respect_robots: bool = True,
        scope_pattern: Optional[str] = None
    ):
        self.session = session
        self.base_url = base_url
        self.base_domain = urlparse(base_url).netloc
        self.max_depth = max_depth
        self.batch_size = batch_size
        self.max_urls = max_urls
        self.respect_robots = respect_robots
        self.scope_pattern = re.compile(scope_pattern) if scope_pattern else None
        
        # State
        self.visited: Set[str] = set()
        self.queue: List[CrawlItem] = []
        self.discovered_count = 0
        self.batch_count = 0
        self.disallowed_paths: Set[str] = set()
        
        # Callbacks
        self._on_url_found: Optional[Callable] = None
        self._on_batch_ready: Optional[Callable] = None
    
    def on_url_found(self, callback: Callable):
        """Set callback for when a new URL is found."""
        self._on_url_found = callback
    
    def on_batch_ready(self, callback: Callable):
        """Set callback for when a batch is ready."""
        self._on_batch_ready = callback
    
    async def _load_robots_txt(self):
        """Load and parse robots.txt."""
        if not self.respect_robots:
            return
        
        robots_url = urljoin(self.base_url, '/robots.txt')
        
        try:
            async with self.session.get(robots_url, timeout=5) as response:
                if response.status == 200:
                    text = await response.text()
                    
                    # Parse disallowed paths
                    for line in text.split('\n'):
                        if line.lower().startswith('disallow:'):
                            path = line.split(':', 1)[1].strip()
                            if path:
                                self.disallowed_paths.add(path)
        except Exception:
            pass
    
    def _get_priority(self, url: str) -> CrawlPriority:
        """Determine crawl priority for a URL."""
        url_lower = url.lower()
        
        # Check skip patterns
        for pattern in self.SKIP_PATTERNS:
            if re.search(pattern, url_lower):
                return CrawlPriority.SKIP
        
        # Check high priority
        for pattern in self.HIGH_PRIORITY_PATTERNS:
            if re.search(pattern, url_lower):
                return CrawlPriority.HIGH
        
        # Check medium priority
        for pattern in self.MEDIUM_PRIORITY_PATTERNS:
            if re.search(pattern, url_lower):
                return CrawlPriority.MEDIUM
        
        return CrawlPriority.LOW
    
    def _normalize_url(self, url: str) -> str:
        """Normalize URL for deduplication."""
        parsed = urlparse(url)
        
        # Remove fragments
        normalized = urlunparse((
            parsed.scheme,
            parsed.netloc.lower(),
            parsed.path.rstrip('/') or '/',
            parsed.params,
            parsed.query,
            ''  # Remove fragment
        ))
        
        return normalized
    
    def _is_in_scope(self, url: str) -> bool:
        """Check if URL is in scope."""
        parsed = urlparse(url)
        
        # Must be same domain
        if parsed.netloc.lower() != self.base_domain.lower():
            return False
        
        # Check custom scope pattern
        if self.scope_pattern and not self.scope_pattern.search(url):
            return False
        
        # Check robots.txt
        if self.respect_robots:
            for disallowed in self.disallowed_paths:
                if parsed.path.startswith(disallowed):
                    return False
        
        return True
    
    def _add_to_queue(self, url: str, depth: int, parent: str = None):
        """Add a URL to the crawl queue."""
        normalized = self._normalize_url(url)
        
        if normalized in self.visited:
            return
        
        if not self._is_in_scope(normalized):
            return
        
        priority = self._get_priority(normalized)
        if priority == CrawlPriority.SKIP:
            return
        
        self.visited.add(normalized)
        self.discovered_count += 1
        
        item = CrawlItem(
            url=normalized,
            depth=depth,
            priority=priority,
            parent_url=parent
        )
        
        # Insert sorted by priority
        self.queue.append(item)
        self.queue.sort()
        
        if self._on_url_found:
            asyncio.create_task(self._call_callback(self._on_url_found, normalized))
    
    async def _call_callback(self, callback, *args):
        """Call a callback safely."""
        try:
            if asyncio.iscoroutinefunction(callback):
                await callback(*args)
            else:
                callback(*args)
        except Exception:
            pass
    
    async def _extract_urls(self, html: str, base_url: str) -> List[str]:
        """Extract URLs from HTML content."""
        urls = []
        
        # Extract href and src attributes
        patterns = [
            r'href\s*=\s*["\']([^"\']+)["\']',
            r'src\s*=\s*["\']([^"\']+)["\']',
            r'action\s*=\s*["\']([^"\']+)["\']',
            r'data-url\s*=\s*["\']([^"\']+)["\']',
        ]
        
        for pattern in patterns:
            for match in re.finditer(pattern, html, re.I):
                url = match.group(1)
                
                # Skip javascript:, mailto:, tel:
                if url.startswith(('javascript:', 'mailto:', 'tel:', '#', 'data:')):
                    continue
                
                # Convert relative to absolute
                absolute_url = urljoin(base_url, url)
                urls.append(absolute_url)
        
        # Extract from JavaScript
        js_patterns = [
            r'["\']/(api|v\d+)/[^"\']+["\']',
            r'fetch\s*\(\s*["\']([^"\']+)["\']',
            r'\.get\s*\(\s*["\']([^"\']+)["\']',
            r'\.post\s*\(\s*["\']([^"\']+)["\']',
        ]
        
        for pattern in js_patterns:
            for match in re.finditer(pattern, html, re.I):
                url = match.group(1) if match.lastindex else match.group(0)
                url = url.strip('"\'')
                if url.startswith('/'):
                    urls.append(urljoin(base_url, url))
        
        return urls
    
    async def _crawl_url(self, item: CrawlItem) -> List[str]:
        """Crawl a single URL and return found URLs."""
        try:
            async with self.session.get(item.url, timeout=10) as response:
                if response.status != 200:
                    return []
                
                content_type = response.headers.get('Content-Type', '')
                if 'text/html' not in content_type.lower():
                    return []
                
                html = await response.text()
                return await self._extract_urls(html, item.url)
                
        except Exception:
            return []
    
    async def crawl_batches(self) -> AsyncIterator[CrawlBatch]:
        """
        Crawl incrementally and yield batches for scanning.
        
        Usage:
            async for batch in crawler.crawl_batches():
                await scan_urls(batch.urls)
        """
        # Load robots.txt
        await self._load_robots_txt()
        
        # Add seed URL
        self._add_to_queue(self.base_url, 0)
        
        current_batch: List[str] = []
        
        while self.queue and self.discovered_count <= self.max_urls:
            # Get next item
            item = self.queue.pop(0)
            
            # Skip if too deep
            if item.depth > self.max_depth:
                continue
            
            # Add to current batch
            current_batch.append(item.url)
            
            # Crawl and find new URLs
            found_urls = await self._crawl_url(item)
            
            for url in found_urls:
                self._add_to_queue(url, item.depth + 1, item.url)
            
            # Yield batch when ready
            if len(current_batch) >= self.batch_size:
                self.batch_count += 1
                
                batch = CrawlBatch(
                    urls=current_batch.copy(),
                    batch_number=self.batch_count,
                    crawl_depth=item.depth,
                    total_discovered=self.discovered_count
                )
                
                if self._on_batch_ready:
                    await self._call_callback(self._on_batch_ready, batch)
                
                yield batch
                current_batch = []
            
            # Small delay to be polite
            await asyncio.sleep(0.05)
        
        # Yield remaining URLs
        if current_batch:
            self.batch_count += 1
            batch = CrawlBatch(
                urls=current_batch,
                batch_number=self.batch_count,
                crawl_depth=self.max_depth,
                total_discovered=self.discovered_count
            )
            yield batch
    
    async def get_all_urls(self) -> List[str]:
        """Convenience method to get all URLs (non-incremental)."""
        all_urls = []
        async for batch in self.crawl_batches():
            all_urls.extend(batch.urls)
        return all_urls
    
    def get_stats(self) -> Dict[str, Any]:
        """Get crawling statistics."""
        return {
            'discovered_count': self.discovered_count,
            'visited_count': len(self.visited),
            'queue_size': len(self.queue),
            'batch_count': self.batch_count,
            'max_depth': self.max_depth,
        }


async def create_incremental_crawler(
    session,
    base_url: str,
    **kwargs
) -> IncrementalCrawler:
    """Create an incremental crawler."""
    return IncrementalCrawler(session, base_url, **kwargs)
