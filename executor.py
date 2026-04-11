"""
Lynx VAPT - CPU Offloading Executor Module

Offloads CPU-intensive operations from the async event loop:
- Large regex scans
- HTML/JS parsing
- Hashing operations
- Base64 decoding
- Response body analysis

Author: Lynx Team
"""

import asyncio
import re
import hashlib
import base64
import html
import json
import threading
from concurrent.futures import ThreadPoolExecutor, ProcessPoolExecutor
from typing import List, Dict, Any, Optional, Callable, Pattern
from functools import partial
from dataclasses import dataclass


# Global executor (shared across the application) with thread safety
_thread_executor: Optional[ThreadPoolExecutor] = None
_process_executor: Optional[ProcessPoolExecutor] = None
_executor_lock = threading.Lock()
_process_lock = threading.Lock()


def get_thread_executor(max_workers: int = 4) -> ThreadPoolExecutor:
    """
    Get or create the shared thread pool executor with thread safety.
    
    Uses double-checked locking pattern to prevent race conditions.
    """
    global _thread_executor
    
    # Fast path without lock
    if _thread_executor is not None:
        return _thread_executor
    
    # Slow path with lock
    with _executor_lock:
        # Double-check in case another thread created it while we waited
        if _thread_executor is None:
            _thread_executor = ThreadPoolExecutor(
                max_workers=max_workers, 
                thread_name_prefix="lynx_cpu"
            )
    
    return _thread_executor


def get_process_executor(max_workers: int = 2) -> ProcessPoolExecutor:
    """
    Get or create the shared process pool executor with thread safety.
    
    Uses double-checked locking pattern to prevent race conditions.
    """
    global _process_executor
    
    # Fast path without lock
    if _process_executor is not None:
        return _process_executor
    
    # Slow path with lock
    with _process_lock:
        # Double-check in case another thread created it while we waited
        if _process_executor is None:
            _process_executor = ProcessPoolExecutor(max_workers=max_workers)
    
    return _process_executor


def shutdown_executors():
    """Shutdown all executors gracefully with thread safety."""
    global _thread_executor, _process_executor
    
    with _executor_lock:
        if _thread_executor:
            _thread_executor.shutdown(wait=True)
            _thread_executor = None
    
    with _process_lock:
        if _process_executor:
            _process_executor.shutdown(wait=True)
            _process_executor = None


def cleanup_executors():
    """Alternative name for shutdown_executors for clarity."""
    shutdown_executors()


@dataclass
class RegexMatch:
    """Result of a regex match operation."""
    pattern: str
    match: str
    start: int
    end: int
    groups: tuple
    line_number: Optional[int] = None
    context: Optional[str] = None


# ============================================================================
# Synchronous CPU-intensive functions (run in executor)
# ============================================================================

def _regex_scan_sync(
    text: str,
    patterns: List[str],
    flags: int = 0,
    max_matches: int = 100,
    include_context: bool = False,
    context_chars: int = 50
) -> List[RegexMatch]:
    """
    Synchronous regex scanning of text against multiple patterns.
    
    This runs in a thread to avoid blocking the event loop.
    """
    results = []
    
    # Pre-calculate line positions for context
    line_starts = [0]
    for i, char in enumerate(text):
        if char == '\n':
            line_starts.append(i + 1)
    
    def get_line_number(pos: int) -> int:
        for i, start in enumerate(line_starts):
            if start > pos:
                return i
        return len(line_starts)
    
    for pattern_str in patterns:
        try:
            pattern = re.compile(pattern_str, flags)
            
            for match in pattern.finditer(text):
                if len(results) >= max_matches:
                    break
                
                context = None
                if include_context:
                    start = max(0, match.start() - context_chars)
                    end = min(len(text), match.end() + context_chars)
                    context = text[start:end]
                
                results.append(RegexMatch(
                    pattern=pattern_str,
                    match=match.group(),
                    start=match.start(),
                    end=match.end(),
                    groups=match.groups(),
                    line_number=get_line_number(match.start()),
                    context=context
                ))
                
        except re.error:
            continue
    
    return results


def _parse_html_sync(html_content: str) -> Dict[str, Any]:
    """
    Synchronous HTML parsing to extract security-relevant elements.
    """
    from bs4 import BeautifulSoup
    
    try:
        soup = BeautifulSoup(html_content, 'html.parser')
    except Exception:
        return {"error": "Failed to parse HTML"}
    
    result = {
        "forms": [],
        "inputs": [],
        "links": [],
        "scripts": [],
        "iframes": [],
        "meta": [],
        "comments": []
    }
    
    # Extract forms
    for form in soup.find_all('form'):
        form_data = {
            "action": form.get('action', ''),
            "method": form.get('method', 'get').upper(),
            "id": form.get('id', ''),
            "inputs": []
        }
        for inp in form.find_all(['input', 'textarea', 'select']):
            form_data["inputs"].append({
                "name": inp.get('name', ''),
                "type": inp.get('type', 'text'),
                "value": inp.get('value', ''),
                "id": inp.get('id', '')
            })
        result["forms"].append(form_data)
    
    # Extract all inputs (including outside forms)
    for inp in soup.find_all(['input', 'textarea', 'select']):
        result["inputs"].append({
            "name": inp.get('name', ''),
            "type": inp.get('type', 'text'),
            "value": inp.get('value', ''),
            "id": inp.get('id', '')
        })
    
    # Extract links
    for link in soup.find_all('a', href=True):
        result["links"].append({
            "href": link['href'],
            "text": link.get_text(strip=True)[:100]
        })
    
    # Extract scripts
    for script in soup.find_all('script'):
        script_data = {
            "src": script.get('src', ''),
            "inline": bool(script.string),
            "content_preview": (script.string or '')[:200] if script.string else ''
        }
        result["scripts"].append(script_data)
    
    # Extract iframes
    for iframe in soup.find_all('iframe'):
        result["iframes"].append({
            "src": iframe.get('src', ''),
            "sandbox": iframe.get('sandbox', '')
        })
    
    # Extract meta tags
    for meta in soup.find_all('meta'):
        result["meta"].append({
            "name": meta.get('name', ''),
            "content": meta.get('content', ''),
            "http_equiv": meta.get('http-equiv', '')
        })
    
    # Extract comments (can contain sensitive info)
    for comment in soup.find_all(string=lambda text: isinstance(text, str) and '<!--' in str(text) or hasattr(text, 'name') and text.name is None):
        if hasattr(comment, 'extract'):
            comment_text = str(comment).strip()
            if comment_text and len(comment_text) > 3:
                result["comments"].append(comment_text[:500])
    
    return result


def _parse_js_sync(js_content: str) -> Dict[str, Any]:
    """
    Synchronous JavaScript parsing to extract security-relevant data.
    
    Note: This is regex-based. For AST-based parsing, see js_ast.py.
    """
    result = {
        "endpoints": [],
        "strings": [],
        "functions": [],
        "variables": [],
        "api_calls": []
    }
    
    # Extract string literals
    string_pattern = r'["\']([^"\']{10,500})["\']'
    for match in re.finditer(string_pattern, js_content):
        string_val = match.group(1)
        # Filter interesting strings
        if any([
            string_val.startswith('/'),
            string_val.startswith('http'),
            'api' in string_val.lower(),
            'token' in string_val.lower(),
            'key' in string_val.lower(),
            'secret' in string_val.lower(),
            'password' in string_val.lower(),
        ]):
            result["strings"].append(string_val)
    
    # Extract endpoints
    endpoint_pattern = r'["\'](\/?api\/[^"\']+)["\']|["\'](\/?v\d+\/[^"\']+)["\']|["\'](\/[a-z]+\/[a-z]+[^"\']*)["\']'
    for match in re.finditer(endpoint_pattern, js_content, re.I):
        endpoint = match.group(1) or match.group(2) or match.group(3)
        if endpoint and endpoint not in result["endpoints"]:
            result["endpoints"].append(endpoint)
    
    # Extract function definitions
    func_pattern = r'(?:function\s+(\w+)|(?:const|let|var)\s+(\w+)\s*=\s*(?:async\s*)?\([^)]*\)\s*=>|(\w+)\s*:\s*(?:async\s*)?function)'
    for match in re.finditer(func_pattern, js_content):
        func_name = match.group(1) or match.group(2) or match.group(3)
        if func_name and func_name not in result["functions"]:
            result["functions"].append(func_name)
    
    # Extract API calls (fetch, axios, XMLHttpRequest)
    api_call_pattern = r'(?:fetch|axios\.(?:get|post|put|delete|patch)|XMLHttpRequest|\.ajax)\s*\(\s*["\']([^"\']+)["\']'
    for match in re.finditer(api_call_pattern, js_content, re.I):
        api_url = match.group(1)
        if api_url not in result["api_calls"]:
            result["api_calls"].append(api_url)
    
    # Deduplicate endpoints
    result["endpoints"] = list(set(result["endpoints"]))[:50]
    result["strings"] = list(set(result["strings"]))[:100]
    
    return result


def _compute_hashes_sync(data: bytes) -> Dict[str, str]:
    """Compute multiple hashes for data."""
    return {
        "md5": hashlib.md5(data).hexdigest(),
        "sha1": hashlib.sha1(data).hexdigest(),
        "sha256": hashlib.sha256(data).hexdigest()
    }


def _decode_base64_sync(encoded: str) -> Optional[str]:
    """Decode base64 string, handling common variants."""
    # Try standard base64
    for encoding in [encoded, encoded + '=', encoded + '==']:
        try:
            decoded = base64.b64decode(encoding)
            return decoded.decode('utf-8', errors='replace')
        except Exception:
            continue
    
    # Try URL-safe base64
    try:
        decoded = base64.urlsafe_b64decode(encoded + '==')
        return decoded.decode('utf-8', errors='replace')
    except Exception:
        pass
    
    return None


def _analyze_response_sync(
    body: str,
    check_secrets: bool = True,
    check_errors: bool = True,
    check_endpoints: bool = True
) -> Dict[str, Any]:
    """
    Comprehensive response body analysis.
    """
    result = {
        "secrets": [],
        "errors": [],
        "endpoints": [],
        "sensitive_data": [],
        "length": len(body),
        "word_count": len(body.split())
    }
    
    if check_secrets:
        secret_patterns = [
            (r'(?:api[_-]?key|apikey)["\s:=]+["\']?([a-zA-Z0-9_\-]{20,})', "API Key"),
            (r'(?:password|passwd|pwd)["\s:=]+["\']?([^\s"\']{6,})', "Password"),
            (r'(?:secret|token)["\s:=]+["\']?([a-zA-Z0-9_\-]{20,})', "Secret/Token"),
            (r'(AKIA[0-9A-Z]{16})', "AWS Access Key"),
            (r'(sk_live_[a-zA-Z0-9]{24,})', "Stripe Key"),
            (r'(gh[ps]_[a-zA-Z0-9]{36,})', "GitHub Token"),
        ]
        
        for pattern, secret_type in secret_patterns:
            for match in re.finditer(pattern, body, re.I):
                result["secrets"].append({
                    "type": secret_type,
                    "value": match.group(1)[:50] + "..." if len(match.group(1)) > 50 else match.group(1),
                    "position": match.start()
                })
    
    if check_errors:
        error_patterns = [
            r'(?:SQL syntax|mysql_|ORA-\d{5}|PostgreSQL|sqlite)',
            r'(?:stack\s*trace|traceback|exception)',
            r'(?:undefined|null reference|cannot read property)',
            r'(?:permission denied|access denied|unauthorized)',
        ]
        
        for pattern in error_patterns:
            if re.search(pattern, body, re.I):
                result["errors"].append(pattern)
    
    if check_endpoints:
        endpoint_pattern = r'["\']((?:/api|/v\d)/[^"\'\s]{5,100})["\']'
        for match in re.finditer(endpoint_pattern, body):
            endpoint = match.group(1)
            if endpoint not in result["endpoints"]:
                result["endpoints"].append(endpoint)
    
    return result


# ============================================================================
# Async wrappers (call these from async code)
# ============================================================================

async def run_regex_scan(
    text: str,
    patterns: List[str],
    flags: int = 0,
    max_matches: int = 100
) -> List[RegexMatch]:
    """
    Run regex scan in thread pool.
    
    Args:
        text: Text to scan
        patterns: List of regex patterns
        flags: Regex flags (e.g., re.IGNORECASE)
        max_matches: Maximum matches to return
    
    Returns:
        List of RegexMatch objects
    """
    loop = asyncio.get_running_loop()
    executor = get_thread_executor()
    
    return await loop.run_in_executor(
        executor,
        partial(_regex_scan_sync, text, patterns, flags, max_matches)
    )


async def run_html_parse(html_content: str) -> Dict[str, Any]:
    """
    Parse HTML in thread pool.
    
    Args:
        html_content: HTML to parse
    
    Returns:
        Dict with forms, inputs, links, scripts, etc.
    """
    loop = asyncio.get_running_loop()
    executor = get_thread_executor()
    
    return await loop.run_in_executor(
        executor,
        partial(_parse_html_sync, html_content)
    )


async def run_js_parse(js_content: str) -> Dict[str, Any]:
    """
    Parse JavaScript in thread pool.
    
    Args:
        js_content: JavaScript code to parse
    
    Returns:
        Dict with endpoints, strings, functions, etc.
    """
    loop = asyncio.get_running_loop()
    executor = get_thread_executor()
    
    return await loop.run_in_executor(
        executor,
        partial(_parse_js_sync, js_content)
    )


async def run_hash(data: bytes) -> Dict[str, str]:
    """
    Compute hashes in thread pool.
    
    Args:
        data: Bytes to hash
    
    Returns:
        Dict with md5, sha1, sha256 hashes
    """
    loop = asyncio.get_running_loop()
    executor = get_thread_executor()
    
    return await loop.run_in_executor(
        executor,
        partial(_compute_hashes_sync, data)
    )


async def run_base64_decode(encoded: str) -> Optional[str]:
    """
    Decode base64 in thread pool.
    
    Args:
        encoded: Base64 encoded string
    
    Returns:
        Decoded string or None
    """
    loop = asyncio.get_running_loop()
    executor = get_thread_executor()
    
    return await loop.run_in_executor(
        executor,
        partial(_decode_base64_sync, encoded)
    )


async def run_response_analysis(
    body: str,
    check_secrets: bool = True,
    check_errors: bool = True,
    check_endpoints: bool = True
) -> Dict[str, Any]:
    """
    Analyze response body in thread pool.
    
    Args:
        body: Response body text
        check_secrets: Whether to scan for secrets
        check_errors: Whether to scan for error patterns
        check_endpoints: Whether to extract endpoints
    
    Returns:
        Dict with secrets, errors, endpoints, etc.
    """
    loop = asyncio.get_running_loop()
    executor = get_thread_executor()
    
    return await loop.run_in_executor(
        executor,
        partial(_analyze_response_sync, body, check_secrets, check_errors, check_endpoints)
    )


async def run_in_executor(func: Callable, *args, **kwargs) -> Any:
    """
    Run any synchronous function in the thread pool.
    
    Args:
        func: Synchronous function to run
        *args: Positional arguments
        **kwargs: Keyword arguments
    
    Returns:
        Function result
    """
    loop = asyncio.get_running_loop()
    executor = get_thread_executor()
    
    if kwargs:
        func = partial(func, **kwargs)
    
    return await loop.run_in_executor(executor, func, *args)


# ============================================================================
# Batch processing utilities
# ============================================================================

async def batch_regex_scan(
    texts: List[str],
    patterns: List[str],
    concurrency: int = 4
) -> List[List[RegexMatch]]:
    """
    Scan multiple texts concurrently.
    
    Args:
        texts: List of texts to scan
        patterns: Pattern list (same for all)
        concurrency: Max concurrent scans
    
    Returns:
        List of match lists (one per input text)
    """
    semaphore = asyncio.Semaphore(concurrency)
    
    async def scan_one(text: str) -> List[RegexMatch]:
        async with semaphore:
            return await run_regex_scan(text, patterns)
    
    return await asyncio.gather(*[scan_one(t) for t in texts])


async def batch_analyze_responses(
    bodies: List[str],
    concurrency: int = 4
) -> List[Dict[str, Any]]:
    """
    Analyze multiple response bodies concurrently.
    
    Args:
        bodies: List of response bodies
        concurrency: Max concurrent analyses
    
    Returns:
        List of analysis results
    """
    semaphore = asyncio.Semaphore(concurrency)
    
    async def analyze_one(body: str) -> Dict[str, Any]:
        async with semaphore:
            return await run_response_analysis(body)
    
    return await asyncio.gather(*[analyze_one(b) for b in bodies])
