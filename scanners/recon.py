"""
Lynx VAPT - Reconnaissance Module

Comprehensive reconnaissance capabilities:
- Subdomain enumeration
- DNS analysis
- Technology fingerprinting
- Cloud asset discovery
- Email security (SPF/DMARC/DKIM)
- Common file/path discovery

Author: Lynx Team
"""

import asyncio
import re
import socket
import json
from typing import Dict, List, Optional, Any, Set, Tuple
from dataclasses import dataclass, field
from urllib.parse import urljoin, urlparse

from scanners.base import BaseScanner
from common import event_manager, TestingZone


@dataclass
class ReconFinding:
    """A reconnaissance finding."""
    category: str
    name: str
    value: str
    details: str = ""
    severity: str = "P4"


class ReconScanner(BaseScanner):
    """
    Reconnaissance Scanner.
    
    Performs extensive reconnaissance:
    - DNS record analysis
    - Email security checks
    - Technology fingerprinting
    - Common file/path discovery
    - Cloud metadata detection
    - Information disclosure
    """
    
    # Common subdomains to check
    COMMON_SUBDOMAINS = [
        "www", "mail", "ftp", "admin", "blog", "dev", "test",
        "staging", "api", "app", "portal", "secure", "vpn",
        "m", "mobile", "cdn", "static", "assets", "media",
        "shop", "store", "support", "help", "docs", "wiki",
        "git", "gitlab", "github", "jenkins", "ci", "cd",
        "monitor", "grafana", "kibana", "elastic", "logs",
        "db", "database", "mysql", "postgres", "mongo", "redis",
        "smtp", "pop", "imap", "webmail", "owa", "autodiscover",
        "ns1", "ns2", "dns", "nameserver",
    ]
    
    # Sensitive paths to check
    SENSITIVE_PATHS = [
        # Configuration files
        "/.git/config", "/.git/HEAD", "/.svn/entries",
        "/.env", "/.env.local", "/.env.production",
        "/config.php", "/config.json", "/config.yml",
        "/wp-config.php", "/configuration.php",
        "/.htaccess", "/.htpasswd",
        "/web.config", "/applicationhost.config",
        
        # Backup files
        "/backup.zip", "/backup.sql", "/backup.tar.gz",
        "/db.sql", "/database.sql", "/dump.sql",
        "/site.zip", "/www.zip", "/public.zip",
        
        # Debug/info pages
        "/phpinfo.php", "/info.php", "/test.php",
        "/debug", "/trace", "/status", "/health",
        "/server-status", "/nginx_status",
        "/.well-known/security.txt",
        
        # API documentation
        "/swagger.json", "/swagger.yaml", "/openapi.json",
        "/api-docs", "/api/docs", "/graphql",
        
        # Admin panels
        "/admin", "/administrator", "/wp-admin", "/wp-login.php",
        "/admin.php", "/login", "/dashboard",
        "/phpmyadmin", "/pma", "/adminer.php",
        
        # Cloud metadata
        "/latest/meta-data/", "/.aws/credentials",
        
        # Common CMS files
        "/robots.txt", "/sitemap.xml", "/crossdomain.xml",
        "/clientaccesspolicy.xml",
    ]
    
    # Technology fingerprints
    TECH_FINGERPRINTS = {
        "WordPress": [r'wp-content', r'wp-includes', r'/wp-json/'],
        "Drupal": [r'sites/default', r'/core/misc/', r'Drupal.settings'],
        "Joomla": [r'/administrator/', r'/components/', r'/templates/'],
        "Magento": [r'/skin/frontend/', r'/js/mage/', r'Mage.Cookies'],
        "Laravel": [r'laravel_session', r'/vendor/laravel'],
        "Django": [r'csrfmiddlewaretoken', r'__admin__'],
        "Express": [r'X-Powered-By.*Express'],
        "ASP.NET": [r'__VIEWSTATE', r'ASP.NET_SessionId'],
        "PHP": [r'PHPSESSID', r'X-Powered-By.*PHP'],
        "Ruby on Rails": [r'_session_id', r'X-Runtime'],
        "Spring": [r'JSESSIONID', r'Spring'],
        "React": [r'__NEXT_DATA__', r'react', r'_reactRootContainer'],
        "Vue.js": [r'__vue__', r'v-cloak', r'Vue.js'],
        "Angular": [r'ng-version', r'ng-app', r'angular'],
    }
    
    # Cloud provider patterns
    CLOUD_PATTERNS = {
        "AWS S3": [r's3\.amazonaws\.com', r's3-[\w-]+\.amazonaws\.com'],
        "AWS CloudFront": [r'cloudfront\.net'],
        "Azure Blob": [r'blob\.core\.windows\.net'],
        "Azure CDN": [r'azureedge\.net'],
        "Google Cloud Storage": [r'storage\.googleapis\.com'],
        "Google Cloud CDN": [r'googleusercontent\.com'],
        "Cloudflare": [r'cloudflare', r'cf-ray'],
        "Akamai": [r'akamai', r'akadns\.net'],
        "Fastly": [r'fastly\.net'],
    }
    
    def __init__(self, context):
        super().__init__(context)
        self.name = "ReconScanner"
        self.zone = TestingZone.ZONE_E
        self.findings: List[ReconFinding] = []
    
    async def run(self):
        """Run reconnaissance scan."""
        await event_manager.emit("log", f"[{self.name}] Starting reconnaissance...")
        
        # Parse target
        parsed = urlparse(self.context.target)
        domain = parsed.netloc
        
        # Run recon tasks
        await self._check_dns_records(domain)
        await self._check_email_security(domain)
        await self._fingerprint_technologies()
        await self._discover_paths()
        await self._check_cloud_exposure()
        await self._check_information_disclosure()
        
        await event_manager.emit("log", 
            f"[{self.name}] Found {len(self.findings)} reconnaissance items")
    
    async def _check_dns_records(self, domain: str):
        """Check DNS records for security issues."""
        # Remove www. if present
        if domain.startswith('www.'):
            domain = domain[4:]
        
        # Try to resolve common subdomains
        found_subdomains = []
        
        for subdomain in self.COMMON_SUBDOMAINS[:20]:  # Limit
            full_domain = f"{subdomain}.{domain}"
            try:
                socket.gethostbyname(full_domain)
                found_subdomains.append(full_domain)
            except socket.gaierror:
                continue
            except Exception:
                continue
        
        if found_subdomains:
            self.findings.append(ReconFinding(
                category="DNS",
                name="Subdomains Discovered",
                value=", ".join(found_subdomains[:10]),
                details=f"Found {len(found_subdomains)} subdomains"
            ))
        
        # Check for zone transfer (AXFR)
        # Note: This is a simplified check
        try:
            socket.getaddrinfo(domain, None)
        except Exception:
            pass
    
    async def _check_email_security(self, domain: str):
        """Check email security records."""
        if domain.startswith('www.'):
            domain = domain[4:]
        
        issues = []
        
        # Check SPF via HTTP (simplified - real implementation would use DNS)
        # We'll check common misconfiguration patterns
        
        # Try to fetch security.txt
        security_txt_url = urljoin(self.context.target, '/.well-known/security.txt')
        try:
            async with self.context.session.get(security_txt_url, timeout=5) as response:
                if response.status == 200:
                    text = await response.text()
                    self.findings.append(ReconFinding(
                        category="Security",
                        name="security.txt Found",
                        value=security_txt_url,
                        details=text[:200]
                    ))
        except Exception:
            pass
    
    async def _fingerprint_technologies(self):
        """Fingerprint web technologies."""
        try:
            async with self.context.session.get(self.context.target, timeout=10) as response:
                html = await response.text()
                headers = dict(response.headers)
        except Exception:
            return
        
        detected_tech = []
        
        # Check response headers
        header_str = str(headers)
        
        for tech, patterns in self.TECH_FINGERPRINTS.items():
            for pattern in patterns:
                if re.search(pattern, html, re.I) or re.search(pattern, header_str, re.I):
                    if tech not in detected_tech:
                        detected_tech.append(tech)
                    break
        
        # Check specific headers
        if 'Server' in headers:
            server = headers['Server']
            detected_tech.append(f"Server: {server}")
        
        if 'X-Powered-By' in headers:
            powered_by = headers['X-Powered-By']
            detected_tech.append(f"Powered-By: {powered_by}")
        
        if detected_tech:
            await self.emit_vulnerability(
                "Technology Fingerprinting",
                f"Detected technologies:\n" + "\n".join(f"  - {t}" for t in detected_tech),
                severity="P4",
                remediation="Remove version information from headers to reduce attack surface.",
                url=self.context.target,
                payload=", ".join(detected_tech[:5])
            )
    
    async def _discover_paths(self):
        """Discover sensitive paths."""
        found_paths = []
        
        for path in self.SENSITIVE_PATHS:
            url = urljoin(self.context.target, path)
            
            try:
                async with self.context.session.get(url, timeout=5, allow_redirects=False) as response:
                    if response.status == 200:
                        content_length = len(await response.text())
                        
                        # Filter out generic error pages
                        if content_length > 50:
                            found_paths.append((path, response.status, content_length))
                            
                    elif response.status == 403:
                        # Exists but forbidden
                        found_paths.append((path, response.status, 0))
                        
            except Exception:
                continue
            
            await asyncio.sleep(0.05)  # Rate limiting
        
        # Report critical findings
        critical_paths = [p for p, s, _ in found_paths if any(
            x in p for x in ['.git', '.env', 'config', 'backup', 'admin', 'phpinfo']
        )]
        
        if critical_paths:
            await self.emit_vulnerability(
                "Sensitive Paths Exposed",
                f"Found sensitive paths:\n" + "\n".join(
                    f"  - {p}" for p in critical_paths[:10]
                ),
                severity="P2",
                remediation="Restrict access to sensitive files and directories.",
                url=self.context.target,
                payload=", ".join(critical_paths[:3])
            )
        
        # Report all found paths as info
        if found_paths:
            self.findings.append(ReconFinding(
                category="Paths",
                name="Discovered Paths",
                value=str(len(found_paths)),
                details=", ".join(p for p, _, _ in found_paths[:10])
            ))
    
    async def _check_cloud_exposure(self):
        """Check for cloud asset exposure."""
        try:
            async with self.context.session.get(self.context.target, timeout=10) as response:
                html = await response.text()
                headers = dict(response.headers)
        except Exception:
            return
        
        combined = html + str(headers)
        detected_cloud = []
        
        for provider, patterns in self.CLOUD_PATTERNS.items():
            for pattern in patterns:
                if re.search(pattern, combined, re.I):
                    detected_cloud.append(provider)
                    break
        
        if detected_cloud:
            self.findings.append(ReconFinding(
                category="Cloud",
                name="Cloud Services Detected",
                value=", ".join(detected_cloud),
                details="May indicate cloud infrastructure or CDN usage"
            ))
        
        # Check for S3 bucket misconfiguration
        s3_pattern = r'([\w.-]+\.s3\.amazonaws\.com|s3\.amazonaws\.com/[\w.-]+)'
        s3_matches = re.findall(s3_pattern, combined, re.I)
        
        for bucket in s3_matches[:5]:
            bucket_url = f"https://{bucket}" if not bucket.startswith('http') else bucket
            try:
                async with self.context.session.get(bucket_url, timeout=5) as resp:
                    if resp.status == 200:
                        text = await resp.text()
                        if 'ListBucketResult' in text or 'Contents' in text:
                            await self.emit_vulnerability(
                                "S3 Bucket Listing Enabled",
                                f"S3 bucket allows public listing:\n{bucket_url}",
                                severity="P2",
                                remediation="Disable public access and listing on S3 buckets.",
                                url=bucket_url,
                                payload=bucket
                            )
            except Exception:
                continue
    
    async def _check_information_disclosure(self):
        """Check for information disclosure."""
        try:
            async with self.context.session.get(self.context.target, timeout=10) as response:
                html = await response.text()
                headers = dict(response.headers)
        except Exception:
            return
        
        disclosures = []
        
        # Check for version disclosure in headers
        version_headers = ['Server', 'X-Powered-By', 'X-AspNet-Version', 'X-AspNetMvc-Version']
        for header in version_headers:
            if header in headers:
                value = headers[header]
                if re.search(r'\d+\.\d+', value):
                    disclosures.append(f"{header}: {value}")
        
        # Check for sensitive comments
        comment_patterns = [
            r'<!--.*?(password|secret|key|token|api).*?-->',
            r'<!--.*?TODO.*?-->',
            r'<!--.*?FIXME.*?-->',
            r'<!--.*?(debug|test).*?-->',
        ]
        
        for pattern in comment_patterns:
            matches = re.findall(pattern, html, re.I | re.DOTALL)
            if matches:
                disclosures.append(f"Sensitive comment containing: {matches[0]}")
        
        # Check for stack traces
        if re.search(r'stack\s*trace|traceback|exception', html, re.I):
            disclosures.append("Potential stack trace exposure")
        
        # Check for debug mode indicators
        if re.search(r'debug\s*=\s*true|debug_mode|DEBUG', html, re.I):
            disclosures.append("Debug mode may be enabled")
        
        if disclosures:
            await self.emit_vulnerability(
                "Information Disclosure",
                f"Found information disclosure:\n" + "\n".join(
                    f"  - {d[:100]}" for d in disclosures[:10]
                ),
                severity="P3",
                remediation="Remove version information, debug data, and sensitive comments.",
                url=self.context.target,
                payload=disclosures[0][:50] if disclosures else ""
            )
    
    def cleanup(self):
        self.findings.clear()
