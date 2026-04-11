import asyncio
import re
import urllib.parse
from bs4 import BeautifulSoup
from .base import BaseScanner
from common import TestingZone, event_manager


class SecurityHeadersCheck(BaseScanner):
    def __init__(self, context):
        super().__init__(context)
        self.zone = TestingZone.ZONE_E

    async def run(self):
        await event_manager.emit("log", f"[{self.name}] Starting scan...")
        try:
            async with self.context.session.get(self.context.target) as response:
                headers = response.headers
                missing_headers = []

                if "strict-transport-security" not in headers:
                    missing_headers.append("Strict-Transport-Security")
                if "content-security-policy" not in headers:
                    missing_headers.append("Content-Security-Policy")
                if "x-frame-options" not in headers:
                    missing_headers.append("X-Frame-Options")
                if "x-content-type-options" not in headers:
                    missing_headers.append("X-Content-Type-Options")
                if "referrer-policy" not in headers:
                    missing_headers.append("Referrer-Policy")

                if missing_headers:
                    await self.emit_vulnerability(
                        "Weak Security Headers",
                        f"Missing security headers: {', '.join(missing_headers)}",
                        "P3",
                        "Add missing security headers to HTTP responses.",
                        url=self.context.target,
                        confidence=0.6,
                        observed_behavior="One or more hardening headers were absent from the response.",
                        verification="heuristic",
                        reproduction_steps=[
                            "Request the target homepage.",
                            "Inspect the response headers for the reported missing headers.",
                            "Verify the application behavior after adding the headers.",
                        ],
                    )
        except Exception as e:
            await event_manager.emit("log", f"[{self.name}] Error: {e}")


class CORSCheck(BaseScanner):
    def __init__(self, context):
        super().__init__(context)
        self.zone = TestingZone.ZONE_E

    async def run(self):
        await event_manager.emit("log", f"[{self.name}] Starting scan...")
        try:
            headers = {"Origin": "http://evil.com"}
            async with self.context.session.get(self.context.target, headers=headers) as response:
                resp_headers = response.headers
                acao = resp_headers.get("access-control-allow-origin", "")
                acac = resp_headers.get("access-control-allow-credentials", "")

                if "*" in acao and "true" in acac.lower():
                    await self.emit_vulnerability(
                        "CORS Misconfiguration",
                        "Wildcard origin with credentials allowed",
                        "P3",
                        "Restrict origins to trusted domains only.",
                        url=self.context.target,
                        confidence=0.84,
                        observed_behavior="Wildcard origin was accepted together with credentialed CORS.",
                        verification="direct",
                        reproduction_steps=[
                            "Send a request with a malicious Origin header.",
                            "Confirm the response allows credentials with wildcard origin.",
                            "Retest after restricting allowed origins.",
                        ],
                    )
        except Exception as e:
            await event_manager.emit("log", f"[{self.name}] Error: {e}")


class CMSScanner(BaseScanner):
    """
    Enhanced CMS Scanner with detailed WordPress enumeration.
    
    Features:
    - CMS detection (WordPress, Shopify, Joomla, Drupal)
    - WordPress version extraction from multiple sources
    - Plugin enumeration
    - Theme detection
    - XML-RPC vulnerability check
    - Debug log exposure
    - Config backup detection
    """
    
    def __init__(self, context):
        super().__init__(context)
        self.zone = TestingZone.ZONE_E
        self.wp_version = None
        self.detected_cms = None
        
        # Common WordPress plugins to check
        self.common_plugins = [
            "contact-form-7", "woocommerce", "akismet", "yoast-seo",
            "elementor", "wpforms-lite", "classic-editor", "jetpack",
            "wordfence", "updraftplus", "really-simple-ssl"
        ]

    async def run(self):
        await event_manager.emit("log", f"[{self.name}] Starting enhanced CMS scan...")
        try:
            async with self.context.session.get(self.context.target, timeout=15) as response:
                html_content = await response.text()
                soup = BeautifulSoup(html_content, 'html.parser')

                # Check meta generator tag
                meta_gen = soup.find("meta", attrs={"name": "generator"})
                if meta_gen:
                    content = meta_gen.get("content", "")
                    await self._detect_cms_from_generator(content)
                
                # WordPress detection
                if "/wp-content/" in html_content or "/wp-includes/" in html_content:
                    self.detected_cms = "WordPress"
                    await event_manager.emit("log", f"[{self.name}] WordPress detected. Running detailed enumeration...")
                    await self._enumerate_wordpress(html_content, soup)
                
                # Shopify detection
                if "cdn.shopify.com" in html_content:
                    await self.emit_vulnerability(
                        "CMS Vulnerability", 
                        "Shopify CMS detected via CDN links.\nPlatform: Shopify (hosted)",
                        "P4", 
                        "Standard Shopify detection. Review app permissions.",
                        url=self.context.target
                    )
                    
        except Exception as e:
            await event_manager.emit("log", f"[{self.name}] Error: {e}")

    async def _detect_cms_from_generator(self, content):
        """Detect CMS from generator meta tag."""
        content_lower = content.lower()
        
        if "wordpress" in content_lower:
            # Extract version
            version_match = re.search(r'wordpress\s*([\d.]+)', content_lower)
            if version_match:
                self.wp_version = version_match.group(1)
                await self.emit_vulnerability(
                    "CMS Vulnerability", 
                    f"WordPress version disclosed in meta tag.\n"
                    f"Version: {self.wp_version}\n"
                    f"Source: <meta name='generator'>",
                    "P3", 
                    "Remove version from meta generator tag. Add: remove_action('wp_head', 'wp_generator');",
                    url=self.context.target,
                    payload=content
                )
            else:
                await self.emit_vulnerability(
                    "CMS Vulnerability", 
                    f"WordPress detected via meta tag: {content}",
                    "P4", 
                    "Consider hiding CMS identity.",
                    url=self.context.target
                )
        elif "joomla" in content_lower:
            await self.emit_vulnerability(
                "CMS Vulnerability", 
                f"Joomla detected via meta tag: {content}",
                "P4", 
                "Hide Joomla version and generator tag.",
                url=self.context.target
            )
        elif "drupal" in content_lower:
            await self.emit_vulnerability(
                "CMS Vulnerability", 
                f"Drupal detected via meta tag: {content}",
                "P4", 
                "Hide Drupal version information.",
                url=self.context.target
            )

    async def _enumerate_wordpress(self, html_content, soup):
        """Perform detailed WordPress enumeration."""
        base_url = self.context.target.rstrip('/')
        
        # Run enumeration tasks
        await asyncio.gather(
            self._check_wp_version_sources(base_url),
            self._check_wp_login(base_url),
            self._check_wp_users_api(base_url),
            self._check_xmlrpc(base_url),
            self._check_debug_log(base_url),
            self._check_config_backups(base_url),
            self._enumerate_plugins(base_url, html_content),
            self._enumerate_themes(base_url, html_content),
        )

    async def _check_wp_version_sources(self, base_url):
        """Check multiple sources for WordPress version."""
        version_sources = [
            (f"{base_url}/readme.html", r'Version\s*([\d.]+)'),
            (f"{base_url}/feed/", r'<generator>https?://wordpress\.org/\?v=([\d.]+)</generator>'),
            (f"{base_url}/feed/rss/", r'<generator>https?://wordpress\.org/\?v=([\d.]+)</generator>'),
        ]
        
        for url, pattern in version_sources:
            try:
                async with self.context.session.get(url, timeout=10) as response:
                    if response.status == 200:
                        text = await response.text()
                        match = re.search(pattern, text, re.IGNORECASE)
                        if match and not self.wp_version:
                            self.wp_version = match.group(1)
                            source_name = url.split('/')[-1] or url.split('/')[-2]
                            await self.emit_vulnerability(
                                "CMS Vulnerability",
                                f"WordPress version disclosed.\n"
                                f"Version: {self.wp_version}\n"
                                f"Source: {source_name}",
                                "P3",
                                f"Remove or restrict access to {source_name}",
                                url=url,
                                payload=f"Version {self.wp_version}"
                            )
            except Exception:
                pass

    async def _check_wp_login(self, base_url):
        """Check if WordPress login page is exposed."""
        login_url = f"{base_url}/wp-login.php"
        try:
            async with self.context.session.get(login_url, timeout=10) as response:
                if response.status == 200:
                    text = await response.text()
                    if "user_login" in text or "wp-login" in text:
                        await self.emit_vulnerability(
                            "CMS Vulnerability", 
                            f"WordPress Login Page Exposed.\n"
                            f"URL: {login_url}\n"
                            f"Risk: Allows brute-force attacks",
                            "P3", 
                            "Restrict access to wp-login.php via IP whitelist, .htaccess, or security plugin. Enable 2FA.",
                            url=login_url
                        )
        except Exception:
            pass

    async def _check_wp_users_api(self, base_url):
        """Check if WordPress REST API exposes users."""
        api_url = f"{base_url}/wp-json/wp/v2/users"
        try:
            async with self.context.session.get(api_url, timeout=10) as response:
                if response.status == 200:
                    text = await response.text()
                    if '"id"' in text and '"slug"' in text:
                        # Try to extract usernames
                        import json
                        try:
                            users = json.loads(text)
                            usernames = [u.get('slug', 'unknown') for u in users[:5]]
                            await self.emit_vulnerability(
                                "CMS Vulnerability", 
                                f"WordPress User Enumeration via REST API.\n"
                                f"URL: {api_url}\n"
                                f"Exposed Users: {', '.join(usernames)}",
                                "P2",  # Higher severity - exposes usernames
                                "Disable REST API user endpoints or use a security plugin like Wordfence.",
                                url=api_url,
                                payload=f"Users: {', '.join(usernames)}"
                            )
                        except json.JSONDecodeError:
                            await self.emit_vulnerability(
                                "CMS Vulnerability", 
                                f"WordPress User Enumeration via REST API.\nURL: {api_url}",
                                "P2",
                                "Disable REST API user endpoints.",
                                url=api_url
                            )
        except Exception:
            pass

    async def _check_xmlrpc(self, base_url):
        """Check if XML-RPC is enabled (used for brute-force attacks)."""
        xmlrpc_url = f"{base_url}/xmlrpc.php"
        try:
            async with self.context.session.post(xmlrpc_url, timeout=10) as response:
                if response.status == 200:
                    text = await response.text()
                    if "XML-RPC server accepts POST requests only" in text or "xmlrpc" in text.lower():
                        await self.emit_vulnerability(
                            "CMS Vulnerability",
                            f"WordPress XML-RPC Enabled.\n"
                            f"URL: {xmlrpc_url}\n"
                            f"Risk: Allows brute-force attacks and pingback DDoS",
                            "P2",
                            "Disable XML-RPC if not needed. Block at .htaccess level or use security plugin.",
                            url=xmlrpc_url
                        )
        except Exception:
            pass

    async def _check_debug_log(self, base_url):
        """Check if debug.log is exposed."""
        debug_url = f"{base_url}/wp-content/debug.log"
        try:
            async with self.context.session.get(debug_url, timeout=10) as response:
                if response.status == 200:
                    text = await response.text()
                    if len(text) > 100:  # Non-empty log file
                        await self.emit_vulnerability(
                            "CMS Vulnerability",
                            f"WordPress Debug Log Exposed!\n"
                            f"URL: {debug_url}\n"
                            f"Size: {len(text)} bytes\n"
                            f"Risk: May contain sensitive paths, errors, database info",
                            "P1",  # Critical - sensitive info exposure
                            "Remove debug.log and disable WP_DEBUG on production. Add .htaccess rule to block access.",
                            url=debug_url
                        )
        except Exception:
            pass

    async def _check_config_backups(self, base_url):
        """Check for exposed configuration backups."""
        backup_files = [
            "/wp-config.php.bak",
            "/wp-config.php.old",
            "/wp-config.php~",
            "/wp-config.php.save",
            "/wp-config.txt",
            "/.wp-config.php.swp",
        ]
        
        for backup in backup_files:
            try:
                url = f"{base_url}{backup}"
                async with self.context.session.get(url, timeout=10) as response:
                    if response.status == 200:
                        text = await response.text()
                        if "DB_NAME" in text or "DB_PASSWORD" in text or "<?php" in text:
                            await self.emit_vulnerability(
                                "CMS Vulnerability",
                                f"WordPress Config Backup Exposed!\n"
                                f"URL: {url}\n"
                                f"Risk: CRITICAL - Database credentials may be exposed",
                                "P1",  # Critical
                                "Remove backup file immediately. Never store config backups in web root.",
                                url=url,
                                payload=backup
                            )
                            return  # Found one, no need to check more
            except Exception:
                pass

    async def _enumerate_plugins(self, base_url, html_content):
        """Enumerate WordPress plugins from page source and common paths."""
        detected_plugins = set()
        
        # Extract from page source
        plugin_pattern = r'/wp-content/plugins/([^/\'"]+)'
        matches = re.findall(plugin_pattern, html_content)
        detected_plugins.update(matches)
        
        # Check common plugins
        for plugin in self.common_plugins:
            if plugin not in detected_plugins:
                try:
                    url = f"{base_url}/wp-content/plugins/{plugin}/"
                    async with self.context.session.get(url, timeout=5) as response:
                        if response.status in [200, 403]:  # 403 means exists but forbidden
                            detected_plugins.add(plugin)
                except Exception:
                    pass
        
        if detected_plugins:
            await self.emit_vulnerability(
                "CMS Vulnerability",
                f"WordPress Plugins Detected.\n"
                f"Plugins ({len(detected_plugins)}): {', '.join(list(detected_plugins)[:10])}\n"
                f"Risk: Check each plugin for known vulnerabilities",
                "P4",
                "Keep plugins updated. Remove unused plugins. Check WPScan for vulnerabilities.",
                url=f"{base_url}/wp-content/plugins/",
                payload=f"Plugins: {', '.join(list(detected_plugins)[:10])}"
            )

    async def _enumerate_themes(self, base_url, html_content):
        """Enumerate WordPress themes."""
        themes = set()
        
        # Extract from page source
        theme_pattern = r'/wp-content/themes/([^/\'"]+)'
        matches = re.findall(theme_pattern, html_content)
        themes.update(matches)
        
        if themes:
            # Try to get theme version from style.css
            for theme in list(themes)[:3]:
                try:
                    style_url = f"{base_url}/wp-content/themes/{theme}/style.css"
                    async with self.context.session.get(style_url, timeout=5) as response:
                        if response.status == 200:
                            text = await response.text()
                            version_match = re.search(r'Version:\s*([\d.]+)', text)
                            if version_match:
                                themes.discard(theme)
                                themes.add(f"{theme} v{version_match.group(1)}")
                except Exception:
                    pass
            
            await self.emit_vulnerability(
                "CMS Vulnerability",
                f"WordPress Themes Detected.\n"
                f"Themes: {', '.join(themes)}\n"
                f"Risk: Check themes for known vulnerabilities",
                "P4",
                "Keep themes updated. Remove unused themes.",
                url=f"{base_url}/wp-content/themes/",
                payload=f"Themes: {', '.join(themes)}"
            )

