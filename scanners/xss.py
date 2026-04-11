import asyncio
import urllib.parse
import contextlib
from bs4 import BeautifulSoup
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.chrome.service import Service
from webdriver_manager.chrome import ChromeDriverManager
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.common.exceptions import TimeoutException, NoAlertPresentException, UnexpectedAlertPresentException, WebDriverException

from .base import BaseScanner
from common import event_manager, TestingZone

class SeleniumXSSScanner(BaseScanner):
    def __init__(self, context):
        super().__init__(context)
        self.zone = TestingZone.ZONE_A
        self.driver = None
        self._driver_lock = asyncio.Lock()

    async def run(self):
        await event_manager.emit("log", f"[{self.name}] Starting dynamic XSS scan...")
        await event_manager.emit("log", f"[{self.name}] Optimizing {len(self.context.crawled_urls)} crawled URLs...")
        
        optimized_endpoints = self._optimize_endpoints()
        
        await event_manager.emit("log", f"[{self.name}] Optimized scan: Testing {len(optimized_endpoints)} endpoints.")
        await event_manager.emit("log", f"[Status] Launching Browser (may take 5-10s)...")

        canary = "LynxXSS"
        payloads = [
            f"<script>alert('{canary}')</script>",
            f"\"><script>alert('{canary}')</script>"
        ]

        test_urls = await self._generate_test_cases(optimized_endpoints, payloads)

        if not test_urls:
             await event_manager.emit("log", f"[{self.name}] No test cases generated.")
             return

        await event_manager.emit("log", f"[{self.name}] Generated {len(test_urls)} test cases.")

        loop = asyncio.get_running_loop()
        try:
            results = await loop.run_in_executor(None, self._selenium_work, test_urls)
        except Exception as e:
            await event_manager.emit("log", f"[red][{self.name}] Error running Selenium work: {e}[/red]")
            return
        finally:
            # Ensure cleanup happens even on error
            await self._async_cleanup()

        for result in results:
            if "error" in result:
                 await event_manager.emit("log", f"[red][{self.name}] Error: {result['error']}[/red]")
            else:
                await self.emit_vulnerability(
                    vuln_type=result["vuln_type"],
                    details=result["details"],
                    severity=result["severity"],
                    remediation=result["remediation"],
                    url=result["url"],
                    payload=result["payload"],
                    confidence=result.get("confidence", 0.98),
                    observed_behavior=result.get("observed_behavior", "Alert dialog executed in headless Chrome."),
                    reproduction_steps=result.get("reproduction_steps"),
                )

    def _optimize_endpoints(self):
        unique_paths = set()
        optimized_endpoints = []

        # Prioritize URLs with parameters
        param_urls = [u for u in self.context.crawled_urls if "?" in u]
        other_urls = [u for u in self.context.crawled_urls if "?" not in u]

        # Add up to 16 param URLs
        for url in param_urls:
            if len(optimized_endpoints) >= 16: break
            optimized_endpoints.append(url)

        # Fill rest with unique paths
        for url in other_urls:
            if len(optimized_endpoints) >= 24: break
            parsed = urllib.parse.urlparse(url)
            if parsed.path not in unique_paths:
                unique_paths.add(parsed.path)
                optimized_endpoints.append(url)
        
        return optimized_endpoints

    async def _generate_test_cases(self, endpoints, payloads):
        test_urls = []
        for endpoint in endpoints:
            # Generate URL-based injections
            for payload in payloads:
                for injected_url in self.generate_injection_points(endpoint, payload):
                    test_urls.append((injected_url, payload))
        return test_urls

    def _selenium_work(self, test_cases):
        """Synchronous method to run Selenium tests with proper resource management."""
        results = []
        
        def log_sync(msg):
            """Helper to log from sync context."""
            try:
                event_manager.emit_sync("log", msg)
            except Exception:
                pass
        
        driver = None
        try:
            for i, (target_url, payload) in enumerate(test_cases):
                display_payload = payload if len(payload) < 20 else payload[:17] + "..."
                log_sync(f"[Status] Selenium: {target_url} | Payload: {display_payload}")

                # Reinitialize driver if needed
                if driver is None:
                    driver = self._init_driver()
                    if not driver:
                        results.append({"error": "Driver failed to initialize"})
                        break  # Exit if driver can't be created
                    self.driver = driver

                try:
                    # Disable webdriver detection
                    driver.execute_cdp_cmd('Page.addScriptToEvaluateOnNewDocument', {
                        'source': 'Object.defineProperty(navigator, "webdriver", {get: () => undefined})'
                    })

                    # 1. Load the page
                    try:
                        driver.get(target_url)
                    except TimeoutException:
                        log_sync(f"[Debug] Timeout loading {target_url}")
                        continue
                    except WebDriverException as e:
                        log_sync(f"[Debug] WebDriver error loading {target_url}: {e}")
                        # Driver might be in bad state, recreate it
                        try:
                            driver.quit()
                        except:
                            pass
                        driver = self._init_driver()
                        if not driver:
                            break
                        self.driver = driver
                        continue
                    except Exception as e:
                        log_sync(f"[Debug] Error loading {target_url}: {e}")
                        continue

                    # 2. Check for Alert (Reflected in URL)
                    try:
                        WebDriverWait(driver, 3).until(EC.alert_is_present())
                        alert = driver.switch_to.alert
                        alert_text = alert.text
                        if "LynxXSS" in alert_text:
                            alert.accept()
                            # Avoid duplicates
                            if not any(r['url'] == target_url and r['payload'] == payload for r in results):
                                results.append({
                                    "vuln_type": "DOM/Reflected XSS (Selenium Verified)",
                                    "details": f"Payload executed successfully in browser.\nAlert Text: {alert_text}",
                                    "severity": "P1",
                                    "remediation": "Sanitize input and use CSP.",
                                    "url": target_url,
                                    "payload": payload
                                })
                                log_sync(f"[bold green][Selenium] VULNERABILITY FOUND (URL): {target_url}[/bold green]")
                        else:
                            alert.accept()
                    except (TimeoutException, NoAlertPresentException):
                        pass
                    except UnexpectedAlertPresentException:
                        try:
                            driver.switch_to.alert.accept()
                        except:
                            pass
                    except Exception as e:
                        log_sync(f"[Debug] Alert check error: {e}")

                except Exception as e:
                    log_sync(f"[Debug] Unexpected error on {target_url}: {str(e)}")
                    # Try to recover by recreating driver
                    try:
                        driver.quit()
                    except:
                        pass
                    driver = self._init_driver()
                    if not driver:
                        break
                    self.driver = driver

        finally:
            # Ensure driver is always cleaned up
            if driver:
                try:
                    driver.quit()
                except Exception:
                    pass
            self.driver = None
        
        return results

    def _init_driver(self):
        """Initialize Chrome driver with proper options."""
        try:
            chrome_options = Options()
            chrome_options.add_argument('--headless=new')
            chrome_options.add_argument('--no-sandbox')
            chrome_options.add_argument('--disable-dev-shm-usage')
            chrome_options.add_argument('--disable-gpu')
            chrome_options.add_argument('--disable-software-rasterizer')
            chrome_options.add_argument('--disable-extensions')
            chrome_options.add_argument('--disable-blink-features=AutomationControlled')
            chrome_options.add_argument('--user-agent=Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36')
            
            service = Service(ChromeDriverManager().install())
            driver = webdriver.Chrome(service=service, options=chrome_options)
            driver.set_page_load_timeout(15)
            return driver
        except Exception as e:
            event_manager.emit_sync("log", f"[red][{self.name}] Failed to initialize driver: {e}[/red]")
            return None

    async def _async_cleanup(self):
        """Async wrapper for cleanup."""
        async with self._driver_lock:
            if self.driver:
                try:
                    await asyncio.get_running_loop().run_in_executor(None, self.driver.quit)
                except Exception:
                    pass
                finally:
                    self.driver = None

    def cleanup(self):
        """Synchronous cleanup with proper error handling."""
        # Just quit the driver directly - don't try to use asyncio.run
        if self.driver:
            try:
                self.driver.quit()
            except Exception:
                pass
            finally:
                self.driver = None
