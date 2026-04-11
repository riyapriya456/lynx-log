"""
Lynx VAPT - Optimized Selenium Manager

Features:
- Single WebDriver instance reuse
- Optimized Chrome flags for speed
- Disable images, CSS, media loading
- Reduced timeouts
- Connection pooling
- Automatic crash recovery

Author: Lynx Team
"""

import asyncio
import atexit
from typing import Optional, Dict, Any, List
from dataclasses import dataclass
from contextlib import asynccontextmanager
import threading
import time


@dataclass
class SeleniumConfig:
    """Configuration for Selenium optimization."""
    headless: bool = True
    disable_images: bool = True
    disable_css: bool = True
    disable_javascript: bool = False  # Usually need JS
    disable_gpu: bool = True
    no_sandbox: bool = True
    disable_dev_shm: bool = True
    page_load_timeout: int = 15
    script_timeout: int = 10
    implicit_wait: int = 5
    window_size: tuple = (1920, 1080)
    user_agent: Optional[str] = None
    proxy: Optional[str] = None


class OptimizedSeleniumManager:
    """
    Manages a pool of optimized WebDriver instances.
    
    Features:
    - Single driver reuse (configurable pool)
    - Optimized Chrome flags
    - Automatic crash recovery
    - Thread-safe
    - Resource cleanup
    """
    
    # Optimized Chrome arguments
    CHROME_ARGS = [
        '--headless=new',
        '--no-sandbox',
        '--disable-dev-shm-usage',
        '--disable-gpu',
        '--disable-software-rasterizer',
        '--disable-extensions',
        '--disable-notifications',
        '--disable-popup-blocking',
        '--disable-translate',
        '--disable-background-timer-throttling',
        '--disable-backgrounding-occluded-windows',
        '--disable-renderer-backgrounding',
        '--disable-sync',
        '--metrics-recording-only',
        '--no-first-run',
        '--safebrowsing-disable-auto-update',
        '--password-store=basic',
        '--use-mock-keychain',
        '--mute-audio',
        '--ignore-certificate-errors',
        '--ignore-ssl-errors',
        '--log-level=3',
        '--silent',
    ]
    
    # Image blocking preferences
    PREFS_NO_IMAGES = {
        'profile.managed_default_content_settings.images': 2,
        'profile.default_content_setting_values.images': 2,
    }
    
    # Full resource blocking preferences
    PREFS_MINIMAL = {
        'profile.managed_default_content_settings.images': 2,
        'profile.managed_default_content_settings.stylesheets': 2,
        'profile.managed_default_content_settings.fonts': 2,
        'profile.managed_default_content_settings.plugins': 2,
        'profile.managed_default_content_settings.popups': 2,
        'profile.managed_default_content_settings.geolocation': 2,
        'profile.managed_default_content_settings.media_stream': 2,
    }
    
    def __init__(
        self,
        config: SeleniumConfig = None,
        pool_size: int = 1,
        auto_cleanup: bool = True
    ):
        self.config = config or SeleniumConfig()
        self.pool_size = pool_size
        self._drivers: List[Any] = []
        self._available: List[Any] = []
        self._lock = threading.Lock()
        self._initialized = False
        
        if auto_cleanup:
            atexit.register(self.cleanup_all)
    
    def _create_driver(self):
        """Create an optimized WebDriver instance."""
        try:
            from selenium import webdriver
            from selenium.webdriver.chrome.service import Service
            from selenium.webdriver.chrome.options import Options
            from webdriver_manager.chrome import ChromeDriverManager
        except ImportError:
            raise ImportError("selenium and webdriver_manager are required")
        
        options = Options()
        
        # Add optimized arguments
        for arg in self.CHROME_ARGS:
            if not self.config.headless and arg.startswith('--headless'):
                continue
            options.add_argument(arg)
        
        # Set window size
        options.add_argument(f'--window-size={self.config.window_size[0]},{self.config.window_size[1]}')
        
        # Set user agent if provided
        if self.config.user_agent:
            options.add_argument(f'--user-agent={self.config.user_agent}')
        
        # Set proxy if provided
        if self.config.proxy:
            options.add_argument(f'--proxy-server={self.config.proxy}')
        
        # Set preferences for resource blocking
        prefs = {}
        if self.config.disable_images:
            prefs.update(self.PREFS_NO_IMAGES)
        if self.config.disable_css:
            prefs.update(self.PREFS_MINIMAL)
        
        # Disable notifications
        prefs['profile.default_content_setting_values.notifications'] = 2
        
        if prefs:
            options.add_experimental_option('prefs', prefs)
        
        # Disable automation detection
        options.add_experimental_option('excludeSwitches', ['enable-automation'])
        options.add_experimental_option('useAutomationExtension', False)
        
        # Create service
        service = Service(ChromeDriverManager().install())
        
        # Create driver
        driver = webdriver.Chrome(service=service, options=options)
        
        # Set timeouts
        driver.set_page_load_timeout(self.config.page_load_timeout)
        driver.set_script_timeout(self.config.script_timeout)
        driver.implicitly_wait(self.config.implicit_wait)
        
        return driver
    
    def _init_pool(self):
        """Initialize the driver pool."""
        if self._initialized:
            return
        
        with self._lock:
            if self._initialized:
                return
            
            for _ in range(self.pool_size):
                try:
                    driver = self._create_driver()
                    self._drivers.append(driver)
                    self._available.append(driver)
                except Exception as e:
                    print(f"Failed to create WebDriver: {e}")
            
            self._initialized = True
    
    def get_driver(self, timeout: float = 30):
        """
        Get an available driver from the pool.
        
        Blocks until a driver is available or timeout.
        """
        self._init_pool()
        
        start = time.time()
        
        while time.time() - start < timeout:
            with self._lock:
                if self._available:
                    driver = self._available.pop(0)
                    
                    # Check if driver is still alive
                    try:
                        _ = driver.current_url
                        return driver
                    except Exception:
                        # Driver crashed, create new one
                        self._drivers.remove(driver)
                        try:
                            driver.quit()
                        except Exception:
                            pass
                        
                        new_driver = self._create_driver()
                        self._drivers.append(new_driver)
                        return new_driver
            
            time.sleep(0.1)
        
        raise TimeoutError("No WebDriver available")
    
    def release_driver(self, driver):
        """Return a driver to the pool."""
        with self._lock:
            if driver in self._drivers and driver not in self._available:
                # Clear state before returning
                try:
                    driver.delete_all_cookies()
                    driver.execute_script("window.localStorage.clear();")
                    driver.execute_script("window.sessionStorage.clear();")
                except Exception:
                    pass
                
                self._available.append(driver)
    
    @asynccontextmanager
    async def driver_context(self):
        """
        Async context manager for driver usage.
        
        Usage:
            async with manager.driver_context() as driver:
                driver.get(url)
        """
        loop = asyncio.get_running_loop()
        driver = await loop.run_in_executor(None, self.get_driver)
        
        try:
            yield driver
        finally:
            await loop.run_in_executor(None, self.release_driver, driver)
    
    def cleanup_all(self):
        """Clean up all drivers."""
        with self._lock:
            for driver in self._drivers:
                try:
                    driver.quit()
                except Exception:
                    pass
            
            self._drivers.clear()
            self._available.clear()
            self._initialized = False
    
    async def navigate(self, url: str, wait_for_load: bool = True) -> str:
        """
        Navigate to URL and return page source.
        
        Convenience method for simple navigation.
        """
        async with self.driver_context() as driver:
            loop = asyncio.get_running_loop()
            
            def _navigate():
                driver.get(url)
                if wait_for_load:
                    # Wait for document ready
                    for _ in range(50):  # 5 seconds max
                        state = driver.execute_script("return document.readyState")
                        if state == "complete":
                            break
                        time.sleep(0.1)
                return driver.page_source
            
            return await loop.run_in_executor(None, _navigate)
    
    async def execute_script(self, url: str, script: str) -> Any:
        """
        Navigate and execute JavaScript.
        """
        async with self.driver_context() as driver:
            loop = asyncio.get_running_loop()
            
            def _execute():
                driver.get(url)
                return driver.execute_script(script)
            
            return await loop.run_in_executor(None, _execute)
    
    async def check_xss_execution(self, url: str, marker: str = "XSS_MARKER") -> bool:
        """
        Check if XSS payload executed.
        
        Injects a marker check and looks for it.
        """
        async with self.driver_context() as driver:
            loop = asyncio.get_running_loop()
            
            def _check():
                driver.get(url)
                
                # Check for alert dialog
                try:
                    alert = driver.switch_to.alert
                    alert_text = alert.text
                    alert.accept()
                    return True
                except Exception:
                    pass
                
                # Check DOM for marker
                try:
                    result = driver.execute_script(
                        f"return document.body.innerHTML.includes('{marker}')"
                    )
                    return bool(result)
                except Exception:
                    return False
            
            return await loop.run_in_executor(None, _check)
    
    async def get_dom_content(self, url: str) -> Dict[str, Any]:
        """
        Get comprehensive DOM content for analysis.
        """
        async with self.driver_context() as driver:
            loop = asyncio.get_running_loop()
            
            def _get_dom():
                driver.get(url)
                
                # Wait for load
                time.sleep(0.5)
                
                return {
                    'url': driver.current_url,
                    'title': driver.title,
                    'source': driver.page_source,
                    'cookies': driver.get_cookies(),
                    'local_storage': driver.execute_script(
                        "return JSON.stringify(localStorage)"
                    ),
                    'session_storage': driver.execute_script(
                        "return JSON.stringify(sessionStorage)"
                    ),
                    'scripts': driver.execute_script(
                        "return Array.from(document.scripts).map(s => s.src || s.innerHTML.substring(0, 200))"
                    ),
                    'forms': driver.execute_script(
                        "return Array.from(document.forms).map(f => ({action: f.action, method: f.method}))"
                    ),
                }
            
            return await loop.run_in_executor(None, _get_dom)


# Global manager instance
_selenium_manager: Optional[OptimizedSeleniumManager] = None


def get_selenium_manager(config: SeleniumConfig = None) -> OptimizedSeleniumManager:
    """Get the global Selenium manager."""
    global _selenium_manager
    if _selenium_manager is None:
        _selenium_manager = OptimizedSeleniumManager(config)
    return _selenium_manager


async def quick_navigate(url: str) -> str:
    """Quick navigation convenience function."""
    manager = get_selenium_manager()
    return await manager.navigate(url)
