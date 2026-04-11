import os
import asyncio
import time
import traceback
from enum import Enum
from typing import Dict, List, Callable, Any
from rich.console import Console

VERSION = "1.0 [BETA]"
AUTHORS = ["Logesh"]
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.114 Safari/537.36"
]

console = Console()

def clear_screen():
    os.system('cls' if os.name == 'nt' else 'clear')

def print_banner():
    clear_screen()
    console.print(r"""
+======================+
| _  __   ___   ___  __|
|| | \ \ / / \ | \ \/ /|
|| |  \ V /|  \| |\  / |
|| |___| | | |\  |/  \ |
||_____|_| |_| \_/_/\_\|
+======================+
""")
    console.print(f"[bold cyan]Lynx v{VERSION} - Advanced VAPT Automation Tool[/bold cyan]")
    console.print(f"[bold cyan]Authors: {', '.join(AUTHORS)}[/bold cyan]\n")

DEBUG_ENABLED = os.getenv("LYNX_DEBUG", "true").lower() == "true"
DEBUG_LOG_FILE = "debug.log"

def debug_log(message):
    if not DEBUG_ENABLED:
        return
    try:
        with open(DEBUG_LOG_FILE, "a", encoding="utf-8") as f:
            try:
                loop = asyncio.get_running_loop()
                timestamp = loop.time()
            except RuntimeError:
                timestamp = time.time()
            f.write(f"[{timestamp:.2f}] {message}\n")
    except Exception:
        pass

class ScanPhase(Enum):
    PRE_ENGAGEMENT = "Pre-Engagement"
    RECONNAISSANCE = "Reconnaissance"
    ACTIVE_MAPPING = "Active Mapping"
    VULNERABILITY_SCANNING = "Vulnerability Scanning"
    EXPLOITATION = "Exploitation"
    REPORTING = "Reporting"

class TestingZone(Enum):
    ZONE_A = "Zone A: Input/Output Validation"
    ZONE_B = "Zone B: Authentication & Authorization"
    ZONE_C = "Zone C: Business Logic"
    ZONE_D = "Zone D: API Security"
    ZONE_E = "Zone E: Server Configuration"
    ZONE_F = "Zone F: Network/Infrastructure"
    ZONE_G = "Zone G: Data Protection"

class EventManager:
    def __init__(self):
        self.listeners: Dict[str, List[Callable]] = {}
        self.main_loop = None
        self.callback_timeout = 5.0  # seconds
        self.dead_callbacks: List[Dict[str, Any]] = []
        self.failed_callback_count = 0

    def set_loop(self, loop):
        self.main_loop = loop

    def subscribe(self, event_type: str, callback: Callable):
        if event_type not in self.listeners:
            self.listeners[event_type] = []
        self.listeners[event_type].append(callback)

    async def _execute_callback_with_timeout(self, callback: Callable, data: Any, event_type: str) -> bool:
        """
        Execute a callback with timeout and error isolation.
        
        Returns: True if successful, False if failed
        """
        try:
            if asyncio.iscoroutinefunction(callback):
                # Use asyncio.wait_for for timeout
                try:
                    await asyncio.wait_for(
                        callback(data),
                        timeout=self.callback_timeout
                    )
                    return True
                except asyncio.TimeoutError:
                    self.failed_callback_count += 1
                    self.dead_callbacks.append({
                        'event_type': event_type,
                        'callback': str(callback),
                        'error': 'Timeout',
                        'timestamp': time.time()
                    })
                    if DEBUG_ENABLED:
                        debug_log(f"[EVENT_ERROR] Callback timeout: {callback} for {event_type}")
                    return False
                except Exception as e:
                    self.failed_callback_count += 1
                    self.dead_callbacks.append({
                        'event_type': event_type,
                        'callback': str(callback),
                        'error': str(e),
                        'timestamp': time.time(),
                        'traceback': traceback.format_exc()
                    })
                    if DEBUG_ENABLED:
                        debug_log(f"[EVENT_ERROR] Callback exception: {e} in {callback}")
                    return False
            else:
                # Synchronous callback
                try:
                    callback(data)
                    return True
                except Exception as e:
                    self.failed_callback_count += 1
                    self.dead_callbacks.append({
                        'event_type': event_type,
                        'callback': str(callback),
                        'error': str(e),
                        'timestamp': time.time(),
                        'traceback': traceback.format_exc()
                    })
                    if DEBUG_ENABLED:
                        debug_log(f"[EVENT_ERROR] Sync callback exception: {e} in {callback}")
                    return False
        except Exception as e:
            self.failed_callback_count += 1
            self.dead_callbacks.append({
                'event_type': event_type,
                'callback': str(callback),
                'error': f'Unexpected error: {str(e)}',
                'timestamp': time.time(),
                'traceback': traceback.format_exc()
            })
            return False

    async def emit(self, event_type: str, data: Any):
        if DEBUG_ENABLED:
            if event_type == "log":
                debug_log(f"[LOG] {data}")
            elif event_type == "vulnerability":
                try:
                    debug_log(f"[VULN] {data.get('type', 'Unknown')} - {data.get('url', 'N/A')}")
                except (AttributeError, TypeError):
                    debug_log(f"[VULN] {data}")
            elif event_type == "net_request_error":
                debug_log(f"[NET_ERR] {data}")

        if event_type in self.listeners:
            # Execute all callbacks with error isolation
            tasks = [
                self._execute_callback_with_timeout(callback, data, event_type)
                for callback in self.listeners[event_type]
            ]
            
            # Wait for all callbacks to complete (or timeout)
            results = await asyncio.gather(*tasks, return_exceptions=True)
            
            # Log if any callbacks failed
            failed_count = sum(1 for r in results if r is False)
            if failed_count > 0 and DEBUG_ENABLED:
                debug_log(f"[EVENT] {failed_count} callbacks failed for {event_type}")

    def emit_sync(self, event_type: str, data: Any):
        if DEBUG_ENABLED:
            if event_type == "log":
                debug_log(f"[LOG] {data}")
            elif event_type == "vulnerability":
                try:
                    debug_log(f"[VULN] {data.get('type', 'Unknown')} - {data.get('url', 'N/A')}")
                except (AttributeError, TypeError):
                    debug_log(f"[VULN] {data}")
            elif event_type == "net_request_error":
                debug_log(f"[NET_ERR] {data}")

        if event_type in self.listeners:
            for callback in self.listeners[event_type]:
                if asyncio.iscoroutinefunction(callback):
                    try:
                        loop = self.main_loop
                        if not loop:
                            # Fallback logic
                            try:
                                loop = asyncio.get_running_loop()
                            except RuntimeError:
                                loop = None

                        if loop and loop.is_running():
                            # Schedule with timeout wrapper
                            future = asyncio.run_coroutine_threadsafe(
                                self._execute_callback_with_timeout(callback, data, event_type),
                                loop
                            )
                            # Don't wait for result in sync context
                        else:
                            # If no loop is running, we can't await a coroutine from sync context easily
                            # unless we run it in a new loop, but that's risky.
                            pass
                    except Exception as e:
                        self.failed_callback_count += 1
                        self.dead_callbacks.append({
                            'event_type': event_type,
                            'callback': str(callback),
                            'error': str(e),
                            'timestamp': time.time(),
                            'traceback': traceback.format_exc()
                        })
                else:
                    # Synchronous callback
                    try:
                        callback(data)
                    except Exception as e:
                        self.failed_callback_count += 1
                        self.dead_callbacks.append({
                            'event_type': event_type,
                            'callback': str(callback),
                            'error': str(e),
                            'timestamp': time.time(),
                            'traceback': traceback.format_exc()
                        })
    
    def get_dead_callback_stats(self) -> Dict[str, Any]:
        """Get statistics about failed callbacks."""
        return {
            'total_failed': self.failed_callback_count,
            'dead_callbacks': len(self.dead_callbacks),
            'recent_failures': self.dead_callbacks[-10:] if self.dead_callbacks else []
        }

    def cleanup_dead_callbacks(self):
        """Clean up old dead callback records (keep last 50)."""
        if len(self.dead_callbacks) > 50:
            self.dead_callbacks = self.dead_callbacks[-50:]
        # Also periodically reset counter to prevent integer overflow
        if self.failed_callback_count > 10000:
            self.failed_callback_count = 0

event_manager = EventManager()