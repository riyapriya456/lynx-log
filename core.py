import asyncio
import aiohttp
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from common import ScanPhase, event_manager
from katana_crawler import KatanaCrawler
from scan_policy import ManagedSession, TrafficGovernor
from scanners import get_scanner_profile


@dataclass
class ScanContext:
    target: str
    session: aiohttp.ClientSession
    payloads_dir: str
    crawled_urls: set = field(default_factory=set)
    config: Dict[str, Any] = field(default_factory=dict)
    current_phase: ScanPhase = ScanPhase.PRE_ENGAGEMENT
    findings: List[Dict] = field(default_factory=list)
    seen_vulns: set = field(default_factory=set)
    ai_api_key: Optional[str] = None
    ai_summary: Optional[str] = None
    governor: Optional[TrafficGovernor] = None


async def on_request_start(session, trace_config_ctx, params):
    await event_manager.emit("net_request_start", str(params.url))


async def on_request_end(session, trace_config_ctx, params):
    await event_manager.emit("net_request_end", {"url": str(params.url), "status": params.response.status})


async def on_request_exception(session, trace_config_ctx, params):
    await event_manager.emit("net_request_error", {"url": str(params.url), "error": str(params.exception)})


class ScanEngine:
    def __init__(self, target: str, scanners: List, payloads_dir: str, crawl: bool = False, ai_api_key: str = None):
        self.target = target
        self.scanners = scanners
        self.payloads_dir = payloads_dir
        self.crawl_enabled = crawl
        self.ai_api_key = ai_api_key
        self.initialized_scanners = []
        self.scanner_status: Dict[str, str] = {}
        self.should_stop = False
        self._running_tasks: List[asyncio.Task] = []
        self.context: Optional[ScanContext] = None
        self.governor = TrafficGovernor(
            initial_concurrency=max(4, min(8, 2 + len(scanners) // 4)),
            min_concurrency=2,
            max_concurrency=10,
        )

    def request_stop(self):
        """Request the scan to stop gracefully."""
        self.should_stop = True
        for task in self._running_tasks:
            if not task.done():
                task.cancel()

    def _ordered_scanners(self):
        def sort_key(scanner_cls):
            profile = get_scanner_profile(scanner_cls.__name__)
            cost_rank = {"low": 0, "medium": 1, "high": 2}.get(profile.get("cost", "medium"), 1)
            return (profile.get("priority", 100), cost_rank, scanner_cls.__name__)

        return sorted(self.scanners, key=sort_key)

    async def _cooldown_if_needed(self, cost_tier: str = "medium"):
        if self.governor.should_defer_high_cost():
            delay = 0.8 if cost_tier == "low" else 1.5 if cost_tier == "medium" else 3.0
            await event_manager.emit("log", f"[Governor] Backing off for {delay:.1f}s before next stage.")
            await asyncio.sleep(delay)

    async def run(self):
        connector = None
        session = None
        try:
            trace_config = aiohttp.TraceConfig()
            trace_config.on_request_start.append(on_request_start)
            trace_config.on_request_end.append(on_request_end)
            trace_config.on_request_exception.append(on_request_exception)

            connector = aiohttp.TCPConnector(
                limit=24,
                limit_per_host=4,
                ttl_dns_cache=300,
                force_close=False,
                enable_cleanup_closed=True,
            )
            timeout = aiohttp.ClientTimeout(total=30, connect=10, sock_read=15)

            async with aiohttp.ClientSession(connector=connector, timeout=timeout, trace_configs=[trace_config]) as raw_session:
                session = ManagedSession(raw_session, self.governor)
                self.context = ScanContext(
                    self.target,
                    session,
                    self.payloads_dir,
                    ai_api_key=self.ai_api_key,
                    governor=self.governor,
                    config={
                        "max_scan_urls": 30,
                        "max_payloads_per_url": 6,
                        "defer_high_cost_on_block": True,
                    },
                )

                self.context.current_phase = ScanPhase.PRE_ENGAGEMENT
                await event_manager.emit("log", "[Phase] Pre-Engagement: Initializing...")

                if self.should_stop:
                    return

                if self.crawl_enabled:
                    self.context.current_phase = ScanPhase.ACTIVE_MAPPING
                    await event_manager.emit("log", "[Phase] Active Mapping: Crawling target with Katana...")
                    crawler = KatanaCrawler(self.context)
                    try:
                        await asyncio.wait_for(crawler.crawl(self.target), timeout=180)
                    except asyncio.TimeoutError:
                        await event_manager.emit("log", "[yellow][Warning] Crawling timed out after 180s, proceeding with found URLs.[/yellow]")
                    except Exception as e:
                        await event_manager.emit("log", f"[yellow][Warning] Crawling error: {e}, proceeding with found URLs.[/yellow]")

                if self.should_stop:
                    return

                if not self.context.crawled_urls:
                    self.context.crawled_urls.add(self.target)

                await event_manager.emit("log", "[Phase] Analysis: Identifying injection points...")
                candidates = [url for url in self.context.crawled_urls if "?" in url]
                if not candidates and "?" in self.context.target:
                    candidates.append(self.context.target)

                if candidates:
                    await event_manager.emit("log", f"[Analysis] Found {len(candidates)} URLs with parameters for injection.")
                else:
                    await event_manager.emit("log", "[Analysis] No parameters found in crawled URLs. Scanners will pivot to path/header checks.")

                if self.should_stop:
                    return

                await event_manager.emit("log", f"[Phase] Vulnerability Scanning: Launching {len(self.scanners)} Modules...")
                self.context.current_phase = ScanPhase.VULNERABILITY_SCANNING

                for scanner_cls in self._ordered_scanners():
                    if self.should_stop:
                        await event_manager.emit("log", "[yellow][Warning] Stop requested. Generating report with findings so far...[/yellow]")
                        break

                    profile = get_scanner_profile(scanner_cls.__name__)
                    cost_tier = profile.get("cost", "medium")

                    if cost_tier == "high" and self.governor.should_skip_heavy_scan():
                        self.scanner_status[scanner_cls.__name__] = "Skipped"
                        await event_manager.emit("log", f"[Governor] Skipping {scanner_cls.__name__} due to target backoff/circuit state.")
                        continue

                    await self._cooldown_if_needed(cost_tier)
                    scanner = scanner_cls(self.context)
                    self.initialized_scanners.append(scanner)
                    self.scanner_status[scanner.name] = "Pending"
                    await self.run_scanner_wrapper(scanner)

                self.context.current_phase = ScanPhase.REPORTING

                if self.ai_api_key and self.context.findings and not self.should_stop:
                    try:
                        from ai_engine import AIEngine

                        ai_engine = AIEngine(self.ai_api_key)
                        await event_manager.emit("log", "[AI] Generating Executive Summary...")
                        self.context.ai_summary = await ai_engine.generate_executive_summary(self.context.findings)
                    except Exception as e:
                        await event_manager.emit("log", f"[AI] Failed to generate summary: {e}")

                if self.should_stop:
                    await event_manager.emit("log", "[yellow]Scan stopped by user. Report will contain partial results.[/yellow]")
                else:
                    await event_manager.emit("log", "All scans completed.")

        finally:
            self.cleanup_scanners()
            if session and not session.closed:
                await session.close()
            if connector and not connector.closed:
                await connector.close()

    async def run_scanner_wrapper(self, scanner):
        """Run a scanner with error handling and stop support."""
        if self.should_stop:
            self.scanner_status[scanner.name] = "Skipped"
            return

        self.scanner_status[scanner.name] = "Running"
        try:
            await event_manager.emit("log", f"[{self.name_display(scanner.name)}] Starting...")
            await scanner.run()
            self.scanner_status[scanner.name] = "Completed"
        except asyncio.CancelledError:
            self.scanner_status[scanner.name] = "Cancelled"
            await event_manager.emit("log", f"[yellow][{self.name_display(scanner.name)}] Cancelled[/yellow]")
            raise
        except aiohttp.ClientError as e:
            self.scanner_status[scanner.name] = "Failed"
            await event_manager.emit("log", f"[red][{self.name_display(scanner.name)}] HTTP error: {type(e).__name__}[/red]")
        except asyncio.TimeoutError:
            self.scanner_status[scanner.name] = "Timeout"
            await event_manager.emit("log", f"[yellow][{self.name_display(scanner.name)}] Timed out[/yellow]")
        except Exception as e:
            self.scanner_status[scanner.name] = "Failed"
            await event_manager.emit("log", f"[red][{self.name_display(scanner.name)}] Error: {type(e).__name__}: {e}[/red]")
        finally:
            status = self.scanner_status.get(scanner.name, "Unknown")
            await event_manager.emit("log", f"[{self.name_display(scanner.name)}] {status}.")
            await event_manager.emit("scanner_status", self.scanner_status)

    @staticmethod
    def name_display(name: str) -> str:
        """Shorten scanner name for display."""
        name = name.replace("Scanner", "").replace("Check", "")
        if len(name) > 20:
            name = name[:17] + "..."
        return name

    def cleanup_scanners(self):
        for scanner in self.initialized_scanners:
            if hasattr(scanner, 'cleanup'):
                try:
                    scanner.cleanup()
                except Exception:
                    pass
