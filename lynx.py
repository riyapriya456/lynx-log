import asyncio
import argparse
import os
import sys
import json
import datetime
import time
from dataclasses import dataclass
from rich.live import Live
from rich.panel import Panel
from rich.prompt import Prompt
from rich.layout import Layout
from rich.console import Console

from common import event_manager, print_banner, console
from core import ScanEngine
from reporter import Reporter
from scanners import get_all_scanners, SQLiScanner, SeleniumXSSScanner, \
    HTMLInjectionScanner, CommandInjectionScanner, XXEScanner, LFIScanner, \
    SecurityHeadersCheck, CORSCheck, CMSScanner, SSRFScanner, IDORScanner, \
    CSRFScanner, OpenRedirectScanner, JSAnalyzerScanner, Bypass403Scanner, \
    AuthBypassScanner, RateLimitBypassScanner, TwoFABypassScanner, \
    JSONAttackScanner, MassAssignmentScanner, CookieAttackScanner, PasswordResetScanner
from updater import check_for_updates
from ui import dashboard

# Global reference to engine for keyboard stop
_engine_ref = None

async def log_handler(message):
    dashboard.add_log(message)

async def status_handler(data):
    if isinstance(data, dict):
        total = len(data)
        completed = sum(1 for status in data.values() if status == "Completed")
        running = sum(1 for status in data.values() if status == "Running")
        skipped = sum(1 for status in data.values() if status == "Skipped")
        failed = sum(1 for status in data.values() if status in {"Failed", "Timeout", "Cancelled"})
        dashboard.current_action = f"{completed}/{total} scanners complete"
        dashboard.status_message = f"Running: {running} | Skipped: {skipped} | Failed: {failed}"
    else:
        dashboard.status_message = str(data)

async def vuln_handler(data):
    dashboard.add_vuln(data)

async def net_start_handler(url):
    dashboard.net_request_start(url)

async def net_end_handler(data):
    dashboard.net_request_end(data)

async def net_error_handler(data):
    dashboard.net_request_error(data)

@dataclass
class MockContext:
    target: str
    findings: list
    ai_summary: str = None


def _keyboard_monitor_thread(engine, stop_event):
    """
    Background thread that monitors keyboard input.
    Runs in a separate thread to not block the event loop.
    
    Controls:
    - 'q' or 'Q': Quit scan and generate report with findings so far
    - Ctrl+C: Stop scan and generate report
    """
    import threading
    while not stop_event.is_set():
        try:
            if os.name == 'nt':
                import msvcrt
                if msvcrt.kbhit():
                    key = msvcrt.getch()
                    if key in (b'q', b'Q'):
                        engine.request_stop()
                        stop_event.set()
                        break
                time.sleep(0.1)
            else:
                import select
                ready, _, _ = select.select([sys.stdin], [], [], 0.2)
                if ready:
                    line = sys.stdin.readline().strip()
                    if line.lower() in ('q', 'quit', 'stop'):
                        engine.request_stop()
                        stop_event.set()
                        break
        except Exception:
            time.sleep(0.2)


def generate_report(engine, target, dashboard):
    """Generate report from current findings. Called on stop/quit/completion."""
    console.print("\n[bold]Generating report from findings...[/bold]")

    if engine.scanner_status:
        console.print("\n[bold cyan]Module Execution Status:[/bold cyan]")
        for name, status in engine.scanner_status.items():
            color_map = {"Completed": "green", "Failed": "red", "Cancelled": "yellow", 
                        "Skipped": "dim", "Timeout": "yellow", "Running": "cyan", "Pending": "dim"}
            color = color_map.get(status, "white")
            console.print(f"  - {name}: [{color}]{status}[/{color}]")

    if dashboard.vulns:
        p1 = sum(1 for v in dashboard.vulns if v.get('severity') == 'P1')
        p2 = sum(1 for v in dashboard.vulns if v.get('severity') == 'P2')
        p3 = sum(1 for v in dashboard.vulns if v.get('severity') == 'P3')
        p4 = sum(1 for v in dashboard.vulns if v.get('severity') == 'P4')

        console.print(f"\n[bold red]Found {len(dashboard.vulns)} vulnerabilities![/bold red]")
        console.print(f"  [red]P1 (Critical): {p1}[/red]")
        console.print(f"  [orange1]P2 (High): {p2}[/orange1]")
        console.print(f"  [yellow]P3 (Medium): {p3}[/yellow]")
        console.print(f"  [cyan]P4 (Low): {p4}[/cyan]")

        console.print("\n[bold]Findings:[/bold]")
        for v in dashboard.vulns:
            console.print(f"  [{v.get('severity', 'P4')}] {v.get('type', 'Unknown')}: {v.get('url', 'N/A')}")

        findings_data = {
            "scan_id": f"LYNX-{datetime.datetime.now().strftime('%Y%m%d-%H%M%S')}",
            "target": target,
            "mode": "active",
            "timestamp": datetime.datetime.now().isoformat(),
            "summary": {
                "total": len(dashboard.vulns),
                "P1": p1, "P2": p2, "P3": p3, "P4": p4
            },
            "findings": dashboard.vulns
        }

        try:
            with open("findings.json", "w", encoding="utf-8") as f:
                json.dump(findings_data, f, indent=2)
            console.print(f"\n[bold cyan]Findings saved to: {os.path.abspath('findings.json')}[/bold cyan]")

            mock_context = MockContext(target, dashboard.vulns, ai_summary=None)
            reporter = Reporter(mock_context)
            report_file = reporter.generate_report()

            if report_file:
                console.print(f"[bold green]Report saved to: {os.path.abspath(report_file)}[/bold green]")
                try:
                    if os.path.exists("findings.json"):
                        os.remove("findings.json")
                except Exception:
                    pass
        except Exception as e:
            console.print(f"[red]Error generating report: {e}[/red]")
    else:
        completed = sum(1 for s in engine.scanner_status.values() if s == "Completed")
        failed = sum(1 for s in engine.scanner_status.values() if s == "Failed")
        console.print(f"\n[yellow]No vulnerabilities found.[/yellow]")
        console.print(f"  Scanners completed: {completed}, failed: {failed}")
        console.print(f"  Total requests: {dashboard.total_requests}, failed: {dashboard.failed_requests}")


async def main_async():
    global _engine_ref

    parser = argparse.ArgumentParser(description="Lynx v1.0 - VAPT Tool")
    parser.add_argument("-u", "--url", help="Target URL")
    parser.add_argument("--quick", action="store_true", help="Run a quick scan (no crawl)")
    parser.add_argument("--update", action="store_true", help="Check for updates")
    parser.add_argument("--crawl", action="store_true", help="Enable crawling")
    parser.add_argument("-s", "--scanner", help="Specific scanner to run (xss, sqli, full)", default="full")
    parser.add_argument("--scanners", help="Comma-separated list of scanners (e.g., sqli,xss)")
    args = parser.parse_args()

    if args.update:
        check_for_updates(force=True)
        return

    target = args.url
    
    # Select scanners based on argument
    if args.scanners:
        scanner_map = {
            "sqli": SQLiScanner, "xss": SeleniumXSSScanner,
            "html": HTMLInjectionScanner, "command": CommandInjectionScanner,
            "xxe": XXEScanner, "lfi": LFIScanner,
            "headers": SecurityHeadersCheck, "cors": CORSCheck, "cms": CMSScanner,
            "ssrf": SSRFScanner, "idor": IDORScanner, "csrf": CSRFScanner,
            "redirect": OpenRedirectScanner, "js": JSAnalyzerScanner,
            "403": Bypass403Scanner, "auth": AuthBypassScanner,
            "ratelimit": RateLimitBypassScanner, "2fa": TwoFABypassScanner,
            "json": JSONAttackScanner, "mass": MassAssignmentScanner,
            "cookie": CookieAttackScanner, "passwordreset": PasswordResetScanner,
        }
        selected_scanners = []
        for name in args.scanners.lower().split(","):
            name = name.strip()
            if name in scanner_map:
                selected_scanners.append(scanner_map[name])
            else:
                console.print(f"[yellow]Warning: Unknown scanner '{name}', ignoring.[/yellow]")
        if not selected_scanners:
            selected_scanners = get_all_scanners()
    elif args.scanner.lower() == "xss":
        selected_scanners = [SeleniumXSSScanner]
    elif args.scanner.lower() == "sqli":
        selected_scanners = [SQLiScanner]
    else:
        selected_scanners = get_all_scanners()
    
    crawl_enabled = True

    print_banner()

    if not target:
        console.print(Panel.fit("[bold cyan]Interactive Mode[/bold cyan]"))
        console.print("1. Comprehensive VAPT Scan (All Zones + Crawl)")
        console.print("2. Quick Scan (No Crawl, Fast Checks)")
        console.print("3. Custom: SQL Injection Only")
        console.print("4. Selenium XSS Scan (Dynamic)")
        console.print("5. 403 Bypass Scan")
        console.print("6. JavaScript Analyzer (Secrets, Endpoints, Vulns)")
        console.print("7. Update Tool")

        choice = Prompt.ask("Select an option", choices=["1", "2", "3", "4", "5", "6", "7"], default="1")

        if choice == "1":
            selected_scanners = get_all_scanners()
            crawl_enabled = True
        elif choice == "2":
            selected_scanners = get_all_scanners()
            crawl_enabled = False
        elif choice == "3":
            selected_scanners = [SQLiScanner]
            crawl_enabled = False
        elif choice == "4":
            selected_scanners = [SeleniumXSSScanner]
            crawl_enabled = True
        elif choice == "5":
            from scanners.bypass403 import Bypass403Scanner
            selected_scanners = [Bypass403Scanner]
            crawl_enabled = False
        elif choice == "6":
            from scanners.js_analyzer import JSAnalyzerScanner
            selected_scanners = [JSAnalyzerScanner]
            crawl_enabled = True
        elif choice == "7":
            if check_for_updates(force=True):
                return
            return

        target = Prompt.ask("[cyan]Enter target URL[/cyan]")

    if args.quick:
        crawl_enabled = False
    elif args.crawl:
        crawl_enabled = True

    event_manager.subscribe("log", log_handler)
    event_manager.subscribe("vulnerability", vuln_handler)
    event_manager.subscribe("net_request_start", net_start_handler)
    event_manager.subscribe("net_request_end", net_end_handler)
    event_manager.subscribe("net_request_error", net_error_handler)
    event_manager.subscribe("scanner_status", status_handler)

    base_dir = os.path.dirname(os.path.abspath(__file__))
    payloads_dir = os.path.join(base_dir, "payloads")

    # Validate AI API key
    ai_api_key = os.getenv("GEMINI_API_KEY")
    ai_enabled = False
    
    if ai_api_key:
        if not isinstance(ai_api_key, str) or len(ai_api_key.strip()) < 10:
            console.print("[yellow]Warning: GEMINI_API_KEY appears invalid. AI disabled.[/yellow]")
            ai_api_key = None
        else:
            console.print("[green]AI features enabled.[/green]")
            ai_enabled = True
    else:
        console.print("[dim]No GEMINI_API_KEY set. Running without AI.[/dim]")
    
    engine = ScanEngine(
        target, selected_scanners, payloads_dir,
        crawl=crawl_enabled, ai_api_key=ai_api_key
    )
    _engine_ref = engine

    dashboard.set_scanner_count(len(selected_scanners))
    dashboard.start_timer()
    dashboard.status_message = "Preparing scan"

    # Show control instructions
    console.print("\n[dim]Controls: [bold]q[/bold] = quit & generate report | [bold]Ctrl+C[/bold] = stop & generate report[/dim]\n")

    import threading
    stop_event = threading.Event()
    kb_thread = None

    with Live(dashboard.generate_layout(), refresh_per_second=4, screen=True) as live:
        # Start keyboard monitor in background thread
        try:
            kb_thread = threading.Thread(
                target=_keyboard_monitor_thread,
                args=(engine, stop_event),
                daemon=True,
                name="KeyboardMonitor"
            )
            kb_thread.start()
        except Exception:
            pass

        task = asyncio.create_task(engine.run())

        try:
            while not task.done():
                live.update(dashboard.generate_layout())
                await asyncio.sleep(0.25)
                # Check if stop was requested via keyboard
                if engine.should_stop:
                    # Give scanners a moment to finish current check
                    try:
                        await asyncio.wait_for(task, timeout=10)
                    except asyncio.TimeoutError:
                        task.cancel()
                        try:
                            await task
                        except asyncio.CancelledError:
                            pass
                    break
            # If task finished normally, await it to get any exceptions
            if not task.done():
                await task
            else:
                # Re-raise any exception from the task
                if task.exception():
                    raise task.exception()
        except asyncio.CancelledError:
            pass
        except KeyboardInterrupt:
            engine.request_stop()
            try:
                await asyncio.wait_for(task, timeout=10)
            except (asyncio.TimeoutError, asyncio.CancelledError):
                task.cancel()
                try:
                    await task
                except asyncio.CancelledError:
                    pass
        except Exception as e:
            console.print(f"\n[bold red]Error during scan:[/bold red] {e}")
            import traceback
            traceback.print_exc()
        finally:
            stop_event.set()
            live.update(dashboard.generate_layout())

    # Generate report with whatever findings we have
    generate_report(engine, target, dashboard)

    console.print("\n[dim]Press Enter to exit...[/dim]")
    try:
        await asyncio.get_running_loop().run_in_executor(None, input)
    except:
        pass


def main():
    global _engine_ref
    loop = None
    try:
        import sys
        if "--update" not in sys.argv:
             try:
                 if check_for_updates():
                     return
             except Exception:
                 pass

        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        event_manager.set_loop(loop)

        task = loop.create_task(main_async())
        loop.run_until_complete(task)
    except KeyboardInterrupt:
        console.print("\n[bold yellow]Scan stopped by user.[/bold yellow]")
        # Try to generate report with whatever we have
        if _engine_ref:
            try:
                _engine_ref.request_stop()
                generate_report(_engine_ref, _engine_ref.target if hasattr(_engine_ref, 'target') else "unknown", dashboard)
            except Exception:
                pass
        if loop and not loop.is_closed():
            try:
                pending = asyncio.all_tasks(loop)
                for t in pending:
                    t.cancel()
                loop.run_until_complete(asyncio.gather(*pending, return_exceptions=True))
            except Exception:
                pass
            finally:
                try:
                    loop.close()
                except Exception:
                    pass
        return
    except Exception as e:
        console.print(f"\n[bold red]Fatal Error: {e}[/bold red]")
        import traceback
        traceback.print_exc()
        if loop and not loop.is_closed():
            try:
                loop.close()
            except Exception:
                pass
        return

if __name__ == "__main__":
    main()
