import asyncio
import os
import json
import shutil
import urllib.parse
from typing import Set
from common import event_manager, console

class KatanaCrawler:
    def __init__(self, context):
        self.context = context
        self.katana_path = shutil.which("katana")
        if not self.katana_path:
             # Fallback to known path if not in PATH (specific to this environment setup)
             if os.path.exists("/home/jules/go/bin/katana"):
                 self.katana_path = "/home/jules/go/bin/katana"
             else:
                 self.katana_path = "katana" # Hope it's in PATH or will fail gracefully with error

    async def crawl(self, target: str):
        if not self.katana_path and not shutil.which("katana"):
             await event_manager.emit("log", "[red][Katana] Error: katana binary not found. Please install projectdiscovery/katana.[/red]")
             return

        await event_manager.emit("log", f"[Katana] Starting crawl for: {target}")

        # Prepare arguments
        args = [
            self.katana_path,
            "-u", target,
            "-jsonl",           # Output as JSONL
            "-silent",          # Only output findings
            "-d", "3",          # Depth 3
            "-jc",              # JS crawl
            "-kf", "all",       # Known files (robots, sitemap)
            "-c", "10",         # Concurrency
            "-timeout", "10",
            "-retry", "1",
            "-headless",        # Enable headless mode for better coverage
        ]

        try:
            process = await asyncio.create_subprocess_exec(
                *args,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )

            while True:
                line = await process.stdout.readline()
                if not line:
                    break

                try:
                    line_text = line.decode().strip()
                    if not line_text:
                        continue

                    data = json.loads(line_text)
                    url = data.get("request", {}).get("endpoint")

                    if url:
                        # Clean up URL
                        parsed = urllib.parse.urlparse(url)
                        if parsed.scheme and parsed.netloc:
                            # Filter out non-http(s)
                            if parsed.scheme not in ["http", "https"]:
                                continue

                            # Filter out static assets
                            ext = os.path.splitext(parsed.path)[1].lower()
                            if ext in ['.css', '.png', '.jpg', '.jpeg', '.gif', '.svg', '.pdf', '.zip', '.woff', '.woff2', '.ttf']:
                                continue

                            if url not in self.context.crawled_urls:
                                self.context.crawled_urls.add(url)
                                await event_manager.emit("log", f"[Katana] Found: {url}")

                except json.JSONDecodeError:
                    pass
                except Exception as e:
                    await event_manager.emit("log", f"[Katana] Error parsing line: {e}")

            await process.wait()

            stderr = await process.stderr.read()
            if stderr:
                # Log stderr but don't treat all as errors, Katana is chatty
                pass

            await event_manager.emit("log", f"[Katana] Crawl finished. Found {len(self.context.crawled_urls)} URLs.")

        except Exception as e:
            await event_manager.emit("log", f"[red][Katana] Failed to execute: {e}[/red]")
