import asyncio
import hashlib
import os
import random
import statistics
import urllib.parse

from bs4 import BeautifulSoup

from common import TestingZone, event_manager
from .base import BaseScanner


class SQLiScanner(BaseScanner):
    """
    SQL Injection scanner with conservative pacing and confidence-based reporting.

    Goals:
    - keep request volume bounded
    - reduce false positives with baseline timing and error markers
    - report reproducible evidence
    """

    def __init__(self, context):
        super().__init__(context)
        self.zone = TestingZone.ZONE_A
        self.scanned_forms = set()
        self.sql_errors = [
            "SQL syntax",
            "mysql_fetch",
            "syntax error",
            "ORA-",
            "PostgreSQL",
            "SQLite/JDBCDriver",
            "SQLSTATE",
            "mysql_num_rows",
            "pg_query",
            "sqlite3_",
            "mssql_query",
            "Microsoft SQL Server",
            "Unclosed quotation",
            "quoted string not properly terminated",
        ]
        self.baseline_times = []
        self.baseline_mean = None
        self.baseline_stddev = None

    async def run(self):
        await event_manager.emit("log", f"[{self.name}] Starting SQLi scan on {len(self.context.crawled_urls)} URLs...")
        await self._measure_baseline()

        payloads_file = os.path.join(self.context.payloads_dir, "sqli", "sqli.txt")
        if not os.path.exists(payloads_file):
            error_payloads = ["'", "\"", "1' OR '1'='1", "1 OR 1=1", "' OR ''='", "admin'--"]
        else:
            with open(payloads_file, "r", encoding="utf-8", errors="ignore") as f:
                error_payloads = [line.strip() for line in f if line.strip()]

        if len(error_payloads) > 18:
            error_payloads = error_payloads[:18]

        time_payloads = [
            "1' WAITFOR DELAY '0:0:5'--",
            "1' AND SLEEP(5)-- -",
            "1 AND SLEEP(5)",
            "1' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--",
        ]

        urls_to_scan = self.context.crawled_urls if self.context.crawled_urls else {self.context.target}
        tasks = []

        for url in urls_to_scan:
            for payload in error_payloads[:10]:
                for target_url in self.generate_injection_points(url, payload):
                    tasks.append(self.check_error_based(payload, target_url))

            for payload in time_payloads[:1]:
                for target_url in self.generate_injection_points(url, payload):
                    tasks.append(self.check_time_based(payload, target_url))

            tasks.append(self.scan_forms(url, error_payloads[:6], time_payloads[:1]))

        chunk_size = 6
        for i in range(0, len(tasks), chunk_size):
            await asyncio.gather(*tasks[i : i + chunk_size])

    async def _measure_baseline(self):
        try:
            times = []
            num_samples = 3

            await event_manager.emit("log", f"[{self.name}] Measuring baseline response time ({num_samples} samples)...")

            for i in range(num_samples):
                start = asyncio.get_running_loop().time()
                try:
                    async with self.context.session.get(self.context.target, timeout=30) as response:
                        await response.read()
                except Exception:
                    continue
                elapsed = asyncio.get_running_loop().time() - start
                times.append(elapsed)
                if i < num_samples - 1:
                    await asyncio.sleep(random.uniform(0.1, 0.3))

            if len(times) < 3:
                self.baseline_mean = 2.0
                self.baseline_stddev = 0.5
                await event_manager.emit("log", f"[{self.name}] Insufficient samples, using default baseline")
                return

            self.baseline_mean = statistics.mean(times)
            self.baseline_stddev = statistics.stdev(times) if len(times) > 1 else 0.5
            await event_manager.emit(
                "log",
                f"[{self.name}] Baseline: mean={self.baseline_mean:.3f}s, "
                f"stddev={self.baseline_stddev:.3f}s, min={min(times):.3f}s, max={max(times):.3f}s",
            )
        except Exception as e:
            self.baseline_mean = 2.0
            self.baseline_stddev = 0.5
            await event_manager.emit("log", f"[{self.name}] Baseline measurement failed, using defaults: {e}")

    def _is_significant_delay(self, elapsed: float) -> bool:
        if self.baseline_mean is None or self.baseline_stddev is None:
            return elapsed > 8

        threshold = self.baseline_mean + (3 * self.baseline_stddev)
        min_delay = 5.0
        is_significant = elapsed > min_delay and elapsed > threshold

        if elapsed > min_delay and not is_significant:
            ratio = (elapsed - self.baseline_mean) / self.baseline_stddev if self.baseline_stddev > 0 else 0
            event_manager.emit_sync(
                "log",
                f"[{self.name}] Delay {elapsed:.2f}s not significant "
                f"(threshold: {threshold:.2f}s, ratio: {ratio:.1f} sigma)",
            )

        return is_significant

    async def scan_forms(self, url, error_payloads, time_payloads):
        try:
            async with self.context.session.get(url, timeout=15) as response:
                html = await response.text()
                soup = BeautifulSoup(html, "html.parser")
                forms = soup.find_all("form")
                for form in forms:
                    action = form.get("action")
                    method = form.get("method", "get").lower()
                    inputs = form.find_all(["input", "textarea"])
                    action_url = urllib.parse.urljoin(url, action) if action else url

                    input_names = sorted([i.get("name", "") for i in inputs])
                    form_sig = f"{action_url}|{method}|{','.join(input_names)}"
                    form_hash = hashlib.md5(form_sig.encode()).hexdigest()

                    if form_hash in self.scanned_forms:
                        continue
                    self.scanned_forms.add(form_hash)

                    for payload in error_payloads[:8]:
                        await self._inject_form(action_url, method, inputs, payload, "error")
                    for payload in time_payloads[:1]:
                        await self._inject_form(action_url, method, inputs, payload, "time")
        except Exception:
            pass

    async def _inject_form(self, url, method, inputs, payload, check_type):
        for input_tag in inputs:
            name = input_tag.get("name")
            if not name:
                continue
            data = {i.get("name"): "test" for i in inputs if i.get("name")}
            data[name] = payload

            try:
                if method == "post":
                    if check_type == "error":
                        await self.check_post_error_based(url, data, payload)
                    elif check_type == "time":
                        await self.check_post_time_based(url, data, payload)
                else:
                    query = urllib.parse.urlencode(data)
                    full_url = f"{url}?{query}"
                    if check_type == "error":
                        await self.check_error_based(payload, full_url)
                    elif check_type == "time":
                        await self.check_time_based(payload, full_url)
            except Exception:
                pass

    async def check_post_error_based(self, url, data, payload):
        try:
            async with self.context.session.post(url, data=data, timeout=15) as response:
                text = await response.text()
                if self.is_vulnerable(text):
                    await self.emit_vulnerability(
                        "SQL Injection (POST)",
                        f"Error-based SQLi detected.\nPayload: {payload}\nForm Data: {data}",
                        "P1",
                        "Use parameterized queries (prepared statements).",
                        url=url,
                        payload=payload,
                        confidence=0.98,
                        response_excerpt=text[:500],
                        observed_behavior="Database error markers returned after the injected payload was submitted.",
                        verification="direct",
                        reproduction_steps=[
                            "Open the affected POST form.",
                            "Submit the recorded payload in the targeted field.",
                            "Observe the SQL error strings in the response body.",
                        ],
                    )
        except Exception:
            pass

    async def check_post_time_based(self, url, data, payload):
        try:
            start = asyncio.get_running_loop().time()
            async with self.context.session.post(url, data=data, timeout=30) as response:
                await response.read()
            elapsed = asyncio.get_running_loop().time() - start

            if self._is_significant_delay(elapsed):
                await self.emit_vulnerability(
                    "Time-Based SQLi (POST)",
                    f"Time-based SQLi detected with statistical confidence.\n"
                    f"Payload: {payload}\n"
                    f"Response Delay: {elapsed:.2f}s\n"
                    f"Baseline Mean: {self.baseline_mean:.2f}s\n"
                    f"Baseline StdDev: {self.baseline_stddev:.2f}s\n"
                    f"Deviation: {(elapsed - self.baseline_mean) / self.baseline_stddev if self.baseline_stddev > 0 else 0:.1f} sigma",
                    "P1",
                    "Use parameterized queries (prepared statements).",
                    url=url,
                    payload=payload,
                    confidence=0.9,
                    observed_behavior=f"Response time increased to {elapsed:.2f}s versus baseline {self.baseline_mean:.2f}s.",
                    verification="statistical",
                    reproduction_steps=[
                        "Capture a baseline response time for the same endpoint.",
                        "Replay the time-delay payload against the same parameter.",
                        "Confirm the response delay exceeds the statistical threshold on repeat requests.",
                    ],
                )
        except asyncio.TimeoutError:
            await self.emit_vulnerability(
                "Time-Based SQLi (POST)",
                f"Possible time-based SQLi (request timed out).\n"
                f"Payload: {payload}\n"
                f"Note: Request exceeded 30s timeout, manual verification needed.",
                "P2",
                "Use parameterized queries (prepared statements).",
                url=url,
                payload=payload,
                confidence=0.68,
                observed_behavior="Injected request exceeded the request timeout window.",
                verification="heuristic",
                reproduction_steps=[
                    "Open the affected POST form.",
                    "Submit the payload in the targeted field.",
                    "Confirm the request stalls or times out consistently.",
                    "Repeat with a baseline request to compare timing.",
                ],
            )
        except Exception:
            pass

    async def check_error_based(self, payload, url=None):
        if not url:
            return
        try:
            async with self.context.session.get(url, timeout=15) as response:
                text = await response.text()
                if self.is_vulnerable(text):
                    await self.emit_vulnerability(
                        "SQL Injection",
                        f"Error-based SQLi detected.\nURL: {url}\nPayload: {payload}",
                        "P1",
                        "Use parameterized queries (prepared statements).",
                        url=url,
                        payload=payload,
                        confidence=0.98,
                        response_excerpt=text[:500],
                        observed_behavior="Database error markers returned after the injected payload was sent.",
                        verification="direct",
                        reproduction_steps=[
                            "Open the affected URL with parameters.",
                            "Replay the payload against the vulnerable parameter.",
                            "Inspect the response for SQL error messages.",
                        ],
                    )
        except Exception:
            pass

    async def check_time_based(self, payload, url):
        try:
            start = asyncio.get_running_loop().time()
            async with self.context.session.get(url, timeout=30) as response:
                await response.read()
            elapsed = asyncio.get_running_loop().time() - start

            if self._is_significant_delay(elapsed):
                await self.emit_vulnerability(
                    "Time-Based SQLi",
                    f"Time-based SQLi detected with statistical confidence.\n"
                    f"URL: {url}\n"
                    f"Payload: {payload}\n"
                    f"Response Delay: {elapsed:.2f}s\n"
                    f"Baseline Mean: {self.baseline_mean:.2f}s\n"
                    f"Baseline StdDev: {self.baseline_stddev:.2f}s\n"
                    f"Deviation: {(elapsed - self.baseline_mean) / self.baseline_stddev if self.baseline_stddev > 0 else 0:.1f} sigma",
                    "P1",
                    "Use parameterized queries (prepared statements).",
                    url=url,
                    payload=payload,
                    confidence=0.9,
                    observed_behavior=f"Response time increased to {elapsed:.2f}s versus baseline {self.baseline_mean:.2f}s.",
                    verification="statistical",
                    reproduction_steps=[
                        "Capture a baseline response time for the same endpoint.",
                        "Replay the time-delay payload against the same parameter.",
                        "Confirm the response delay exceeds the statistical threshold on repeat requests.",
                    ],
                )
        except asyncio.TimeoutError:
            await self.emit_vulnerability(
                "Time-Based SQLi",
                f"Possible time-based SQLi (request timed out).\n"
                f"URL: {url}\n"
                f"Payload: {payload}\n"
                f"Note: Request exceeded 30s timeout, manual verification recommended.",
                "P2",
                "Use parameterized queries (prepared statements).",
                url=url,
                payload=payload,
                confidence=0.66,
                observed_behavior="Request exceeded the timeout threshold during payload execution.",
                verification="heuristic",
                reproduction_steps=[
                    "Capture a baseline response for the same endpoint.",
                    "Submit the payload and observe the request timeout.",
                    "Repeat the test to confirm the timeout is reproducible.",
                ],
            )
        except Exception:
            pass

    def is_vulnerable(self, text):
        text_lower = text.lower()
        return any(err.lower() in text_lower for err in self.sql_errors)
