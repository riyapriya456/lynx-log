"""Scan governance primitives for Lynx.

This module centralizes request pacing, circuit breaking, and finding
evidence normalization so scanners can stay focused on detection logic.
"""

from __future__ import annotations

import asyncio
import random
import time
from collections import deque
from contextlib import suppress
from dataclasses import dataclass, field, asdict
from typing import Any, Dict, Iterable, List, Optional
from urllib.parse import urlparse


@dataclass
class FindingEvidence:
    """Structured evidence attached to a vulnerability finding."""

    request_method: str = "GET"
    request_url: str = ""
    request_headers: Dict[str, str] = field(default_factory=dict)
    payload: Optional[str] = None
    status_code: Optional[int] = None
    response_excerpt: Optional[str] = None
    observed_behavior: Optional[str] = None
    reproduction_steps: List[str] = field(default_factory=list)
    verification: str = "heuristic"
    confidence_reason: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            key: value
            for key, value in asdict(self).items()
            if value not in (None, "", [], {})
        }


@dataclass
class HostBudget:
    """Adaptive request budget for a single host."""

    host: str
    delay_seconds: float = 0.0
    error_streak: int = 0
    block_streak: int = 0
    in_flight: int = 0
    last_request_at: float = 0.0
    pause_until: float = 0.0
    circuit_open_until: float = 0.0
    recent_statuses: deque = field(default_factory=lambda: deque(maxlen=12))
    recent_latencies: deque = field(default_factory=lambda: deque(maxlen=12))

    def is_blocked(self, now: Optional[float] = None) -> bool:
        now = now or time.time()
        return now < self.circuit_open_until or now < self.pause_until

    def current_penalty(self) -> float:
        penalty = self.delay_seconds
        if self.block_streak >= 3:
            penalty = max(penalty, min(10.0, 0.25 * (2 ** min(self.block_streak, 5))))
        return penalty


class TrafficGovernor:
    """Adaptive traffic governor with per-host backoff and circuit breaking."""

    def __init__(
        self,
        initial_concurrency: int = 8,
        min_concurrency: int = 2,
        max_concurrency: int = 12,
        max_delay_seconds: float = 15.0,
        base_delay_seconds: float = 0.15,
        jitter_range: tuple[float, float] = (0.05, 0.2),
    ):
        self._semaphore = asyncio.Semaphore(max(1, initial_concurrency))
        self.min_concurrency = max(1, min_concurrency)
        self.max_concurrency = max(self.min_concurrency, max_concurrency)
        self.max_delay_seconds = max_delay_seconds
        self.base_delay_seconds = base_delay_seconds
        self.jitter_range = jitter_range
        self._host_budgets: Dict[str, HostBudget] = {}
        self._lock = asyncio.Lock()
        self._request_count = 0
        self._error_count = 0
        self._blocked_count = 0
        self._last_adjustment = time.time()

    def _host_key(self, url: str) -> str:
        parsed = urlparse(url)
        return parsed.netloc.lower() or "unknown"

    def _budget_for(self, url: str) -> HostBudget:
        host = self._host_key(url)
        if host not in self._host_budgets:
            self._host_budgets[host] = HostBudget(host=host)
        return self._host_budgets[host]

    async def before_request(self, url: str, scanner_name: str = "", cost_tier: str = "medium") -> None:
        budget = self._budget_for(url)
        now = time.time()

        penalty = budget.current_penalty()
        if cost_tier == "high":
            penalty = max(penalty, 0.35)

        if budget.is_blocked(now):
            wait_time = max(budget.pause_until, budget.circuit_open_until) - now
            wait_time += random.uniform(*self.jitter_range)
            await asyncio.sleep(max(0.0, wait_time))
        elif penalty > 0:
            elapsed = now - budget.last_request_at
            if elapsed < penalty:
                wait_time = (penalty - elapsed) + random.uniform(*self.jitter_range)
                await asyncio.sleep(max(0.0, wait_time))

        await self._semaphore.acquire()
        async with self._lock:
            budget.in_flight += 1
            budget.last_request_at = time.time()
            self._request_count += 1

    async def after_request(
        self,
        url: str,
        status: Optional[int],
        elapsed_seconds: float,
        headers: Optional[Dict[str, str]] = None,
        error: Optional[str] = None,
    ) -> None:
        budget = self._budget_for(url)
        headers = headers or {}
        now = time.time()
        status = int(status or 0)
        is_block = status in {401, 403, 406, 429, 503}
        is_error = status >= 500 or error is not None

        async with self._lock:
            budget.in_flight = max(0, budget.in_flight - 1)
            budget.recent_statuses.append(status)
            budget.recent_latencies.append(elapsed_seconds)

            if is_block:
                budget.block_streak += 1
                budget.error_streak += 1
                self._blocked_count += 1
                new_delay = min(
                    self.max_delay_seconds,
                    self.base_delay_seconds * (2 ** min(budget.block_streak, 5)),
                )
                budget.delay_seconds = max(budget.delay_seconds, new_delay)
                budget.pause_until = now + min(self.max_delay_seconds, budget.delay_seconds * 1.5)
                if budget.block_streak >= 3:
                    budget.circuit_open_until = now + min(60.0, budget.delay_seconds * 4)
            elif is_error:
                budget.error_streak += 1
                self._error_count += 1
                budget.delay_seconds = min(self.max_delay_seconds, max(budget.delay_seconds, self.base_delay_seconds))
                if budget.error_streak >= 4:
                    budget.pause_until = now + min(self.max_delay_seconds, 2.5)
            else:
                budget.error_streak = max(0, budget.error_streak - 1)
                budget.block_streak = max(0, budget.block_streak - 1)
                budget.delay_seconds = max(0.0, budget.delay_seconds * 0.7)
                if status < 400:
                    budget.pause_until = min(budget.pause_until, now)
                    budget.circuit_open_until = min(budget.circuit_open_until, now)

            if elapsed_seconds > 3.0:
                budget.pause_until = max(budget.pause_until, now + min(5.0, elapsed_seconds / 2))

            self._adjust_concurrency_unlocked()

        with suppress(Exception):
            self._semaphore.release()

    def _adjust_concurrency_unlocked(self) -> None:
        # Keep concurrency fixed and rely on per-host pacing, pause windows,
        # and circuit-breaker style backoff to avoid bursty overload.
        self._last_adjustment = time.time()

    def should_defer_high_cost(self) -> bool:
        now = time.time()
        return any(
            budget.block_streak >= 2 or budget.is_blocked(now) or budget.delay_seconds >= 1.0
            for budget in self._host_budgets.values()
        )

    def should_skip_heavy_scan(self) -> bool:
        return self.should_defer_high_cost() and self._blocked_count >= 3

    def summary(self) -> Dict[str, Any]:
        now = time.time()
        host_summaries = []
        for budget in self._host_budgets.values():
            host_summaries.append(
                {
                    "host": budget.host,
                    "delay_seconds": round(budget.delay_seconds, 2),
                    "error_streak": budget.error_streak,
                    "block_streak": budget.block_streak,
                    "pause_remaining": max(0.0, round(budget.pause_until - now, 2)),
                    "circuit_open_remaining": max(0.0, round(budget.circuit_open_until - now, 2)),
                    "recent_statuses": list(budget.recent_statuses),
                }
            )

        return {
            "hosts": host_summaries,
            "request_count": self._request_count,
            "error_count": self._error_count,
            "blocked_count": self._blocked_count,
            "degraded": self.should_defer_high_cost(),
        }


class ManagedRequestContext:
    """Async context manager that applies governor pacing around a request."""

    def __init__(self, session: Any, governor: TrafficGovernor, method: str, url: str, kwargs: Dict[str, Any]):
        self._session = session
        self._governor = governor
        self._method = method
        self._url = url
        self._kwargs = kwargs
        self._request_cm = None
        self._response = None
        self._started_at = 0.0
        self._status = None

    async def __aenter__(self):
        cost_tier = self._kwargs.pop("_cost_tier", "medium")
        await self._governor.before_request(self._url, cost_tier=cost_tier)
        self._started_at = time.perf_counter()
        self._request_cm = self._session.request(self._method, self._url, **self._kwargs)
        try:
            self._response = await self._request_cm.__aenter__()
            return self._response
        except Exception as exc:
            await self._governor.after_request(self._url, None, time.perf_counter() - self._started_at, error=str(exc))
            raise

    async def __aexit__(self, exc_type, exc, tb):
        status = getattr(self._response, "status", None)
        headers = dict(getattr(self._response, "headers", {}) or {})
        elapsed = time.perf_counter() - self._started_at if self._started_at else 0.0
        try:
            return await self._request_cm.__aexit__(exc_type, exc, tb)
        finally:
            await self._governor.after_request(self._url, status, elapsed, headers=headers, error=str(exc) if exc else None)


class ManagedSession:
    """Lightweight session proxy that enforces request governance."""

    def __init__(self, session: Any, governor: TrafficGovernor):
        self._session = session
        self._governor = governor

    def request(self, method: str, url: str, **kwargs) -> ManagedRequestContext:
        return ManagedRequestContext(self._session, self._governor, method, url, kwargs)

    def get(self, url: str, **kwargs) -> ManagedRequestContext:
        return self.request("GET", url, **kwargs)

    def post(self, url: str, **kwargs) -> ManagedRequestContext:
        return self.request("POST", url, **kwargs)

    async def close(self):
        await self._session.close()

    @property
    def closed(self) -> bool:
        return self._session.closed

    def __getattr__(self, item: str):
        return getattr(self._session, item)
