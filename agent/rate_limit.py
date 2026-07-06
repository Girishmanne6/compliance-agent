from __future__ import annotations

import os
import time
import threading
from collections import defaultdict
from typing import Callable

from fastapi import HTTPException, Request


class TokenBucketLimiter:
    """Simple in-memory per-IP token bucket rate limiter."""

    def __init__(self, max_requests: int, window_seconds: int) -> None:
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self._hits: dict[str, list[float]] = defaultdict(list)
        self._lock = threading.Lock()

    def _client_key(self, request: Request) -> str:
        forwarded = request.headers.get("X-Forwarded-For")
        if forwarded:
            return forwarded.split(",")[0].strip()
        if request.client:
            return request.client.host
        return "unknown"

    def check(self, request: Request) -> None:
        key = self._client_key(request)
        now = time.time()
        with self._lock:
            window_start = now - self.window_seconds
            self._hits[key] = [t for t in self._hits[key] if t > window_start]
            if len(self._hits[key]) >= self.max_requests:
                raise HTTPException(
                    status_code=429,
                    detail=f"Rate limit exceeded. Max {self.max_requests} requests per {self.window_seconds}s.",
                )
            self._hits[key].append(now)


def _parse_limit(value: str) -> tuple[int, int]:
    # Format: "10/minute" or "5/60"
    count_part, _, period = value.partition("/")
    count = int(count_part)
    period = period.strip().lower()
    windows = {"second": 1, "minute": 60, "hour": 3600}
    if period.isdigit():
        return count, int(period)
    return count, windows.get(period, 60)


_limit_value = os.getenv("SCAN_REPO_RATE_LIMIT", "10/minute")
_max_requests, _window_seconds = _parse_limit(_limit_value)
repo_scan_limiter = TokenBucketLimiter(_max_requests, _window_seconds)


def enforce_repo_rate_limit(request: Request) -> None:
    repo_scan_limiter.check(request)
