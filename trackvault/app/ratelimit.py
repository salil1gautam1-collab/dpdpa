"""In-process sliding-window rate limiter (per client IP).

Adequate for a single instance. A horizontally-scaled deployment should back
this with Redis; the interface stays the same.
"""
from __future__ import annotations

import threading
import time
from collections import defaultdict, deque

_lock = threading.Lock()
_hits: dict[str, deque] = defaultdict(deque)


def allow(key: str, limit: int, window_seconds: int = 60) -> bool:
    now = time.monotonic()
    with _lock:
        dq = _hits[key]
        while dq and dq[0] <= now - window_seconds:
            dq.popleft()
        if len(dq) >= limit:
            return False
        dq.append(now)
        return True
