"""
Simple in-memory rate limiter, keyed by client IP. Good enough for a single
process; for multi-instance deployments swap the store for Redis
(INCR + EXPIRE) but keep the same interface.
"""
import time
from collections import defaultdict, deque

from fastapi import Request
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware

from app.config import settings

_hits = defaultdict(deque)


class RateLimitMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        client_ip = request.client.host if request.client else "unknown"
        now = time.time()
        window = 60.0
        bucket = _hits[client_ip]

        while bucket and now - bucket[0] > window:
            bucket.popleft()

        if len(bucket) >= settings.rate_limit_per_minute:
            return JSONResponse(
                status_code=429,
                content={"detail": "Rate limit exceeded. Please slow down."},
            )

        bucket.append(now)
        return await call_next(request)
