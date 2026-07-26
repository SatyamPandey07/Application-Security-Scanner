import time
from typing import Dict, List
from fastapi import HTTPException, status

# Simple in-memory sliding window rate limiter
_REQUEST_HISTORY: Dict[str, List[float]] = {}


def check_rate_limit(key: str, max_requests: int = 10, window_seconds: int = 60):
    """
    Enforces a sliding window rate limit per user/IP key.
    """
    now = time.time()
    if key not in _REQUEST_HISTORY:
        _REQUEST_HISTORY[key] = []

    # Clean timestamps outside window
    _REQUEST_HISTORY[key] = [t for t in _REQUEST_HISTORY[key] if now - t < window_seconds]

    if len(_REQUEST_HISTORY[key]) >= max_requests:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=f"Rate limit exceeded. Maximum {max_requests} scan submissions allowed per {window_seconds} seconds."
        )

    _REQUEST_HISTORY[key].append(now)
