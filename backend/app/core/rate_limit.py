"""Redis-backed fixed-window limits for the expensive URL scan endpoint."""

from hashlib import sha256
import logging
import time

from fastapi import Depends, HTTPException, Request, status
from redis import Redis
from redis.exceptions import RedisError

from app.api.dependencies import optional_current_user
from app.core.config import settings
from app.models.user import User

logger = logging.getLogger(__name__)
_client: Redis | None = None
WINDOW_SECONDS = 60 * 60

_INCREMENT_SCRIPT = """
local count = redis.call('INCR', KEYS[1])
if count == 1 then
  redis.call('EXPIRE', KEYS[1], ARGV[1])
end
return {count, redis.call('TTL', KEYS[1])}
"""


def _redis() -> Redis:
    global _client
    if _client is None:
        _client = Redis.from_url(settings.redis_url, socket_connect_timeout=2, socket_timeout=2,
                                 health_check_interval=30)
    return _client


def scan_rate_limit(request: Request,
                    user: User | None = Depends(optional_current_user)) -> None:
    """Count scan requests per UTC hour; fail closed if Redis is down."""
    if user is None:
        limit = settings.scan_limit_anonymous_per_hour
        # Do not trust X-Forwarded-For; only proxy-aware deployments should configure
        # and validate a trusted-proxy layer before using forwarded client addresses.
        client_ip = request.client.host if request.client else "unknown"
        identity = "ip-" + sha256(client_ip.encode("utf-8", errors="replace")).hexdigest()
        scope = "anonymous"
    else:
        limit = (settings.scan_limit_admin_per_hour if user.role == "admin"
                 else settings.scan_limit_authenticated_per_hour)
        identity = "user-" + str(user.id)
        scope = user.role if user.role in {"admin", "analyst", "viewer"} else "authenticated"

    now = int(time.time())
    window_start = now // WINDOW_SECONDS
    key = f"linkshield:rate:scan:{scope}:{identity}:{window_start}"
    try:
        count, ttl = _redis().eval(_INCREMENT_SCRIPT, 1, key, WINDOW_SECONDS)
    except RedisError as exc:
        # Avoid logging a connection exception that may include deployment-specific
        # connection details. The exception class is sufficient for operations.
        logger.warning("Scan rate limiter could not reach Redis (%s)", type(exc).__name__)
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                            detail="Scan service is temporarily unavailable.") from None

    remaining = max(0, limit - int(count))
    request.state.scan_rate_limit = limit
    request.state.scan_rate_remaining = remaining
    if int(count) > limit:
        raise HTTPException(status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                            detail="Scan limit reached. Try again after the current hourly window.",
                            headers={"Retry-After": str(max(1, int(ttl)))})
