"""Per-tenant rate limiting for the AumOS Security Runtime.

Implements a sliding window counter using Redis INCR + EXPIRE.
Returns rate limit headers and enforces per-tenant RPS limits.
"""

import time
import uuid
from dataclasses import dataclass

from aumos_common.observability import get_logger

logger = get_logger(__name__)


@dataclass
class RateLimitResult:
    """Result of a rate limit check.

    Attributes:
        allowed: Whether the request is within the rate limit.
        current: Current request count in this window.
        limit: Maximum allowed requests per window.
        reset_at: Unix timestamp when the window resets.
    """

    allowed: bool
    current: int
    limit: int
    reset_at: int


class TenantRateLimiter:
    """Per-tenant rate limiter using Redis sliding window counters.

    Uses Redis INCR + EXPIRE for a 1-second sliding window per tenant.
    Default limit is configurable; per-tenant overrides stored in Redis.

    Args:
        redis: Async Redis client.
        default_rps: Default requests per second limit (default: 1000).
    """

    def __init__(self, redis: object, default_rps: int = 1000) -> None:
        self._redis = redis
        self._default_rps = default_rps

    async def check_and_increment(
        self,
        tenant_id: uuid.UUID,
    ) -> RateLimitResult:
        """Check rate limit and increment counter for the tenant.

        Uses a 1-second time window keyed by tenant_id and current Unix second.

        Args:
            tenant_id: The tenant to check the rate limit for.

        Returns:
            RateLimitResult indicating if the request is allowed.
        """
        now = int(time.time())
        window_key = f"secruntime:ratelimit:{tenant_id}:{now}"
        limit = await self._get_tenant_limit(tenant_id)

        try:
            pipe = self._redis.pipeline()  # type: ignore[attr-defined]
            pipe.incr(window_key)
            pipe.expire(window_key, 2)  # 2-second TTL for safety margin
            results = await pipe.execute()
            current = results[0]
        except Exception as exc:
            logger.warning("rate_limiter_redis_error", tenant_id=str(tenant_id), error=str(exc))
            # Fail open — allow request if Redis is unavailable
            return RateLimitResult(allowed=True, current=0, limit=limit, reset_at=now + 1)

        allowed = current <= limit
        if not allowed:
            logger.warning(
                "rate_limit_exceeded",
                tenant_id=str(tenant_id),
                current=current,
                limit=limit,
            )

        return RateLimitResult(
            allowed=allowed,
            current=current,
            limit=limit,
            reset_at=now + 1,
        )

    async def get_tenant_limit(self, tenant_id: uuid.UUID) -> int:
        """Get the rate limit for a specific tenant.

        Args:
            tenant_id: The tenant UUID.

        Returns:
            RPS limit for the tenant.
        """
        return await self._get_tenant_limit(tenant_id)

    async def set_tenant_limit(self, tenant_id: uuid.UUID, rps: int) -> None:
        """Set a custom rate limit for a specific tenant.

        Args:
            tenant_id: The tenant UUID.
            rps: Requests per second limit.
        """
        config_key = f"secruntime:ratelimit_config:{tenant_id}"
        await self._redis.set(config_key, str(rps), ex=86400 * 30)  # type: ignore[attr-defined]
        logger.info("tenant_rate_limit_set", tenant_id=str(tenant_id), rps=rps)

    async def _get_tenant_limit(self, tenant_id: uuid.UUID) -> int:
        """Get rate limit from Redis config key, fallback to default."""
        config_key = f"secruntime:ratelimit_config:{tenant_id}"
        try:
            value = await self._redis.get(config_key)  # type: ignore[attr-defined]
            if value is not None:
                return int(value)
        except Exception:
            pass
        return self._default_rps
