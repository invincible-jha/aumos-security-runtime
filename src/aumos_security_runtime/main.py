"""AumOS Security Runtime service entry point.

Initializes the security pipeline at startup:
1. Compiles and caches regex patterns
2. Loads ML models into memory (spaCy)
3. Initializes Presidio PII analyzer
4. Opens DB connections and Kafka publisher

All heavy initialization happens once at startup to keep
request latency within the <50ms budget.
"""

from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager

from fastapi import FastAPI

from aumos_common.app import create_app
from aumos_common.database import init_database
from aumos_common.observability import get_logger

from aumos_security_runtime.api.router import router
from aumos_security_runtime.settings import Settings

logger = get_logger(__name__)
settings = Settings()


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    """Manage application startup and shutdown lifecycle.

    Performs all heavy initialization at startup to keep request
    latency within the <50ms budget. Models and compiled patterns
    are loaded once and reused across all requests.

    Args:
        app: The FastAPI application instance.

    Yields:
        None
    """
    logger.info("Starting aumos-security-runtime", version="0.1.0")

    # Initialize database connection pool
    init_database(settings.database)
    logger.info("Database initialized")

    # Pre-warm the pattern scanner cache
    # This compiles and caches all regex patterns at startup
    from aumos_security_runtime.adapters.prompt_injection.pattern_scanner import (
        PatternScanner,
    )

    pattern_scanner = PatternScanner(cache_size=settings.pattern_cache_size)
    await pattern_scanner.initialize()
    app.state.pattern_scanner = pattern_scanner
    logger.info("Pattern scanner initialized", cache_size=settings.pattern_cache_size)

    # Pre-load ML model if enabled
    if settings.enable_ml_scanner:
        from aumos_security_runtime.adapters.prompt_injection.ml_scanner import (
            MLScanner,
        )

        ml_scanner = MLScanner(model_path=settings.ml_model_path)
        await ml_scanner.initialize()
        app.state.ml_scanner = ml_scanner
        logger.info("ML scanner initialized", model_path=settings.ml_model_path or "base")
    else:
        app.state.ml_scanner = None
        logger.info("ML scanner disabled by configuration")

    # Pre-load Presidio PII analyzer if enabled
    if settings.enable_pii_scanner:
        from aumos_security_runtime.adapters.pii_scanner import PIIScanner

        pii_scanner = PIIScanner(confidence_threshold=settings.pii_confidence_threshold)
        await pii_scanner.initialize()
        app.state.pii_scanner = pii_scanner
        logger.info("PII scanner initialized", threshold=settings.pii_confidence_threshold)
    else:
        app.state.pii_scanner = None
        logger.info("PII scanner disabled by configuration")

    logger.info("aumos-security-runtime startup complete — ready to enforce security policies")

    yield

    # Shutdown
    logger.info("Shutting down aumos-security-runtime")
    # TODO: Close Kafka publisher connections
    # TODO: Release any async resources


app: FastAPI = create_app(
    service_name="aumos-security-runtime",
    version="0.1.0",
    settings=settings,
    lifespan=lifespan,
    health_checks=[
        # HealthCheck(name="postgres", check_fn=check_db),
        # HealthCheck(name="kafka", check_fn=check_kafka),
    ],
)

app.include_router(router, prefix="/api/v1")
