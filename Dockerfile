# ============================================================================
# Dockerfile — aumos-security-runtime
# Multi-stage build for the AumOS Runtime AI Security service
# ============================================================================

# Stage 1: Build dependencies
FROM python:3.11-slim AS builder

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /build
COPY pyproject.toml README.md ./
COPY src/ ./src/

RUN pip install --prefix=/install --no-warn-script-location .

# Download spaCy model for ML-based injection detection
RUN pip install --prefix=/install spacy && \
    python -m spacy download en_core_web_sm --no-deps && \
    cp -r /root/.local/lib/python3.11/site-packages/en_core_web_sm /install/lib/python3.11/site-packages/

# Stage 2: Runtime
FROM python:3.11-slim AS runtime

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

# Security: non-root user
RUN groupadd -r aumos && useradd -r -g aumos -d /app -s /sbin/nologin aumos

# Copy installed packages from builder
COPY --from=builder /install /usr/local

# Copy application code
COPY src/ /app/src/
WORKDIR /app

# Set ownership
RUN chown -R aumos:aumos /app

USER aumos

EXPOSE 8000

# Health check — liveness endpoint must respond quickly
HEALTHCHECK --interval=30s --timeout=5s --start-period=30s --retries=3 \
    CMD python -c "import httpx; r = httpx.get('http://localhost:8000/live'); r.raise_for_status()" || exit 1

# Start service with 2 workers for security throughput
CMD ["uvicorn", "aumos_security_runtime.main:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "2"]
