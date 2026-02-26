# CLAUDE.md — AumOS Security Runtime

## Project Overview

AumOS Enterprise is a composable enterprise AI platform with 9 products + 2 services
across 62 repositories. This repo (`aumos-security-runtime`) is part of **Tier 1: Platform Infrastructure**:
Cross-cutting security enforcement layer applied to all LLM-consuming services.

**Release Tier:** C: Proprietary
**Product Mapping:** Product 6 — AI Trust & Safety
**Phase:** 3 (Months 9-14)

## Repo Purpose

aumos-security-runtime is the real-time AI security enforcement engine for the AumOS platform.
It intercepts all LLM inputs and outputs, running prompt injection detection, PII scanning,
toxicity filtering, and data extraction prevention within a strict <50ms latency budget.
All LLM-consuming services in AumOS route traffic through this runtime before sending to or
receiving from any language model.

## Architecture Position

```
aumos-common ──────────────────────► aumos-security-runtime ──► All LLM-consuming repos
aumos-proto  ──────────────────────►                         ──► aumos-event-bus (security events)
aumos-auth-gateway ────────────────►                         ──► aumos-data-layer (scan records)
                                    ↑
                           All LLM-consuming repos
                           (aumos-llm-gateway,
                            aumos-agent-runtime,
                            aumos-rag-engine, etc.)
```

**Upstream dependencies (this repo IMPORTS from):**
- `aumos-common` — auth, database, events, errors, config, health, pagination
- `aumos-proto` — Protobuf message definitions for Kafka security events
- `aumos-auth-gateway` — tenant context and JWT validation

**Downstream dependents (other repos IMPORT from this):**
- `aumos-llm-gateway` — all LLM traffic is scanned before/after model calls
- `aumos-agent-runtime` — agent inputs/outputs are security-scanned
- `aumos-rag-engine` — retrieved context and generated output scanned
- `aumos-prompt-engine` — prompts scanned before execution

## Tech Stack (DO NOT DEVIATE)

| Component | Version | Purpose |
|-----------|---------|---------|
| Python | 3.11+ | Runtime |
| FastAPI | 0.110+ | REST API framework |
| SQLAlchemy | 2.0+ (async) | Database ORM |
| asyncpg | 0.29+ | PostgreSQL async driver |
| Pydantic | 2.6+ | Data validation, settings, API schemas |
| confluent-kafka | 2.3+ | Kafka producer/consumer |
| structlog | 24.1+ | Structured JSON logging |
| OpenTelemetry | 1.23+ | Distributed tracing |
| presidio-analyzer | 2.2+ | PII detection (MIT license) |
| presidio-anonymizer | 2.2+ | PII redaction (MIT license) |
| spacy | 3.7+ | NLP for ML-based detection (MIT license) |
| cachetools | 5.3+ | In-memory caching for compiled patterns |
| pytest | 8.0+ | Testing framework |
| ruff | 0.3+ | Linting and formatting |
| mypy | 1.8+ | Type checking |

## Coding Standards

### ABSOLUTE RULES (violations will break integration with other repos)

1. **Import aumos-common, never reimplement.** If aumos-common provides it, use it.
   ```python
   # CORRECT
   from aumos_common.auth import get_current_tenant, get_current_user
   from aumos_common.database import get_db_session, Base, AumOSModel, BaseRepository
   from aumos_common.events import EventPublisher, Topics
   from aumos_common.errors import NotFoundError, ErrorCode
   from aumos_common.config import AumOSSettings
   from aumos_common.health import create_health_router
   from aumos_common.pagination import PageRequest, PageResponse, paginate
   from aumos_common.app import create_app

   # WRONG — never reimplement these
   # from jose import jwt  (use aumos_common.auth instead)
   # from sqlalchemy import create_engine  (use aumos_common.database instead)
   # import logging  (use aumos_common.observability.get_logger instead)
   ```

2. **Type hints on EVERY function.** No exceptions.

3. **Pydantic models for ALL API inputs/outputs.** Never return raw dicts.

4. **RLS tenant isolation via aumos-common.** Never write raw SQL that bypasses RLS.

5. **Structured logging via structlog.** Never use print() or logging.getLogger().

6. **Publish domain events to Kafka after state changes.**

7. **Async by default.** All I/O operations must be async.

8. **Google-style docstrings** on all public classes and functions.

### CRITICAL: <50ms Latency Budget

This is the most important non-functional requirement.

- **SecurityPipelineService.scan_input()** MUST complete in <50ms P95
- **All checks run in parallel** using `asyncio.gather()` — never sequential
- **Short-circuit on critical threats** — return immediately on confidence > 0.95
- **Cache compiled regex patterns** using `cachetools.LRUCache` — never recompile on every request
- **Cache tenant policy configs** with TTL=60s — DB reads are too slow for hot path
- **Use in-process ML models** — no remote API calls in the scan hot path

```python
# CORRECT — parallel execution
results = await asyncio.gather(
    self._pattern_scanner.scan(content),
    self._ml_scanner.scan(content),
    self._pii_scanner.scan(content),
    return_exceptions=True,
)

# WRONG — sequential is 3x slower
result1 = await self._pattern_scanner.scan(content)
result2 = await self._ml_scanner.scan(content)
result3 = await self._pii_scanner.scan(content)
```

### Style Rules

- Max line length: **120 characters**
- Import order: stdlib → third-party → aumos-common → local
- Linter: `ruff` (select E, W, F, I, N, UP, ANN, B, A, COM, C4, PT, RUF)
- Type checker: `mypy` strict mode
- Formatter: `ruff format`

### File Structure Convention

```
src/aumos_security_runtime/
├── __init__.py
├── main.py                    # FastAPI app entry point
├── settings.py                # Extends AumOSSettings with AUMOS_SECRUNTIME_ prefix
├── api/
│   ├── __init__.py
│   ├── router.py              # All security scan endpoints
│   └── schemas.py             # Pydantic request/response models
├── core/
│   ├── __init__.py
│   ├── models.py              # sec_ prefix ORM models
│   ├── services.py            # SecurityPipelineService, GuardrailService, ThreatDetectionService
│   └── interfaces.py          # Protocol interfaces for DI
└── adapters/
    ├── __init__.py
    ├── repositories.py        # SecurityScanRepository, ThreatDetectionRepository
    ├── kafka.py               # SecurityEventPublisher
    ├── prompt_injection/
    │   ├── __init__.py
    │   ├── pattern_scanner.py # Regex/pattern-based detection
    │   └── ml_scanner.py      # ML-based detection
    ├── guardrails/
    │   ├── __init__.py
    │   ├── input_guard.py     # LLM Guard input scanning
    │   └── output_guard.py    # LLM Guard output scanning
    ├── pii_scanner.py         # Real-time PII detection and redaction
    └── container_scanner.py   # Trivy container scanning integration
```

## Database Conventions

- Table prefix: `sec_` (e.g., `sec_security_scans`, `sec_threat_detections`)
- ALL tenant-scoped tables: extend `AumOSModel` (gets id, tenant_id, created_at, updated_at)
- RLS policy on every tenant table (created in migration)
- Migration naming: `{timestamp}_sec_{description}.py`
- Foreign keys to other repos' tables: use UUID type, no FK constraints (cross-service)

## API Conventions

- All endpoints under `/api/v1/` prefix
- Auth: Bearer JWT token (validated by aumos-common)
- Tenant: `X-Tenant-ID` header (set by auth middleware)
- Request ID: `X-Request-ID` header (auto-generated if missing)
- Pagination: `?page=1&page_size=20&sort_by=created_at&sort_order=desc`
- Errors: Standard `ErrorResponse` from aumos-common

## Kafka Conventions

- Publish events via `EventPublisher` from aumos-common
- Use `Topics.*` constants for topic names
- Always include `tenant_id` and `correlation_id` in security events
- Security events are high-priority — use dedicated partitions if available

## Testing

- Minimum coverage: **80%** for core modules, **60%** for adapters
- **Latency tests required** — assert P95 scan time < 50ms using pytest-benchmark
- Import fixtures from `aumos_common.testing`
- Mock all external services (Trivy, ML models) in unit tests
- Use `testcontainers` for integration tests with real PostgreSQL/Kafka/Redis

## Environment Variables

All standard env vars are defined in `aumos_common.config.AumOSSettings`.
Repo-specific vars use the prefix `AUMOS_SECRUNTIME_`.

## Repo-Specific Context

### Security Domain

This service enforces the AumOS AI Trust & Safety framework. The key threat categories are:

1. **Prompt Injection** — Adversarial inputs that attempt to override LLM system prompts
   or exfiltrate internal instructions. Detected via pattern matching + ML classifier.
   Target: >95% detection rate at <5% false positive rate.

2. **PII Leakage** — Personally Identifiable Information appearing in LLM inputs/outputs.
   Detected via Microsoft Presidio (MIT license). Supports 50+ entity types.
   Action: REDACT (replace with `[REDACTED]`) or BLOCK based on policy.

3. **Data Extraction** — Attempts to retrieve bulk data, credentials, or internal configs
   from LLM context windows. Detected in output scanning stage.

4. **Toxicity** — Harmful content in inputs or outputs. Filtered at output scanning stage.

### Latency Budget Breakdown (total: <50ms)

| Component | Budget |
|-----------|--------|
| Input validation + routing | 2ms |
| Pattern scanner (cached regex) | 5ms |
| PII scanner (Presidio) | 15ms |
| ML injection classifier | 20ms |
| DB write (security scan record) | 5ms |
| Kafka event publish (async) | 3ms |
| Total | <50ms |

### What Claude Code Should NOT Do

1. **Do NOT add AGPL/GPL dependencies.** spaCy, Presidio, and regex are all MIT/Apache.
   LLM Guard is AGPL — do NOT use it. Use Presidio for PII scanning instead.
2. **Do NOT make synchronous HTTP calls** in the scan hot path — latency budget will be violated.
3. **Do NOT load ML models on every request** — load once at startup and cache in service instance.
4. **Do NOT log PII content** — log hashes or entity counts only.
5. **Do NOT skip the latency budget checks** — add `time.perf_counter()` instrumentation.
6. **Do NOT use LLM Guard** — it is AGPL licensed and prohibited.
