# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Initial project scaffolding from aumos-repo-template
- Pattern-based prompt injection detection with compiled regex caching
- ML-based prompt injection classification using spaCy
- Real-time PII detection and redaction via Microsoft Presidio (MIT license)
- Input guardrail scanning (PII, toxicity detection)
- Output guardrail scanning (data extraction prevention)
- Trivy container scanning integration
- SecurityPipelineService with parallel asyncio.gather execution for <50ms budget
- GuardrailService for tenant-configurable rule management
- ThreatDetectionService for threat record management
- SecurityEventPublisher for Kafka event emission
- ORM models with sec_ table prefix: SecurityScan, ThreatDetection, GuardrailRule, SecurityPolicy
- REST API: POST /scan/input, POST /scan/output, GET /scans
- REST API: POST/GET /guardrails, GET /threats, POST /policies
- REST API: GET /metrics, POST /container-scan
- Docker multi-stage build with non-root user
- CI/CD pipeline with lint, typecheck, test, docker build, license check
- docker-compose.dev.yml for local development
