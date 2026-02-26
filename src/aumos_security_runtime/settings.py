"""Service-specific settings extending AumOS base config.

All standard AumOS configuration is inherited from AumOSSettings.
Security runtime settings use the AUMOS_SECRUNTIME_ env prefix.

Critical performance settings:
- MAX_LATENCY_MS: Hard budget for input scans (default 50ms)
- PATTERN_CACHE_SIZE: LRU cache for compiled regex (default 1000)
- POLICY_CACHE_TTL_SECONDS: Tenant policy cache TTL (default 60s)
"""

from pydantic_settings import SettingsConfigDict

from aumos_common.config import AumOSSettings


class Settings(AumOSSettings):
    """Settings for aumos-security-runtime.

    Inherits all standard AumOS settings (database, kafka, keycloak, etc.)
    and adds security-runtime-specific configuration.

    Environment variable prefix: AUMOS_SECRUNTIME_
    """

    service_name: str = "aumos-security-runtime"

    # Latency budget — hard limit in milliseconds for input scan P95
    max_latency_ms: int = 50

    # Pattern scanner — LRU cache size for compiled regex patterns
    pattern_cache_size: int = 1000

    # Tenant policy cache TTL in seconds
    policy_cache_ttl_seconds: int = 60

    # ML scanner — path to fine-tuned model (empty = use base spaCy model)
    ml_model_path: str = ""

    # PII detection — minimum Presidio confidence score (0.0–1.0)
    pii_confidence_threshold: float = 0.7

    # Trivy container scanning — endpoint for Trivy server (empty = disabled)
    trivy_endpoint: str = ""

    # Feature flags
    enable_ml_scanner: bool = True
    enable_pii_scanner: bool = True
    enable_container_scanner: bool = False

    # Prompt injection thresholds
    injection_block_threshold: float = 0.85
    injection_warn_threshold: float = 0.60

    model_config = SettingsConfigDict(env_prefix="AUMOS_SECRUNTIME_")
