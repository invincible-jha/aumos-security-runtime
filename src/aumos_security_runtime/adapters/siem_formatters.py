"""SIEM payload formatters for the AumOS Security Runtime.

Supports multiple SIEM formats for webhook delivery:
- Generic JSON (default)
- Splunk HEC (HTTP Event Collector)
- Datadog Events API
- Microsoft Sentinel CEF
"""

import hashlib
import hmac
import json
import uuid
from datetime import datetime, timezone
from typing import Any, Literal

from aumos_common.observability import get_logger

logger = get_logger(__name__)

SIEMFormat = Literal["json", "splunk_hec", "datadog", "sentinel_cef"]


def format_security_event(
    event: dict[str, Any],
    siem_format: SIEMFormat,
) -> dict[str, Any]:
    """Format a security threat event for a specific SIEM target.

    Args:
        event: The raw security threat event dict.
        siem_format: Target SIEM format.

    Returns:
        Formatted payload dict ready for HTTP POST.
    """
    formatters = {
        "json": _format_generic_json,
        "splunk_hec": _format_splunk_hec,
        "datadog": _format_datadog,
        "sentinel_cef": _format_sentinel_cef,
    }
    formatter = formatters.get(siem_format, _format_generic_json)
    return formatter(event)


def sign_payload(payload: dict[str, Any], signing_secret: str) -> str:
    """Create HMAC-SHA256 signature for webhook payload verification.

    Args:
        payload: The payload dict to sign.
        signing_secret: The shared signing secret.

    Returns:
        Hex-encoded HMAC-SHA256 signature.
    """
    payload_bytes = json.dumps(payload, sort_keys=True, default=str).encode("utf-8")
    signature = hmac.new(
        signing_secret.encode("utf-8"),
        payload_bytes,
        hashlib.sha256,
    ).hexdigest()
    return signature


def _format_generic_json(event: dict[str, Any]) -> dict[str, Any]:
    """Format as generic JSON — passthrough with timestamp normalization."""
    return {
        "source": "aumos-security-runtime",
        "version": "1.0",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        **event,
    }


def _format_splunk_hec(event: dict[str, Any]) -> dict[str, Any]:
    """Format for Splunk HTTP Event Collector.

    Splunk HEC expects: {"time": epoch_float, "source": str, "event": {...}}
    """
    return {
        "time": datetime.now(timezone.utc).timestamp(),
        "source": "aumos-security-runtime",
        "sourcetype": "_json",
        "index": "security",
        "event": {
            "message": f"AumOS Security Alert: {event.get('threat_type', 'unknown')}",
            **event,
        },
    }


def _format_datadog(event: dict[str, Any]) -> dict[str, Any]:
    """Format for Datadog Events API.

    Datadog expects: {"title": str, "text": str, "tags": [...], "alert_type": str}
    """
    severity = event.get("severity", "medium")
    alert_type_map = {
        "critical": "error",
        "high": "error",
        "medium": "warning",
        "low": "info",
    }
    return {
        "title": f"AumOS Security Alert: {event.get('threat_type', 'unknown')}",
        "text": event.get("description", "Security threat detected by AumOS Security Runtime"),
        "tags": [
            f"tenant_id:{event.get('tenant_id', 'unknown')}",
            f"threat_type:{event.get('threat_type', 'unknown')}",
            f"severity:{severity}",
            "source:aumos-security-runtime",
        ],
        "alert_type": alert_type_map.get(severity, "warning"),
        "aggregation_key": f"aumos-security-{event.get('threat_type', 'unknown')}",
        "source_type_name": "aumos",
        "date_happened": int(datetime.now(timezone.utc).timestamp()),
        "payload": event,
    }


def _format_sentinel_cef(event: dict[str, Any]) -> dict[str, Any]:
    """Format for Microsoft Sentinel Common Event Format (CEF).

    CEF header: CEF:Version|DeviceVendor|DeviceProduct|DeviceVersion|SignatureID|Name|Severity|Extension
    """
    severity_map = {"critical": 10, "high": 8, "medium": 5, "low": 2}
    severity_int = severity_map.get(event.get("severity", "medium"), 5)
    cef_header = (
        f"CEF:0|AumOS|SecurityRuntime|1.0|"
        f"{event.get('threat_type', 'UNKNOWN')}|"
        f"AumOS Security Alert|"
        f"{severity_int}|"
    )
    extensions = {
        "src": event.get("source_ip", ""),
        "dst": event.get("target_service", ""),
        "msg": event.get("description", "Security threat detected"),
        "cs1": event.get("scan_id", ""),
        "cs1Label": "ScanID",
        "cs2": event.get("tenant_id", ""),
        "cs2Label": "TenantID",
        "cs3": str(event.get("confidence", 0.0)),
        "cs3Label": "Confidence",
    }
    extension_str = " ".join(f"{k}={v}" for k, v in extensions.items() if v)
    return {
        "cef_message": cef_header + extension_str,
        "raw_event": event,
    }
