"""Supply chain behavioral backdoor testing for aumos-security-runtime.

Modules:
    backdoor_tester — BackdoorBehaviorTester: probes models with trigger patterns
        and flags if prediction distributions shift by more than 30%.
"""

from aumos_security_runtime.supply_chain.backdoor_tester import (
    BackdoorBehaviorTester,
    BackdoorTestResult,
    ModelType,
    TriggerProbeResult,
)

__all__ = [
    "BackdoorBehaviorTester",
    "BackdoorTestResult",
    "ModelType",
    "TriggerProbeResult",
]
