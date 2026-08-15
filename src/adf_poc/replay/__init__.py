"""Historical-replay and shadow-read-only framework for AI Decision Firewall Phase 2."""

from .contracts import (
    ALLOWED_REPLAY_MODES,
    CONTRACT_VERSION,
    RECORD_FAILURE_POLICIES,
    ContractValidationError,
    ManifestValidationError,
    ReplayConfig,
    ReplayConfigurationError,
    ReplayManifest,
    load_and_validate_manifest,
)
from .harness import ReplayHarness, ReplayRunResult, ReplaySafetyViolation
from .gate_b import (
    GateBAuthorization,
    GateBStopConditionViolation,
    GateBValidationError,
    ManifestControl,
    evaluate_qualification_stop_conditions,
    load_gate_b_authorization,
    load_manifest_control,
    validate_gate_b_current,
)
from .qualification import (
    QUALIFICATION_TAXONOMY_VERSION,
    QualificationFatalError,
    QualificationResult,
    qualify_case_bytes,
    qualify_case_file,
)

__all__ = [
    "ALLOWED_REPLAY_MODES",
    "CONTRACT_VERSION",
    "QUALIFICATION_TAXONOMY_VERSION",
    "RECORD_FAILURE_POLICIES",
    "ContractValidationError",
    "ManifestValidationError",
    "ReplayConfig",
    "ReplayConfigurationError",
    "ReplayHarness",
    "ReplayManifest",
    "ReplayRunResult",
    "ReplaySafetyViolation",
    "GateBAuthorization",
    "GateBStopConditionViolation",
    "GateBValidationError",
    "ManifestControl",
    "QualificationFatalError",
    "QualificationResult",
    "qualify_case_bytes",
    "qualify_case_file",
    "evaluate_qualification_stop_conditions",
    "load_gate_b_authorization",
    "load_manifest_control",
    "validate_gate_b_current",
    "load_and_validate_manifest",
]
