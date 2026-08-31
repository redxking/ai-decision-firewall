from __future__ import annotations

from dataclasses import dataclass

from .gate_b import CLASSIFIED_GATE_B_FAILURE_IDENTITIES, GateBValidationError


class GateBFailureIdentityError(ValueError):
    """Raised when a campaign attempts to score an unclassified Gate B failure."""


# Compatibility alias for callers that already imported the oracle's registry.
# The validator owns the sole registry so emitted and accepted identities cannot drift.
ALLOWED_GATE_B_FAILURE_IDENTITIES = CLASSIFIED_GATE_B_FAILURE_IDENTITIES


@dataclass(frozen=True, slots=True)
class GateBFailureExpectation:
    stage: str
    control_id: str
    reason_code: str

    def __post_init__(self) -> None:
        if self.identity not in ALLOWED_GATE_B_FAILURE_IDENTITIES:
            raise GateBFailureIdentityError(
                "Gate B failure expectations must use a closed causal identity."
            )

    @property
    def identity(self) -> tuple[str, str, str]:
        return self.stage, self.control_id, self.reason_code


def require_classified_failure(error: GateBValidationError) -> tuple[str, str, str]:
    """Return a causal identity, rejecting generic fail-shut behavior as evidence."""

    identity = error.failure_identity
    if identity not in ALLOWED_GATE_B_FAILURE_IDENTITIES:
        raise GateBFailureIdentityError(
            "A Gate B campaign cannot score an unknown or unclassified failure."
        )
    return identity


def matches_expected_failure(
    error: GateBValidationError,
    expected: GateBFailureExpectation,
) -> bool:
    """Require exact stage, control, and reason equality for a negative control."""

    return require_classified_failure(error) == expected.identity


__all__ = [
    "ALLOWED_GATE_B_FAILURE_IDENTITIES",
    "GateBFailureExpectation",
    "GateBFailureIdentityError",
    "matches_expected_failure",
    "require_classified_failure",
]
