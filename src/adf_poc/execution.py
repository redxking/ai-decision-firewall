from __future__ import annotations

from enum import Enum


class SafetyInvariantError(RuntimeError):
    """Raised when runtime wiring would violate an execution-mode boundary."""


class ExecutionMode(str, Enum):
    """Code-owned execution modes supported by the POC.

    The POC intentionally defines no live-action mode. Historical replay and
    shadow processing are observation-only and cannot authorize or broker an
    action. Synthetic simulation is the original v0.1 in-memory behavior.
    """

    SYNTHETIC_SIMULATION = "synthetic_simulation"
    HISTORICAL_REPLAY = "historical_replay"
    SHADOW_READ_ONLY = "shadow_read_only"

    @property
    def is_read_only(self) -> bool:
        return self in {
            ExecutionMode.HISTORICAL_REPLAY,
            ExecutionMode.SHADOW_READ_ONLY,
        }
