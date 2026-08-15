from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field
from threading import Lock
from typing import Any, Iterable


@dataclass(slots=True)
class _MetricState:
    dispositions: Counter[str] = field(default_factory=Counter)
    policy_rule_matches: Counter[str] = field(default_factory=Counter)
    evidence_conflicts: int = 0
    authorization_failures: int = 0
    broker_rejections: int = 0
    verification_failures: int = 0
    decision_latencies_ms: list[float] = field(default_factory=list)


class Phase3Metrics:
    """Small, thread-safe runtime metric collector for the simulation MVP."""

    def __init__(self) -> None:
        self._state = _MetricState()
        self._lock = Lock()

    def record_decision(
        self,
        outcome: str,
        *,
        policy_rules: Iterable[str],
        evidence_conflicts: int,
        latency_ms: float,
    ) -> None:
        with self._lock:
            self._state.dispositions[outcome] += 1
            self._state.policy_rule_matches.update(policy_rules)
            self._state.evidence_conflicts += int(evidence_conflicts)
            self._state.decision_latencies_ms.append(max(0.0, float(latency_ms)))

    def record_authorization_failure(self) -> None:
        with self._lock:
            self._state.authorization_failures += 1

    def record_broker_rejection(self) -> None:
        with self._lock:
            self._state.broker_rejections += 1

    def record_verification_failure(self) -> None:
        with self._lock:
            self._state.verification_failures += 1

    def snapshot(self) -> dict[str, Any]:
        with self._lock:
            latencies = list(self._state.decision_latencies_ms)
            total = sum(self._state.dispositions.values())
            return {
                "decisions_total": total,
                "decision_counts": {
                    outcome: self._state.dispositions.get(outcome, 0)
                    for outcome in (
                        "ALLOW",
                        "DENY",
                        "ESCALATE",
                        "ALLOW_CONSTRAINED",
                    )
                },
                "policy_rule_matches": dict(
                    sorted(self._state.policy_rule_matches.items())
                ),
                "evidence_conflicts": self._state.evidence_conflicts,
                "authorization_failures": self._state.authorization_failures,
                "broker_rejections": self._state.broker_rejections,
                "verification_failures": self._state.verification_failures,
                "decision_latency_ms": {
                    "count": len(latencies),
                    "mean": (
                        round(sum(latencies) / len(latencies), 6) if latencies else 0.0
                    ),
                    "max": round(max(latencies), 6) if latencies else 0.0,
                },
            }
