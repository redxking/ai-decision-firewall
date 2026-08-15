"""Closed, simulation-only execution boundary for the Phase 3 MVP.

The mutable target state exists only inside :func:`build_simulated_execution_boundary`.
Caller-visible objects retain one application-private closure each and never retain an
environment object, a target-state mapping, or a raw mutation callable. This is an
application-encapsulation boundary for a same-process Python MVP; it is not a claim of
protection against hostile interpreter introspection or an OS/process isolation claim.
"""

from __future__ import annotations

import uuid
from copy import deepcopy
from datetime import datetime, timedelta, timezone
import math
from threading import Lock
from types import MappingProxyType
from typing import Any, Callable, Mapping

from adf_poc.utils import sha256_json

from .authorization import AuthorizationError, AuthorizationGate
from .config import TargetRecord
from .metrics import Phase3Metrics
from .models import (
    AuthorizationToken,
    BrokerResult,
    PostActionVerification,
    VerificationStatus,
)

__all__ = (
    "ActionBroker",
    "IndependentTargetVerifier",
    "SimulationBoundaryError",
    "TargetStateObserver",
    "build_simulated_execution_boundary",
)


class SimulationBoundaryError(RuntimeError):
    def __init__(self, reason_code: str, message: str) -> None:
        super().__init__(message)
        self.reason_code = reason_code


_BOUNDARY_CONSTRUCTION_KEY = object()
_COMMAND_KEYS = frozenset({"type", "target", "parameters"})
_VALID_FAULT_MODES = frozenset({"NONE", "FAILED", "PARTIAL", "UNEXPECTED_EFFECT"})


def _default_id_factory(prefix: str) -> str:
    return f"{prefix}-{uuid.uuid4()}"


def _copy_exact_json(value: object) -> object:
    if type(value) is dict:
        if any(type(key) is not str for key in value):
            raise TypeError("Synthetic command object keys must be exact strings.")
        return {key: _copy_exact_json(child) for key, child in value.items()}
    if type(value) is list:
        return [_copy_exact_json(child) for child in value]
    if value is None or type(value) in (str, bool, int):
        return value
    if type(value) is float and math.isfinite(value):
        return value
    raise TypeError("Synthetic command values must be exact finite JSON primitives.")


def _normalize_command(value: object) -> dict[str, Any] | None:
    """Return a detached exact command or ``None`` for an ambiguous shape."""

    if type(value) is not dict or set(value) != _COMMAND_KEYS:
        return None
    action_type = value.get("type")
    target_id = value.get("target")
    parameters = value.get("parameters")
    if type(action_type) is not str or not action_type:
        return None
    if type(target_id) is not str or not target_id:
        return None
    if type(parameters) is not dict:
        return None
    try:
        normalized_parameters = _copy_exact_json(parameters)
    except TypeError:
        return None
    if type(normalized_parameters) is not dict:  # structural invariant
        return None
    return {
        "type": action_type,
        "target": target_id,
        "parameters": normalized_parameters,
    }


def _changed_fields(
    before: Mapping[str, Any], observed: Mapping[str, Any]
) -> tuple[str, ...]:
    return tuple(
        sorted(
            key
            for key in set(before) | set(observed)
            if before.get(key) != observed.get(key)
        )
    )


def _ordered_unique(values: list[str]) -> tuple[str, ...]:
    return tuple(dict.fromkeys(values))


class TargetStateObserver:
    """Read-only view of synthetic target state.

    Instances are produced only by the boundary factory. The retained closure can
    copy state but has no mutation operation.
    """

    __slots__ = ("__observe_state",)

    def __init__(
        self,
        construction_key: object,
        observe_state: Callable[[str], dict[str, Any]],
    ) -> None:
        if construction_key is not _BOUNDARY_CONSTRUCTION_KEY:
            raise TypeError(
                "TargetStateObserver instances must come from the simulation boundary."
            )
        self.__observe_state = observe_state

    def observe(self, target_id: str) -> dict[str, Any]:
        if type(target_id) is not str or not target_id:
            raise SimulationBoundaryError(
                "TARGET_ID_INVALID",
                "A non-empty synthetic target identifier is required.",
            )
        return self.__observe_state(target_id)


class SimulatedTargetEnvironment:
    """Non-instantiable migration guard for the removed adapter-style API."""

    __slots__ = ()

    def __new__(cls, *_: object, **__: object) -> "SimulatedTargetEnvironment":
        raise TypeError(
            "Caller-constructed target environments are prohibited; use the closed "
            "simulation boundary factory."
        )


class ActionBroker:
    """Mandatory authorization-and-execution entry point.

    The broker deliberately stores only one combined authorize-and-execute closure.
    It does not retain an authorization gate, environment, target state, or separate
    apply callback as an object attribute.
    """

    __slots__ = ("__authorize_and_execute",)

    def __init__(
        self,
        construction_key: object,
        authorize_and_execute: Callable[..., BrokerResult],
    ) -> None:
        if construction_key is not _BOUNDARY_CONSTRUCTION_KEY:
            raise TypeError(
                "ActionBroker instances must come from the simulation boundary."
            )
        self.__authorize_and_execute = authorize_and_execute

    def execute(
        self,
        *,
        token: AuthorizationToken | None,
        command: dict[str, Any],
        request_id: str,
        decision_id: str,
        agent_id: str,
        policy_id: str,
        policy_version: str,
        policy_sha256: str,
        decision_context_sha256: str,
    ) -> BrokerResult:
        return self.__authorize_and_execute(
            token=token,
            command=command,
            request_id=request_id,
            decision_id=decision_id,
            agent_id=agent_id,
            policy_id=policy_id,
            policy_version=policy_version,
            policy_sha256=policy_sha256,
            decision_context_sha256=decision_context_sha256,
        )


class IndependentTargetVerifier:
    """Read-back verifier bound to the target and broker-attempt ledger."""

    __slots__ = ("__verify_execution",)

    def __init__(
        self,
        construction_key: object,
        verify_execution: Callable[..., PostActionVerification],
    ) -> None:
        if construction_key is not _BOUNDARY_CONSTRUCTION_KEY:
            raise TypeError(
                "IndependentTargetVerifier instances must come from the "
                "simulation boundary."
            )
        self.__verify_execution = verify_execution

    def verify(
        self,
        *,
        token: AuthorizationToken,
        permitted_command: dict[str, Any],
        request_id: str,
        decision_id: str,
        broker_result: BrokerResult,
        state_before: dict[str, Any],
    ) -> PostActionVerification:
        return self.__verify_execution(
            token=token,
            permitted_command=permitted_command,
            request_id=request_id,
            decision_id=decision_id,
            broker_result=broker_result,
            state_before=state_before,
        )


def build_simulated_execution_boundary(
    *,
    target_inventory: Mapping[str, Any],
    gate: AuthorizationGate,
    metrics: Phase3Metrics,
    fault_modes: Mapping[str, str] | None = None,
    clock: Callable[[], datetime] | None = None,
    id_factory: Callable[[str], str] | None = None,
) -> tuple[TargetStateObserver, ActionBroker, IndependentTargetVerifier]:
    """Build one closed in-memory target, broker, and verifier boundary.

    ``target_inventory`` and ``fault_modes`` are inert configuration values. No
    target adapter or caller-supplied execution function is accepted. A fresh call
    creates a fresh, unreachable state store; consequently, constructing another
    gate or broker cannot grant authority over an existing target boundary.
    """

    if type(gate) is not AuthorizationGate:
        raise TypeError("The simulation broker requires the exact AuthorizationGate.")
    if type(metrics) is not Phase3Metrics:
        raise TypeError(
            "The simulation boundary requires the exact Phase3Metrics sink."
        )
    closed_mapping_types = (dict, type(MappingProxyType({})))
    if type(target_inventory) not in closed_mapping_types or not target_inventory:
        raise ValueError("The synthetic target inventory must be a non-empty mapping.")
    if fault_modes is not None and type(fault_modes) not in closed_mapping_types:
        raise TypeError("Synthetic fault modes must be an inert mapping.")

    configured_faults = dict(fault_modes or {})
    if any(
        type(target_id) is not str or type(mode) is not str
        for target_id, mode in configured_faults.items()
    ):
        raise TypeError("Synthetic fault-mode keys and values must be strings.")
    unknown_targets = set(configured_faults) - set(target_inventory)
    invalid_faults = set(configured_faults.values()) - _VALID_FAULT_MODES
    if unknown_targets or invalid_faults:
        raise ValueError("Synthetic fault configuration is not closed and valid.")

    state_lock = Lock()
    attempt_lock = Lock()
    states: dict[str, dict[str, Any]] = {}
    attempt_binding_digests: dict[str, str | None] = {}
    for target_id, record in target_inventory.items():
        if type(target_id) is not str or not target_id:
            raise ValueError("Synthetic target identifiers must be non-empty strings.")
        if type(record) is not TargetRecord or record.id != target_id:
            raise TypeError(
                "Synthetic target records must be exact, identifier-bound "
                "TargetRecord values."
            )
        states[target_id] = {
            "target_id": target_id,
            "target_type": record.type,
            "network_state": "connected",
            "management_channel": True,
            "isolation_expires_at": None,
            "service_health": "healthy",
            "last_action_id": None,
        }

    boundary_clock = clock or (lambda: datetime.now(timezone.utc))
    boundary_id_factory = id_factory or _default_id_factory
    validate_and_consume = gate.validate_and_consume

    def observe_state(target_id: str) -> dict[str, Any]:
        with state_lock:
            if target_id not in states:
                raise SimulationBoundaryError(
                    "TARGET_UNKNOWN",
                    "Target is not present in the synthetic simulation inventory.",
                )
            return deepcopy(states[target_id])

    def authorize_and_execute(
        *,
        token: AuthorizationToken | None,
        command: dict[str, Any],
        request_id: str,
        decision_id: str,
        agent_id: str,
        policy_id: str,
        policy_version: str,
        policy_sha256: str,
        decision_context_sha256: str,
    ) -> BrokerResult:
        if token is None:
            metrics.record_broker_rejection()
            metrics.record_authorization_failure()
            raise AuthorizationError(
                "AUTHORIZATION_MISSING",
                "The action broker requires an authorization token.",
            )
        if type(token) is not AuthorizationToken:
            metrics.record_broker_rejection()
            metrics.record_authorization_failure()
            raise AuthorizationError(
                "AUTHORIZATION_TYPE_INVALID",
                "The action broker requires an exact Phase 3 authorization token.",
            )
        normalized_command = _normalize_command(command)
        if normalized_command is None:
            metrics.record_broker_rejection()
            metrics.record_authorization_failure()
            raise AuthorizationError(
                "AUTHORIZATION_COMMAND_SHAPE_INVALID",
                "The broker command must contain only type, target, and parameters.",
            )

        action_type = normalized_command["type"]
        target_id = normalized_command["target"]
        parameters = normalized_command["parameters"]
        try:
            state_before = observe_state(target_id)
        except SimulationBoundaryError as exc:
            metrics.record_broker_rejection()
            metrics.record_authorization_failure()
            raise AuthorizationError(exc.reason_code, str(exc)) from exc

        attempt_id = boundary_id_factory("attempt")
        if type(attempt_id) is not str or not attempt_id:
            raise SimulationBoundaryError(
                "ATTEMPT_ID_INVALID",
                "The synthetic broker could not allocate a valid attempt identifier.",
            )
        with attempt_lock:
            if attempt_id in attempt_binding_digests:
                raise SimulationBoundaryError(
                    "ATTEMPT_ID_COLLISION",
                    "The synthetic broker attempt identifier was already used.",
                )
            # Reserve before authorization so concurrent executions cannot collide.
            attempt_binding_digests[attempt_id] = None

        attempted_at = boundary_clock()
        if attempted_at.tzinfo is None or attempted_at.utcoffset() is None:
            with attempt_lock:
                attempt_binding_digests.pop(attempt_id, None)
            raise SimulationBoundaryError(
                "SIMULATION_CLOCK_INVALID",
                "The simulation clock must return an offset-aware timestamp.",
            )
        attempted_at = attempted_at.astimezone(timezone.utc).replace(microsecond=0)

        try:
            validate_and_consume(
                token,
                request_id=request_id,
                decision_id=decision_id,
                agent_id=agent_id,
                action_type=action_type,
                target_id=target_id,
                parameters=parameters,
                policy_id=policy_id,
                policy_version=policy_version,
                policy_sha256=policy_sha256,
                decision_context_sha256=decision_context_sha256,
                target_state_sha256=sha256_json(state_before),
                evaluated_at=attempted_at,
            )
        except AuthorizationError:
            with attempt_lock:
                attempt_binding_digests.pop(attempt_id, None)
            metrics.record_broker_rejection()
            raise

        reported_success = False
        message = ""
        try:
            with state_lock:
                if target_id not in states:
                    raise SimulationBoundaryError(
                        "TARGET_UNKNOWN",
                        "Target is not present in the synthetic simulation inventory.",
                    )
                state = states[target_id]
                if sha256_json(state) != token.target_state_sha256:
                    raise SimulationBoundaryError(
                        "TARGET_STATE_PRECONDITION_CHANGED",
                        "Target state changed after authorization validation.",
                    )
                if action_type != "NETWORK_ISOLATE":
                    raise SimulationBoundaryError(
                        "ACTION_NOT_IMPLEMENTED",
                        "The synthetic target implements only NETWORK_ISOLATE.",
                    )

                fault_mode = configured_faults.get(target_id, "NONE")
                if fault_mode == "FAILED":
                    message = "Injected synthetic downstream failure; no state changed."
                else:
                    duration_seconds = int(parameters["duration_seconds"])
                    preserve_management = bool(parameters["preserve_management"])
                    state["last_action_id"] = attempt_id
                    state["network_state"] = "isolated"
                    if fault_mode == "PARTIAL":
                        state["isolation_expires_at"] = None
                        reported_success = True
                        message = "Injected partial transition in the synthetic target."
                    else:
                        state["management_channel"] = preserve_management
                        state["isolation_expires_at"] = (
                            (attempted_at + timedelta(seconds=duration_seconds))
                            .replace(microsecond=0)
                            .isoformat()
                        )
                        reported_success = True
                        if fault_mode == "UNEXPECTED_EFFECT":
                            state["service_health"] = "degraded"
                            message = (
                                "Synthetic action completed with an injected "
                                "unexpected effect."
                            )
                        else:
                            message = (
                                "Synthetic network isolation applied to the "
                                "in-memory target."
                            )
                state_after = deepcopy(state)
        except SimulationBoundaryError as exc:
            metrics.record_broker_rejection()
            message = f"{exc.reason_code}: {exc}"
            state_after = observe_state(target_id)

        result = BrokerResult(
            attempt_id=attempt_id,
            token_id=token.token_id,
            request_id=token.request_id,
            decision_id=token.decision_id,
            action_type=action_type,
            target_id=target_id,
            parameters=deepcopy(parameters),
            executed_at=attempted_at.isoformat(),
            attempted=True,
            accepted=True,
            reported_success=reported_success,
            message=message,
            state_before_sha256=sha256_json(state_before),
            state_after_sha256=sha256_json(state_after),
        )
        attempt_binding = {
            "authorization": token.to_dict(include_signature=True),
            "permitted_command": deepcopy(normalized_command),
            "broker_result": result.to_dict(),
        }
        with attempt_lock:
            attempt_binding_digests[attempt_id] = sha256_json(attempt_binding)
        return result

    def verify_execution(
        *,
        token: AuthorizationToken,
        permitted_command: dict[str, Any],
        request_id: str,
        decision_id: str,
        broker_result: BrokerResult,
        state_before: dict[str, Any],
    ) -> PostActionVerification:
        if type(token) is not AuthorizationToken:
            raise SimulationBoundaryError(
                "VERIFICATION_AUTHORIZATION_INVALID",
                "Post-action verification requires the exact authorization token.",
            )
        if type(broker_result) is not BrokerResult:
            raise SimulationBoundaryError(
                "VERIFICATION_BROKER_RESULT_INVALID",
                "Post-action verification requires an exact broker result.",
            )

        verification_id = boundary_id_factory("verify")
        normalized_permitted = _normalize_command(permitted_command)
        before = deepcopy(state_before) if type(state_before) is dict else {}
        binding_reasons: list[str] = []

        if request_id != token.request_id:
            binding_reasons.append("VERIFICATION_REQUEST_MISMATCH")
        if decision_id != token.decision_id:
            binding_reasons.append("VERIFICATION_DECISION_MISMATCH")
        if broker_result.token_id != token.token_id:
            binding_reasons.append("VERIFICATION_TOKEN_MISMATCH")
        if broker_result.request_id != token.request_id:
            binding_reasons.append("VERIFICATION_BROKER_REQUEST_MISMATCH")
        if broker_result.decision_id != token.decision_id:
            binding_reasons.append("VERIFICATION_BROKER_DECISION_MISMATCH")
        if normalized_permitted is None:
            binding_reasons.append("VERIFICATION_COMMAND_SHAPE_INVALID")
        else:
            if normalized_permitted["type"] != token.action_type:
                binding_reasons.append("VERIFICATION_COMMAND_ACTION_MISMATCH")
            if normalized_permitted["target"] != token.target_id:
                binding_reasons.append("VERIFICATION_COMMAND_TARGET_MISMATCH")
            if normalized_permitted["parameters"] != token.permitted_parameters:
                binding_reasons.append("VERIFICATION_COMMAND_PARAMETERS_MISMATCH")
        if broker_result.action_type != token.action_type:
            binding_reasons.append("VERIFICATION_ACTION_MISMATCH")
        if broker_result.target_id != token.target_id:
            binding_reasons.append("VERIFICATION_TARGET_MISMATCH")
        if broker_result.parameters != token.permitted_parameters:
            binding_reasons.append("VERIFICATION_PARAMETERS_MISMATCH")
        try:
            executed_at = datetime.fromisoformat(broker_result.executed_at).astimezone(
                timezone.utc
            )
            token_issued = datetime.fromisoformat(token.issued_at).astimezone(
                timezone.utc
            )
            token_expires = datetime.fromisoformat(token.expires_at).astimezone(
                timezone.utc
            )
            if not (token_issued <= executed_at < token_expires):
                binding_reasons.append("VERIFICATION_EXECUTION_TIME_INVALID")
        except (TypeError, ValueError, OverflowError):
            executed_at = None
            binding_reasons.append("VERIFICATION_EXECUTION_TIME_INVALID")
        if not broker_result.attempted or not broker_result.accepted:
            binding_reasons.append("VERIFICATION_BROKER_DISPOSITION_INVALID")
        if type(broker_result.attempt_id) is not str or not broker_result.attempt_id:
            binding_reasons.append("VERIFICATION_ATTEMPT_INVALID")

        before_sha256 = sha256_json(before)
        if before_sha256 != token.target_state_sha256:
            binding_reasons.append("VERIFICATION_PRESTATE_AUTHORIZATION_MISMATCH")
        if broker_result.state_before_sha256 != before_sha256:
            binding_reasons.append("VERIFICATION_BROKER_PRESTATE_MISMATCH")

        # Observe the authorization target, never a caller- or broker-result target.
        try:
            observed = observe_state(token.target_id)
        except Exception:
            metrics.record_verification_failure()
            return PostActionVerification(
                verification_id=verification_id,
                request_id=token.request_id,
                decision_id=token.decision_id,
                attempt_id=broker_result.attempt_id,
                token_id=token.token_id,
                action_type=token.action_type,
                target_id=token.target_id,
                parameters_sha256=sha256_json(token.permitted_parameters),
                status=VerificationStatus.FAILED.value,
                expected_state={
                    "action_type": token.action_type,
                    "target_id": token.target_id,
                    "last_action_id": broker_result.attempt_id,
                },
                observed_state={},
                changed_fields=(),
                unexpected_fields=(),
                rollback_required=False,
                reason_codes=("TARGET_OBSERVATION_UNAVAILABLE",),
            )

        observed_sha256 = sha256_json(observed)
        if broker_result.state_after_sha256 != observed_sha256:
            binding_reasons.append("VERIFICATION_BROKER_POSTSTATE_MISMATCH")
        if observed.get("last_action_id") != broker_result.attempt_id:
            binding_reasons.append("VERIFICATION_ATTEMPT_STATE_MISMATCH")

        with attempt_lock:
            expected_attempt_digest = attempt_binding_digests.get(
                broker_result.attempt_id
            )
        observed_attempt_digest: str | None = None
        if normalized_permitted is not None:
            try:
                observed_attempt_digest = sha256_json(
                    {
                        "authorization": token.to_dict(include_signature=True),
                        "permitted_command": normalized_permitted,
                        "broker_result": broker_result.to_dict(),
                    }
                )
            except (TypeError, ValueError):
                observed_attempt_digest = None
        if (
            expected_attempt_digest is None
            or observed_attempt_digest is None
            or expected_attempt_digest != observed_attempt_digest
        ):
            binding_reasons.append("VERIFICATION_ATTEMPT_ORIGIN_UNVERIFIED")

        changed_fields = _changed_fields(before, observed)
        allowed_changes = {
            "network_state",
            "management_channel",
            "isolation_expires_at",
            "last_action_id",
        }
        unexpected_fields = tuple(
            sorted(key for key in changed_fields if key not in allowed_changes)
        )
        state_changed = observed != before
        expected = {
            "action_type": token.action_type,
            "target_id": token.target_id,
            "parameters": deepcopy(token.permitted_parameters),
            "network_state": "isolated",
            "management_channel": bool(
                token.permitted_parameters.get("preserve_management")
            ),
            "isolation_expires_at_present": True,
            "isolation_expires_at": (
                (
                    executed_at
                    + timedelta(
                        seconds=int(token.permitted_parameters["duration_seconds"])
                    )
                )
                .replace(microsecond=0)
                .isoformat()
                if executed_at is not None
                else None
            ),
            "last_action_id": broker_result.attempt_id,
        }

        if binding_reasons:
            rollback_required = state_changed
            status = (
                VerificationStatus.ROLLBACK_REQUIRED.value
                if rollback_required
                else VerificationStatus.FAILED.value
            )
            reasons = ["POST_ACTION_BINDING_FAILED", *binding_reasons]
            if rollback_required:
                reasons.append("ROLLBACK_REQUIRED")
        elif token.action_type != "NETWORK_ISOLATE":
            rollback_required = state_changed
            status = (
                VerificationStatus.ROLLBACK_REQUIRED.value
                if rollback_required
                else VerificationStatus.FAILED.value
            )
            reasons = ["ACTION_VERIFICATION_UNSUPPORTED"]
            if rollback_required:
                reasons.append("ROLLBACK_REQUIRED")
        else:
            transition_checks = (
                observed.get("network_state") == "isolated",
                observed.get("management_channel")
                == bool(token.permitted_parameters["preserve_management"]),
                observed.get("isolation_expires_at") is not None,
                observed.get("isolation_expires_at")
                == expected["isolation_expires_at"],
                observed.get("last_action_id") == broker_result.attempt_id,
            )
            matched = sum(1 for passed in transition_checks if passed)
            if unexpected_fields:
                status = VerificationStatus.UNEXPECTED_EFFECT.value
                rollback_required = True
                reasons = [
                    "UNEXPECTED_TARGET_STATE_CHANGE",
                    "ROLLBACK_REQUIRED",
                ]
            elif matched == len(transition_checks) and broker_result.reported_success:
                status = VerificationStatus.VERIFIED.value
                rollback_required = False
                reasons = ["EXPECTED_STATE_OBSERVED"]
            elif matched == len(transition_checks):
                status = VerificationStatus.UNEXPECTED_EFFECT.value
                rollback_required = True
                reasons = [
                    "BROKER_REPORT_STATE_DISAGREEMENT",
                    "ROLLBACK_REQUIRED",
                ]
            elif 0 < matched < len(transition_checks):
                status = VerificationStatus.PARTIAL.value
                rollback_required = True
                reasons = ["PARTIAL_STATE_TRANSITION", "ROLLBACK_REQUIRED"]
            else:
                status = VerificationStatus.FAILED.value
                rollback_required = False
                reasons = ["EXPECTED_STATE_NOT_OBSERVED"]

        if status != VerificationStatus.VERIFIED.value:
            metrics.record_verification_failure()
        return PostActionVerification(
            verification_id=verification_id,
            request_id=token.request_id,
            decision_id=token.decision_id,
            attempt_id=broker_result.attempt_id,
            token_id=token.token_id,
            action_type=token.action_type,
            target_id=token.target_id,
            parameters_sha256=sha256_json(token.permitted_parameters),
            status=status,
            expected_state=expected,
            observed_state=observed,
            changed_fields=changed_fields,
            unexpected_fields=unexpected_fields,
            rollback_required=rollback_required,
            reason_codes=_ordered_unique(reasons),
        )

    observer = TargetStateObserver(_BOUNDARY_CONSTRUCTION_KEY, observe_state)
    broker = ActionBroker(_BOUNDARY_CONSTRUCTION_KEY, authorize_and_execute)
    verifier = IndependentTargetVerifier(_BOUNDARY_CONSTRUCTION_KEY, verify_execution)
    return observer, broker, verifier
