from __future__ import annotations

import hashlib
import hmac
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Callable

from adf_poc.stage_a import (
    ControlLedgerError,
    InMemoryControlLedger,
    SQLiteControlLedger,
)
from adf_poc.utils import canonical_json, sha256_json

from .metrics import Phase3Metrics
from .models import (
    AuthorizationToken,
    DecisionOutcome,
    DecisionRecord,
    DecisionVerification,
)


class AuthorizationError(RuntimeError):
    def __init__(self, reason_code: str, message: str) -> None:
        super().__init__(message)
        self.reason_code = reason_code


class AttemptPersistenceError(RuntimeError):
    """A possible effect exists but its durable attempt outcome did not commit."""

    def __init__(self, reason_code: str, message: str, *, attempt_id: str) -> None:
        super().__init__(message)
        self.reason_code = reason_code
        self.attempt_id = attempt_id


def _parse_timestamp(value: str) -> datetime:
    parsed = datetime.fromisoformat(value)
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise AuthorizationError(
            "AUTHORIZATION_TIME_INVALID",
            "Authorization timestamps must include a UTC offset.",
        )
    return parsed.astimezone(timezone.utc)


class InMemoryAuthorizationLedger(InMemoryControlLedger):
    """Backward-compatible name for the Phase 3 process-local ledger."""


class AuthorizationGate:
    def __init__(
        self,
        *,
        signing_key: bytes,
        decision_verification_key: bytes,
        verifier_instance_id: str,
        ttl_seconds: int,
        metrics: Phase3Metrics,
        clock: Callable[[], datetime] | None = None,
        ledger: InMemoryControlLedger | SQLiteControlLedger | None = None,
        issuer_instance_id: str | None = None,
        id_factory: Callable[[str], str] | None = None,
    ) -> None:
        if len(signing_key) < 32:
            raise ValueError(
                "Phase 3 authorization signing key must be at least 32 bytes."
            )
        if ttl_seconds < 1 or ttl_seconds > 3600:
            raise ValueError("Authorization TTL must be within 1..3600 seconds.")
        self._signing_key = bytes(signing_key)
        self.authorization_key_domain_id = (
            "phase3-authorization-hmac-sha256-"
            + hashlib.sha256(signing_key).hexdigest()[:24]
        )
        if len(decision_verification_key) < 32 or not verifier_instance_id:
            raise ValueError("Decision-verification trust configuration is invalid.")
        self._decision_verification_key = bytes(decision_verification_key)
        self._verifier_instance_id = str(verifier_instance_id)
        self.ttl_seconds = int(ttl_seconds)
        self.metrics = metrics
        self.clock = clock or (lambda: datetime.now(timezone.utc))
        if ledger is not None and type(ledger) not in {
            InMemoryControlLedger,
            InMemoryAuthorizationLedger,
            SQLiteControlLedger,
        }:
            raise TypeError("Authorization ledger type is not supported.")
        self.ledger = ledger or InMemoryAuthorizationLedger()
        self.issuer_instance_id = (
            issuer_instance_id
            or getattr(self.ledger, "issuer_instance_id", None)
            or f"issuer-{uuid.uuid4()}"
        )
        self.id_factory = id_factory or (lambda prefix: f"{prefix}-{uuid.uuid4()}")

    def _sign(self, value: dict[str, Any]) -> str:
        return hmac.new(
            self._signing_key,
            canonical_json(value).encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()

    def issue(
        self,
        *,
        decision: DecisionRecord,
        agent_id: str,
        target_state_sha256: str,
        decision_verification: DecisionVerification,
    ) -> AuthorizationToken:
        if type(decision) is not DecisionRecord:
            self.metrics.record_authorization_failure()
            raise AuthorizationError(
                "AUTHORIZATION_DECISION_TYPE_INVALID",
                "Authorization requires an exact immutable DecisionRecord.",
            )
        decision_projection = DecisionRecord.to_dict(decision)
        authorization_projection = dict(decision_projection)
        authorization_projection.pop("latency_ms", None)
        authorization_projection.pop("explanation", None)
        authorization_projection.pop("approval_requirement", None)
        decision_authorization_sha256 = sha256_json(authorization_projection)
        if decision.outcome not in {
            DecisionOutcome.ALLOW.value,
            DecisionOutcome.ALLOW_CONSTRAINED.value,
        }:
            self.metrics.record_authorization_failure()
            raise AuthorizationError(
                "AUTHORIZATION_OUTCOME_PROHIBITED",
                "Only ALLOW or ALLOW_CONSTRAINED decisions may be authorized.",
            )
        if type(decision_verification) is not DecisionVerification:
            self.metrics.record_authorization_failure()
            raise AuthorizationError(
                "AUTHORIZATION_DECISION_VERIFICATION_INVALID",
                "Authorization requires a signed decision-verification receipt.",
            )
        expected_verification_signature = hmac.new(
            self._decision_verification_key,
            canonical_json(decision_verification.unsigned_dict()).encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()
        now = self.clock().astimezone(timezone.utc).replace(microsecond=0)
        try:
            verification_age = (
                now - _parse_timestamp(decision_verification.verified_at)
            ).total_seconds()
        except AuthorizationError:
            verification_age = -1.0
        verification_bound = (
            hmac.compare_digest(
                expected_verification_signature, decision_verification.signature
            )
            and decision_verification.verifier_instance_id == self._verifier_instance_id
            and decision_verification.passed
            and decision_verification.decision_id == decision.decision_id
            and decision_verification.decision_context_sha256
            == decision.decision_context_sha256
            and decision_verification.decision_sha256 == decision_authorization_sha256
            and decision_verification.request_sha256 == decision.request_sha256
            and decision_verification.principal_id == agent_id
            and decision_verification.policy_sha256 == decision.policy_sha256
            and decision.authority.principal_id == agent_id
            and 0.0 <= verification_age <= 60.0
        )
        if not verification_bound:
            self.metrics.record_authorization_failure()
            raise AuthorizationError(
                "AUTHORIZATION_DECISION_NOT_VERIFIED",
                "The signed deterministic decision verification did not pass or bind exactly.",
            )
        permitted = decision_projection["permitted_action"]
        if not isinstance(permitted, dict):
            self.metrics.record_authorization_failure()
            raise AuthorizationError(
                "AUTHORIZATION_SCOPE_MISSING",
                "Allowed decision does not contain an exact permitted command.",
            )

        unsigned = {
            "token_id": self.id_factory("auth"),
            "issuer_instance_id": self.issuer_instance_id,
            "request_id": decision.request_id,
            "decision_id": decision.decision_id,
            "agent_id": agent_id,
            "action_type": str(permitted["type"]),
            "target_id": str(permitted["target"]),
            "permitted_parameters": dict(permitted["parameters"]),
            "issued_at": now.isoformat(),
            "expires_at": (now + timedelta(seconds=self.ttl_seconds)).isoformat(),
            "policy_id": decision.policy_id,
            "policy_version": decision.policy_version,
            "policy_sha256": decision.policy_sha256,
            "decision_context_sha256": decision.decision_context_sha256,
            "target_state_sha256": target_state_sha256,
            "nonce": self.id_factory("nonce"),
        }
        token = AuthorizationToken(signature=self._sign(unsigned), **unsigned)
        try:
            self.ledger.register(
                token.token_id,
                verification_id=decision_verification.verification_id,
                decision_id=decision.decision_id,
                principal_id=agent_id,
                request_id=decision.request_id,
                request_sha256=decision.request_sha256,
                unsigned_token_sha256=sha256_json(token.unsigned_dict()),
                issuer_instance_id=token.issuer_instance_id,
                key_domain_id=self.authorization_key_domain_id,
                decision_authorization_sha256=decision_authorization_sha256,
                issued_at=token.issued_at,
            )
        except ControlLedgerError as exc:
            self.metrics.record_authorization_failure()
            raise AuthorizationError(exc.reason_code, str(exc)) from exc
        return token

    def validate_and_consume(
        self,
        token: AuthorizationToken,
        *,
        request_id: str,
        decision_id: str,
        agent_id: str,
        action_type: str,
        target_id: str,
        parameters: dict[str, Any],
        policy_id: str,
        policy_version: str,
        policy_sha256: str,
        decision_context_sha256: str,
        target_state_sha256: str,
        evaluated_at: datetime | None = None,
        attempt_id: str | None = None,
        attempt_binding_sha256: str | None = None,
        idempotency_key: str | None = None,
        recovery_summary: dict[str, Any] | None = None,
    ) -> None:
        try:
            self._validate(
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
                target_state_sha256=target_state_sha256,
                evaluated_at=evaluated_at,
            )
            consumed_at = (
                evaluated_at or self.clock()
            ).astimezone(timezone.utc).replace(microsecond=0).isoformat()
            self.ledger.consume_once(
                token.token_id,
                attempt_id=attempt_id,
                attempt_binding_sha256=attempt_binding_sha256,
                consumed_at=consumed_at,
                idempotency_key=idempotency_key,
                recovery_summary=recovery_summary,
            )
        except ControlLedgerError as exc:
            self.metrics.record_authorization_failure()
            raise AuthorizationError(exc.reason_code, str(exc)) from exc
        except AuthorizationError:
            self.metrics.record_authorization_failure()
            raise

    def record_attempt_outcome(
        self,
        *,
        attempt_id: str,
        outcome_state: str,
        outcome_sha256: str,
        completed_at: str,
    ) -> None:
        try:
            self.ledger.record_attempt_outcome(
                attempt_id,
                outcome_state=outcome_state,
                outcome_sha256=outcome_sha256,
                completed_at=completed_at,
            )
        except ControlLedgerError as exc:
            raise AttemptPersistenceError(
                exc.reason_code,
                "Durable attempt outcome did not commit; effect is indeterminate.",
                attempt_id=attempt_id,
            ) from exc

    def record_adapter_receipt(
        self,
        *,
        attempt_id: str,
        adapter_receipt_sha256: str,
        receipt_outcome_sha256: str,
        recorded_at: str,
    ) -> None:
        try:
            self.ledger.record_adapter_receipt(
                attempt_id,
                adapter_receipt_sha256=adapter_receipt_sha256,
                receipt_outcome_sha256=receipt_outcome_sha256,
                recorded_at=recorded_at,
            )
        except ControlLedgerError as exc:
            raise AttemptPersistenceError(
                exc.reason_code,
                "Durable adapter receipt did not commit; effect is indeterminate.",
                attempt_id=attempt_id,
            ) from exc

    def _validate(
        self,
        token: AuthorizationToken,
        *,
        request_id: str,
        decision_id: str,
        agent_id: str,
        action_type: str,
        target_id: str,
        parameters: dict[str, Any],
        policy_id: str,
        policy_version: str,
        policy_sha256: str,
        decision_context_sha256: str,
        target_state_sha256: str,
        evaluated_at: datetime | None,
    ) -> None:
        expected_signature = self._sign(token.unsigned_dict())
        if not hmac.compare_digest(expected_signature, token.signature):
            raise AuthorizationError(
                "AUTHORIZATION_SIGNATURE_INVALID",
                "Authorization signature is invalid.",
            )
        if token.issuer_instance_id != self.issuer_instance_id:
            raise AuthorizationError(
                "AUTHORIZATION_ISSUER_MISMATCH",
                "Authorization belongs to another firewall instance.",
            )
        try:
            ledger_state = self.ledger.state(token.token_id)
        except ControlLedgerError as exc:
            raise AuthorizationError(exc.reason_code, str(exc)) from exc
        if ledger_state != "ISSUED":
            raise AuthorizationError(
                "AUTHORIZATION_REPLAY",
                "Authorization is not in the single-use ISSUED state.",
            )
        bindings: tuple[tuple[str, Any, Any], ...] = (
            ("REQUEST", token.request_id, request_id),
            ("DECISION", token.decision_id, decision_id),
            ("AGENT", token.agent_id, agent_id),
            ("ACTION", token.action_type, action_type),
            ("TARGET", token.target_id, target_id),
            ("PARAMETERS", token.permitted_parameters, parameters),
            ("POLICY_ID", token.policy_id, policy_id),
            ("POLICY_VERSION", token.policy_version, policy_version),
            ("POLICY_DIGEST", token.policy_sha256, policy_sha256),
            (
                "DECISION_CONTEXT",
                token.decision_context_sha256,
                decision_context_sha256,
            ),
            ("TARGET_STATE", token.target_state_sha256, target_state_sha256),
        )
        for name, expected, observed in bindings:
            if expected != observed:
                raise AuthorizationError(
                    f"AUTHORIZATION_{name}_MISMATCH",
                    f"Authorization {name.lower()} binding does not match.",
                )
        now = (evaluated_at or self.clock()).astimezone(timezone.utc)
        if now < _parse_timestamp(token.issued_at):
            raise AuthorizationError(
                "AUTHORIZATION_NOT_YET_VALID",
                "Authorization issue time is in the future.",
            )
        if now >= _parse_timestamp(token.expires_at):
            raise AuthorizationError(
                "AUTHORIZATION_EXPIRED",
                "Authorization has expired.",
            )
