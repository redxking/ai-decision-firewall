from __future__ import annotations

import hashlib
import hmac
import uuid
from dataclasses import replace
from datetime import datetime, timezone
from pathlib import Path
from threading import Lock
from time import perf_counter
from typing import Any, Callable

from adf_poc.audit import AuditLogger
from adf_poc.utils import canonical_json, sha256_json

from .approval import HumanApprovalGate
from .attestation import EvidenceAttestationVerifier
from .audit import validate_phase3_audit_chain, validate_phase3_lifecycle
from .authorization import AuthorizationError, AuthorizationGate
from .config import Phase3PolicyConfig
from .consequence import assess_consequence
from .contracts import (
    AgentSecurityStatus,
    AuthenticatedPrincipal,
    DecisionRequest,
    RequestValidationError,
    load_decision_request_json,
)
from .decision import assess_authority, build_decision
from .evidence import assess_evidence
from .identity import (
    PrincipalAuthenticationError,
    ResolvedPrincipal,
    TrustedPrincipalResolver,
)
from .metrics import Phase3Metrics
from .models import (
    AuthorityAssessment,
    ApprovalReceipt,
    ApprovalRequirement,
    DecisionOutcome,
    DecisionRecord,
    Phase3Result,
    PostActionVerification,
    VerificationStatus,
)
from .simulation import (
    build_simulated_execution_boundary,
)
from .verifier import IndependentDecisionVerifier


MAX_REQUEST_AGE_SECONDS = 300


def _deterministic_failure_id(prefix: str, *bindings: str) -> str:
    material = canonical_json([prefix, *bindings]).encode("utf-8")
    return f"{prefix}-{hashlib.sha256(material).hexdigest()[:24]}"


def _fallback_utc_now() -> datetime:
    return datetime.now(timezone.utc).replace(microsecond=0)


class _RequestLedger:
    def __init__(self) -> None:
        self._requests: dict[tuple[str, str], str] = {}
        self._lock = Lock()

    def claim(self, principal_id: str, request_id: str, request_sha256: str) -> str:
        key = (principal_id, request_id)
        with self._lock:
            existing = self._requests.get(key)
            if existing is None:
                self._requests[key] = request_sha256
                return "NEW"
            if existing == request_sha256:
                return "DUPLICATE"
            return "CONFLICT"


class Phase3DecisionFirewall:
    """Simulation-only Phase 3 request-to-decision-to-verification path."""

    execution_mode = "synthetic_simulation"

    def __init__(
        self,
        *,
        policy: Phase3PolicyConfig,
        signing_key: bytes,
        evidence_attestation_keys: dict[str, bytes],
        principal_resolver: TrustedPrincipalResolver,
        audit_path: str | Path | None = None,
        clock: Callable[[], datetime] | None = None,
        id_factory: Callable[[str], str] | None = None,
        fault_modes: dict[str, str] | None = None,
    ) -> None:
        if type(policy) is not Phase3PolicyConfig:
            raise TypeError("Phase 3 requires an exact validated policy object.")
        if type(principal_resolver) is not TrustedPrincipalResolver:
            raise TypeError("Phase 3 requires the closed trusted-principal resolver.")
        if type(signing_key) is not bytes or len(signing_key) < 32:
            raise TypeError(
                "Phase 3 signing key must be an exact bytes value of at least 32 bytes."
            )
        if type(evidence_attestation_keys) is not dict:
            raise TypeError("Phase 3 evidence attestation keys require an exact dict.")
        trust_material_digests = [hashlib.sha256(signing_key).digest()]
        trust_material_digests.extend(
            hashlib.sha256(value).digest()
            for value in evidence_attestation_keys.values()
            if type(value) is bytes
        )
        trust_material_digests.extend(principal_resolver.credential_digests())
        if len(trust_material_digests) != len(set(trust_material_digests)):
            raise ValueError(
                "Phase 3 signing, evidence-source, and invocation trust domains "
                "must use distinct key material."
            )
        self._policy = Phase3PolicyConfig.from_dict(Phase3PolicyConfig.to_dict(policy))
        self._policy_sha256 = sha256_json(Phase3PolicyConfig.to_dict(self._policy))
        self.__principal_resolver = principal_resolver.immutable_snapshot()
        self.clock = clock or (lambda: datetime.now(timezone.utc))
        self.id_factory = id_factory or (lambda prefix: f"{prefix}-{uuid.uuid4()}")
        self._audit = AuditLogger(audit_path)
        existing_audit_valid, existing_audit_errors = validate_phase3_audit_chain(
            self._audit.read_all()
        )
        if not existing_audit_valid:
            raise ValueError(
                "Existing Phase 3 audit chain is invalid: "
                + "; ".join(existing_audit_errors)
            )
        self._metrics = Phase3Metrics()
        self._process_lock = Lock()
        self._request_ledger = _RequestLedger()
        self.__evidence_attestation_verifier = EvidenceAttestationVerifier(
            evidence_attestation_keys,
            required_source_instances=set(self._policy.evidence.trusted_sources),
        )
        verifier_key = hmac.new(
            bytes(signing_key), b"phase3-decision-verifier", hashlib.sha256
        ).digest()
        approval_key = hmac.new(
            bytes(signing_key), b"phase3-human-approval", hashlib.sha256
        ).digest()
        self.__approval_gate = HumanApprovalGate(
            signing_key=approval_key,
            ttl_seconds=self._policy.approval_ttl_seconds,
            principal_resolver=self.__principal_resolver,
            clock=self.clock,
            id_factory=self.id_factory,
        )
        self.__decision_verifier = IndependentDecisionVerifier(
            signing_key=verifier_key,
            attestation_verifier=self.__evidence_attestation_verifier,
            approval_gate=self.__approval_gate,
            principal_resolver=self.__principal_resolver,
            clock=self.clock,
            id_factory=self.id_factory,
        )
        self.__authorization_gate = AuthorizationGate(
            signing_key=signing_key,
            decision_verification_key=verifier_key,
            verifier_instance_id=self.__decision_verifier.verifier_instance_id,
            ttl_seconds=self._policy.authorization_ttl_seconds,
            metrics=self._metrics,
            clock=self.clock,
            id_factory=self.id_factory,
        )
        self.observer, self.__broker, self.__target_verifier = (
            build_simulated_execution_boundary(
                target_inventory=self._policy.target_inventory,
                gate=self.__authorization_gate,
                metrics=self._metrics,
                fault_modes=fault_modes,
                clock=self.clock,
                id_factory=self.id_factory,
            )
        )

    @property
    def policy(self) -> Phase3PolicyConfig:
        return self._policy

    def _audit_start(self) -> int:
        return len(self._audit.read_all())

    def _audit_rows(self, start: int) -> tuple[dict[str, Any], ...]:
        return tuple(self._audit.read_all()[start:])

    def _validated_result(self, result: Phase3Result) -> Phase3Result:
        chain_valid, chain_errors = validate_phase3_audit_chain(self._audit.read_all())
        lifecycle_valid, lifecycle_errors = validate_phase3_lifecycle(
            result.audit_records
        )
        if not chain_valid or not lifecycle_valid:
            raise RuntimeError(
                "Phase 3 audit lifecycle did not close: "
                + "; ".join(chain_errors + lifecycle_errors)
            )
        return result

    def _append(
        self,
        record_type: str,
        *,
        intake_id: str,
        request_id: str,
        decision_id: str,
        payload: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        before = self._audit.read_all()
        audit_payload = {
            "intake_id": intake_id,
            "request_id": request_id,
            "decision_id": decision_id,
            **(payload or {}),
        }
        try:
            record = self._audit.append(record_type, audit_payload)
        except Exception:
            # An append can become durable before a caller observes an fsync or
            # readback failure. Reconcile the exact next row before propagating;
            # retrying an ambiguous write could duplicate a security event.
            try:
                reconciled = self._audit.read_all()
                chain_valid, _chain_errors = validate_phase3_audit_chain(reconciled)
            except Exception:
                raise
            if (
                len(reconciled) == len(before) + 1
                and reconciled[-1].get("record_type") == record_type
                and canonical_json(reconciled[-1].get("payload"))
                == canonical_json(audit_payload)
                and chain_valid
            ):
                return reconciled[-1]
            raise
        after = self._audit.read_all()
        chain_valid, chain_errors = validate_phase3_audit_chain(after)
        if (
            len(after) != len(before) + 1
            or not after
            or canonical_json(after[-1]) != canonical_json(record)
            or not chain_valid
        ):
            raise RuntimeError(
                "Phase 3 audit append/readback failed: "
                + "; ".join(chain_errors or ["record not durably observable"])
            )
        return record

    @staticmethod
    def _decision_audit_payload(decision: DecisionRecord) -> dict[str, Any]:
        """Return the closed, non-secret projection used for lifecycle binding."""

        projection = decision.to_dict()
        permitted = projection.get("permitted_action")
        requested = projection["requested_action"]
        return {
            "outcome": decision.outcome,
            "reason_codes": list(decision.reason_codes),
            "decision_context_sha256": decision.decision_context_sha256,
            "decision_sha256": DecisionRecord.authorization_sha256(decision),
            "request_sha256": decision.request_sha256,
            "principal_id": decision.authority.principal_id,
            "policy_id": decision.policy_id,
            "policy_version": decision.policy_version,
            "policy_sha256": decision.policy_sha256,
            "requested_action_sha256": sha256_json(projection["requested_action"]),
            "requested_action_type": requested["type"],
            "requested_target_id": requested["target"],
            "requested_parameters_sha256": sha256_json(requested["parameters"]),
            "action_type": permitted.get("type") if permitted else None,
            "target_id": permitted.get("target") if permitted else None,
            "parameters_sha256": (
                sha256_json(permitted["parameters"]) if permitted else None
            ),
        }

    def _fail_closed_decision(
        self,
        *,
        decision_id: str,
        request_id: str,
        request_sha256: str,
        principal: AuthenticatedPrincipal,
        reason_code: str,
        additional_reason_codes: tuple[str, ...] = (),
        requested_action: dict[str, Any] | None = None,
        decided_at: datetime | None = None,
    ) -> DecisionRecord:
        now = (
            (decided_at or _fallback_utc_now())
            .astimezone(timezone.utc)
            .replace(microsecond=0)
        )
        reasons = tuple(
            dict.fromkeys(("INVALID_REQUEST", reason_code, *additional_reason_codes))
        )
        authority = AuthorityAssessment(
            authenticated=bool(principal.authenticated),
            principal_id=principal.id,
            claimed_agent_id="",
            attributes_match=False,
            trusted_roles=tuple(sorted(principal.roles)),
            trusted_authority=tuple(sorted(principal.authority)),
            required_authority="unresolved",
            authorized=False,
            reason_codes=(reason_code,),
        )
        context_hash = sha256_json(
            {
                "request_sha256": request_sha256,
                "policy_id": self.policy.policy_id,
                "policy_version": self.policy.version,
                "policy_sha256": self._policy_sha256,
                "outcome": DecisionOutcome.DENY.value,
                "reason_codes": list(reasons),
            }
        )
        return DecisionRecord(
            decision_id=decision_id,
            request_id=request_id,
            decided_at=now.isoformat(),
            policy_id=self.policy.policy_id,
            policy_version=self.policy.version,
            policy_sha256=self._policy_sha256,
            outcome=DecisionOutcome.DENY.value,
            reason_codes=reasons,
            applicable_rules=("P3-FAIL-CLOSED",),
            requested_action=requested_action or {},
            permitted_action=None,
            authority=authority,
            evidence=None,
            consequence=None,
            constraints=(),
            explanation={
                "decision": DecisionOutcome.DENY.value,
                "reason_codes": list(reasons),
                "evidence_assessment": None,
                "applicable_policies": ["P3-FAIL-CLOSED"],
                "agent_authority": authority.to_dict(),
                "target_criticality": "UNRESOLVED",
                "risk_and_consequence": None,
                "conflicting_evidence": None,
                "missing_evidence": [],
                "constraints": [],
                "human_approval_requirement": None,
                "agent_recommendation_is_authoritative": False,
                "agent_confidence_is_authoritative": False,
            },
            request_sha256=request_sha256,
            decision_context_sha256=context_hash,
        )

    def _finish_nonexecuting_result(
        self,
        *,
        audit_start: int,
        intake_id: str,
        decision: DecisionRecord,
        conflict_count: int,
        started: float,
    ) -> Phase3Result:
        latency_ms = round((perf_counter() - started) * 1000.0, 6)
        decision = replace(decision, latency_ms=latency_ms)
        self._append(
            "AUTHORIZATION_NOT_ISSUED",
            intake_id=intake_id,
            request_id=decision.request_id,
            decision_id=decision.decision_id,
            payload={"outcome": decision.outcome},
        )
        self._append(
            "BROKER_SKIPPED",
            intake_id=intake_id,
            request_id=decision.request_id,
            decision_id=decision.decision_id,
            payload={"reason": "Decision did not authorize execution."},
        )
        self._append(
            "ACTION_SKIPPED",
            intake_id=intake_id,
            request_id=decision.request_id,
            decision_id=decision.decision_id,
            payload={"operational_effects": 0},
        )
        self._append(
            "VERIFICATION_SKIPPED",
            intake_id=intake_id,
            request_id=decision.request_id,
            decision_id=decision.decision_id,
            payload={"status": "NOT_APPLICABLE"},
        )
        target_id = decision.requested_action.get("target")
        final_state = None
        if isinstance(target_id, str):
            try:
                final_state = self.observer.observe(target_id)
            except Exception:
                final_state = None
        self._append(
            "FINAL_STATE_RECORDED",
            intake_id=intake_id,
            request_id=decision.request_id,
            decision_id=decision.decision_id,
            payload={
                "outcome": decision.outcome,
                "operational_effects": 0,
                "target_state_sha256": (
                    sha256_json(final_state) if final_state is not None else ""
                ),
            },
        )
        self._metrics.record_decision(
            decision.outcome,
            policy_rules=decision.applicable_rules,
            evidence_conflicts=conflict_count,
            latency_ms=latency_ms,
        )
        return self._validated_result(
            Phase3Result(
                decision=decision,
                authorization=None,
                broker_result=None,
                verification=None,
                final_state=final_state,
                audit_records=self._audit_rows(audit_start),
            )
        )

    def _close_post_effect_accounting_failure(
        self,
        *,
        failed_record_type: str,
        failure: Exception,
        audit_start: int,
        intake_id: str,
        request_id: str,
        decision_id: str,
        decision: DecisionRecord,
        evidence_conflict_count: int,
        started: float,
        token: Any,
        command: dict[str, Any],
        broker_result: Any,
        state_before: dict[str, Any],
        verification: PostActionVerification | None = None,
    ) -> Phase3Result:
        """Close a post-effect path when its ordinary audit record cannot commit.

        The alternate record carries the complete attempt and verification
        projections. It is intentionally conservative: any observed change after
        an accounting-control failure requires rollback review even if the target
        otherwise reached the requested synthetic state.
        """

        if verification is None:
            try:
                verification = self.__target_verifier.verify(
                    request_id=request_id,
                    decision_id=decision_id,
                    broker_result=broker_result,
                    state_before=state_before,
                    token=token,
                    permitted_command=command,
                )
            except Exception:
                try:
                    observed = self.observer.observe(token.target_id)
                    observation_failed = False
                except Exception:
                    observed = {
                        "target_id": token.target_id,
                        "state_unavailable": True,
                    }
                    observation_failed = True
                changed = observation_failed or observed != state_before
                verification = PostActionVerification(
                    verification_id=_deterministic_failure_id(
                        "verify", token.token_id, broker_result.attempt_id
                    ),
                    request_id=token.request_id,
                    decision_id=token.decision_id,
                    attempt_id=broker_result.attempt_id,
                    token_id=token.token_id,
                    action_type=token.action_type,
                    target_id=token.target_id,
                    parameters_sha256=sha256_json(token.permitted_parameters),
                    status=(
                        VerificationStatus.ROLLBACK_REQUIRED.value
                        if changed
                        else VerificationStatus.FAILED.value
                    ),
                    expected_state={
                        "action_type": token.action_type,
                        "target_id": token.target_id,
                        "last_action_id": broker_result.attempt_id,
                    },
                    observed_state=observed,
                    changed_fields=tuple(
                        sorted(
                            key
                            for key in set(state_before) | set(observed)
                            if state_before.get(key) != observed.get(key)
                        )
                    ),
                    unexpected_fields=(),
                    rollback_required=changed,
                    reason_codes=(
                        "POST_EFFECT_VERIFIER_FAILURE",
                        *(
                            ("POST_ACTION_OBSERVATION_FAILED",)
                            if observation_failed
                            else ()
                        ),
                    ),
                )

        final_state = dict(verification.observed_state)
        operational_effects = int(final_state != state_before)
        conservative_status = (
            VerificationStatus.ROLLBACK_REQUIRED.value
            if operational_effects
            else VerificationStatus.FAILED.value
        )
        conservative_reasons = tuple(
            dict.fromkeys(
                (
                    *verification.reason_codes,
                    "POST_EFFECT_ACCOUNTING_FAILURE",
                    failed_record_type,
                    type(failure).__name__,
                    *(("ROLLBACK_REQUIRED",) if operational_effects else ()),
                )
            )
        )
        verification = replace(
            verification,
            status=conservative_status,
            rollback_required=bool(operational_effects),
            reason_codes=conservative_reasons,
        )
        self._metrics.record_verification_failure()
        self._append(
            "POST_EFFECT_ACCOUNTING_FAILURE",
            intake_id=intake_id,
            request_id=request_id,
            decision_id=decision_id,
            payload={
                "failed_record_type": failed_record_type,
                "failure_type": type(failure).__name__,
                "token_id": token.token_id,
                "attempt_id": broker_result.attempt_id,
                "action": broker_result.to_dict(),
                "verification": verification.to_dict(),
                "operational_effects": operational_effects,
            },
        )
        latency_ms = round((perf_counter() - started) * 1000.0, 6)
        decision = replace(decision, latency_ms=latency_ms)
        self._append(
            "FINAL_STATE_RECORDED",
            intake_id=intake_id,
            request_id=request_id,
            decision_id=decision_id,
            payload={
                "outcome": decision.outcome,
                "verification_status": verification.status,
                "operational_effects": operational_effects,
                "target_state_sha256": sha256_json(final_state),
            },
        )
        self._metrics.record_decision(
            decision.outcome,
            policy_rules=decision.applicable_rules,
            evidence_conflicts=evidence_conflict_count,
            latency_ms=latency_ms,
        )
        return self._validated_result(
            Phase3Result(
                decision=decision,
                authorization=token,
                broker_result=broker_result,
                verification=verification,
                final_state=final_state,
                audit_records=self._audit_rows(audit_start),
            )
        )

    def process_json(
        self,
        raw_request: str | bytes,
        *,
        credential: bytes,
    ) -> Phase3Result:
        """Process an untrusted request through a firewall-owned identity boundary."""

        try:
            principal_resolution = self.__principal_resolver.resolve(credential)
            principal = self.__principal_resolver.verify_resolution(
                principal_resolution
            )
        except PrincipalAuthenticationError as exc:
            principal_resolution = None
            principal = AuthenticatedPrincipal.from_dict(
                {
                    "id": "UNRESOLVED_INVOCATION",
                    "type": "UNAUTHENTICATED",
                    "authenticated": False,
                    "roles": [],
                    "authority": [],
                    "security_status": "UNKNOWN",
                    "identity_source": "firewall_trusted_credential_resolver",
                    "authentication_reason_code": exc.reason_code,
                }
            )

        with self._process_lock:
            if (
                sha256_json(Phase3PolicyConfig.to_dict(self._policy))
                != self._policy_sha256
            ):
                raise RuntimeError("Phase 3 policy snapshot integrity changed.")
            metrics_before = self._metrics.snapshot()
            result = self._process_authenticated_json(
                raw_request,
                principal=principal,
                principal_resolution=principal_resolution,
            )
            metrics_after = self._metrics.snapshot()
            if (
                metrics_after["decisions_total"]
                != metrics_before["decisions_total"] + 1
                or metrics_after["decision_counts"].get(result.decision.outcome, 0)
                != metrics_before["decision_counts"].get(result.decision.outcome, 0) + 1
            ):
                raise RuntimeError("Phase 3 decision metrics did not reconcile.")
            return result

    def _process_authenticated_json(
        self,
        raw_request: str | bytes,
        *,
        principal: AuthenticatedPrincipal,
        principal_resolution: ResolvedPrincipal | None,
    ) -> Phase3Result:
        started = perf_counter()
        audit_start = self._audit_start()
        raw_bytes = (
            raw_request.encode("utf-8")
            if isinstance(raw_request, str)
            else (
                bytes(raw_request)
                if isinstance(raw_request, bytes)
                else repr(raw_request).encode("utf-8")
            )
        )
        raw_sha256 = hashlib.sha256(raw_bytes).hexdigest()
        intake_id = f"intake-{raw_sha256[:16]}"
        provisional_request_id = f"invalid-{raw_sha256[:16]}"
        try:
            decision_id = self.id_factory("decision")
            decision_id_failed = type(decision_id) is not str or not decision_id
        except Exception:
            decision_id = _deterministic_failure_id(
                "decision", intake_id, provisional_request_id
            )
            decision_id_failed = True
        self._append(
            "REQUEST_RECEIVED",
            intake_id=intake_id,
            request_id=provisional_request_id,
            decision_id=decision_id,
            payload={"raw_sha256": raw_sha256, "raw_size_bytes": len(raw_bytes)},
        )

        if decision_id_failed:
            self._append(
                "REQUEST_REJECTED",
                intake_id=intake_id,
                request_id=provisional_request_id,
                decision_id=decision_id,
                payload={"reason_code": "DECISION_IDENTIFIER_FAILURE"},
            )
            decision = self._fail_closed_decision(
                decision_id=decision_id,
                request_id=provisional_request_id,
                request_sha256=raw_sha256,
                principal=principal,
                reason_code="DECISION_IDENTIFIER_FAILURE",
                decided_at=_fallback_utc_now(),
            )
            self._append(
                "DECISION_PRODUCED",
                intake_id=intake_id,
                request_id=provisional_request_id,
                decision_id=decision_id,
                payload={
                    "outcome": decision.outcome,
                    "reason_codes": list(decision.reason_codes),
                },
            )
            return self._finish_nonexecuting_result(
                audit_start=audit_start,
                intake_id=intake_id,
                decision=decision,
                conflict_count=0,
                started=started,
            )

        try:
            validation_now = self.clock()
            request = load_decision_request_json(raw_request, now=validation_now)
        except RequestValidationError as exc:
            self._append(
                "REQUEST_REJECTED",
                intake_id=intake_id,
                request_id=provisional_request_id,
                decision_id=decision_id,
                payload={"reason_code": exc.reason_code},
            )
            decision = self._fail_closed_decision(
                decision_id=decision_id,
                request_id=provisional_request_id,
                request_sha256=raw_sha256,
                principal=principal,
                reason_code=exc.reason_code,
            )
            self._append(
                "DECISION_PRODUCED",
                intake_id=intake_id,
                request_id=decision.request_id,
                decision_id=decision_id,
                payload={
                    "outcome": decision.outcome,
                    "reason_codes": list(decision.reason_codes),
                },
            )
            return self._finish_nonexecuting_result(
                audit_start=audit_start,
                intake_id=intake_id,
                decision=decision,
                conflict_count=0,
                started=started,
            )
        except Exception as exc:
            self._append(
                "REQUEST_REJECTED",
                intake_id=intake_id,
                request_id=provisional_request_id,
                decision_id=decision_id,
                payload={
                    "reason_code": "REQUEST_VALIDATION_INTERNAL_FAILURE",
                    "stage": type(exc).__name__,
                },
            )
            decision = self._fail_closed_decision(
                decision_id=decision_id,
                request_id=provisional_request_id,
                request_sha256=raw_sha256,
                principal=principal,
                reason_code="REQUEST_VALIDATION_INTERNAL_FAILURE",
                decided_at=_fallback_utc_now(),
            )
            self._append(
                "DECISION_PRODUCED",
                intake_id=intake_id,
                request_id=provisional_request_id,
                decision_id=decision_id,
                payload={
                    "outcome": decision.outcome,
                    "reason_codes": list(decision.reason_codes),
                },
            )
            return self._finish_nonexecuting_result(
                audit_start=audit_start,
                intake_id=intake_id,
                decision=decision,
                conflict_count=0,
                started=started,
            )

        request_id = request.request_id
        request_sha256 = request.request_sha256()
        now = validation_now.astimezone(timezone.utc)
        self._append(
            "REQUEST_VALIDATED",
            intake_id=intake_id,
            request_id=request_id,
            decision_id=decision_id,
            payload={
                "schema_version": request.schema_version,
                "request_sha256": request_sha256,
                "requested_action_type": request.action.type.value,
                "requested_target_id": request.action.target,
                "requested_parameters_sha256": sha256_json(
                    request.action.parameters.to_dict()
                ),
            },
        )
        if (
            not principal.authenticated
            or principal.security_status != AgentSecurityStatus.TRUSTED
        ):
            reason = principal.authentication_reason_code or (
                "AGENT_NOT_AUTHENTICATED"
                if not principal.authenticated
                else "AGENT_SECURITY_STATUS_INVALID"
            )
            authority = AuthorityAssessment(
                authenticated=principal.authenticated,
                principal_id=principal.id,
                claimed_agent_id=request.agent.id,
                attributes_match=False,
                trusted_roles=tuple(sorted(principal.roles)),
                trusted_authority=tuple(sorted(principal.authority)),
                required_authority="unresolved",
                authorized=False,
                reason_codes=(reason,),
            )
            self._append(
                "IDENTITY_EVALUATED",
                intake_id=intake_id,
                request_id=request_id,
                decision_id=decision_id,
                payload=authority.to_dict(),
            )
            decision = self._fail_closed_decision(
                decision_id=decision_id,
                request_id=request_id,
                request_sha256=request_sha256,
                principal=principal,
                reason_code=reason,
                additional_reason_codes=(
                    "AGENT_NOT_AUTHENTICATED",
                    "AGENT_IDENTITY_MISMATCH",
                ),
                requested_action=request.action.to_dict(),
                decided_at=now,
            )
            self._append(
                "DECISION_PRODUCED",
                intake_id=intake_id,
                request_id=request_id,
                decision_id=decision_id,
                payload={
                    "outcome": decision.outcome,
                    "reason_codes": list(decision.reason_codes),
                    "decision_context_sha256": decision.decision_context_sha256,
                },
            )
            return self._finish_nonexecuting_result(
                audit_start=audit_start,
                intake_id=intake_id,
                decision=decision,
                conflict_count=0,
                started=started,
            )
        principal_claims_match = (
            principal.id == request.agent.id
            and principal.type == request.agent.type
            and set(principal.roles) == set(request.agent.roles)
            and set(principal.authority) == set(request.agent.authority)
            and principal.security_status == request.agent.security_status
            and request.agent.authenticated is True
        )
        if not principal_claims_match:
            authority = AuthorityAssessment(
                authenticated=True,
                principal_id=principal.id,
                claimed_agent_id=request.agent.id,
                attributes_match=False,
                trusted_roles=tuple(sorted(principal.roles)),
                trusted_authority=tuple(sorted(principal.authority)),
                required_authority="unresolved",
                authorized=False,
                reason_codes=("AGENT_ATTRIBUTE_MISMATCH",),
            )
            self._append(
                "IDENTITY_EVALUATED",
                intake_id=intake_id,
                request_id=request_id,
                decision_id=decision_id,
                payload=authority.to_dict(),
            )
            decision = self._fail_closed_decision(
                decision_id=decision_id,
                request_id=request_id,
                request_sha256=request_sha256,
                principal=principal,
                reason_code="AGENT_ATTRIBUTE_MISMATCH",
                requested_action=request.action.to_dict(),
                decided_at=now,
            )
            self._append(
                "DECISION_PRODUCED",
                intake_id=intake_id,
                request_id=request_id,
                decision_id=decision_id,
                payload={
                    "outcome": decision.outcome,
                    "reason_codes": list(decision.reason_codes),
                    "decision_context_sha256": decision.decision_context_sha256,
                },
            )
            return self._finish_nonexecuting_result(
                audit_start=audit_start,
                intake_id=intake_id,
                decision=decision,
                conflict_count=0,
                started=started,
            )
        try:
            request_time = datetime.fromisoformat(
                request.timestamp[:-1] + "+00:00"
                if request.timestamp.endswith("Z")
                else request.timestamp
            ).astimezone(timezone.utc)
            age_seconds = (now - request_time).total_seconds()
        except (TypeError, ValueError, OverflowError):
            age_seconds = MAX_REQUEST_AGE_SECONDS + 1

        preflight_reason = ""
        if age_seconds < -300:
            preflight_reason = "REQUEST_TIMESTAMP_FUTURE"
        elif age_seconds > MAX_REQUEST_AGE_SECONDS:
            preflight_reason = "REQUEST_TIMESTAMP_STALE"

        if preflight_reason:
            self._append(
                "REQUEST_REJECTED",
                intake_id=intake_id,
                request_id=request_id,
                decision_id=decision_id,
                payload={"reason_code": preflight_reason},
            )
            decision = self._fail_closed_decision(
                decision_id=decision_id,
                request_id=request_id,
                request_sha256=request_sha256,
                principal=principal,
                reason_code=preflight_reason,
                requested_action=request.action.to_dict(),
                decided_at=now,
            )
            self._append(
                "DECISION_PRODUCED",
                intake_id=intake_id,
                request_id=request_id,
                decision_id=decision_id,
                payload={
                    "outcome": decision.outcome,
                    "reason_codes": list(decision.reason_codes),
                },
            )
            return self._finish_nonexecuting_result(
                audit_start=audit_start,
                intake_id=intake_id,
                decision=decision,
                conflict_count=0,
                started=started,
            )

        try:
            target = self.policy.target_record(request.action.target)
            action_policy = self.policy.action_policy(request.action.type)
        except (KeyError, ValueError):
            self._append(
                "POLICY_EVALUATION_FAILED",
                intake_id=intake_id,
                request_id=request_id,
                decision_id=decision_id,
                payload={"reason_code": "TARGET_OR_ACTION_UNKNOWN"},
            )
            decision = self._fail_closed_decision(
                decision_id=decision_id,
                request_id=request_id,
                request_sha256=request_sha256,
                principal=principal,
                reason_code="TARGET_OR_ACTION_UNKNOWN",
                requested_action=request.action.to_dict(),
                decided_at=now,
            )
            self._append(
                "DECISION_PRODUCED",
                intake_id=intake_id,
                request_id=request_id,
                decision_id=decision_id,
                payload={
                    "outcome": decision.outcome,
                    "reason_codes": list(decision.reason_codes),
                },
            )
            return self._finish_nonexecuting_result(
                audit_start=audit_start,
                intake_id=intake_id,
                decision=decision,
                conflict_count=0,
                started=started,
            )

        ledger_state = self._request_ledger.claim(
            principal.id, request_id, request_sha256
        )
        if ledger_state != "NEW":
            preflight_reason = (
                "DUPLICATE_REQUEST"
                if ledger_state == "DUPLICATE"
                else "REQUEST_ID_CONFLICT"
            )
            self._append(
                "REQUEST_REJECTED",
                intake_id=intake_id,
                request_id=request_id,
                decision_id=decision_id,
                payload={"reason_code": preflight_reason},
            )
            decision = self._fail_closed_decision(
                decision_id=decision_id,
                request_id=request_id,
                request_sha256=request_sha256,
                principal=principal,
                reason_code=preflight_reason,
                requested_action=request.action.to_dict(),
                decided_at=now,
            )
            self._append(
                "DECISION_PRODUCED",
                intake_id=intake_id,
                request_id=request_id,
                decision_id=decision_id,
                payload={
                    "outcome": decision.outcome,
                    "reason_codes": list(decision.reason_codes),
                },
            )
            return self._finish_nonexecuting_result(
                audit_start=audit_start,
                intake_id=intake_id,
                decision=decision,
                conflict_count=0,
                started=started,
            )

        required_authority = (
            action_policy.tier_0_required_authority
            if target.criticality == "TIER_0"
            else action_policy.required_authority
        )
        authority = assess_authority(
            request, principal, required_authority=required_authority
        )
        self._append(
            "IDENTITY_EVALUATED",
            intake_id=intake_id,
            request_id=request_id,
            decision_id=decision_id,
            payload=authority.to_dict(),
        )

        try:
            evidence = assess_evidence(
                request,
                evidence_policy=self.policy.evidence,
                attestation_verifier=self.__evidence_attestation_verifier,
                evaluated_at=now,
            )
            self._append(
                "EVIDENCE_EVALUATED",
                intake_id=intake_id,
                request_id=request_id,
                decision_id=decision_id,
                payload=evidence.to_dict(),
            )
            consequence = assess_consequence(
                target=target,
                action_policy=action_policy,
                consequence_policy=self.policy.consequence,
                parameters=request.action.parameters.to_dict(),
            )
            self._append(
                "CONSEQUENCE_EVALUATED",
                intake_id=intake_id,
                request_id=request_id,
                decision_id=decision_id,
                payload=consequence.to_dict(),
            )
            decision = build_decision(
                request=request,
                principal=principal,
                policy=self.policy,
                evidence=evidence,
                consequence=consequence,
                target=target,
                action_policy=action_policy,
                decided_at=now,
                decision_id=decision_id,
                approval_requirement_factory=self.__approval_gate.issue_requirement,
            )
        except Exception as exc:
            self._append(
                "CONTROL_PLANE_FAILURE",
                intake_id=intake_id,
                request_id=request_id,
                decision_id=decision_id,
                payload={
                    "reason_code": "INTERNAL_CONTROL_FAILURE",
                    "stage": type(exc).__name__,
                },
            )
            decision = self._fail_closed_decision(
                decision_id=decision_id,
                request_id=request_id,
                request_sha256=request_sha256,
                principal=principal,
                reason_code="INTERNAL_CONTROL_FAILURE",
                requested_action=request.action.to_dict(),
                decided_at=now,
            )
            self._append(
                "DECISION_PRODUCED",
                intake_id=intake_id,
                request_id=request_id,
                decision_id=decision_id,
                payload={
                    "outcome": decision.outcome,
                    "reason_codes": list(decision.reason_codes),
                },
            )
            return self._finish_nonexecuting_result(
                audit_start=audit_start,
                intake_id=intake_id,
                decision=decision,
                conflict_count=0,
                started=started,
            )

        self._append(
            "POLICY_EVALUATED",
            intake_id=intake_id,
            request_id=request_id,
            decision_id=decision_id,
            payload={
                "policy_id": decision.policy_id,
                "policy_version": decision.policy_version,
                "policy_sha256": decision.policy_sha256,
                "outcome": decision.outcome,
                "applicable_rules": list(decision.applicable_rules),
                "reason_codes": list(decision.reason_codes),
            },
        )
        try:
            decision_verification = self.__decision_verifier.verify(
                request=request,
                principal=principal,
                principal_resolution=principal_resolution,
                policy=self.policy,
                target=target,
                decision=decision,
                evaluated_at=now,
            )
        except Exception as exc:
            self._append(
                "CONTROL_PLANE_FAILURE",
                intake_id=intake_id,
                request_id=request_id,
                decision_id=decision_id,
                payload={
                    "reason_code": "DECISION_VERIFIER_INTERNAL_FAILURE",
                    "stage": type(exc).__name__,
                },
            )
            decision = self._fail_closed_decision(
                decision_id=decision_id,
                request_id=request_id,
                request_sha256=request_sha256,
                principal=principal,
                reason_code="DECISION_VERIFIER_INTERNAL_FAILURE",
                requested_action=request.action.to_dict(),
                decided_at=now,
            )
            self._append(
                "DECISION_PRODUCED",
                intake_id=intake_id,
                request_id=request_id,
                decision_id=decision_id,
                payload={
                    "outcome": decision.outcome,
                    "reason_codes": list(decision.reason_codes),
                    "decision_context_sha256": decision.decision_context_sha256,
                },
            )
            return self._finish_nonexecuting_result(
                audit_start=audit_start,
                intake_id=intake_id,
                decision=decision,
                conflict_count=evidence.conflict_count,
                started=started,
            )
        self._append(
            "DECISION_VERIFIED",
            intake_id=intake_id,
            request_id=request_id,
            decision_id=decision_id,
            payload=decision_verification.to_dict(),
        )
        if not decision_verification.passed:
            explanation = dict(decision.explanation)
            reason_codes = tuple(
                list(decision.reason_codes) + ["DECISION_VERIFIER_FAILED"]
            )
            explanation.update(
                {
                    "decision": DecisionOutcome.DENY.value,
                    "reason_codes": list(reason_codes),
                    "verifier_blockers": list(
                        decision_verification.blocking_reason_codes
                    ),
                    "human_approval_requirement": None,
                }
            )
            decision = replace(
                decision,
                outcome=DecisionOutcome.DENY.value,
                reason_codes=reason_codes,
                applicable_rules=tuple(
                    list(decision.applicable_rules) + ["P3-FAIL-CLOSED-VERIFIER"]
                ),
                permitted_action=None,
                constraints=(),
                approval_requirement=None,
                explanation=explanation,
                decision_context_sha256=sha256_json(
                    {
                        "prior_context": decision.decision_context_sha256,
                        "outcome": DecisionOutcome.DENY.value,
                        "reason_codes": list(reason_codes),
                    }
                ),
            )

        if decision.outcome not in {
            DecisionOutcome.ALLOW.value,
            DecisionOutcome.ALLOW_CONSTRAINED.value,
        }:
            self._append(
                "DECISION_PRODUCED",
                intake_id=intake_id,
                request_id=request_id,
                decision_id=decision_id,
                payload=self._decision_audit_payload(decision),
            )
            if decision.approval_requirement is not None:
                self._append(
                    "APPROVAL_REQUIREMENT_PRODUCED",
                    intake_id=intake_id,
                    request_id=request_id,
                    decision_id=decision_id,
                    payload={
                        "approval_id": decision.approval_requirement.approval_id,
                        "issuer_instance_id": (
                            decision.approval_requirement.issuer_instance_id
                        ),
                        "request_id_bound": decision.approval_requirement.request_id,
                        "decision_id_bound": decision.approval_requirement.decision_id,
                        "decision_context_sha256": (
                            decision.approval_requirement.decision_context_sha256
                        ),
                        "policy_id": decision.approval_requirement.policy_id,
                        "policy_version": decision.approval_requirement.policy_version,
                        "policy_sha256": decision.approval_requirement.policy_sha256,
                        "action_type": decision.approval_requirement.action_type,
                        "target_id": decision.approval_requirement.target_id,
                        "parameters_sha256": (
                            decision.approval_requirement.parameters_sha256
                        ),
                        "evidence_sha256": (
                            decision.approval_requirement.evidence_sha256
                        ),
                        "reason_codes": list(
                            decision.approval_requirement.reason_codes
                        ),
                        "scope_sha256": decision.approval_requirement.scope_sha256,
                        "created_at": decision.approval_requirement.created_at,
                        "expires_at": decision.approval_requirement.expires_at,
                        "status": decision.approval_requirement.status,
                        "required_approving_authority": (
                            decision.approval_requirement.required_approving_authority
                        ),
                    },
                )
            return self._finish_nonexecuting_result(
                audit_start=audit_start,
                intake_id=intake_id,
                decision=decision,
                conflict_count=evidence.conflict_count,
                started=started,
            )

        try:
            state_before = self.observer.observe(target.id)
            token = self.__authorization_gate.issue(
                decision=decision,
                agent_id=principal.id,
                target_state_sha256=sha256_json(state_before),
                decision_verification=decision_verification,
            )
        except Exception as exc:
            self._append(
                "CONTROL_PLANE_FAILURE",
                intake_id=intake_id,
                request_id=request_id,
                decision_id=decision_id,
                payload={
                    "reason_code": "AUTHORIZATION_PRECONDITION_FAILURE",
                    "stage": type(exc).__name__,
                },
            )
            decision = self._fail_closed_decision(
                decision_id=decision_id,
                request_id=request_id,
                request_sha256=request_sha256,
                principal=principal,
                reason_code="AUTHORIZATION_PRECONDITION_FAILURE",
                requested_action=request.action.to_dict(),
                decided_at=now,
            )
            self._append(
                "DECISION_PRODUCED",
                intake_id=intake_id,
                request_id=request_id,
                decision_id=decision_id,
                payload={
                    "outcome": decision.outcome,
                    "reason_codes": list(decision.reason_codes),
                    "decision_context_sha256": decision.decision_context_sha256,
                },
            )
            return self._finish_nonexecuting_result(
                audit_start=audit_start,
                intake_id=intake_id,
                decision=decision,
                conflict_count=evidence.conflict_count,
                started=started,
            )

        self._append(
            "DECISION_PRODUCED",
            intake_id=intake_id,
            request_id=request_id,
            decision_id=decision_id,
            payload=self._decision_audit_payload(decision),
        )
        self._append(
            "AUTHORIZATION_PRODUCED",
            intake_id=intake_id,
            request_id=request_id,
            decision_id=decision_id,
            payload={
                "token_id": token.token_id,
                "agent_id": token.agent_id,
                "action_type": token.action_type,
                "target_id": token.target_id,
                "permitted_parameters": token.permitted_parameters,
                "parameters_sha256": sha256_json(token.permitted_parameters),
                "issued_at": token.issued_at,
                "expires_at": token.expires_at,
                "policy_id": token.policy_id,
                "policy_version": token.policy_version,
                "policy_sha256": token.policy_sha256,
                "decision_context_sha256": token.decision_context_sha256,
                "decision_sha256": decision_verification.decision_sha256,
                "request_sha256": decision_verification.request_sha256,
                "target_state_sha256": token.target_state_sha256,
            },
        )
        command = decision.to_dict()["permitted_action"] or {}
        self._append(
            "BROKER_INVOKED",
            intake_id=intake_id,
            request_id=request_id,
            decision_id=decision_id,
            payload={
                "token_id": token.token_id,
                "action_type": command.get("type"),
                "target_id": command.get("target"),
                "parameters_sha256": sha256_json(command.get("parameters", {})),
            },
        )
        try:
            broker_result = self.__broker.execute(
                token=token,
                command=command,
                request_id=request_id,
                decision_id=decision_id,
                agent_id=principal.id,
                policy_id=self.policy.policy_id,
                policy_version=self.policy.version,
                policy_sha256=self._policy_sha256,
                decision_context_sha256=decision.decision_context_sha256,
            )
        except AuthorizationError as exc:
            self._append(
                "BROKER_REJECTED",
                intake_id=intake_id,
                request_id=request_id,
                decision_id=decision_id,
                payload={"token_id": token.token_id, "reason_code": exc.reason_code},
            )
            self._append(
                "ACTION_SKIPPED",
                intake_id=intake_id,
                request_id=request_id,
                decision_id=decision_id,
                payload={"operational_effects": 0, "reason_code": exc.reason_code},
            )
            self._append(
                "VERIFICATION_SKIPPED",
                intake_id=intake_id,
                request_id=request_id,
                decision_id=decision_id,
                payload={"status": "NOT_APPLICABLE", "reason_code": exc.reason_code},
            )
            # The closed broker authorizes before mutation, so an authorization
            # rejection cannot have changed the target. Reuse the trusted
            # pre-state rather than introducing another fallible dependency.
            final_state = state_before
            latency_ms = round((perf_counter() - started) * 1000.0, 6)
            decision = replace(decision, latency_ms=latency_ms)
            self._append(
                "FINAL_STATE_RECORDED",
                intake_id=intake_id,
                request_id=request_id,
                decision_id=decision_id,
                payload={
                    "outcome": decision.outcome,
                    "operational_effects": 0,
                    "target_state_sha256": sha256_json(final_state),
                },
            )
            self._metrics.record_decision(
                decision.outcome,
                policy_rules=decision.applicable_rules,
                evidence_conflicts=evidence.conflict_count,
                latency_ms=latency_ms,
            )
            return self._validated_result(
                Phase3Result(
                    decision=decision,
                    authorization=token,
                    broker_result=None,
                    verification=None,
                    final_state=final_state,
                    audit_records=self._audit_rows(audit_start),
                )
            )
        except Exception as exc:
            try:
                final_state = self.observer.observe(target.id)
                observation_failed = False
            except Exception:
                final_state = {
                    "target_id": token.target_id,
                    "state_unavailable": True,
                }
                observation_failed = True
            operational_effects = int(observation_failed or final_state != state_before)
            status = (
                VerificationStatus.ROLLBACK_REQUIRED.value
                if operational_effects
                else VerificationStatus.FAILED.value
            )
            attempt_id = _deterministic_failure_id(
                "failed-attempt", token.token_id, request_id, decision_id
            )
            verification = PostActionVerification(
                verification_id=_deterministic_failure_id(
                    "verify", token.token_id, attempt_id
                ),
                request_id=request_id,
                decision_id=decision_id,
                attempt_id=attempt_id,
                token_id=token.token_id,
                action_type=token.action_type,
                target_id=token.target_id,
                parameters_sha256=sha256_json(token.permitted_parameters),
                status=status,
                expected_state={
                    "action_type": token.action_type,
                    "target_id": token.target_id,
                    "last_action_id": attempt_id,
                },
                observed_state=final_state,
                changed_fields=tuple(
                    sorted(
                        key
                        for key in set(state_before) | set(final_state)
                        if state_before.get(key) != final_state.get(key)
                    )
                ),
                unexpected_fields=(),
                rollback_required=bool(operational_effects),
                reason_codes=(
                    "BROKER_INTERNAL_FAILURE",
                    *(
                        ("POST_ACTION_OBSERVATION_FAILED",)
                        if observation_failed
                        else ()
                    ),
                    *(("ROLLBACK_REQUIRED",) if operational_effects else ()),
                ),
            )
            self._metrics.record_broker_rejection()
            self._metrics.record_verification_failure()
            self._append(
                "BROKER_FAILURE",
                intake_id=intake_id,
                request_id=request_id,
                decision_id=decision_id,
                payload={
                    "token_id": token.token_id,
                    "reason_code": "BROKER_INTERNAL_FAILURE",
                    "stage": type(exc).__name__,
                },
            )
            self._append(
                "ACTION_ATTEMPTED",
                intake_id=intake_id,
                request_id=request_id,
                decision_id=decision_id,
                payload={
                    "attempt_id": attempt_id,
                    "token_id": token.token_id,
                    "outcome_known": False,
                    "operational_effects": operational_effects,
                },
            )
            self._append(
                "VERIFICATION_PERFORMED",
                intake_id=intake_id,
                request_id=request_id,
                decision_id=decision_id,
                payload=verification.to_dict(),
            )
            latency_ms = round((perf_counter() - started) * 1000.0, 6)
            decision = replace(decision, latency_ms=latency_ms)
            self._append(
                "FINAL_STATE_RECORDED",
                intake_id=intake_id,
                request_id=request_id,
                decision_id=decision_id,
                payload={
                    "outcome": decision.outcome,
                    "verification_status": status,
                    "operational_effects": operational_effects,
                    "target_state_sha256": sha256_json(final_state),
                },
            )
            self._metrics.record_decision(
                decision.outcome,
                policy_rules=decision.applicable_rules,
                evidence_conflicts=evidence.conflict_count,
                latency_ms=latency_ms,
            )
            return self._validated_result(
                Phase3Result(
                    decision=decision,
                    authorization=token,
                    broker_result=None,
                    verification=verification,
                    final_state=final_state,
                    audit_records=self._audit_rows(audit_start),
                )
            )

        try:
            self._append(
                "ACTION_ATTEMPTED",
                intake_id=intake_id,
                request_id=request_id,
                decision_id=decision_id,
                payload=broker_result.to_dict(),
            )
        except Exception as exc:
            return self._close_post_effect_accounting_failure(
                failed_record_type="ACTION_ATTEMPTED",
                failure=exc,
                audit_start=audit_start,
                intake_id=intake_id,
                request_id=request_id,
                decision_id=decision_id,
                decision=decision,
                evidence_conflict_count=evidence.conflict_count,
                started=started,
                token=token,
                command=command,
                broker_result=broker_result,
                state_before=state_before,
            )
        try:
            verification = self.__target_verifier.verify(
                request_id=request_id,
                decision_id=decision_id,
                broker_result=broker_result,
                state_before=state_before,
                token=token,
                permitted_command=command,
            )
        except Exception as exc:
            try:
                observed_after_failure = self.observer.observe(token.target_id)
                observation_failed = False
            except Exception:
                observed_after_failure = {
                    "target_id": token.target_id,
                    "state_unavailable": True,
                }
                observation_failed = True
            state_changed = observation_failed or observed_after_failure != state_before
            self._metrics.record_verification_failure()
            verification = PostActionVerification(
                verification_id=_deterministic_failure_id(
                    "verify", token.token_id, broker_result.attempt_id
                ),
                request_id=token.request_id,
                decision_id=token.decision_id,
                attempt_id=broker_result.attempt_id,
                token_id=token.token_id,
                action_type=token.action_type,
                target_id=token.target_id,
                parameters_sha256=sha256_json(token.permitted_parameters),
                status=(
                    VerificationStatus.ROLLBACK_REQUIRED.value
                    if state_changed
                    else VerificationStatus.FAILED.value
                ),
                expected_state={
                    "action_type": token.action_type,
                    "target_id": token.target_id,
                    "last_action_id": broker_result.attempt_id,
                },
                observed_state=observed_after_failure,
                changed_fields=tuple(
                    sorted(
                        key
                        for key in set(state_before) | set(observed_after_failure)
                        if state_before.get(key) != observed_after_failure.get(key)
                    )
                ),
                unexpected_fields=(),
                rollback_required=state_changed,
                reason_codes=(
                    "VERIFIER_INTERNAL_FAILURE",
                    type(exc).__name__,
                    *(
                        ("POST_ACTION_OBSERVATION_FAILED",)
                        if observation_failed
                        else ()
                    ),
                    *(("ROLLBACK_REQUIRED",) if state_changed else ()),
                ),
            )
        try:
            self._append(
                "VERIFICATION_PERFORMED",
                intake_id=intake_id,
                request_id=request_id,
                decision_id=decision_id,
                payload=verification.to_dict(),
            )
        except Exception as exc:
            return self._close_post_effect_accounting_failure(
                failed_record_type="VERIFICATION_PERFORMED",
                failure=exc,
                audit_start=audit_start,
                intake_id=intake_id,
                request_id=request_id,
                decision_id=decision_id,
                decision=decision,
                evidence_conflict_count=evidence.conflict_count,
                started=started,
                token=token,
                command=command,
                broker_result=broker_result,
                state_before=state_before,
                verification=verification,
            )
        final_state = dict(verification.observed_state)
        operational_effects = int(final_state != state_before)
        latency_ms = round((perf_counter() - started) * 1000.0, 6)
        decision = replace(decision, latency_ms=latency_ms)
        try:
            self._append(
                "FINAL_STATE_RECORDED",
                intake_id=intake_id,
                request_id=request_id,
                decision_id=decision_id,
                payload={
                    "outcome": decision.outcome,
                    "verification_status": verification.status,
                    "operational_effects": operational_effects,
                    "target_state_sha256": sha256_json(final_state),
                },
            )
        except Exception as exc:
            return self._close_post_effect_accounting_failure(
                failed_record_type="FINAL_STATE_RECORDED",
                failure=exc,
                audit_start=audit_start,
                intake_id=intake_id,
                request_id=request_id,
                decision_id=decision_id,
                decision=decision,
                evidence_conflict_count=evidence.conflict_count,
                started=started,
                token=token,
                command=command,
                broker_result=broker_result,
                state_before=state_before,
                verification=verification,
            )
        self._metrics.record_decision(
            decision.outcome,
            policy_rules=decision.applicable_rules,
            evidence_conflicts=evidence.conflict_count,
            latency_ms=latency_ms,
        )
        return self._validated_result(
            Phase3Result(
                decision=decision,
                authorization=token,
                broker_result=broker_result,
                verification=verification,
                final_state=final_state,
                audit_records=self._audit_rows(audit_start),
            )
        )

    def metrics_snapshot(self) -> dict[str, Any]:
        return self._metrics.snapshot()

    def read_audit(self) -> tuple[dict[str, Any], ...]:
        return tuple(self._audit.read_all())

    def approve_for_reevaluation(
        self,
        *,
        requirement: ApprovalRequirement,
        credential: bytes,
        action_type: str,
        target_id: str,
        parameters: dict[str, Any],
        evidence_sha256: str,
    ) -> ApprovalReceipt:
        """Record exact human approval for later reevaluation; never execute."""

        with self._process_lock:
            matching_rows = [
                row
                for row in self._audit.read_all()
                if row.get("payload", {}).get("decision_id") == requirement.decision_id
            ]
            intake_id = (
                str(matching_rows[-1]["payload"]["intake_id"])
                if matching_rows
                else f"approval-{requirement.request_id}"
            )

            def commit_receipt(receipt: ApprovalReceipt) -> None:
                receipt_payload = {
                    "approval_id": requirement.approval_id,
                    "receipt_id": receipt.receipt_id,
                    "issuer_instance_id": receipt.issuer_instance_id,
                    "approver_id": receipt.approver_id,
                    "approving_authority": receipt.approving_authority,
                    "action_type": receipt.action_type,
                    "target_id": receipt.target_id,
                    "parameters_sha256": receipt.parameters_sha256,
                    "evidence_sha256": receipt.evidence_sha256,
                    "requirement_scope_sha256": (receipt.requirement_scope_sha256),
                    "status": receipt.status,
                    "approved_at": receipt.approved_at,
                    "reevaluation_required": True,
                    "authorization_produced": False,
                }
                existing = [
                    row
                    for row in self._audit.read_all()
                    if row.get("record_type") == "APPROVAL_RECORDED"
                    and row.get("payload", {}).get("approval_id")
                    == requirement.approval_id
                ]
                expected_full_payload = {
                    "intake_id": intake_id,
                    "request_id": requirement.request_id,
                    "decision_id": requirement.decision_id,
                    **receipt_payload,
                }
                if existing:
                    if len(existing) == 1 and canonical_json(
                        existing[0].get("payload")
                    ) == canonical_json(expected_full_payload):
                        return
                    raise ApprovalError(
                        "APPROVAL_AUDIT_CONFLICT",
                        "Approval audit already contains a conflicting receipt.",
                    )
                self._append(
                    "APPROVAL_RECORDED",
                    intake_id=intake_id,
                    request_id=requirement.request_id,
                    decision_id=requirement.decision_id,
                    payload=receipt_payload,
                )

            receipt = self.__approval_gate.approve(
                requirement=requirement,
                credential=credential,
                action_type=action_type,
                target_id=target_id,
                parameters=parameters,
                evidence_sha256=evidence_sha256,
                commit_receipt=commit_receipt,
            )
            return receipt
