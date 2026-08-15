from __future__ import annotations

import hashlib
import hmac
import uuid
from datetime import datetime, timezone
from typing import Any, Callable

from adf_poc.utils import canonical_json, sha256_json

from .approval import ApprovalError, HumanApprovalGate
from .attestation import EvidenceAttestationVerifier
from .config import Phase3PolicyConfig, TargetRecord
from .contracts import (
    AuthenticatedPrincipal,
    DecisionRequest,
    validate_decision_request_dict,
)
from .consequence import assess_consequence
from .decision import build_decision
from .evidence import assess_evidence
from .identity import ResolvedPrincipal, TrustedPrincipalResolver
from .models import DecisionRecord, DecisionVerification


class IndependentDecisionVerifier:
    """Functionally separate deterministic pre-authorization verifier.

    This is same-process, same-project assurance. It is not an external oracle
    or organizationally independent approval authority.
    """

    def __init__(
        self,
        *,
        signing_key: bytes,
        attestation_verifier: EvidenceAttestationVerifier,
        approval_gate: HumanApprovalGate,
        principal_resolver: TrustedPrincipalResolver,
        clock: Callable[[], datetime] | None = None,
        id_factory: Callable[[str], str] | None = None,
        verifier_instance_id: str | None = None,
    ) -> None:
        if len(signing_key) < 32:
            raise ValueError("Decision-verifier signing key must be at least 32 bytes.")
        self.__signing_key = bytes(signing_key)
        self.__attestation_verifier = attestation_verifier
        self.__approval_gate = approval_gate
        if type(principal_resolver) is not TrustedPrincipalResolver:
            raise TypeError("Decision verifier requires a trusted-principal resolver.")
        self.__principal_resolver = principal_resolver.immutable_snapshot()
        self.__clock = clock or (lambda: datetime.now(timezone.utc))
        self.__id_factory = id_factory or (lambda prefix: f"{prefix}-{uuid.uuid4()}")
        self.__verifier_instance_id = verifier_instance_id or f"verifier-{uuid.uuid4()}"

    @property
    def verifier_instance_id(self) -> str:
        return self.__verifier_instance_id

    def _sign(self, value: dict[str, Any]) -> str:
        return hmac.new(
            self.__signing_key,
            canonical_json(value).encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()

    def verify(
        self,
        *,
        request: DecisionRequest,
        principal: AuthenticatedPrincipal,
        principal_resolution: ResolvedPrincipal,
        policy: Phase3PolicyConfig,
        target: TargetRecord,
        decision: DecisionRecord,
        evaluated_at: datetime,
    ) -> DecisionVerification:
        if type(decision) is not DecisionRecord:
            raise TypeError(
                "Decision verifier requires an exact immutable DecisionRecord."
            )
        if (
            type(request) is not DecisionRequest
            or type(principal) is not AuthenticatedPrincipal
        ):
            raise TypeError("Decision verifier inputs must use exact validated types.")
        if type(policy) is not Phase3PolicyConfig or type(target) is not TargetRecord:
            raise TypeError("Decision verifier policy and target types are invalid.")
        # Revalidate and reconstruct one detached plain-data request projection.
        # This prevents scalar subclasses or caller-owned mutable containers from
        # influencing semantic comparisons in the public verifier API.
        request = validate_decision_request_dict(
            DecisionRequest.to_dict(request), now=evaluated_at
        )
        checks: list[dict[str, Any]] = []
        blockers: list[str] = []

        def check(name: str, passed: bool, detail: str) -> None:
            row = {"check": name, "passed": bool(passed), "detail": detail}
            checks.append(row)
            if not passed:
                blockers.append(name)

        try:
            resolved_principal = self.__principal_resolver.verify_resolution(
                principal_resolution
            )
            resolution_valid = resolved_principal == principal
        except Exception:
            resolved_principal = principal
            resolution_valid = False
        principal = resolved_principal
        trusted_target = policy.target_inventory[request.action.target]
        supplied_target_matches = (
            type(target) is TargetRecord and target == trusted_target
        )
        target = trusted_target
        action_policy = policy.action_catalog[request.action.type.value]
        evaluated_at = evaluated_at.astimezone(timezone.utc).replace(microsecond=0)
        request_time = datetime.fromisoformat(
            request.timestamp[:-1] + "+00:00"
            if request.timestamp.endswith("Z")
            else request.timestamp
        ).astimezone(timezone.utc)
        verifier_now = self.__clock().astimezone(timezone.utc)
        chronology_valid = (
            request_time <= evaluated_at
            and abs((verifier_now - evaluated_at).total_seconds()) <= 5.0
            and decision.decided_at == evaluated_at.isoformat()
        )
        expected_evidence = assess_evidence(
            request,
            evidence_policy=policy.evidence,
            attestation_verifier=self.__attestation_verifier,
            evaluated_at=evaluated_at,
        )
        expected_consequence = assess_consequence(
            target=target,
            action_policy=action_policy,
            consequence_policy=policy.consequence,
            parameters=request.action.parameters.to_dict(),
        )
        expected = build_decision(
            request=request,
            principal=principal,
            policy=policy,
            evidence=expected_evidence,
            consequence=expected_consequence,
            target=target,
            action_policy=action_policy,
            decided_at=evaluated_at,
            decision_id=decision.decision_id,
            approval_requirement_factory=lambda **_: decision.approval_requirement,
        )
        check(
            "P3-VERIFY-REQUEST-BINDING",
            chronology_valid
            and decision.request_id == request.request_id
            and decision.request_sha256 == request.request_sha256(),
            "Decision must bind the exact validated request.",
        )
        check(
            "P3-VERIFY-POLICY-BINDING",
            type(policy) is Phase3PolicyConfig
            and decision.policy_id == policy.policy_id
            and decision.policy_version == policy.version
            and decision.policy_sha256
            == sha256_json(Phase3PolicyConfig.to_dict(policy)),
            "Decision must bind the loaded policy identity and version.",
        )
        check(
            "P3-VERIFY-PRINCIPAL-BINDING",
            resolution_valid and decision.authority == expected.authority,
            "Decision authority must be independently recomputed from the trusted principal.",
        )
        check(
            "P3-VERIFY-TARGET-BINDING",
            supplied_target_matches
            and decision.requested_action.get("target") == request.action.target
            and request.action.target == target.id,
            "Requested action and trusted target must agree.",
        )
        check(
            "P3-VERIFY-EVIDENCE-RECOMPUTATION",
            decision.evidence == expected_evidence,
            "Evidence must match the separately recomputed assessment.",
        )
        check(
            "P3-VERIFY-CONSEQUENCE-RECOMPUTATION",
            decision.consequence == expected_consequence,
            "Consequence must match the separately recomputed assessment.",
        )
        core_fields = (
            "outcome",
            "reason_codes",
            "applicable_rules",
            "requested_action",
            "permitted_action",
            "constraints",
            "request_sha256",
            "decision_context_sha256",
        )
        check(
            "P3-VERIFY-DECISION-RECOMPUTATION",
            all(
                getattr(decision, name) == getattr(expected, name)
                for name in core_fields
            ),
            "Outcome, rules, command, constraints, and context digest must be recomputed.",
        )

        approval_valid = decision.approval_requirement is None
        if decision.approval_requirement is not None:
            approval = decision.approval_requirement
            try:
                self.__approval_gate.verify_requirement(approval, check_time=False)
                approval_valid = (
                    decision.outcome == "ESCALATE"
                    and approval.request_id == request.request_id
                    and approval.decision_id == decision.decision_id
                    and approval.decision_context_sha256
                    == decision.decision_context_sha256
                    and approval.policy_sha256 == decision.policy_sha256
                    and approval.policy_id == decision.policy_id
                    and approval.policy_version == decision.policy_version
                    and approval.action_type == request.action.type.value
                    and approval.target_id == target.id
                    and approval.parameters_sha256
                    == sha256_json(request.action.parameters.to_dict())
                    and approval.evidence_sha256
                    == sha256_json([item.to_dict() for item in request.evidence])
                    and approval.required_approving_authority
                    == expected.authority.required_authority
                    and tuple(approval.reason_codes) == tuple(expected.reason_codes)
                )
            except ApprovalError:
                approval_valid = False
        check(
            "P3-VERIFY-APPROVAL-ORIGIN",
            approval_valid
            and (
                (decision.outcome == "ESCALATE")
                == (decision.approval_requirement is not None)
            ),
            "Escalation approval must be signed, registered, and exactly decision-bound.",
        )

        verified_at = self.__clock().astimezone(timezone.utc).replace(microsecond=0)
        unsigned = {
            "verification_id": self.__id_factory("decision-verification"),
            "verifier_instance_id": self.__verifier_instance_id,
            "decision_id": decision.decision_id,
            "decision_context_sha256": decision.decision_context_sha256,
            "decision_sha256": DecisionRecord.authorization_sha256(decision),
            "request_sha256": request.request_sha256(),
            "principal_id": principal.id,
            "principal_resolution_sha256": sha256_json(
                principal_resolution.to_dict()
                if type(principal_resolution) is ResolvedPrincipal
                else {"invalid": True}
            ),
            "policy_sha256": sha256_json(Phase3PolicyConfig.to_dict(policy)),
            "passed": not blockers,
            "checks": tuple(checks),
            "blocking_reason_codes": tuple(blockers),
            "verified_at": verified_at.isoformat(),
        }
        return DecisionVerification(**unsigned, signature=self._sign(unsigned))
