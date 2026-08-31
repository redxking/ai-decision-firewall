from __future__ import annotations

from dataclasses import asdict, dataclass, field
from enum import Enum
import math
from types import MappingProxyType
from typing import Any, Mapping

from adf_poc.utils import sha256_json


_MAPPING_PROXY_TYPE = type(MappingProxyType({}))


def _deep_freeze(value: Any, *, path: str = "$") -> Any:
    """Copy exact JSON primitives into an immutable, non-polymorphic tree."""

    if type(value) in (dict, _MAPPING_PROXY_TYPE):
        frozen: dict[str, Any] = {}
        for key, child in value.items():
            if type(key) is not str:
                raise TypeError(f"{path} keys must be exact strings.")
            frozen[key] = _deep_freeze(child, path=f"{path}.{key}")
        return MappingProxyType(frozen)
    if type(value) in (list, tuple):
        return tuple(
            _deep_freeze(child, path=f"{path}[{index}]")
            for index, child in enumerate(value)
        )
    if value is None or type(value) in (str, bool, int):
        return value
    if type(value) is float and math.isfinite(value):
        return value
    raise TypeError(f"{path} contains a non-JSON or polymorphic scalar value.")


def _deep_thaw(value: Any) -> Any:
    if type(value) is _MAPPING_PROXY_TYPE:
        return {key: _deep_thaw(child) for key, child in value.items()}
    if type(value) is tuple:
        return [_deep_thaw(child) for child in value]
    if value is None or type(value) in (str, bool, int, float):
        return value
    raise TypeError("Immutable decision projection contains an invalid value.")


class DecisionOutcome(str, Enum):
    ALLOW = "ALLOW"
    DENY = "DENY"
    ESCALATE = "ESCALATE"
    ALLOW_CONSTRAINED = "ALLOW_CONSTRAINED"


class VerificationStatus(str, Enum):
    VERIFIED = "VERIFIED"
    FAILED = "FAILED"
    PARTIAL = "PARTIAL"
    UNEXPECTED_EFFECT = "UNEXPECTED_EFFECT"
    ROLLBACK_REQUIRED = "ROLLBACK_REQUIRED"
    NOT_APPLICABLE = "NOT_APPLICABLE"


@dataclass(frozen=True, slots=True)
class AuthorityAssessment:
    authenticated: bool
    principal_id: str
    claimed_agent_id: str
    attributes_match: bool
    trusted_roles: tuple[str, ...]
    trusted_authority: tuple[str, ...]
    required_authority: str
    authorized: bool
    reason_codes: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True, slots=True)
class EvidenceItemAssessment:
    evidence_id: str
    subject_target_id: str
    source_type: str
    source_instance: str
    provenance_verified: bool
    integrity_verified: bool
    content_digest_matches: bool
    freshness: str
    age_seconds: float
    reliability: float
    trust_weight: float
    relevance: float
    supports: tuple[str, ...]
    contradicts: tuple[str, ...]
    poisoned: bool
    score: float
    reason_codes: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True, slots=True)
class EvidenceAssessment:
    overall_strength: float
    decision_grade: bool
    automation_grade: bool
    corroborating_sources: int
    conflict_count: int
    stale_evidence_ids: tuple[str, ...]
    missing_expected_sources: tuple[str, ...]
    invalid_evidence_ids: tuple[str, ...]
    poisoned_evidence_ids: tuple[str, ...]
    assessed_items: tuple[EvidenceItemAssessment, ...]
    reason_codes: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        value = asdict(self)
        value["assessed_items"] = [item.to_dict() for item in self.assessed_items]
        return value


@dataclass(frozen=True, slots=True)
class ConsequenceAssessment:
    score: float
    level: str
    reversible: bool
    blast_radius: str
    downtime_minutes: int
    privilege_impact: str
    mission_impact: str
    safety_impact: str
    availability_impact: str
    dependency_count: int
    cascading_effect_possible: bool
    human_approval_required: bool
    reason_codes: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True, slots=True)
class ApprovalRequirement:
    approval_id: str
    issuer_instance_id: str
    request_id: str
    decision_id: str
    decision_context_sha256: str
    policy_id: str
    policy_version: str
    policy_sha256: str
    action_type: str
    target_id: str
    parameters_sha256: str
    evidence_sha256: str
    reason_codes: tuple[str, ...]
    required_approving_authority: str
    created_at: str
    expires_at: str
    scope_sha256: str
    signature: str
    status: str = "PENDING"

    def __post_init__(self) -> None:
        string_fields = (
            "approval_id",
            "issuer_instance_id",
            "request_id",
            "decision_id",
            "decision_context_sha256",
            "policy_id",
            "policy_version",
            "policy_sha256",
            "action_type",
            "target_id",
            "parameters_sha256",
            "evidence_sha256",
            "required_approving_authority",
            "created_at",
            "expires_at",
            "scope_sha256",
            "signature",
            "status",
        )
        if any(type(getattr(self, name)) is not str for name in string_fields):
            raise TypeError("Approval requirement bindings must be exact strings.")
        if type(self.reason_codes) is not tuple or any(
            type(value) is not str for value in self.reason_codes
        ):
            raise TypeError(
                "Approval requirement reasons must be an exact string tuple."
            )

    def to_dict(self, *, include_signature: bool = True) -> dict[str, Any]:
        value = asdict(self)
        if not include_signature:
            value.pop("signature", None)
        return value


@dataclass(frozen=True, slots=True)
class ApprovalReceipt:
    receipt_id: str
    issuer_instance_id: str
    approval_id: str
    request_id: str
    decision_id: str
    approver_id: str
    approving_authority: str
    action_type: str
    target_id: str
    parameters_sha256: str
    evidence_sha256: str
    requirement_scope_sha256: str
    approved_at: str
    signature: str
    status: str = "APPROVED_FOR_REEVALUATION"

    def __post_init__(self) -> None:
        if any(
            type(getattr(self, name)) is not str
            for name in (
                "receipt_id",
                "issuer_instance_id",
                "approval_id",
                "request_id",
                "decision_id",
                "approver_id",
                "approving_authority",
                "action_type",
                "target_id",
                "parameters_sha256",
                "evidence_sha256",
                "requirement_scope_sha256",
                "approved_at",
                "signature",
                "status",
            )
        ):
            raise TypeError("Approval receipt bindings must be exact strings.")

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True, slots=True)
class DecisionRecord:
    decision_id: str
    request_id: str
    decided_at: str
    policy_id: str
    policy_version: str
    policy_sha256: str
    outcome: str
    reason_codes: tuple[str, ...]
    applicable_rules: tuple[str, ...]
    requested_action: dict[str, Any]
    permitted_action: dict[str, Any] | None
    authority: AuthorityAssessment
    evidence: EvidenceAssessment | None
    consequence: ConsequenceAssessment | None
    constraints: tuple[dict[str, Any], ...]
    explanation: dict[str, Any]
    request_sha256: str
    decision_context_sha256: str
    approval_requirement: ApprovalRequirement | None = None
    latency_ms: float = 0.0

    def __post_init__(self) -> None:
        string_fields = (
            "decision_id",
            "request_id",
            "decided_at",
            "policy_id",
            "policy_version",
            "policy_sha256",
            "outcome",
            "request_sha256",
            "decision_context_sha256",
        )
        if any(type(getattr(self, name)) is not str for name in string_fields):
            raise TypeError("Decision scalar bindings must be exact strings.")
        if type(self.reason_codes) is not tuple or any(
            type(value) is not str for value in self.reason_codes
        ):
            raise TypeError("Decision reason codes must be an exact string tuple.")
        if type(self.applicable_rules) is not tuple or any(
            type(value) is not str for value in self.applicable_rules
        ):
            raise TypeError("Decision applicable rules must be an exact string tuple.")
        if type(self.authority) is not AuthorityAssessment:
            raise TypeError("Decision authority assessment type is invalid.")
        if self.evidence is not None and type(self.evidence) is not EvidenceAssessment:
            raise TypeError("Decision evidence assessment type is invalid.")
        if (
            self.consequence is not None
            and type(self.consequence) is not ConsequenceAssessment
        ):
            raise TypeError("Decision consequence assessment type is invalid.")
        if (
            self.approval_requirement is not None
            and type(self.approval_requirement) is not ApprovalRequirement
        ):
            raise TypeError("Decision approval requirement type is invalid.")
        if type(self.latency_ms) not in (int, float) or not math.isfinite(
            float(self.latency_ms)
        ):
            raise TypeError("Decision latency must be a finite exact number.")
        for path, value in (
            ("$.authority", self.authority.to_dict()),
            ("$.evidence", self.evidence.to_dict() if self.evidence else None),
            (
                "$.consequence",
                self.consequence.to_dict() if self.consequence else None,
            ),
            (
                "$.approval_requirement",
                (
                    self.approval_requirement.to_dict()
                    if self.approval_requirement is not None
                    else None
                ),
            ),
        ):
            _deep_freeze(value, path=path)
        object.__setattr__(
            self,
            "requested_action",
            _deep_freeze(self.requested_action, path="$.requested_action"),
        )
        object.__setattr__(
            self,
            "permitted_action",
            (
                _deep_freeze(self.permitted_action, path="$.permitted_action")
                if self.permitted_action is not None
                else None
            ),
        )
        object.__setattr__(
            self,
            "constraints",
            _deep_freeze(self.constraints, path="$.constraints"),
        )
        object.__setattr__(
            self,
            "explanation",
            _deep_freeze(self.explanation, path="$.explanation"),
        )

    def to_dict(self, *, include_approval_signature: bool = False) -> dict[str, Any]:
        return {
            "decision_id": self.decision_id,
            "request_id": self.request_id,
            "decided_at": self.decided_at,
            "policy_id": self.policy_id,
            "policy_version": self.policy_version,
            "policy_sha256": self.policy_sha256,
            "outcome": self.outcome,
            "reason_codes": list(self.reason_codes),
            "applicable_rules": list(self.applicable_rules),
            "requested_action": _deep_thaw(self.requested_action),
            "permitted_action": _deep_thaw(self.permitted_action),
            "authority": self.authority.to_dict(),
            "evidence": self.evidence.to_dict() if self.evidence else None,
            "consequence": self.consequence.to_dict() if self.consequence else None,
            "constraints": _deep_thaw(self.constraints),
            "explanation": _deep_thaw(self.explanation),
            "request_sha256": self.request_sha256,
            "decision_context_sha256": self.decision_context_sha256,
            "approval_requirement": (
                self.approval_requirement.to_dict(
                    include_signature=include_approval_signature
                )
                if self.approval_requirement is not None
                else None
            ),
            "latency_ms": self.latency_ms,
        }

    def authorization_sha256(self) -> str:
        value = self.to_dict()
        value.pop("latency_ms", None)
        value.pop("explanation", None)
        value.pop("approval_requirement", None)
        return sha256_json(value)

    def semantic_dict(self) -> dict[str, Any]:
        """Return decision semantics without volatile identifiers or timing."""

        value = self.to_dict()
        for key in ("decision_id", "decided_at", "latency_ms"):
            value.pop(key, None)
        approval = value.get("approval_requirement")
        if isinstance(approval, dict):
            for key in ("approval_id", "decision_id", "created_at", "expires_at"):
                approval.pop(key, None)
        return value


@dataclass(frozen=True, slots=True)
class AuthorizationToken:
    token_id: str
    issuer_instance_id: str
    request_id: str
    decision_id: str
    agent_id: str
    action_type: str
    target_id: str
    permitted_parameters: dict[str, Any]
    issued_at: str
    expires_at: str
    policy_id: str
    policy_version: str
    policy_sha256: str
    decision_context_sha256: str
    target_state_sha256: str
    nonce: str
    signature: str

    def unsigned_dict(self) -> dict[str, Any]:
        value = asdict(self)
        value.pop("signature", None)
        return value

    def to_dict(self, *, include_signature: bool = True) -> dict[str, Any]:
        value = asdict(self)
        if not include_signature:
            value.pop("signature", None)
        return value


@dataclass(frozen=True, slots=True)
class BrokerResult:
    attempt_id: str
    token_id: str
    request_id: str
    decision_id: str
    action_type: str
    target_id: str
    parameters: dict[str, Any]
    executed_at: str
    attempted: bool
    accepted: bool
    reported_success: bool
    message: str
    state_before_sha256: str
    state_after_sha256: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True, slots=True)
class PostActionVerification:
    verification_id: str
    request_id: str
    decision_id: str
    attempt_id: str
    token_id: str
    action_type: str
    target_id: str
    parameters_sha256: str
    status: str
    expected_state: dict[str, Any]
    observed_state: dict[str, Any]
    changed_fields: tuple[str, ...]
    unexpected_fields: tuple[str, ...]
    rollback_required: bool
    reason_codes: tuple[str, ...]

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True, slots=True)
class DecisionVerification:
    verification_id: str
    verifier_instance_id: str
    decision_id: str
    decision_context_sha256: str
    decision_sha256: str
    request_sha256: str
    principal_id: str
    principal_resolution_sha256: str
    policy_sha256: str
    passed: bool
    checks: tuple[dict[str, Any], ...]
    blocking_reason_codes: tuple[str, ...]
    verified_at: str
    signature: str

    def unsigned_dict(self) -> dict[str, Any]:
        value = asdict(self)
        value.pop("signature", None)
        return value

    def to_dict(self, *, include_signature: bool = False) -> dict[str, Any]:
        value = asdict(self)
        if not include_signature:
            value.pop("signature", None)
        return value


@dataclass(frozen=True, slots=True)
class Phase3Result:
    decision: DecisionRecord
    authorization: AuthorizationToken | None
    broker_result: BrokerResult | None
    verification: PostActionVerification | None
    final_state: dict[str, Any] | None
    audit_records: tuple[dict[str, Any], ...] = field(default_factory=tuple)

    def to_dict(self, *, include_token_signature: bool = False) -> dict[str, Any]:
        return {
            "decision": self.decision.to_dict(),
            "authorization": (
                self.authorization.to_dict(include_signature=include_token_signature)
                if self.authorization
                else None
            ),
            "broker_result": (
                self.broker_result.to_dict() if self.broker_result else None
            ),
            "verification": self.verification.to_dict() if self.verification else None,
            "final_state": self.final_state,
            "audit_records": list(self.audit_records),
        }
