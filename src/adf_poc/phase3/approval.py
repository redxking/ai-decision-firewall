from __future__ import annotations

import hashlib
import hmac
import uuid
from datetime import datetime, timedelta, timezone
from threading import Lock
from typing import Any, Callable

from adf_poc.utils import canonical_json, sha256_json

from .contracts import AgentSecurityStatus
from .identity import PrincipalAuthenticationError, TrustedPrincipalResolver
from .models import ApprovalReceipt, ApprovalRequirement, DecisionRecord


class ApprovalError(RuntimeError):
    def __init__(self, reason_code: str, message: str) -> None:
        super().__init__(message)
        self.reason_code = reason_code


def _parse_timestamp(value: str) -> datetime:
    parsed = datetime.fromisoformat(value)
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ApprovalError(
            "APPROVAL_TIME_INVALID", "Approval timestamps require a UTC offset."
        )
    return parsed.astimezone(timezone.utc)


def _copy_exact_json(value: object) -> object:
    if type(value) is dict:
        if any(type(key) is not str for key in value):
            raise ApprovalError(
                "APPROVAL_PARAMETERS_INVALID",
                "Approval parameter keys must be exact strings.",
            )
        return {key: _copy_exact_json(child) for key, child in value.items()}
    if type(value) is list:
        return [_copy_exact_json(child) for child in value]
    if value is None or type(value) in (str, bool, int):
        return value
    if type(value) is float and value == value and abs(value) != float("inf"):
        return value
    raise ApprovalError(
        "APPROVAL_PARAMETERS_INVALID",
        "Approval parameters must use exact finite JSON primitives.",
    )


class HumanApprovalGate:
    """Validate a human approval against the exact escalated scope.

    A successful receipt permits a separately governed reevaluation. It never
    becomes an action authorization and never invokes the broker directly.
    """

    def __init__(
        self,
        *,
        signing_key: bytes,
        ttl_seconds: int,
        principal_resolver: TrustedPrincipalResolver,
        clock: Callable[[], datetime] | None = None,
        id_factory: Callable[[str], str] | None = None,
        issuer_instance_id: str | None = None,
    ) -> None:
        if len(signing_key) < 32:
            raise ValueError("Approval signing key must be at least 32 bytes.")
        if ttl_seconds < 60 or ttl_seconds > 86400:
            raise ValueError("Approval TTL must be within 60..86400 seconds.")
        if type(principal_resolver) is not TrustedPrincipalResolver:
            raise TypeError("Approval requires the closed trusted-principal resolver.")
        self.__signing_key = bytes(signing_key)
        self.__ttl_seconds = int(ttl_seconds)
        self.__clock = clock or (lambda: datetime.now(timezone.utc))
        self.__id_factory = id_factory or (lambda prefix: f"{prefix}-{uuid.uuid4()}")
        self.__issuer_instance_id = (
            issuer_instance_id or f"approval-issuer-{uuid.uuid4()}"
        )
        self.__principal_resolver = principal_resolver.immutable_snapshot()
        self.__requirements: dict[str, ApprovalRequirement] = {}
        self.__issued_decision_ids: set[str] = set()
        self.__used: set[str] = set()
        self.__pending_receipts: dict[str, ApprovalReceipt] = {}
        self.__lock = Lock()

    def __sign(self, value: dict[str, Any]) -> str:
        return hmac.new(
            self.__signing_key,
            canonical_json(value).encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()

    def issue_requirement(
        self,
        *,
        decision: DecisionRecord,
        action_type: str,
        target_id: str,
        parameters: dict[str, Any],
        evidence_sha256: str,
        required_approving_authority: str,
        reason_codes: tuple[str, ...],
    ) -> ApprovalRequirement:
        if (
            type(decision) is not DecisionRecord
            or decision.outcome != "ESCALATE"
            or decision.permitted_action is not None
            or decision.approval_requirement is not None
        ):
            raise ApprovalError(
                "APPROVAL_OUTCOME_INVALID",
                "Only a non-executable ESCALATE decision can issue an approval requirement.",
            )
        if (
            not reason_codes
            or required_approving_authority != decision.authority.required_authority
            or tuple(reason_codes) != tuple(decision.reason_codes)
        ):
            raise ApprovalError(
                "APPROVAL_SCOPE_INCOMPLETE",
                "Approval requirements need reasons and an approving authority.",
            )
        now = self.__clock().astimezone(timezone.utc).replace(microsecond=0)
        base = {
            "approval_id": self.__id_factory("approval"),
            "issuer_instance_id": self.__issuer_instance_id,
            "request_id": decision.request_id,
            "decision_id": decision.decision_id,
            "decision_context_sha256": decision.decision_context_sha256,
            "policy_id": decision.policy_id,
            "policy_version": decision.policy_version,
            "policy_sha256": decision.policy_sha256,
            "action_type": action_type,
            "target_id": target_id,
            "parameters_sha256": sha256_json(parameters),
            "evidence_sha256": evidence_sha256,
            "reason_codes": tuple(reason_codes),
            "required_approving_authority": required_approving_authority,
            "created_at": now.isoformat(),
            "expires_at": (now + timedelta(seconds=self.__ttl_seconds)).isoformat(),
            "status": "PENDING",
        }
        scope_sha256 = sha256_json(base)
        signed = {**base, "scope_sha256": scope_sha256}
        requirement = ApprovalRequirement(
            **signed,
            signature=self.__sign(signed),
        )
        with self.__lock:
            if (
                requirement.approval_id in self.__requirements
                or decision.decision_id in self.__issued_decision_ids
            ):
                raise ApprovalError(
                    "APPROVAL_ID_COLLISION", "Approval identifier already exists."
                )
            self.__requirements[requirement.approval_id] = requirement
            self.__issued_decision_ids.add(decision.decision_id)
        return requirement

    def verify_requirement(
        self,
        requirement: ApprovalRequirement,
        *,
        check_time: bool = True,
        evaluated_at: datetime | None = None,
    ) -> None:
        if type(requirement) is not ApprovalRequirement:
            raise ApprovalError("APPROVAL_TYPE_INVALID", "Approval type is invalid.")
        unsigned = requirement.to_dict()
        signature = str(unsigned.pop("signature"))
        scope_sha256 = str(unsigned.pop("scope_sha256"))
        if sha256_json(unsigned) != scope_sha256:
            raise ApprovalError(
                "APPROVAL_SCOPE_DIGEST_INVALID", "Approval scope changed."
            )
        signed = {**unsigned, "scope_sha256": scope_sha256}
        if not hmac.compare_digest(self.__sign(signed), signature):
            raise ApprovalError(
                "APPROVAL_SIGNATURE_INVALID", "Approval signature is invalid."
            )
        if requirement.issuer_instance_id != self.__issuer_instance_id:
            raise ApprovalError(
                "APPROVAL_ISSUER_MISMATCH", "Approval has another issuer."
            )
        with self.__lock:
            registered = self.__requirements.get(requirement.approval_id)
        if registered != requirement:
            raise ApprovalError(
                "APPROVAL_NOT_REGISTERED",
                "Approval was not issued by this firewall instance.",
            )
        if requirement.status != "PENDING" or not requirement.reason_codes:
            raise ApprovalError("APPROVAL_STATUS_INVALID", "Approval is not pending.")
        created = _parse_timestamp(requirement.created_at)
        expires = _parse_timestamp(requirement.expires_at)
        if created >= expires:
            raise ApprovalError(
                "APPROVAL_TIME_INVALID", "Approval interval is invalid."
            )
        if check_time:
            now = (evaluated_at or self.__clock()).astimezone(timezone.utc)
            if now < created:
                raise ApprovalError(
                    "APPROVAL_NOT_YET_VALID", "Approval is not yet valid."
                )
            if now >= expires:
                raise ApprovalError("APPROVAL_EXPIRED", "Approval has expired.")

    def approve(
        self,
        *,
        requirement: ApprovalRequirement,
        credential: bytes,
        action_type: str,
        target_id: str,
        parameters: dict,
        evidence_sha256: str,
        commit_receipt: Callable[[ApprovalReceipt], None] | None = None,
    ) -> ApprovalReceipt:
        if (
            type(action_type) is not str
            or not action_type
            or type(target_id) is not str
            or not target_id
            or type(evidence_sha256) is not str
            or not evidence_sha256
            or type(parameters) is not dict
        ):
            raise ApprovalError(
                "APPROVAL_SCOPE_TYPE_INVALID",
                "Approval scope requires exact string bindings and an exact parameter object.",
            )
        normalized_parameters = _copy_exact_json(parameters)
        if type(normalized_parameters) is not dict:  # structural invariant
            raise ApprovalError(
                "APPROVAL_PARAMETERS_INVALID", "Approval parameters are invalid."
            )
        now = self.__clock().astimezone(timezone.utc).replace(microsecond=0)
        self.verify_requirement(requirement, evaluated_at=now)
        try:
            approver_resolution = self.__principal_resolver.resolve(credential)
            approver = self.__principal_resolver.verify_resolution(approver_resolution)
        except PrincipalAuthenticationError as exc:
            raise ApprovalError(
                "APPROVER_CREDENTIAL_REJECTED",
                "Human approval credential was not resolved at the trusted boundary.",
            ) from exc
        if (
            not approver.authenticated
            or approver.security_status != AgentSecurityStatus.TRUSTED
        ):
            raise ApprovalError(
                "APPROVER_NOT_AUTHENTICATED",
                "Approver must be a trusted authenticated principal.",
            )
        if (
            not approver.human_session
            or approver.type not in {"HUMAN_ANALYST", "HUMAN_OPERATOR"}
            or "HUMAN_APPROVER" not in set(approver.roles)
        ):
            raise ApprovalError(
                "APPROVER_NOT_HUMAN",
                "Approval requires a positively attested trusted human session.",
            )
        if requirement.required_approving_authority not in set(approver.authority):
            raise ApprovalError(
                "APPROVER_AUTHORITY_INSUFFICIENT",
                "Approver lacks the authority required by the escalation.",
            )
        bindings = (
            ("ACTION", requirement.action_type, action_type),
            ("TARGET", requirement.target_id, target_id),
            (
                "PARAMETERS",
                requirement.parameters_sha256,
                sha256_json(normalized_parameters),
            ),
            ("EVIDENCE", requirement.evidence_sha256, evidence_sha256),
        )
        for name, expected, observed in bindings:
            if expected != observed:
                raise ApprovalError(
                    f"APPROVAL_{name}_MISMATCH",
                    f"Approval {name.lower()} differs from the reviewed scope.",
                )
        with self.__lock:
            if requirement.approval_id in self.__used:
                raise ApprovalError(
                    "APPROVAL_REPLAY", "Approval requirement has already been consumed."
                )
            if self.__requirements.get(requirement.approval_id) != requirement:
                raise ApprovalError(
                    "APPROVAL_NOT_REGISTERED",
                    "Approval was not issued by this firewall instance.",
                )
            receipt = self.__pending_receipts.get(requirement.approval_id)
            if receipt is None:
                receipt_id = self.__id_factory("approval-receipt")
                if type(receipt_id) is not str or not receipt_id:
                    raise ApprovalError(
                        "APPROVAL_RECEIPT_ID_INVALID",
                        "Approval receipt identifier allocation failed.",
                    )
                base = {
                    "receipt_id": receipt_id,
                    "issuer_instance_id": self.__issuer_instance_id,
                    "approval_id": requirement.approval_id,
                    "request_id": requirement.request_id,
                    "decision_id": requirement.decision_id,
                    "approver_id": approver.id,
                    "approving_authority": requirement.required_approving_authority,
                    "action_type": action_type,
                    "target_id": target_id,
                    "parameters_sha256": requirement.parameters_sha256,
                    "evidence_sha256": evidence_sha256,
                    "requirement_scope_sha256": requirement.scope_sha256,
                    "approved_at": now.isoformat(),
                    "status": "APPROVED_FOR_REEVALUATION",
                }
                receipt = ApprovalReceipt(**base, signature=self.__sign(base))
                self.__pending_receipts[requirement.approval_id] = receipt
            elif (
                receipt.approver_id != approver.id
                or receipt.approving_authority
                != requirement.required_approving_authority
                or receipt.action_type != action_type
                or receipt.target_id != target_id
                or receipt.parameters_sha256 != requirement.parameters_sha256
                or receipt.evidence_sha256 != evidence_sha256
                or receipt.requirement_scope_sha256 != requirement.scope_sha256
            ):
                raise ApprovalError(
                    "APPROVAL_PENDING_CONFLICT",
                    "A pending approval receipt has different reviewed bindings.",
                )
            if commit_receipt is not None:
                commit_receipt(receipt)
            self.__used.add(requirement.approval_id)
            self.__pending_receipts.pop(requirement.approval_id, None)
        return receipt
