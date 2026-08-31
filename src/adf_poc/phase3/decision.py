from __future__ import annotations

import uuid
from dataclasses import replace
from datetime import datetime, timezone
from typing import Any, Callable

from adf_poc.utils import sha256_json

from .config import ActionPolicy, Phase3PolicyConfig, TargetRecord
from .contracts import AgentSecurityStatus, AuthenticatedPrincipal, DecisionRequest
from .models import (
    ApprovalRequirement,
    AuthorityAssessment,
    ConsequenceAssessment,
    DecisionOutcome,
    DecisionRecord,
    EvidenceAssessment,
)


_REASON_PRIORITY = (
    "INVALID_REQUEST",
    "AGENT_NOT_AUTHENTICATED",
    "INVOCATION_CREDENTIAL_INVALID",
    "INVOCATION_CREDENTIAL_REJECTED",
    "AGENT_IDENTITY_MISMATCH",
    "AGENT_ATTRIBUTE_MISMATCH",
    "AGENT_SECURITY_STATUS_INVALID",
    "TARGET_UNKNOWN",
    "TARGET_CLAIM_MISMATCH",
    "ACTION_TARGET_TYPE_PROHIBITED",
    "PROTECTED_ASSET",
    "INSUFFICIENT_AUTHORITY",
    "EVIDENCE_SOURCE_UNTRUSTED",
    "EVIDENCE_SUBJECT_MISMATCH",
    "EVIDENCE_SOURCE_TYPE_MISMATCH",
    "EVIDENCE_TRUST_CLAIM_MISMATCH",
    "EVIDENCE_PROVENANCE_INVALID",
    "EVIDENCE_INTEGRITY_INVALID",
    "EVIDENCE_CONTENT_DIGEST_MISMATCH",
    "PROMPT_INJECTION_DETECTED",
    "FUTURE_EVIDENCE",
    "STALE_EVIDENCE",
    "CONFLICTING_EVIDENCE",
    "MISSING_EXPECTED_EVIDENCE",
    "INSUFFICIENT_CORROBORATION",
    "INSUFFICIENT_EVIDENCE_STRENGTH",
    "AUTHENTICATION_SERVICE_DEPENDENCY",
    "CASCADING_EFFECT_POSSIBLE",
    "HIGH_OPERATIONAL_CONSEQUENCE",
    "HIGH_ISOLATION_CONSEQUENCE",
    "HUMAN_APPROVAL_REQUIRED",
    "DURATION_CONSTRAINED",
    "MANAGEMENT_ACCESS_CONSTRAINED",
    "AUTHORIZED_AGENT",
    "DECISION_GRADE_EVIDENCE",
    "ACCEPTABLE_OPERATIONAL_CONSEQUENCE",
    "REVERSIBLE_ACTION",
)


def _ordered_reasons(values: list[str]) -> tuple[str, ...]:
    seen = set(values)
    ordered = [value for value in _REASON_PRIORITY if value in seen]
    ordered.extend(sorted(seen - set(_REASON_PRIORITY)))
    return tuple(ordered)


def _target_claims_match(request: DecisionRequest, target: TargetRecord) -> bool:
    claims = request.target
    return (
        claims.id == target.id
        and claims.type.value == target.type
        and claims.criticality.value == target.criticality
        and claims.classification.value == target.classification
        and set(claims.dependencies) == set(target.dependencies)
    )


def assess_authority(
    request: DecisionRequest,
    principal: AuthenticatedPrincipal,
    *,
    required_authority: str,
) -> AuthorityAssessment:
    reasons: list[str] = []
    if principal.authentication_reason_code:
        reasons.append(principal.authentication_reason_code)
    if not principal.authenticated:
        reasons.append("AGENT_NOT_AUTHENTICATED")
    if principal.id != request.agent.id:
        reasons.append("AGENT_IDENTITY_MISMATCH")
    attributes_match = (
        principal.type == request.agent.type
        and principal.authenticated == request.agent.authenticated
        and set(principal.roles) == set(request.agent.roles)
        and set(principal.authority) == set(request.agent.authority)
        and principal.security_status == request.agent.security_status
    )
    if not attributes_match:
        reasons.append("AGENT_ATTRIBUTE_MISMATCH")
    if principal.security_status != AgentSecurityStatus.TRUSTED:
        reasons.append("AGENT_SECURITY_STATUS_INVALID")
    authorized = required_authority in set(principal.authority)
    if not authorized:
        reasons.append("INSUFFICIENT_AUTHORITY")
    return AuthorityAssessment(
        authenticated=principal.authenticated,
        principal_id=principal.id,
        claimed_agent_id=request.agent.id,
        attributes_match=attributes_match,
        trusted_roles=tuple(sorted(principal.roles)),
        trusted_authority=tuple(sorted(principal.authority)),
        required_authority=required_authority,
        authorized=authorized,
        reason_codes=_ordered_reasons(reasons),
    )


def build_decision(
    *,
    request: DecisionRequest,
    principal: AuthenticatedPrincipal,
    policy: Phase3PolicyConfig,
    evidence: EvidenceAssessment,
    consequence: ConsequenceAssessment,
    target: TargetRecord,
    action_policy: ActionPolicy,
    decided_at: datetime,
    decision_id: str | None = None,
    approval_requirement_factory: Callable[..., ApprovalRequirement] | None = None,
) -> DecisionRecord:
    decision_identifier = decision_id or f"decision-{uuid.uuid4()}"
    now = decided_at.astimezone(timezone.utc).replace(microsecond=0)
    required_authority = (
        action_policy.tier_0_required_authority
        if target.criticality == "TIER_0"
        else action_policy.required_authority
    )
    authority = assess_authority(
        request, principal, required_authority=required_authority
    )

    target_claims_match = _target_claims_match(request, target)
    reasons: list[str] = list(authority.reason_codes)
    reasons.extend(evidence.reason_codes)
    reasons.extend(consequence.reason_codes)
    if not target_claims_match:
        reasons.append("TARGET_CLAIM_MISMATCH")

    requested_action = request.action.to_dict()
    permitted_parameters = request.action.parameters.to_dict()
    constraints: list[dict[str, Any]] = []
    if (
        permitted_parameters["duration_seconds"]
        > action_policy.maximum_duration_seconds
    ):
        constraints.append(
            {
                "parameter": "duration_seconds",
                "requested": permitted_parameters["duration_seconds"],
                "permitted": action_policy.maximum_duration_seconds,
                "reason_code": "DURATION_CONSTRAINED",
            }
        )
        permitted_parameters["duration_seconds"] = (
            action_policy.maximum_duration_seconds
        )
        reasons.append("DURATION_CONSTRAINED")
    if (
        action_policy.preserve_management_required
        and not permitted_parameters["preserve_management"]
    ):
        constraints.append(
            {
                "parameter": "preserve_management",
                "requested": False,
                "permitted": True,
                "reason_code": "MANAGEMENT_ACCESS_CONSTRAINED",
            }
        )
        permitted_parameters["preserve_management"] = True
        reasons.append("MANAGEMENT_ACCESS_CONSTRAINED")

    identity_fatal = bool(
        {
            "AGENT_NOT_AUTHENTICATED",
            "AGENT_IDENTITY_MISMATCH",
            "AGENT_ATTRIBUTE_MISMATCH",
            "AGENT_SECURITY_STATUS_INVALID",
        }
        & set(authority.reason_codes)
    )
    evidence_fatal = bool(
        evidence.invalid_evidence_ids or evidence.poisoned_evidence_ids
    )
    target_type_prohibited = target.type not in set(action_policy.allowed_target_types)
    if target_type_prohibited:
        reasons.append("ACTION_TARGET_TYPE_PROHIBITED")

    conditions = {
        "IDENTITY_FATAL": identity_fatal,
        "EVIDENCE_FATAL": evidence_fatal,
        "TARGET_TYPE_PROHIBITED": target_type_prohibited,
        "TARGET_TIER_0": target.criticality == "TIER_0",
        "CONSEQUENCE_REQUIRES_APPROVAL": consequence.human_approval_required,
        "AUTHORITY_INSUFFICIENT": not authority.authorized,
        "EVIDENCE_NOT_AUTOMATION_GRADE": not evidence.automation_grade,
        "PARAMETER_CONSTRAINTS_PRESENT": bool(constraints),
        "DEFAULT": True,
    }
    selected_rule = next(
        rule for rule in policy.decision_rules if conditions[rule.condition]
    )
    outcome = selected_rule.outcome
    applicable_rules = [selected_rule.id]

    if authority.authorized and not identity_fatal:
        reasons.append("AUTHORIZED_AGENT")
    if evidence.automation_grade:
        reasons.append("DECISION_GRADE_EVIDENCE")
    if consequence.level in {"LOW", "MEDIUM"}:
        reasons.append("ACCEPTABLE_OPERATIONAL_CONSEQUENCE")

    permitted_action = None
    if outcome in {
        DecisionOutcome.ALLOW.value,
        DecisionOutcome.ALLOW_CONSTRAINED.value,
    }:
        permitted_action = {
            "type": request.action.type.value,
            "target": target.id,
            "parameters": permitted_parameters,
        }

    ordered_reasons = _ordered_reasons(reasons)
    context = {
        "request_sha256": request.request_sha256(),
        "policy_id": policy.policy_id,
        "policy_version": policy.version,
        "policy_sha256": sha256_json(policy.to_dict()),
        "principal": principal.to_dict(),
        "trusted_target": target.to_dict(),
        "authority": authority.to_dict(),
        "evidence": evidence.to_dict(),
        "consequence": consequence.to_dict(),
        "outcome": outcome,
        "reason_codes": list(ordered_reasons),
        "applicable_rules": list(applicable_rules),
        "constraints": constraints,
        "permitted_action": permitted_action,
    }
    context_sha256 = sha256_json(context)

    explanation = {
        "decision": outcome,
        "reason_codes": list(ordered_reasons),
        "evidence_assessment": evidence.to_dict(),
        "applicable_policies": list(applicable_rules),
        "agent_authority": authority.to_dict(),
        "target_criticality": target.criticality,
        "risk_and_consequence": consequence.to_dict(),
        "conflicting_evidence": evidence.conflict_count,
        "missing_evidence": list(evidence.missing_expected_sources),
        "constraints": constraints,
        "human_approval_requirement": None,
        "agent_recommendation_is_authoritative": False,
        "agent_confidence_is_authoritative": False,
    }
    preliminary = DecisionRecord(
        decision_id=decision_identifier,
        request_id=request.request_id,
        decided_at=now.isoformat(),
        policy_id=policy.policy_id,
        policy_version=policy.version,
        policy_sha256=sha256_json(policy.to_dict()),
        outcome=outcome,
        reason_codes=ordered_reasons,
        applicable_rules=tuple(applicable_rules),
        requested_action=requested_action,
        permitted_action=permitted_action,
        authority=authority,
        evidence=evidence,
        consequence=consequence,
        constraints=tuple(constraints),
        explanation=explanation,
        request_sha256=request.request_sha256(),
        decision_context_sha256=context_sha256,
        approval_requirement=None,
    )
    if outcome != DecisionOutcome.ESCALATE.value:
        return preliminary
    if approval_requirement_factory is None:
        raise RuntimeError(
            "ESCALATE decisions require a firewall-owned approval requirement issuer."
        )
    approval_requirement = approval_requirement_factory(
        decision=preliminary,
        action_type=request.action.type.value,
        target_id=target.id,
        parameters=request.action.parameters.to_dict(),
        evidence_sha256=sha256_json([item.to_dict() for item in request.evidence]),
        required_approving_authority=required_authority,
        reason_codes=ordered_reasons,
    )
    explanation = dict(preliminary.explanation)
    explanation["human_approval_requirement"] = approval_requirement.to_dict(
        include_signature=False
    )
    return replace(
        preliminary,
        approval_requirement=approval_requirement,
        explanation=explanation,
    )
