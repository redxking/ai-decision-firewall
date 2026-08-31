from __future__ import annotations

import math
import re
from datetime import datetime, timezone
from typing import Any, Iterable

from adf_poc.utils import canonical_json

from .attestation import EvidenceAttestationVerifier
from .contracts import DecisionRequest, EvidenceIntegrityStatus
from .models import EvidenceAssessment, EvidenceItemAssessment


_INSTRUCTION_PATTERNS = (
    re.compile(r"\bignore\s+(all\s+)?(prior|previous|policy)\b", re.IGNORECASE),
    re.compile(r"\b(system|assistant|developer)\s*:\s*", re.IGNORECASE),
    re.compile(
        r"\b(bypass|disable|override)\s+(the\s+)?(firewall|policy|control)\b",
        re.IGNORECASE,
    ),
    re.compile(r"\breturn\s+(allow|approved)\b", re.IGNORECASE),
)


def _field(value: Any, name: str) -> Any:
    if isinstance(value, dict):
        return value[name]
    return getattr(value, name)


def _parse_timestamp(value: str) -> datetime:
    normalized = value[:-1] + "+00:00" if value.endswith("Z") else value
    parsed = datetime.fromisoformat(normalized)
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValueError("Evidence timestamp lacks a UTC offset.")
    return parsed.astimezone(timezone.utc)


def _ordered_unique(values: Iterable[str]) -> tuple[str, ...]:
    seen: set[str] = set()
    ordered: list[str] = []
    for value in values:
        if value not in seen:
            seen.add(value)
            ordered.append(value)
    return tuple(ordered)


def assess_evidence(
    request: DecisionRequest,
    *,
    evidence_policy: Any,
    attestation_verifier: EvidenceAttestationVerifier,
    evaluated_at: datetime,
) -> EvidenceAssessment:
    """Assess request evidence using trusted source policy and firewall time."""

    now = evaluated_at.astimezone(timezone.utc)
    maximum_age = int(_field(evidence_policy, "maximum_age_seconds"))
    minimum_reliability = float(_field(evidence_policy, "minimum_reliability"))
    minimum_relevance = float(_field(evidence_policy, "minimum_relevance"))
    minimum_strength = float(
        _field(evidence_policy, "minimum_overall_strength_for_allow")
    )
    minimum_sources = int(_field(evidence_policy, "minimum_corroborating_sources"))
    maximum_conflicts = int(_field(evidence_policy, "maximum_conflicts_for_allow"))
    hypothesis_claim = str(_field(evidence_policy, "hypothesis_claim"))
    trust_weights = dict(_field(evidence_policy, "trust_weights"))
    trusted_sources = dict(_field(evidence_policy, "trusted_sources"))
    required_by_action = dict(
        _field(evidence_policy, "required_source_types_by_action")
    )
    required_sources = {
        str(value) for value in required_by_action.get(request.action.type.value, ())
    }

    assessed: list[EvidenceItemAssessment] = []
    invalid_ids: list[str] = []
    stale_ids: list[str] = []
    poisoned_ids: list[str] = []
    valid_source_types: set[str] = set()
    corroborating_instances: set[tuple[str, str]] = set()
    conflict_instances: set[tuple[str, str]] = set()
    supporting_scores_by_instance: dict[tuple[str, str], float] = {}
    aggregate_reasons: list[str] = []

    for item in request.evidence:
        item_reasons: list[str] = []
        if item.subject_target_id != request.action.target:
            item_reasons.append("EVIDENCE_SUBJECT_MISMATCH")
        source_record = trusted_sources.get(item.source_instance)
        source_registered = source_record is not None
        if not source_registered:
            item_reasons.append("EVIDENCE_SOURCE_UNTRUSTED")
            registry_type = ""
            registry_reliability = 0.0
            registry_trust = "UNTRUSTED"
        else:
            registry_type = str(_field(source_record, "source_type"))
            registry_reliability = float(_field(source_record, "reliability"))
            registry_trust = str(_field(source_record, "trust_level"))
            if registry_type != item.source_type:
                item_reasons.append("EVIDENCE_SOURCE_TYPE_MISMATCH")
            if (
                not math.isclose(item.reliability, registry_reliability, abs_tol=1e-12)
                or item.trust_level.value != registry_trust
            ):
                item_reasons.append("EVIDENCE_TRUST_CLAIM_MISMATCH")

        provenance_signature_valid = attestation_verifier.verify(item)
        provenance_verified = (
            bool(item.provenance.id)
            and item.provenance.verified
            and provenance_signature_valid
        )
        if not provenance_verified:
            item_reasons.append("EVIDENCE_PROVENANCE_INVALID")
        if not provenance_signature_valid:
            item_reasons.append("EVIDENCE_PROVENANCE_SIGNATURE_INVALID")
        integrity_verified = item.integrity.status == EvidenceIntegrityStatus.VERIFIED
        if not integrity_verified:
            item_reasons.append("EVIDENCE_INTEGRITY_INVALID")
        digest_matches = item.content_digest_matches()
        if not digest_matches:
            item_reasons.append("EVIDENCE_CONTENT_DIGEST_MISMATCH")

        observed_at = _parse_timestamp(item.observed_at)
        age_seconds = (now - observed_at).total_seconds()
        if age_seconds < 0:
            freshness = "FUTURE"
            item_reasons.append("FUTURE_EVIDENCE")
            freshness_factor = 0.0
        elif age_seconds > maximum_age:
            freshness = "STALE"
            stale_ids.append(item.id)
            item_reasons.append("STALE_EVIDENCE")
            freshness_factor = 0.0
        else:
            freshness = "FRESH"
            # Fresh evidence retains at least 75% of its time contribution at
            # the exact policy boundary; one tick beyond the boundary is stale.
            freshness_factor = 1.0 - 0.25 * (age_seconds / maximum_age)

        serialized_content = item.untrusted_text + "\n" + canonical_json(item.payload)
        poisoned = any(
            pattern.search(serialized_content) for pattern in _INSTRUCTION_PATTERNS
        )
        if poisoned:
            poisoned_ids.append(item.id)
            item_reasons.append("PROMPT_INJECTION_DETECTED")
        if item.reliability < minimum_reliability:
            item_reasons.append("EVIDENCE_RELIABILITY_BELOW_MINIMUM")
        if item.relevance < minimum_relevance:
            item_reasons.append("EVIDENCE_RELEVANCE_BELOW_MINIMUM")

        fatal_reasons = {
            "EVIDENCE_SOURCE_UNTRUSTED",
            "EVIDENCE_SUBJECT_MISMATCH",
            "EVIDENCE_SOURCE_TYPE_MISMATCH",
            "EVIDENCE_TRUST_CLAIM_MISMATCH",
            "EVIDENCE_PROVENANCE_INVALID",
            "EVIDENCE_PROVENANCE_SIGNATURE_INVALID",
            "EVIDENCE_INTEGRITY_INVALID",
            "EVIDENCE_CONTENT_DIGEST_MISMATCH",
            "FUTURE_EVIDENCE",
            "PROMPT_INJECTION_DETECTED",
            "EVIDENCE_RELIABILITY_BELOW_MINIMUM",
            "EVIDENCE_RELEVANCE_BELOW_MINIMUM",
        }
        valid = not (set(item_reasons) & fatal_reasons)
        if not valid:
            invalid_ids.append(item.id)
        else:
            valid_source_types.add(item.source_type)

        trust_weight = float(trust_weights.get(registry_trust, 0.0))
        score = (
            registry_reliability
            * trust_weight
            * float(item.relevance)
            * freshness_factor
            if valid
            else 0.0
        )
        supports_hypothesis = hypothesis_claim in item.supports
        contradicts_hypothesis = hypothesis_claim in item.contradicts
        source_key = (item.source_type, item.source_instance)
        if valid and freshness == "FRESH" and supports_hypothesis and score > 0.0:
            corroborating_instances.add(source_key)
            supporting_scores_by_instance[source_key] = max(
                score, supporting_scores_by_instance.get(source_key, 0.0)
            )
        if valid and contradicts_hypothesis:
            conflict_instances.add(source_key)

        assessed.append(
            EvidenceItemAssessment(
                evidence_id=item.id,
                subject_target_id=item.subject_target_id,
                source_type=item.source_type,
                source_instance=item.source_instance,
                provenance_verified=provenance_verified,
                integrity_verified=integrity_verified,
                content_digest_matches=digest_matches,
                freshness=freshness,
                age_seconds=round(age_seconds, 6),
                reliability=registry_reliability,
                trust_weight=trust_weight,
                relevance=float(item.relevance),
                supports=tuple(item.supports),
                contradicts=tuple(item.contradicts),
                poisoned=poisoned,
                score=round(score, 6),
                reason_codes=_ordered_unique(item_reasons),
            )
        )
        aggregate_reasons.extend(item_reasons)

    missing = tuple(sorted(required_sources - valid_source_types))
    if missing:
        aggregate_reasons.append("MISSING_EXPECTED_EVIDENCE")
    conflicts = len(conflict_instances)
    if conflicts:
        aggregate_reasons.append("CONFLICTING_EVIDENCE")
    if len(corroborating_instances) < minimum_sources:
        aggregate_reasons.append("INSUFFICIENT_CORROBORATION")
    overall_strength = (
        math.fsum(supporting_scores_by_instance.values())
        / len(supporting_scores_by_instance)
        if supporting_scores_by_instance
        else 0.0
    )
    if overall_strength < minimum_strength:
        aggregate_reasons.append("INSUFFICIENT_EVIDENCE_STRENGTH")

    decision_grade = not invalid_ids and bool(assessed)
    automation_grade = (
        decision_grade
        and not stale_ids
        and not missing
        and conflicts <= maximum_conflicts
        and len(corroborating_instances) >= minimum_sources
        and overall_strength > 0.0
        and overall_strength >= minimum_strength
    )
    return EvidenceAssessment(
        overall_strength=round(overall_strength, 6),
        decision_grade=decision_grade,
        automation_grade=automation_grade,
        corroborating_sources=len(corroborating_instances),
        conflict_count=conflicts,
        stale_evidence_ids=tuple(sorted(stale_ids)),
        missing_expected_sources=missing,
        invalid_evidence_ids=tuple(sorted(invalid_ids)),
        poisoned_evidence_ids=tuple(sorted(poisoned_ids)),
        assessed_items=tuple(assessed),
        reason_codes=_ordered_unique(aggregate_reasons),
    )
