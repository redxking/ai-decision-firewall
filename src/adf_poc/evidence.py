from __future__ import annotations

import re
from dataclasses import asdict, dataclass
from datetime import datetime
from statistics import mean
from typing import Any

from .feature_contract import select_evidence_attributes, select_modeled_attributes
from .schemas import IdentityCase, IntegrityStatus
from .utils import clamp


INSTRUCTION_PATTERNS = (
    re.compile(r"\bignore\s+(all\s+)?(prior|previous)\b", re.IGNORECASE),
    re.compile(r"\b(system|assistant)\s*:\s*", re.IGNORECASE),
    re.compile(r"\bdo\s+not\s+ask\b", re.IGNORECASE),
    re.compile(r"\bdisable\s+(the\s+)?account\b", re.IGNORECASE),
)

POSITIVE_INDICATORS = {
    "threat_ip",
    "token_reuse",
    "credential_dumping",
    "lateral_movement",
    "edr_malware",
    "mfa_fatigue",
    "oauth_grant",
    "unusual_admin_action",
    "new_device",
    "impossible_travel",
}
BENIGN_INDICATORS = {
    "known_vpn",
    "approved_travel",
    "maintenance_window",
    "service_account_baseline",
    "strong_mfa",
}
EXPECTED_SOURCES = {
    "asset_inventory",
    "identity",
    "network",
    "endpoint",
    "threat_intel",
    "change_management",
    "user_context",
}


@dataclass(slots=True)
class EvidenceAssessment:
    evidence_quality: float
    provenance_valid_ratio: float
    integrity_verified_ratio: float
    freshness_score: float
    source_diversity_score: float
    mean_source_trust: float
    independent_supporting_sources: int
    positive_event_ids: list[str]
    benign_event_ids: list[str]
    missing_expected_sources: list[str]
    conflict_count: int
    poisoned_evidence: bool
    poisoned_event_ids: list[str]
    reasons: list[str]

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _parse_time(value: str) -> datetime:
    return datetime.fromisoformat(value)


def assess_evidence(case: IdentityCase) -> EvidenceAssessment:
    if not case.events:
        return EvidenceAssessment(
            evidence_quality=0.0,
            provenance_valid_ratio=0.0,
            integrity_verified_ratio=0.0,
            freshness_score=0.0,
            source_diversity_score=0.0,
            mean_source_trust=0.0,
            independent_supporting_sources=0,
            positive_event_ids=[],
            benign_event_ids=[],
            missing_expected_sources=sorted(EXPECTED_SOURCES),
            conflict_count=0,
            poisoned_evidence=False,
            poisoned_event_ids=[],
            reasons=["No evidence events were supplied."],
        )

    provenance_valid = [bool(event.provenance_id) for event in case.events]
    integrity_verified = [
        event.integrity == IntegrityStatus.VERIFIED.value for event in case.events
    ]
    freshness_values: list[float] = []
    sources = {event.source_type for event in case.events}
    positive_event_ids: list[str] = []
    benign_event_ids: list[str] = []
    supporting_sources: set[str] = set()
    poisoned_event_ids: list[str] = []
    conflict_count = 0

    for event in case.events:
        delay_seconds = max(
            0.0,
            (
                _parse_time(event.collected_at) - _parse_time(event.observed_at)
            ).total_seconds(),
        )
        # Full credit below five minutes; linearly decays to zero by two hours.
        freshness_values.append(clamp(1.0 - max(0.0, delay_seconds - 300.0) / 6900.0))
        modeled = select_modeled_attributes(
            event.source_type,
            event.attributes,
            label=f"event[{event.event_id}].attributes",
        )
        evidence_attributes = select_evidence_attributes(
            event.source_type,
            event.attributes,
            label=f"event[{event.event_id}].attributes",
        )
        event_positive = any(modeled.get(key) is True for key in POSITIVE_INDICATORS)
        event_benign = any(modeled.get(key) is True for key in BENIGN_INDICATORS)
        if event_positive:
            positive_event_ids.append(event.event_id)
            supporting_sources.add(event.source_type)
        if event_benign:
            benign_event_ids.append(event.event_id)
        if evidence_attributes.get("source_conflict") is True:
            conflict_count += 1
        text_is_instructional = event.contains_instructional_content or any(
            pattern.search(event.untrusted_text or "")
            for pattern in INSTRUCTION_PATTERNS
        )
        if text_is_instructional:
            poisoned_event_ids.append(event.event_id)

    provenance_ratio = mean(1.0 if flag else 0.0 for flag in provenance_valid)
    integrity_ratio = mean(1.0 if flag else 0.0 for flag in integrity_verified)
    freshness_score = mean(freshness_values)
    diversity_score = clamp(len(sources) / len(EXPECTED_SOURCES))
    trust_score = mean(event.trust_score for event in case.events)
    missing = sorted(EXPECTED_SOURCES - sources)
    poisoned = bool(poisoned_event_ids)

    quality = (
        0.27 * provenance_ratio
        + 0.23 * integrity_ratio
        + 0.18 * freshness_score
        + 0.17 * diversity_score
        + 0.15 * trust_score
    )
    quality -= min(0.25, 0.10 * conflict_count)
    if poisoned:
        quality -= 0.30
    if len(missing) >= 2:
        quality -= 0.12
    quality = clamp(quality)

    reasons: list[str] = []
    if provenance_ratio < 1.0:
        reasons.append("One or more evidence events lack verifiable provenance.")
    if integrity_ratio < 1.0:
        reasons.append(
            "One or more evidence events failed integrity verification or remain unverified."
        )
    if freshness_score < 0.80:
        reasons.append("One or more telemetry sources are stale.")
    if missing:
        reasons.append(f"Expected evidence sources are missing: {', '.join(missing)}.")
    if conflict_count:
        reasons.append("Independent telemetry sources conflict.")
    if poisoned:
        reasons.append(
            "Untrusted content contains instructions directed at an AI agent; content is excluded from model input and blocks autonomous action."
        )
    if not reasons:
        reasons.append(
            "Evidence provenance, integrity, freshness, and source diversity meet the POC baseline."
        )

    return EvidenceAssessment(
        evidence_quality=round(quality, 6),
        provenance_valid_ratio=round(provenance_ratio, 6),
        integrity_verified_ratio=round(integrity_ratio, 6),
        freshness_score=round(freshness_score, 6),
        source_diversity_score=round(diversity_score, 6),
        mean_source_trust=round(trust_score, 6),
        independent_supporting_sources=len(supporting_sources),
        positive_event_ids=positive_event_ids,
        benign_event_ids=benign_event_ids,
        missing_expected_sources=missing,
        conflict_count=conflict_count,
        poisoned_evidence=poisoned,
        poisoned_event_ids=poisoned_event_ids,
        reasons=reasons,
    )
