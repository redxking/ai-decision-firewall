from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any

from .evidence import EvidenceAssessment
from .model import ModelAssessment
from .policy import DecisionProposal, PolicyConfig
from .schemas import Disposition, IdentityCase


@dataclass(slots=True)
class VerificationResult:
    passed: bool
    checks: list[dict[str, Any]]
    blocking_reasons: list[str]

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class IndependentVerifier:
    """Deterministic, non-model verifier that independently checks action eligibility."""

    def __init__(self, config: PolicyConfig) -> None:
        self.config = config

    def verify(
        self,
        case: IdentityCase,
        model: ModelAssessment,
        evidence: EvidenceAssessment,
        proposal: DecisionProposal,
    ) -> VerificationResult:
        checks: list[dict[str, Any]] = []
        blockers: list[str] = []
        known_event_ids = {event.event_id for event in case.events}
        autonomous_actions = set(self.config.authority["autonomous_actions"])
        human_only_actions = set(self.config.authority["human_only_actions"])

        def check(name: str, passed: bool, detail: str) -> None:
            checks.append({"check": name, "passed": bool(passed), "detail": detail})
            if not passed:
                blockers.append(f"{name}: {detail}")

        check("MODEL-PROBABILITY-RANGE", 0.0 <= model.compromise_probability <= 1.0, "Probability must be within [0,1].")
        check("TRACE-EVENTS-EXIST", set(proposal.evidence_event_ids).issubset(known_event_ids), "All cited evidence IDs must exist in the case.")
        traced_ids = {event_id for rows in model.feature_trace.values() for event_id in rows}
        check("MODEL-FEATURE-TRACE", traced_ids.issubset(known_event_ids), "Every model feature trace must resolve to a case event.")
        check("NO-HUMAN-ONLY-EXECUTION", not (set(proposal.executable_actions) & human_only_actions), "Human-only actions cannot appear in the executable action set.")
        check("EXECUTABLE-ACTIONS-ALLOWLISTED", set(proposal.executable_actions).issubset(autonomous_actions), "Executable actions must be on the autonomous allowlist.")

        if proposal.disposition == Disposition.CONTAIN_REVERSIBLE.value:
            threshold = float(self.config.thresholds["autonomous_containment_min_probability"])
            check("CONTAIN-RISK-THRESHOLD", model.compromise_probability >= threshold, f"Containment requires probability >= {threshold:.2f}.")
            check("CONTAIN-EVIDENCE-QUALITY", evidence.evidence_quality >= float(self.config.evidence["minimum_quality"]), "Evidence quality must meet the automation threshold.")
            check("CONTAIN-PROVENANCE", evidence.provenance_valid_ratio >= float(self.config.evidence["minimum_provenance_ratio"]), "Evidence provenance ratio is insufficient.")
            check("CONTAIN-INTEGRITY", evidence.integrity_verified_ratio >= float(self.config.evidence["minimum_integrity_verified_ratio"]), "Evidence integrity ratio is insufficient.")
            check("CONTAIN-CORROBORATION", evidence.independent_supporting_sources >= int(self.config.evidence["minimum_independent_supporting_sources"]), "Independent source corroboration is insufficient.")
            check("CONTAIN-NO-CONFLICT", evidence.conflict_count <= int(self.config.evidence["maximum_conflicts_for_automation"]), "Conflicting sources prohibit automation.")
            check("CONTAIN-NO-POISON", not evidence.poisoned_evidence, "Instructional or poisoned evidence prohibits automation.")
            check("CONTAIN-NOT-BREAK-GLASS", not case.break_glass, "Break-glass identities require human authorization.")
            check("CONTAIN-ASSET-BOUNDARY", case.asset_criticality <= float(self.config.authority["maximum_asset_criticality_for_automation"]), "Asset criticality exceeds the autonomous boundary.")
            check("CONTAIN-ROLLBACK", all(action in proposal.rollback_plan for action in proposal.executable_actions), "Every autonomous action requires a rollback plan.")
            check("CONTAIN-ACTIONS-PRESENT", bool(proposal.executable_actions), "Containment disposition requires at least one executable action.")
        else:
            check("NON-CONTAIN-NO-EXECUTION", not proposal.executable_actions, "Non-containment dispositions cannot execute production actions.")

        return VerificationResult(passed=not blockers, checks=checks, blocking_reasons=blockers)
