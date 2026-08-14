from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from .evidence import EvidenceAssessment
from .model import ModelAssessment
from .schemas import Disposition, IdentityCase


@dataclass(slots=True)
class PolicyConfig:
    policy_id: str
    version: str
    thresholds: dict[str, float]
    evidence: dict[str, float]
    authority: dict[str, Any]
    safety: dict[str, Any]

    @classmethod
    def load(cls, path: str | Path) -> "PolicyConfig":
        value = json.loads(Path(path).read_text(encoding="utf-8"))
        return cls(**value)


@dataclass(slots=True)
class DecisionProposal:
    disposition: str
    executable_actions: list[str]
    recommended_human_actions: list[str]
    investigation_actions: list[str]
    rationale: list[str]
    policy_rules_applied: list[str]
    evidence_event_ids: list[str]
    required_authority: str
    rollback_plan: dict[str, str]

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class PolicyEngine:
    def __init__(self, config: PolicyConfig) -> None:
        self.config = config

    def propose(
        self,
        case: IdentityCase,
        model: ModelAssessment,
        evidence: EvidenceAssessment,
    ) -> DecisionProposal:
        probability = model.compromise_probability
        t = self.config.thresholds
        e = self.config.evidence
        a = self.config.authority
        s = self.config.safety
        severe = any(
            model.feature_values.get(name, 0.0) >= 1.0
            for name in ("credential_dumping", "lateral_movement", "token_reuse", "oauth_grant")
        )
        rationale: list[str] = []
        rules: list[str] = []
        evidence_ids = sorted(set(evidence.positive_event_ids + evidence.benign_event_ids + evidence.poisoned_event_ids))

        evidence_is_decision_grade = (
            evidence.evidence_quality >= float(e["minimum_quality"])
            and evidence.provenance_valid_ratio >= float(e["minimum_provenance_ratio"])
            and evidence.integrity_verified_ratio >= float(e["minimum_integrity_verified_ratio"])
            and evidence.conflict_count <= int(e["maximum_conflicts_for_automation"])
            and len(evidence.missing_expected_sources) <= int(e["maximum_missing_expected_sources_for_decision"])
            and not (bool(s["poisoned_evidence_blocks_automation"]) and evidence.poisoned_evidence)
        )
        evidence_is_automation_grade = (
            evidence_is_decision_grade
            and evidence.independent_supporting_sources >= int(e["minimum_independent_supporting_sources"])
        )

        if evidence.poisoned_evidence and bool(s["poisoned_evidence_blocks_automation"]):
            rules.append("SAFETY-POISON-ABSTAIN")
            rationale.append("Adversarial or instructional content is present in an untrusted source; autonomous action is prohibited.")
            return self._investigate(rationale, rules, evidence_ids)

        if case.break_glass and bool(a["break_glass_requires_human"]):
            rules.append("AUTH-BREAK-GLASS-HUMAN")
            rationale.append("The subject is a break-glass identity; all containment requires explicit human authorization.")
            return DecisionProposal(
                disposition=Disposition.ESCALATE_HUMAN.value,
                executable_actions=[],
                recommended_human_actions=["disable_account", "revoke_active_sessions", "validate_emergency_use"],
                investigation_actions=["validate_emergency_use", "contact_incident_commander"],
                rationale=rationale,
                policy_rules_applied=rules,
                evidence_event_ids=evidence_ids,
                required_authority="incident_commander_or_identity_owner",
                rollback_plan={},
            )

        if not evidence_is_decision_grade:
            rules.append("EVIDENCE-NOT-DECISION-GRADE")
            rationale.extend(evidence.reasons)
            rationale.append("The decision firewall abstains until provenance, integrity, completeness, or corroboration is improved.")
            return self._investigate(rationale, rules, evidence_ids)

        if probability <= float(t["no_action_max_probability"]) and not severe:
            rules.append("RISK-BELOW-NO-ACTION-THRESHOLD")
            rationale.append(f"Compromise probability {probability:.3f} is below the no-action threshold and no severe indicator is present.")
            return DecisionProposal(
                disposition=Disposition.NO_ACTION.value,
                executable_actions=[],
                recommended_human_actions=[],
                investigation_actions=[],
                rationale=rationale,
                policy_rules_applied=rules,
                evidence_event_ids=evidence_ids,
                required_authority="none",
                rollback_plan={},
            )

        can_auto_contain = (
            probability >= float(t["autonomous_containment_min_probability"])
            and case.asset_criticality <= float(a["maximum_asset_criticality_for_automation"])
            and evidence_is_automation_grade
        )
        if can_auto_contain:
            rules.extend(["RISK-AUTO-CONTAIN-THRESHOLD", "AUTH-REVERSIBLE-ACTIONS-ONLY"])
            rationale.append(
                f"Compromise probability {probability:.3f}, evidence quality {evidence.evidence_quality:.3f}, "
                f"and asset criticality {case.asset_criticality:.3f} satisfy the reversible-containment policy."
            )
            return DecisionProposal(
                disposition=Disposition.CONTAIN_REVERSIBLE.value,
                executable_actions=list(a["autonomous_actions"]),
                recommended_human_actions=[],
                investigation_actions=[],
                rationale=rationale,
                policy_rules_applied=rules,
                evidence_event_ids=evidence_ids,
                required_authority="deterministic_policy_gate",
                rollback_plan={
                    "revoke_active_sessions": "restore only through normal reauthentication; no session token is reinstated",
                    "force_step_up_auth": "remove temporary step-up requirement after analyst review",
                    "increase_monitoring": "return telemetry policy to baseline after closure",
                },
            )

        if probability >= float(t["human_escalation_min_probability"]) or severe:
            rules.append("RISK-HUMAN-ESCALATION")
            if case.asset_criticality > float(a["maximum_asset_criticality_for_automation"]):
                rules.append("AUTH-ASSET-CRITICALITY-HUMAN")
                rationale.append("Asset criticality exceeds the autonomous-action boundary.")
            rationale.append(f"Compromise probability {probability:.3f} or severe evidence requires human containment authority.")
            return DecisionProposal(
                disposition=Disposition.ESCALATE_HUMAN.value,
                executable_actions=[],
                recommended_human_actions=["disable_account", "revoke_active_sessions", "isolate_endpoint"],
                investigation_actions=["confirm_business_owner", "validate_blast_radius"],
                rationale=rationale,
                policy_rules_applied=rules,
                evidence_event_ids=evidence_ids,
                required_authority="soc_shift_lead_or_identity_owner",
                rollback_plan={},
            )

        rules.append("RISK-UNCERTAIN-INVESTIGATE")
        rationale.append(f"Compromise probability {probability:.3f} is not low enough for closure and not high enough for containment.")
        return self._investigate(rationale, rules, evidence_ids)

    @staticmethod
    def _investigate(rationale: list[str], rules: list[str], evidence_ids: list[str]) -> DecisionProposal:
        return DecisionProposal(
            disposition=Disposition.INVESTIGATE.value,
            executable_actions=[],
            recommended_human_actions=[],
            investigation_actions=[
                "query_identity_history",
                "query_endpoint_telemetry",
                "validate_change_and_travel_context",
            ],
            rationale=rationale,
            policy_rules_applied=rules,
            evidence_event_ids=evidence_ids,
            required_authority="read_only_automation",
            rollback_plan={},
        )
