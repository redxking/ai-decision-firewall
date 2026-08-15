from __future__ import annotations

import math
from typing import Any

from .models import ConsequenceAssessment


def _field(value: Any, name: str) -> Any:
    if isinstance(value, dict):
        return value[name]
    return getattr(value, name)


def assess_consequence(
    *,
    target: Any,
    action_policy: Any,
    consequence_policy: Any,
    parameters: dict[str, Any],
) -> ConsequenceAssessment:
    """Evaluate the consequence of the requested synthetic action.

    All authoritative values are supplied by the validated target and action
    catalogs, not by the external request's target labels.
    """

    criticality = str(_field(target, "criticality"))
    isolation_consequence = str(_field(target, "isolation_consequence"))
    dependencies = tuple(str(row) for row in _field(target, "dependencies"))
    blast_radius = str(_field(target, "blast_radius"))
    catalog_downtime = int(_field(target, "estimated_downtime_minutes"))
    mission_impact = str(_field(target, "mission_impact"))
    safety_impact = str(_field(target, "safety_impact"))
    availability_impact = str(_field(target, "availability_impact"))
    reversible = bool(_field(action_policy, "reversible"))
    maximum_duration = int(_field(action_policy, "maximum_duration_seconds"))
    requested_duration = int(parameters["duration_seconds"])
    effective_duration = min(requested_duration, maximum_duration)
    downtime = max(catalog_downtime, math.ceil(effective_duration / 60.0))
    approval_criticalities = {
        str(row) for row in _field(action_policy, "human_approval_criticalities")
    }
    target_requires_approval = bool(_field(target, "human_approval_required"))

    factor_weights = dict(_field(consequence_policy, "factor_weights"))
    criticality_weights = dict(_field(consequence_policy, "criticality_weights"))
    blast_weights = dict(_field(consequence_policy, "blast_radius_weights"))
    impact_weights = dict(_field(consequence_policy, "impact_weights"))
    downtime_reference = int(_field(consequence_policy, "downtime_reference_minutes"))
    dependency_reference = int(_field(consequence_policy, "dependency_reference_count"))
    high_threshold = float(_field(consequence_policy, "high_threshold"))
    critical_threshold = float(_field(consequence_policy, "critical_threshold"))
    approval_levels = set(_field(consequence_policy, "approval_levels"))
    approval_isolation = set(
        _field(consequence_policy, "approval_isolation_consequences")
    )
    approval_mission = set(_field(consequence_policy, "approval_mission_impacts"))
    approval_safety = set(_field(consequence_policy, "approval_safety_impacts"))
    approval_availability = set(
        _field(consequence_policy, "approval_availability_impacts")
    )
    approval_blast = set(_field(consequence_policy, "approval_blast_radii"))
    approval_downtime = int(_field(consequence_policy, "approval_downtime_minutes"))
    cascade_requires_approval = bool(
        _field(consequence_policy, "cascading_requires_approval")
    )

    dependency_pressure = min(1.0, len(dependencies) / dependency_reference)
    downtime_pressure = min(1.0, downtime / downtime_reference)
    score = (
        float(factor_weights["criticality"]) * float(criticality_weights[criticality])
        + float(factor_weights["blast_radius"]) * float(blast_weights[blast_radius])
        + float(factor_weights["downtime"]) * downtime_pressure
        + float(factor_weights["mission_impact"])
        * float(impact_weights[mission_impact])
        + float(factor_weights["safety_impact"]) * float(impact_weights[safety_impact])
        + float(factor_weights["availability_impact"])
        * float(impact_weights[availability_impact])
        + float(factor_weights["dependency"]) * dependency_pressure
        + float(factor_weights["isolation_consequence"])
        * float(impact_weights[isolation_consequence])
    )
    if not reversible:
        score += float(_field(consequence_policy, "irreversible_penalty"))
    score = round(min(1.0, max(0.0, score)), 6)

    if score >= critical_threshold:
        level = "CRITICAL"
    elif score >= high_threshold:
        level = "HIGH"
    elif score >= 0.25:
        level = "MEDIUM"
    else:
        level = "LOW"

    cascading = bool(dependencies) and blast_radius in {"SERVICE", "ENTERPRISE"}
    human_approval = (
        target_requires_approval
        or criticality in approval_criticalities
        or level in approval_levels
        or isolation_consequence in approval_isolation
        or mission_impact in approval_mission
        or safety_impact in approval_safety
        or availability_impact in approval_availability
        or blast_radius in approval_blast
        or downtime >= approval_downtime
        # A cataloged dependency with service- or enterprise-scale blast
        # radius can propagate beyond the named target even when that target
        # is otherwise low criticality.  Treat that ambiguity as an approval
        # boundary instead of allowing a locally scored action to automate.
        or (cascading and cascade_requires_approval)
    )
    reasons: list[str] = []
    if criticality == "TIER_0":
        reasons.append("PROTECTED_ASSET")
    if "AUTHENTICATION_SERVICE" in dependencies:
        reasons.append("AUTHENTICATION_SERVICE_DEPENDENCY")
    if cascading:
        reasons.append("CASCADING_EFFECT_POSSIBLE")
    if level in {"HIGH", "CRITICAL"}:
        reasons.append("HIGH_OPERATIONAL_CONSEQUENCE")
    if isolation_consequence in {"HIGH", "CRITICAL"}:
        reasons.append("HIGH_ISOLATION_CONSEQUENCE")
    if human_approval:
        reasons.append("HUMAN_APPROVAL_REQUIRED")
    if reversible:
        reasons.append("REVERSIBLE_ACTION")
    else:
        reasons.append("IRREVERSIBLE_ACTION")

    return ConsequenceAssessment(
        score=score,
        level=level,
        reversible=reversible,
        blast_radius=blast_radius,
        downtime_minutes=downtime,
        privilege_impact="HIGH" if criticality in {"HIGH", "TIER_0"} else "MEDIUM",
        mission_impact=mission_impact,
        safety_impact=safety_impact,
        availability_impact=availability_impact,
        dependency_count=len(dependencies),
        cascading_effect_possible=cascading,
        human_approval_required=human_approval,
        reason_codes=tuple(reasons),
    )
