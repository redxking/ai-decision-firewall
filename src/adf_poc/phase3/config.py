from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from types import MappingProxyType
from typing import Any, Mapping

from jsonschema import Draft202012Validator, FormatChecker
from jsonschema.exceptions import SchemaError

from adf_poc.phase3.contracts import ActionType
from adf_poc.utils import StrictJSONError, strict_json_loads


POLICY_SCHEMA_VERSION = "0.3.0"
MAX_POLICY_BYTES = 1024 * 1024
DEFAULT_POLICY_SCHEMA = (
    Path(__file__).resolve().parents[3]
    / "contracts"
    / "v0.3.0"
    / "phase3-policy.schema.json"
)


class PolicyValidationError(ValueError):
    """Fail-closed policy error with a stable machine-readable reason code."""

    def __init__(self, reason_code: str, message: str) -> None:
        self.reason_code = reason_code
        self.code = reason_code
        self.message = message
        super().__init__(f"{reason_code}: {message}")


@dataclass(frozen=True, slots=True)
class TrustedSourcePolicy:
    source_instance: str
    source_type: str
    reliability: float
    trust_level: str

    @classmethod
    def from_dict(
        cls, source_instance: str, value: dict[str, Any]
    ) -> "TrustedSourcePolicy":
        return cls(
            source_instance=source_instance,
            source_type=str(value["source_type"]),
            reliability=float(value["reliability"]),
            trust_level=str(value["trust_level"]),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "source_type": self.source_type,
            "reliability": self.reliability,
            "trust_level": self.trust_level,
        }


@dataclass(frozen=True, slots=True)
class EvidencePolicyRules:
    hypothesis_claim: str
    maximum_age_seconds: int
    minimum_reliability: float
    minimum_relevance: float
    minimum_overall_strength_for_allow: float
    minimum_corroborating_sources: int
    maximum_conflicts_for_allow: int
    trust_weights: Mapping[str, float]
    required_source_types_by_action: Mapping[str, tuple[str, ...]]
    trusted_sources: Mapping[str, TrustedSourcePolicy]

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "trust_weights",
            MappingProxyType(dict(self.trust_weights)),
        )
        object.__setattr__(
            self,
            "required_source_types_by_action",
            MappingProxyType(
                {
                    str(action): tuple(source_types)
                    for action, source_types in self.required_source_types_by_action.items()
                }
            ),
        )
        object.__setattr__(
            self,
            "trusted_sources",
            MappingProxyType(dict(self.trusted_sources)),
        )

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> "EvidencePolicyRules":
        return cls(
            hypothesis_claim=str(value["hypothesis_claim"]),
            maximum_age_seconds=int(value["maximum_age_seconds"]),
            minimum_reliability=float(value["minimum_reliability"]),
            minimum_relevance=float(value["minimum_relevance"]),
            minimum_overall_strength_for_allow=float(
                value["minimum_overall_strength_for_allow"]
            ),
            minimum_corroborating_sources=int(value["minimum_corroborating_sources"]),
            maximum_conflicts_for_allow=int(value["maximum_conflicts_for_allow"]),
            trust_weights={
                str(name): float(weight)
                for name, weight in value["trust_weights"].items()
            },
            required_source_types_by_action={
                str(action): tuple(str(item) for item in source_types)
                for action, source_types in value[
                    "required_source_types_by_action"
                ].items()
            },
            trusted_sources={
                str(name): TrustedSourcePolicy.from_dict(str(name), row)
                for name, row in value["trusted_sources"].items()
            },
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "hypothesis_claim": self.hypothesis_claim,
            "maximum_age_seconds": self.maximum_age_seconds,
            "minimum_reliability": self.minimum_reliability,
            "minimum_relevance": self.minimum_relevance,
            "minimum_overall_strength_for_allow": self.minimum_overall_strength_for_allow,
            "minimum_corroborating_sources": self.minimum_corroborating_sources,
            "maximum_conflicts_for_allow": self.maximum_conflicts_for_allow,
            "trust_weights": dict(self.trust_weights),
            "required_source_types_by_action": {
                action: list(source_types)
                for action, source_types in self.required_source_types_by_action.items()
            },
            "trusted_sources": {
                name: source.to_dict() for name, source in self.trusted_sources.items()
            },
        }


@dataclass(frozen=True, slots=True)
class ConsequencePolicy:
    factor_weights: Mapping[str, float]
    criticality_weights: Mapping[str, float]
    blast_radius_weights: Mapping[str, float]
    impact_weights: Mapping[str, float]
    downtime_reference_minutes: int
    dependency_reference_count: int
    irreversible_penalty: float
    high_threshold: float
    critical_threshold: float
    approval_levels: tuple[str, ...]
    approval_isolation_consequences: tuple[str, ...]
    approval_mission_impacts: tuple[str, ...]
    approval_safety_impacts: tuple[str, ...]
    approval_availability_impacts: tuple[str, ...]
    approval_blast_radii: tuple[str, ...]
    approval_downtime_minutes: int
    cascading_requires_approval: bool

    def __post_init__(self) -> None:
        for field_name in (
            "factor_weights",
            "criticality_weights",
            "blast_radius_weights",
            "impact_weights",
        ):
            object.__setattr__(
                self,
                field_name,
                MappingProxyType(dict(getattr(self, field_name))),
            )

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> "ConsequencePolicy":
        return cls(
            factor_weights={
                str(k): float(v) for k, v in value["factor_weights"].items()
            },
            criticality_weights={
                str(k): float(v) for k, v in value["criticality_weights"].items()
            },
            blast_radius_weights={
                str(k): float(v) for k, v in value["blast_radius_weights"].items()
            },
            impact_weights={
                str(k): float(v) for k, v in value["impact_weights"].items()
            },
            downtime_reference_minutes=int(value["downtime_reference_minutes"]),
            dependency_reference_count=int(value["dependency_reference_count"]),
            irreversible_penalty=float(value["irreversible_penalty"]),
            high_threshold=float(value["high_threshold"]),
            critical_threshold=float(value["critical_threshold"]),
            approval_levels=tuple(str(row) for row in value["approval_levels"]),
            approval_isolation_consequences=tuple(
                str(row) for row in value["approval_isolation_consequences"]
            ),
            approval_mission_impacts=tuple(
                str(row) for row in value["approval_mission_impacts"]
            ),
            approval_safety_impacts=tuple(
                str(row) for row in value["approval_safety_impacts"]
            ),
            approval_availability_impacts=tuple(
                str(row) for row in value["approval_availability_impacts"]
            ),
            approval_blast_radii=tuple(
                str(row) for row in value["approval_blast_radii"]
            ),
            approval_downtime_minutes=int(value["approval_downtime_minutes"]),
            cascading_requires_approval=bool(value["cascading_requires_approval"]),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "factor_weights": dict(self.factor_weights),
            "criticality_weights": dict(self.criticality_weights),
            "blast_radius_weights": dict(self.blast_radius_weights),
            "impact_weights": dict(self.impact_weights),
            "downtime_reference_minutes": self.downtime_reference_minutes,
            "dependency_reference_count": self.dependency_reference_count,
            "irreversible_penalty": self.irreversible_penalty,
            "high_threshold": self.high_threshold,
            "critical_threshold": self.critical_threshold,
            "approval_levels": list(self.approval_levels),
            "approval_isolation_consequences": list(
                self.approval_isolation_consequences
            ),
            "approval_mission_impacts": list(self.approval_mission_impacts),
            "approval_safety_impacts": list(self.approval_safety_impacts),
            "approval_availability_impacts": list(self.approval_availability_impacts),
            "approval_blast_radii": list(self.approval_blast_radii),
            "approval_downtime_minutes": self.approval_downtime_minutes,
            "cascading_requires_approval": self.cascading_requires_approval,
        }


@dataclass(frozen=True, slots=True)
class DecisionRule:
    id: str
    condition: str
    outcome: str

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> "DecisionRule":
        return cls(
            id=str(value["id"]),
            condition=str(value["condition"]),
            outcome=str(value["outcome"]),
        )

    def to_dict(self) -> dict[str, Any]:
        return {"id": self.id, "condition": self.condition, "outcome": self.outcome}


@dataclass(frozen=True, slots=True)
class ActionPolicy:
    action_type: ActionType
    reversible: bool
    allowed_target_types: tuple[str, ...]
    required_authority: str
    tier_0_required_authority: str
    maximum_duration_seconds: int
    preserve_management_required: bool
    human_approval_criticalities: tuple[str, ...]

    @classmethod
    def from_dict(cls, action_type: str, value: dict[str, Any]) -> "ActionPolicy":
        return cls(
            action_type=ActionType(action_type),
            reversible=bool(value["reversible"]),
            allowed_target_types=tuple(
                str(item) for item in value["allowed_target_types"]
            ),
            required_authority=str(value["required_authority"]),
            tier_0_required_authority=str(value["tier_0_required_authority"]),
            maximum_duration_seconds=int(value["maximum_duration_seconds"]),
            preserve_management_required=bool(value["preserve_management_required"]),
            human_approval_criticalities=tuple(
                str(item) for item in value["human_approval_criticalities"]
            ),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "reversible": self.reversible,
            "allowed_target_types": list(self.allowed_target_types),
            "required_authority": self.required_authority,
            "tier_0_required_authority": self.tier_0_required_authority,
            "maximum_duration_seconds": self.maximum_duration_seconds,
            "preserve_management_required": self.preserve_management_required,
            "human_approval_criticalities": list(self.human_approval_criticalities),
        }


@dataclass(frozen=True, slots=True)
class TargetRecord:
    id: str
    type: str
    criticality: str
    classification: str
    dependencies: tuple[str, ...]
    isolation_consequence: str
    estimated_downtime_minutes: int
    blast_radius: str
    mission_impact: str
    safety_impact: str
    availability_impact: str
    human_approval_required: bool

    @classmethod
    def from_dict(cls, target_id: str, value: dict[str, Any]) -> "TargetRecord":
        return cls(
            id=target_id,
            type=str(value["type"]),
            criticality=str(value["criticality"]),
            classification=str(value["classification"]),
            dependencies=tuple(str(item) for item in value["dependencies"]),
            isolation_consequence=str(value["isolation_consequence"]),
            estimated_downtime_minutes=int(value["estimated_downtime_minutes"]),
            blast_radius=str(value["blast_radius"]),
            mission_impact=str(value["mission_impact"]),
            safety_impact=str(value["safety_impact"]),
            availability_impact=str(value["availability_impact"]),
            human_approval_required=bool(value["human_approval_required"]),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "type": self.type,
            "criticality": self.criticality,
            "classification": self.classification,
            "dependencies": list(self.dependencies),
            "isolation_consequence": self.isolation_consequence,
            "estimated_downtime_minutes": self.estimated_downtime_minutes,
            "blast_radius": self.blast_radius,
            "mission_impact": self.mission_impact,
            "safety_impact": self.safety_impact,
            "availability_impact": self.availability_impact,
            "human_approval_required": self.human_approval_required,
        }


@dataclass(frozen=True, slots=True)
class Phase3PolicyConfig:
    schema_version: str
    policy_id: str
    version: str
    evidence: EvidencePolicyRules
    consequence: ConsequencePolicy
    decision_rules: tuple[DecisionRule, ...]
    action_catalog: Mapping[str, ActionPolicy]
    target_inventory: Mapping[str, TargetRecord]
    authorization_ttl_seconds: int
    authorization_single_use: bool
    approval_ttl_seconds: int

    def __post_init__(self) -> None:
        object.__setattr__(
            self, "action_catalog", MappingProxyType(dict(self.action_catalog))
        )
        object.__setattr__(
            self, "target_inventory", MappingProxyType(dict(self.target_inventory))
        )

    @property
    def evidence_rules(self) -> EvidencePolicyRules:
        return self.evidence

    def action_policy(self, action_type: str | ActionType) -> ActionPolicy:
        name = action_type.value if isinstance(action_type, ActionType) else action_type
        return self.action_catalog[name]

    def target_record(self, target_id: str) -> TargetRecord:
        return self.target_inventory[target_id]

    @classmethod
    def load(
        cls,
        path: str | Path,
        schema_path: str | Path | None = None,
    ) -> "Phase3PolicyConfig":
        target = Path(path)
        try:
            raw = target.read_bytes()
        except OSError as exc:
            raise PolicyValidationError(
                "POLICY_READ_ERROR", "Phase 3 policy could not be read."
            ) from exc
        if len(raw) > MAX_POLICY_BYTES:
            raise PolicyValidationError(
                "POLICY_TOO_LARGE", "Phase 3 policy exceeds the 1 MiB bound."
            )
        try:
            value = strict_json_loads(raw)
        except (
            StrictJSONError,
            json.JSONDecodeError,
            UnicodeError,
            RecursionError,
        ) as exc:
            raise PolicyValidationError(
                "POLICY_JSON_INVALID",
                "Phase 3 policy is not strict JSON; duplicate members and non-finite numbers are prohibited.",
            ) from exc
        if not isinstance(value, dict):
            raise PolicyValidationError(
                "POLICY_NOT_OBJECT", "Phase 3 policy must be a JSON object."
            )
        if (
            "schema_version" in value
            and value["schema_version"] != POLICY_SCHEMA_VERSION
        ):
            raise PolicyValidationError(
                "UNSUPPORTED_POLICY_VERSION",
                f"Only Phase 3 policy schema {POLICY_SCHEMA_VERSION} is supported.",
            )

        return cls.from_dict(value, schema_path=schema_path)

    @classmethod
    def from_dict(
        cls,
        value: dict[str, Any],
        schema_path: str | Path | None = None,
    ) -> "Phase3PolicyConfig":
        """Validate and freeze a decoded policy value.

        This is also used by the firewall constructor to take a deep,
        schema-validated snapshot rather than retaining caller-owned mappings.
        """

        if not isinstance(value, dict):
            raise PolicyValidationError(
                "POLICY_NOT_OBJECT", "Phase 3 policy must be a JSON object."
            )
        if (
            "schema_version" in value
            and value["schema_version"] != POLICY_SCHEMA_VERSION
        ):
            raise PolicyValidationError(
                "UNSUPPORTED_POLICY_VERSION",
                f"Only Phase 3 policy schema {POLICY_SCHEMA_VERSION} is supported.",
            )
        schema = _load_policy_schema(schema_path)
        validator = Draft202012Validator(schema, format_checker=FormatChecker())
        errors = sorted(
            validator.iter_errors(value),
            key=lambda error: (
                tuple(str(item) for item in error.absolute_path),
                error.message,
            ),
        )
        if errors:
            error = errors[0]
            path_label = ".".join(str(item) for item in error.absolute_path)
            prefix = f"{path_label}: " if path_label else ""
            raise PolicyValidationError(
                "POLICY_SCHEMA_INVALID", (prefix + error.message)[:500]
            )
        _validate_policy_safety_invariants(value)

        return cls(
            schema_version=str(value["schema_version"]),
            policy_id=str(value["policy_id"]),
            version=str(value["version"]),
            evidence=EvidencePolicyRules.from_dict(value["evidence"]),
            consequence=ConsequencePolicy.from_dict(value["consequence"]),
            decision_rules=tuple(
                DecisionRule.from_dict(row) for row in value["decision_rules"]
            ),
            action_catalog={
                str(name): ActionPolicy.from_dict(str(name), row)
                for name, row in value["action_catalog"].items()
            },
            target_inventory={
                str(name): TargetRecord.from_dict(str(name), row)
                for name, row in value["target_inventory"].items()
            },
            authorization_ttl_seconds=int(value["authorization"]["ttl_seconds"]),
            authorization_single_use=bool(value["authorization"]["single_use"]),
            approval_ttl_seconds=int(value["approval"]["ttl_seconds"]),
        )

    def immutable_snapshot(self) -> "Phase3PolicyConfig":
        return Phase3PolicyConfig.from_dict(Phase3PolicyConfig.to_dict(self))

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "policy_id": self.policy_id,
            "version": self.version,
            "evidence": self.evidence.to_dict(),
            "consequence": self.consequence.to_dict(),
            "decision_rules": [rule.to_dict() for rule in self.decision_rules],
            "action_catalog": {
                name: policy.to_dict() for name, policy in self.action_catalog.items()
            },
            "target_inventory": {
                name: target.to_dict() for name, target in self.target_inventory.items()
            },
            "authorization": {
                "ttl_seconds": self.authorization_ttl_seconds,
                "single_use": self.authorization_single_use,
            },
            "approval": {"ttl_seconds": self.approval_ttl_seconds},
        }


def _load_policy_schema(path: str | Path | None) -> dict[str, Any]:
    target = Path(path) if path is not None else DEFAULT_POLICY_SCHEMA
    try:
        raw = target.read_bytes()
        if len(raw) > MAX_POLICY_BYTES:
            raise PolicyValidationError(
                "POLICY_SCHEMA_INVALID_CONFIGURATION",
                "Phase 3 policy schema exceeds its size bound.",
            )
        value = strict_json_loads(raw)
        if not isinstance(value, dict):
            raise PolicyValidationError(
                "POLICY_SCHEMA_INVALID_CONFIGURATION",
                "Phase 3 policy schema must be a JSON object.",
            )
        Draft202012Validator.check_schema(value)
        return value
    except PolicyValidationError:
        raise
    except (OSError, StrictJSONError, ValueError, UnicodeError, SchemaError) as exc:
        raise PolicyValidationError(
            "POLICY_SCHEMA_INVALID_CONFIGURATION",
            "Phase 3 policy schema could not be loaded or validated.",
        ) from exc


def _validate_policy_safety_invariants(value: dict[str, Any]) -> None:
    evidence = value["evidence"]
    if evidence["hypothesis_claim"] != "COMPROMISE":
        raise PolicyValidationError(
            "POLICY_SAFETY_INVARIANT",
            "The Phase 3 SOC MVP evaluates the closed COMPROMISE hypothesis.",
        )
    trust_weights = evidence["trust_weights"]
    if not (
        float(trust_weights["HIGH"])
        > float(trust_weights["MEDIUM"])
        > float(trust_weights["LOW"])
        > float(trust_weights["UNTRUSTED"])
        == 0.0
    ):
        raise PolicyValidationError(
            "POLICY_SAFETY_INVARIANT",
            "Evidence trust weights must descend from HIGH to an exact zero UNTRUSTED weight.",
        )
    if (
        float(evidence["minimum_reliability"]) < 0.5
        or float(evidence["minimum_relevance"]) <= 0.0
        or float(evidence["minimum_overall_strength_for_allow"]) < 0.5
        or int(evidence["minimum_corroborating_sources"]) < 2
        or int(evidence["maximum_conflicts_for_allow"]) != 0
    ):
        raise PolicyValidationError(
            "POLICY_SAFETY_INVARIANT",
            "Automation-grade evidence thresholds must retain conservative positive floors.",
        )
    if any(
        row["trust_level"] == "UNTRUSTED"
        or float(row["reliability"]) < float(evidence["minimum_reliability"])
        for row in evidence["trusted_sources"].values()
    ):
        raise PolicyValidationError(
            "POLICY_SAFETY_INVARIANT",
            "Registered trusted sources cannot be untrusted or below the reliability floor.",
        )

    consequence = value["consequence"]

    def _strictly_increasing(mapping: dict[str, Any], order: tuple[str, ...]) -> bool:
        values = [float(mapping[name]) for name in order]
        return all(left < right for left, right in zip(values, values[1:]))

    if (
        not _strictly_increasing(
            consequence["criticality_weights"], ("LOW", "MEDIUM", "HIGH", "TIER_0")
        )
        or not _strictly_increasing(
            consequence["blast_radius_weights"], ("LOCAL", "SERVICE", "ENTERPRISE")
        )
        or not _strictly_increasing(
            consequence["impact_weights"], ("NONE", "LOW", "MEDIUM", "HIGH", "CRITICAL")
        )
    ):
        raise PolicyValidationError(
            "POLICY_SAFETY_INVARIANT",
            "Consequence severity weights must increase monotonically.",
        )
    if any(float(weight) <= 0 for weight in consequence["factor_weights"].values()):
        raise PolicyValidationError(
            "POLICY_SAFETY_INVARIANT",
            "Every consequence factor must retain a positive weight.",
        )
    if consequence["high_threshold"] >= consequence["critical_threshold"]:
        raise PolicyValidationError(
            "POLICY_SAFETY_INVARIANT",
            "Consequence HIGH threshold must be lower than CRITICAL threshold.",
        )
    if not consequence["cascading_requires_approval"]:
        raise PolicyValidationError(
            "POLICY_SAFETY_INVARIANT",
            "Cascading service effects must remain a human-approval boundary.",
        )
    if not {"HIGH", "CRITICAL"}.issubset(consequence["approval_levels"]):
        raise PolicyValidationError(
            "POLICY_SAFETY_INVARIANT",
            "HIGH and CRITICAL consequence levels must require human approval.",
        )
    if not {"HIGH", "CRITICAL"}.issubset(
        consequence["approval_isolation_consequences"]
    ):
        raise PolicyValidationError(
            "POLICY_SAFETY_INVARIANT",
            "HIGH and CRITICAL isolation consequences must require human approval.",
        )
    severe_floors = (
        ("approval_mission_impacts", {"CRITICAL"}),
        ("approval_safety_impacts", {"HIGH"}),
        ("approval_availability_impacts", {"CRITICAL"}),
        ("approval_blast_radii", {"ENTERPRISE"}),
    )
    if (
        any(
            not required.issubset(set(consequence[name]))
            for name, required in severe_floors
        )
        or int(consequence["approval_downtime_minutes"]) > 60
    ):
        raise PolicyValidationError(
            "POLICY_SAFETY_INVARIANT",
            "Single severe consequence factors must retain human-approval floors.",
        )

    required_rule_sequence = (
        ("IDENTITY_FATAL", "DENY"),
        ("EVIDENCE_FATAL", "DENY"),
        ("TARGET_TYPE_PROHIBITED", "DENY"),
        ("TARGET_TIER_0", "ESCALATE"),
        ("CONSEQUENCE_REQUIRES_APPROVAL", "ESCALATE"),
        ("AUTHORITY_INSUFFICIENT", "DENY"),
        ("EVIDENCE_NOT_AUTOMATION_GRADE", "ESCALATE"),
        ("PARAMETER_CONSTRAINTS_PRESENT", "ALLOW_CONSTRAINED"),
        ("DEFAULT", "ALLOW"),
    )
    observed_rule_sequence = tuple(
        (row["condition"], row["outcome"]) for row in value["decision_rules"]
    )
    if observed_rule_sequence != required_rule_sequence:
        raise PolicyValidationError(
            "POLICY_SAFETY_INVARIANT",
            "Decision rules must use the closed fail-closed Phase 3 precedence.",
        )
    rule_ids = [row["id"] for row in value["decision_rules"]]
    if len(rule_ids) != len(set(rule_ids)):
        raise PolicyValidationError(
            "POLICY_SAFETY_INVARIANT", "Decision rule identifiers must be unique."
        )

    action = value["action_catalog"][ActionType.NETWORK_ISOLATE.value]
    if not action["reversible"] or not action["preserve_management_required"]:
        raise PolicyValidationError(
            "POLICY_SAFETY_INVARIANT",
            "NETWORK_ISOLATE must remain reversible and preserve management access.",
        )
    if not {"HIGH", "TIER_0"}.issubset(action["human_approval_criticalities"]):
        raise PolicyValidationError(
            "POLICY_SAFETY_INVARIANT",
            "HIGH and TIER_0 NETWORK_ISOLATE requests must require human approval.",
        )

    inventory = value["target_inventory"]
    for target_id, target in inventory.items():
        if target["type"] == "DOMAIN_CONTROLLER" and (
            target["criticality"] != "TIER_0"
            or not target["human_approval_required"]
            or target["isolation_consequence"] not in {"HIGH", "CRITICAL"}
            or "AUTHENTICATION_SERVICE" not in target["dependencies"]
        ):
            raise PolicyValidationError(
                "POLICY_SAFETY_INVARIANT",
                f"{target_id} must remain a Tier-0 protected authentication dependency.",
            )
    workstation = inventory["WORKSTATION_042"]
    if workstation["type"] != "WORKSTATION" or workstation["criticality"] != "LOW":
        raise PolicyValidationError(
            "POLICY_SAFETY_INVARIANT",
            "WORKSTATION_042 must remain the low-criticality workstation target.",
        )

    trusted_source_types = {
        row["source_type"] for row in value["evidence"]["trusted_sources"].values()
    }
    required_source_types = set(
        value["evidence"]["required_source_types_by_action"][
            ActionType.NETWORK_ISOLATE.value
        ]
    )
    missing_trusted_types = required_source_types - trusted_source_types
    if missing_trusted_types:
        raise PolicyValidationError(
            "POLICY_SAFETY_INVARIANT",
            "Each required evidence source type must have an authoritative trusted-source policy.",
        )
