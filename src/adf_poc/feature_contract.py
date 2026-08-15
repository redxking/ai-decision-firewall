"""Typed, source-authorized boundary for model-driving event attributes.

Event ``attributes`` remain extensible for source-specific context.  Only the
top-level attributes declared here may drive model features, and each such
attribute is accepted only from its authorized source type with its exact
runtime type.
"""

from __future__ import annotations

import math
import re
from collections.abc import Iterable, Mapping
from typing import Any, Final


MAX_FAILED_LOGINS: Final = 1_000_000
_IDENTIFIER_PATTERN: Final = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")

MODELED_BOOLEAN_ATTRIBUTE_SOURCES: Final[dict[str, frozenset[str]]] = {
    "new_device": frozenset({"identity"}),
    "impossible_travel": frozenset({"identity"}),
    "threat_ip": frozenset({"network", "threat_intel"}),
    "mfa_fatigue": frozenset({"identity"}),
    "token_reuse": frozenset({"identity"}),
    "credential_dumping": frozenset({"endpoint"}),
    "lateral_movement": frozenset({"network"}),
    "unusual_admin_action": frozenset({"endpoint"}),
    "edr_malware": frozenset({"endpoint"}),
    "after_hours": frozenset({"identity"}),
    "known_vpn": frozenset({"network"}),
    "approved_travel": frozenset({"user_context"}),
    "maintenance_window": frozenset({"change_management"}),
    "service_account_baseline": frozenset({"change_management"}),
    "strong_mfa": frozenset({"identity"}),
    "device_noncompliant": frozenset({"endpoint"}),
    "oauth_grant": frozenset({"identity"}),
}

MODELED_INTEGER_ATTRIBUTE_SOURCES: Final[dict[str, frozenset[str]]] = {
    "failed_logins": frozenset({"identity"}),
}

# These attributes do not enter the model vector, but they do influence the
# evidence-quality assessment and can therefore change policy disposition.
# They receive the same exact-type and source-authority treatment as modeled
# attributes instead of being treated as opaque context.
EVIDENCE_BOOLEAN_ATTRIBUTE_SOURCES: Final[dict[str, frozenset[str]]] = {
    "source_conflict": frozenset({"network"}),
}

MODELED_ATTRIBUTE_SOURCES: Final[dict[str, frozenset[str]]] = {
    **MODELED_BOOLEAN_ATTRIBUTE_SOURCES,
    **MODELED_INTEGER_ATTRIBUTE_SOURCES,
}

MODELED_ATTRIBUTE_NAMES: Final[tuple[str, ...]] = tuple(MODELED_ATTRIBUTE_SOURCES)
MODELED_BOOLEAN_ATTRIBUTE_NAMES: Final[tuple[str, ...]] = tuple(
    MODELED_BOOLEAN_ATTRIBUTE_SOURCES
)


class FeatureContractError(ValueError):
    """Raised when model-driving attributes violate type or source authority."""


def _require_identifier(value: Any, label: str) -> str:
    if not isinstance(value, str) or not _IDENTIFIER_PATTERN.fullmatch(value):
        raise FeatureContractError(f"{label} must be an identifier.")
    return value


def _require_unit_interval(value: Any, label: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise FeatureContractError(f"{label} must be numeric.")
    try:
        candidate = float(value)
    except OverflowError:
        raise FeatureContractError(
            f"{label} must be finite and within [0, 1]."
        ) from None
    if not math.isfinite(candidate) or not 0.0 <= candidate <= 1.0:
        raise FeatureContractError(f"{label} must be finite and within [0, 1].")
    return candidate


def validate_canonical_case_feature_context(
    *,
    asset_id: Any,
    privilege_level: Any,
    break_glass: Any,
    asset_criticality: Any,
    inventory_attributes: Iterable[Mapping[str, Any]],
) -> float:
    """Validate case fields and every inventory assertion used by policy/features."""

    canonical_asset_id = _require_identifier(asset_id, "case.asset_id")
    canonical_privilege = _require_identifier(
        privilege_level,
        "case.privilege_level",
    )
    if type(break_glass) is not bool:
        raise FeatureContractError("case.break_glass must be a boolean.")
    canonical_criticality = _require_unit_interval(
        asset_criticality,
        "case.asset_criticality",
    )
    inventory = list(inventory_attributes)
    if not inventory:
        raise FeatureContractError("Case requires at least one asset_inventory event.")
    required = {
        "asset_id",
        "privilege_level",
        "break_glass",
        "asset_criticality",
    }
    for attributes in inventory:
        if not required.issubset(attributes):
            raise FeatureContractError(
                "asset_inventory attributes must include asset_id, privilege_level, "
                "break_glass, and asset_criticality."
            )
        inventory_asset_id = _require_identifier(
            attributes["asset_id"],
            "asset_inventory.attributes.asset_id",
        )
        inventory_privilege = _require_identifier(
            attributes["privilege_level"],
            "asset_inventory.attributes.privilege_level",
        )
        inventory_break_glass = attributes["break_glass"]
        if type(inventory_break_glass) is not bool:
            raise FeatureContractError(
                "asset_inventory.attributes.break_glass must be a boolean."
            )
        inventory_criticality = _require_unit_interval(
            attributes["asset_criticality"],
            "asset_inventory.attributes.asset_criticality",
        )
        if inventory_asset_id != canonical_asset_id:
            raise FeatureContractError(
                "Canonical asset_id must equal asset_inventory.attributes.asset_id."
            )
        if inventory_privilege != canonical_privilege:
            raise FeatureContractError(
                "Canonical privilege_level must equal "
                "asset_inventory.attributes.privilege_level."
            )
        if inventory_break_glass is not break_glass:
            raise FeatureContractError(
                "Canonical break_glass must equal "
                "asset_inventory.attributes.break_glass."
            )
        if inventory_criticality != canonical_criticality:
            raise FeatureContractError(
                "Canonical asset_criticality must equal "
                "asset_inventory.attributes.asset_criticality."
            )
    return canonical_criticality


def select_modeled_attributes(
    source_type: str,
    attributes: Mapping[str, Any],
    *,
    label: str = "event.attributes",
) -> dict[str, bool | int]:
    """Validate and return only authorized model-driving attributes.

    Unknown attributes are deliberately retained outside this projection and
    cannot influence feature extraction.
    """

    _require_identifier(source_type, "event.source_type")
    modeled: dict[str, bool | int] = {}
    for name in MODELED_ATTRIBUTE_NAMES:
        if name not in attributes:
            continue
        if source_type not in MODELED_ATTRIBUTE_SOURCES[name]:
            raise FeatureContractError(
                f"{label}.{name} is not authorized for this source_type."
            )
        value = attributes[name]
        if name in MODELED_BOOLEAN_ATTRIBUTE_SOURCES:
            if type(value) is not bool:
                raise FeatureContractError(f"{label}.{name} must be a boolean.")
            modeled[name] = value
            continue
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            raise FeatureContractError(f"{label}.{name} must be an integer.")
        if isinstance(value, float):
            if not math.isfinite(value):
                raise FeatureContractError(
                    f"{label}.{name} must be finite and within "
                    f"[0, {MAX_FAILED_LOGINS}]."
                )
            if not value.is_integer():
                raise FeatureContractError(f"{label}.{name} must be an integer.")
            candidate = int(value)
        else:
            candidate = value
        if not 0 <= candidate <= MAX_FAILED_LOGINS:
            raise FeatureContractError(
                f"{label}.{name} must be finite and within "
                f"[0, {MAX_FAILED_LOGINS}]."
            )
        modeled[name] = candidate
    return modeled


def select_evidence_attributes(
    source_type: str,
    attributes: Mapping[str, Any],
    *,
    label: str = "event.attributes",
) -> dict[str, bool]:
    """Validate and return source-authorized evidence-quality attributes."""

    _require_identifier(source_type, "event.source_type")
    selected: dict[str, bool] = {}
    for name, authorized_sources in EVIDENCE_BOOLEAN_ATTRIBUTE_SOURCES.items():
        if name not in attributes:
            continue
        if source_type not in authorized_sources:
            raise FeatureContractError(
                f"{label}.{name} is not authorized for this source_type."
            )
        value = attributes[name]
        if type(value) is not bool:
            raise FeatureContractError(f"{label}.{name} must be a boolean.")
        selected[name] = value
    return selected


__all__ = [
    "FeatureContractError",
    "EVIDENCE_BOOLEAN_ATTRIBUTE_SOURCES",
    "MAX_FAILED_LOGINS",
    "MODELED_ATTRIBUTE_NAMES",
    "MODELED_ATTRIBUTE_SOURCES",
    "MODELED_BOOLEAN_ATTRIBUTE_NAMES",
    "MODELED_BOOLEAN_ATTRIBUTE_SOURCES",
    "MODELED_INTEGER_ATTRIBUTE_SOURCES",
    "select_modeled_attributes",
    "select_evidence_attributes",
    "validate_canonical_case_feature_context",
]
