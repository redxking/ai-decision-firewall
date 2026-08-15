from __future__ import annotations

from collections import defaultdict

from .feature_contract import (
    MAX_FAILED_LOGINS,
    MODELED_BOOLEAN_ATTRIBUTE_NAMES,
    select_modeled_attributes,
    validate_canonical_case_feature_context,
)
from .schemas import IdentityCase


FEATURE_NAMES: tuple[str, ...] = (
    "failed_login_intensity",
    "new_device",
    "impossible_travel",
    "threat_ip",
    "mfa_fatigue",
    "token_reuse",
    "credential_dumping",
    "lateral_movement",
    "unusual_admin_action",
    "edr_malware",
    "after_hours",
    "privilege_global_admin",
    "asset_criticality",
    "known_vpn",
    "approved_travel",
    "maintenance_window",
    "service_account_baseline",
    "strong_mfa",
    "device_noncompliant",
    "oauth_grant",
)


def extract_features(
    case: IdentityCase,
) -> tuple[dict[str, float], dict[str, list[str]]]:
    """Extract allow-listed structured features and trace each feature to source events.

    Untrusted free text is intentionally excluded from the model input. It is evaluated only by
    the evidence-safety layer.
    """
    values: dict[str, float] = {name: 0.0 for name in FEATURE_NAMES}
    trace: dict[str, list[str]] = defaultdict(list)

    asset_criticality = validate_canonical_case_feature_context(
        asset_id=case.asset_id,
        privilege_level=case.privilege_level,
        break_glass=case.break_glass,
        asset_criticality=case.asset_criticality,
        inventory_attributes=(
            event.attributes
            for event in case.events
            if event.source_type == "asset_inventory"
        ),
    )
    values["privilege_global_admin"] = (
        1.0 if case.privilege_level == "global_admin" else 0.0
    )
    values["asset_criticality"] = asset_criticality

    for event in case.events:
        modeled = select_modeled_attributes(
            event.source_type,
            event.attributes,
            label=f"event[{event.event_id}].attributes",
        )
        if "failed_logins" in modeled:
            failed_logins = modeled["failed_logins"]
            if (
                type(failed_logins) is not int
                or not 0 <= failed_logins <= MAX_FAILED_LOGINS
            ):
                raise AssertionError(
                    "Validated failed_logins invariant was not preserved."
                )
            values["failed_login_intensity"] = max(
                values["failed_login_intensity"],
                min(failed_logins / 20.0, 1.0),
            )
            trace["failed_login_intensity"].append(event.event_id)
        for key in MODELED_BOOLEAN_ATTRIBUTE_NAMES:
            if key in modeled:
                value = modeled[key]
                if type(value) is not bool:
                    raise AssertionError(
                        "Validated modeled-boolean invariant was not preserved."
                    )
                numeric = 1.0 if value else 0.0
                if numeric > values[key]:
                    values[key] = numeric
                trace[key].append(event.event_id)

    # Case-level fields are traceable to the asset-inventory event when available.
    inventory_events = [
        event.event_id
        for event in case.events
        if event.source_type == "asset_inventory"
    ]
    trace["privilege_global_admin"].extend(inventory_events)
    trace["asset_criticality"].extend(inventory_events)
    return values, dict(trace)


def vectorize(features: dict[str, float]) -> list[float]:
    return [float(features.get(name, 0.0)) for name in FEATURE_NAMES]
