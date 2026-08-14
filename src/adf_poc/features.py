from __future__ import annotations

from collections import defaultdict
from typing import Any

from .schemas import IdentityCase
from .utils import clamp


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


def extract_features(case: IdentityCase) -> tuple[dict[str, float], dict[str, list[str]]]:
    """Extract allow-listed structured features and trace each feature to source events.

    Untrusted free text is intentionally excluded from the model input. It is evaluated only by
    the evidence-safety layer.
    """
    values: dict[str, float] = {name: 0.0 for name in FEATURE_NAMES}
    trace: dict[str, list[str]] = defaultdict(list)

    values["privilege_global_admin"] = 1.0 if case.privilege_level == "global_admin" else 0.0
    values["asset_criticality"] = clamp(case.asset_criticality)

    for event in case.events:
        attrs = event.attributes
        if "failed_logins" in attrs:
            values["failed_login_intensity"] = max(values["failed_login_intensity"], clamp(float(attrs["failed_logins"]) / 20.0))
            trace["failed_login_intensity"].append(event.event_id)
        for key in (
            "new_device", "impossible_travel", "threat_ip", "mfa_fatigue", "token_reuse",
            "credential_dumping", "lateral_movement", "unusual_admin_action", "edr_malware",
            "after_hours", "known_vpn", "approved_travel", "maintenance_window",
            "service_account_baseline", "strong_mfa", "device_noncompliant", "oauth_grant",
        ):
            if key in attrs:
                numeric = 1.0 if bool(attrs[key]) else 0.0
                if numeric > values[key]:
                    values[key] = numeric
                trace[key].append(event.event_id)

    # Case-level fields are traceable to the asset-inventory event when available.
    inventory_events = [event.event_id for event in case.events if event.source_type == "asset_inventory"]
    trace["privilege_global_admin"].extend(inventory_events)
    trace["asset_criticality"].extend(inventory_events)
    return values, dict(trace)


def vectorize(features: dict[str, float]) -> list[float]:
    return [float(features.get(name, 0.0)) for name in FEATURE_NAMES]
