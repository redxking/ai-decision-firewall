"""Diverse, read-only recomputation of Phase 2 model feature projections.

This module intentionally uses only the Python standard library and does not
reuse the production feature, model, policy, verifier, harness, or metrics
paths.  Its public verifier emits metadata-only assurance records.  A failed
comparison raises a code-owned exception before any projection values or traces
can be returned to the caller.
"""

from __future__ import annotations

from datetime import datetime
import hashlib
import json
import math
import re
from typing import Any


REFERENCE_FEATURE_NAMES: tuple[str, ...] = (
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

_BOOLEAN_FEATURE_SOURCES: dict[str, frozenset[str]] = {
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

_FAILED_LOGIN_SOURCES = frozenset({"identity"})
_MAX_FAILED_LOGINS = 1_000_000
_CASE_FIELDS = frozenset(
    {
        "case_id",
        "opened_at",
        "subject_id",
        "privilege_level",
        "break_glass",
        "asset_id",
        "asset_criticality",
        "events",
    }
)
_EVENT_FIELDS = frozenset(
    {
        "event_id",
        "case_id",
        "source_type",
        "source_instance",
        "observed_at",
        "collected_at",
        "integrity",
        "provenance_id",
        "trust_score",
        "entity_refs",
        "attributes",
        "untrusted_text",
        "contains_instructional_content",
    }
)
_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_INTEGRITY_VALUES = frozenset({"verified", "unverified", "failed"})


class ReferenceFeatureAssuranceError(ValueError):
    """Fail-closed reference assurance error containing only a stable code."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


def _fail(code: str) -> None:
    raise ReferenceFeatureAssuranceError(code)


def _is_number(value: Any) -> bool:
    return isinstance(value, (int, float)) and not isinstance(value, bool)


def _bounded_number(value: Any, *, code: str) -> float:
    if not _is_number(value):
        _fail(code)
    try:
        number = float(value)
    except OverflowError:
        _fail(code)
    if not math.isfinite(number) or not 0.0 <= number <= 1.0:
        _fail(code)
    return number


def _identifier(value: Any, *, code: str, allow_empty: bool = False) -> str:
    if not isinstance(value, str):
        _fail(code)
    if allow_empty and value == "":
        return value
    if _IDENTIFIER.fullmatch(value) is None:
        _fail(code)
    return value


def _timestamp(value: Any) -> datetime:
    if not isinstance(value, str):
        _fail("REFERENCE_FEATURE_TIMESTAMP")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        _fail("REFERENCE_FEATURE_TIMESTAMP")
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        _fail("REFERENCE_FEATURE_TIMESTAMP")
    return parsed


def _canonical_sha256(value: Any) -> str:
    try:
        encoded = json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError):
        _fail("REFERENCE_FEATURE_CANONICALIZATION")
    return hashlib.sha256(encoded).hexdigest()


def _validate_event(
    event: Any,
    *,
    case_id: str,
) -> tuple[dict[str, Any], tuple[datetime, datetime, str, str, str]]:
    if not isinstance(event, dict) or frozenset(event) != _EVENT_FIELDS:
        _fail("REFERENCE_FEATURE_EVENT_SHAPE")

    event_id = _identifier(
        event.get("event_id"), code="REFERENCE_FEATURE_EVENT_IDENTIFIER"
    )
    bound_case_id = _identifier(
        event.get("case_id"), code="REFERENCE_FEATURE_EVENT_IDENTIFIER"
    )
    if bound_case_id != case_id:
        _fail("REFERENCE_FEATURE_EVENT_CASE_BINDING")
    source_type = _identifier(
        event.get("source_type"), code="REFERENCE_FEATURE_EVENT_IDENTIFIER"
    )
    source_instance = _identifier(
        event.get("source_instance"), code="REFERENCE_FEATURE_EVENT_IDENTIFIER"
    )
    observed_at = _timestamp(event.get("observed_at"))
    collected_at = _timestamp(event.get("collected_at"))
    if collected_at < observed_at:
        _fail("REFERENCE_FEATURE_EVENT_TIME_ORDER")

    if event.get("integrity") not in _INTEGRITY_VALUES:
        _fail("REFERENCE_FEATURE_EVENT_TYPE")
    _identifier(
        event.get("provenance_id"),
        code="REFERENCE_FEATURE_EVENT_IDENTIFIER",
        allow_empty=True,
    )
    _bounded_number(event.get("trust_score"), code="REFERENCE_FEATURE_EVENT_RANGE")

    entity_refs = event.get("entity_refs")
    if not isinstance(entity_refs, list):
        _fail("REFERENCE_FEATURE_EVENT_TYPE")
    checked_refs = [
        _identifier(value, code="REFERENCE_FEATURE_EVENT_IDENTIFIER")
        for value in entity_refs
    ]
    if len(checked_refs) != len(set(checked_refs)):
        _fail("REFERENCE_FEATURE_EVENT_DUPLICATE_REFERENCE")
    if not isinstance(event.get("attributes"), dict):
        _fail("REFERENCE_FEATURE_EVENT_TYPE")
    if not isinstance(event.get("untrusted_text"), str):
        _fail("REFERENCE_FEATURE_EVENT_TYPE")
    if type(event.get("contains_instructional_content")) is not bool:
        _fail("REFERENCE_FEATURE_EVENT_TYPE")

    sort_key = (
        observed_at,
        collected_at,
        source_type,
        source_instance,
        event_id,
    )
    return event, sort_key


def _project_case(case: Any) -> tuple[str, dict[str, Any], str]:
    if not isinstance(case, dict) or frozenset(case) != _CASE_FIELDS:
        _fail("REFERENCE_FEATURE_CASE_SHAPE")

    case_id = _identifier(case.get("case_id"), code="REFERENCE_FEATURE_CASE_IDENTIFIER")
    _timestamp(case.get("opened_at"))
    _identifier(case.get("subject_id"), code="REFERENCE_FEATURE_CASE_IDENTIFIER")
    privilege_level = _identifier(
        case.get("privilege_level"), code="REFERENCE_FEATURE_CASE_IDENTIFIER"
    )
    if type(case.get("break_glass")) is not bool:
        _fail("REFERENCE_FEATURE_CASE_TYPE")
    asset_id = _identifier(
        case.get("asset_id"), code="REFERENCE_FEATURE_CASE_IDENTIFIER"
    )
    asset_criticality = _bounded_number(
        case.get("asset_criticality"), code="REFERENCE_FEATURE_CASE_RANGE"
    )

    events = case.get("events")
    if not isinstance(events, list) or not events:
        _fail("REFERENCE_FEATURE_EVENT_COUNT")
    checked_events = [_validate_event(event, case_id=case_id) for event in events]
    event_ids = [event[0]["event_id"] for event in checked_events]
    if len(event_ids) != len(set(event_ids)):
        _fail("REFERENCE_FEATURE_EVENT_ID_DUPLICATE")
    checked_events.sort(key=lambda item: item[1])

    values = {name: 0.0 for name in REFERENCE_FEATURE_NAMES}
    traces: dict[str, list[str]] = {}
    canonical_event_ids: list[str] = []
    inventory_ids: list[str] = []

    for event, _ in checked_events:
        event_id = event["event_id"]
        source_type = event["source_type"]
        attributes = event["attributes"]
        canonical_event_ids.append(event_id)

        if source_type == "asset_inventory":
            inventory_ids.append(event_id)
            required_inventory_fields = {
                "asset_id",
                "privilege_level",
                "break_glass",
                "asset_criticality",
            }
            if not required_inventory_fields.issubset(attributes):
                _fail("REFERENCE_FEATURE_INVENTORY_SHAPE")
            inventory_criticality = _bounded_number(
                attributes["asset_criticality"],
                code="REFERENCE_FEATURE_INVENTORY_RANGE",
            )
            if inventory_criticality != asset_criticality:
                _fail("REFERENCE_FEATURE_INVENTORY_BINDING")
            inventory_privilege = _identifier(
                attributes["privilege_level"],
                code="REFERENCE_FEATURE_INVENTORY_TYPE",
            )
            inventory_asset_id = _identifier(
                attributes["asset_id"],
                code="REFERENCE_FEATURE_INVENTORY_TYPE",
            )
            if inventory_privilege != privilege_level:
                _fail("REFERENCE_FEATURE_INVENTORY_BINDING")
            if inventory_asset_id != asset_id:
                _fail("REFERENCE_FEATURE_INVENTORY_BINDING")
            if (
                type(attributes["break_glass"]) is not bool
                or attributes["break_glass"] is not case["break_glass"]
            ):
                _fail("REFERENCE_FEATURE_INVENTORY_BINDING")

        if "failed_logins" in attributes:
            if source_type not in _FAILED_LOGIN_SOURCES:
                _fail("REFERENCE_FEATURE_SOURCE_CONTEXT")
            failed_logins = attributes["failed_logins"]
            if not _is_number(failed_logins):
                _fail("REFERENCE_FEATURE_ATTRIBUTE_TYPE")
            try:
                failed_login_count = float(failed_logins)
            except OverflowError:
                _fail("REFERENCE_FEATURE_ATTRIBUTE_RANGE")
            if (
                not math.isfinite(failed_login_count)
                or not failed_login_count.is_integer()
            ):
                _fail("REFERENCE_FEATURE_ATTRIBUTE_TYPE")
            if not 0.0 <= failed_login_count <= _MAX_FAILED_LOGINS:
                _fail("REFERENCE_FEATURE_ATTRIBUTE_RANGE")
            intensity = min(1.0, failed_login_count / 20.0)
            values["failed_login_intensity"] = max(
                values["failed_login_intensity"], intensity
            )
            traces.setdefault("failed_login_intensity", []).append(event_id)

        for feature_name, allowed_sources in _BOOLEAN_FEATURE_SOURCES.items():
            if feature_name not in attributes:
                continue
            if source_type not in allowed_sources:
                _fail("REFERENCE_FEATURE_SOURCE_CONTEXT")
            if type(attributes[feature_name]) is not bool:
                _fail("REFERENCE_FEATURE_ATTRIBUTE_TYPE")
            if attributes[feature_name]:
                values[feature_name] = 1.0
            traces.setdefault(feature_name, []).append(event_id)

    if not inventory_ids:
        _fail("REFERENCE_FEATURE_INVENTORY_MISSING")
    values["privilege_global_admin"] = 1.0 if privilege_level == "global_admin" else 0.0
    values["asset_criticality"] = asset_criticality
    traces["privilege_global_admin"] = list(inventory_ids)
    traces["asset_criticality"] = list(inventory_ids)

    rounded_values = {
        name: round(float(values[name]), 6) for name in REFERENCE_FEATURE_NAMES
    }
    projection = {
        "case_id": case_id,
        "feature_values": rounded_values,
        "model_feature_trace": traces,
        "traceability_feature_trace": traces,
        "traceability_input_event_ids": canonical_event_ids,
    }
    return case_id, projection, _canonical_sha256(case)


def _validated_observed_values(value: Any) -> dict[str, float]:
    if not isinstance(value, dict) or set(value) != set(REFERENCE_FEATURE_NAMES):
        _fail("REFERENCE_FEATURE_DECISION_SHAPE")
    checked: dict[str, float] = {}
    for name in REFERENCE_FEATURE_NAMES:
        number = _bounded_number(value[name], code="REFERENCE_FEATURE_DECISION_RANGE")
        if number != round(number, 6):
            _fail("REFERENCE_FEATURE_DECISION_PRECISION")
        checked[name] = number
    return checked


def _validated_observed_trace(
    value: Any,
    *,
    known_event_ids: frozenset[str],
) -> dict[str, list[str]]:
    if not isinstance(value, dict):
        _fail("REFERENCE_FEATURE_DECISION_SHAPE")
    checked: dict[str, list[str]] = {}
    for feature_name, event_ids in value.items():
        if feature_name not in REFERENCE_FEATURE_NAMES or not isinstance(
            event_ids, list
        ):
            _fail("REFERENCE_FEATURE_DECISION_SHAPE")
        checked_ids = [
            _identifier(event_id, code="REFERENCE_FEATURE_DECISION_TRACE_IDENTIFIER")
            for event_id in event_ids
        ]
        if len(checked_ids) != len(set(checked_ids)):
            _fail("REFERENCE_FEATURE_DECISION_TRACE_DUPLICATE")
        if not set(checked_ids).issubset(known_event_ids):
            _fail("REFERENCE_FEATURE_DECISION_TRACE_BINDING")
        checked[feature_name] = checked_ids
    return checked


def _observed_projection(
    decision: Any,
    *,
    case_id: str,
    canonical_event_ids: list[str],
) -> dict[str, Any]:
    if not isinstance(decision, dict):
        _fail("REFERENCE_FEATURE_DECISION_SHAPE")
    decision_case_id = _identifier(
        decision.get("case_id"), code="REFERENCE_FEATURE_DECISION_CASE_IDENTIFIER"
    )
    if decision_case_id != case_id:
        _fail("REFERENCE_FEATURE_CASE_SET")

    model_assessment = decision.get("model_assessment")
    traceability = decision.get("traceability")
    if not isinstance(model_assessment, dict) or not isinstance(traceability, dict):
        _fail("REFERENCE_FEATURE_DECISION_SHAPE")

    known_event_ids = frozenset(canonical_event_ids)
    feature_values = _validated_observed_values(model_assessment.get("feature_values"))
    model_trace = _validated_observed_trace(
        model_assessment.get("feature_trace"), known_event_ids=known_event_ids
    )
    traceability_trace = _validated_observed_trace(
        traceability.get("feature_trace"), known_event_ids=known_event_ids
    )
    input_event_ids = traceability.get("input_event_ids")
    if not isinstance(input_event_ids, list):
        _fail("REFERENCE_FEATURE_DECISION_SHAPE")
    checked_input_ids = [
        _identifier(event_id, code="REFERENCE_FEATURE_DECISION_TRACE_IDENTIFIER")
        for event_id in input_event_ids
    ]
    if len(checked_input_ids) != len(set(checked_input_ids)):
        _fail("REFERENCE_FEATURE_DECISION_TRACE_DUPLICATE")
    if set(checked_input_ids) != known_event_ids:
        _fail("REFERENCE_FEATURE_DECISION_TRACE_BINDING")

    return {
        "case_id": case_id,
        "feature_values": feature_values,
        "model_feature_trace": model_trace,
        "traceability_feature_trace": traceability_trace,
        "traceability_input_event_ids": checked_input_ids,
    }


def verify_reference_feature_projections(
    cases: list[dict[str, Any]],
    decisions: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Recompute and verify feature projections, returning closed metadata only.

    The case and decision sets must have unique, exactly matching case IDs.  The
    returned list is sorted by case ID.  Any invalid source context, malformed
    value, or projection mismatch raises :class:`ReferenceFeatureAssuranceError`
    before a partial record list is returned.
    """

    if not isinstance(cases, list) or not isinstance(decisions, list):
        _fail("REFERENCE_FEATURE_INPUT_TYPE")

    projected_cases: dict[str, tuple[dict[str, Any], str]] = {}
    for case in cases:
        case_id, projection, normalized_case_hash = _project_case(case)
        if case_id in projected_cases:
            _fail("REFERENCE_FEATURE_CASE_ID_DUPLICATE")
        projected_cases[case_id] = (projection, normalized_case_hash)

    decisions_by_case: dict[str, dict[str, Any]] = {}
    for decision in decisions:
        if not isinstance(decision, dict):
            _fail("REFERENCE_FEATURE_DECISION_SHAPE")
        case_id = _identifier(
            decision.get("case_id"),
            code="REFERENCE_FEATURE_DECISION_CASE_IDENTIFIER",
        )
        if case_id in decisions_by_case:
            _fail("REFERENCE_FEATURE_DECISION_CASE_ID_DUPLICATE")
        decisions_by_case[case_id] = decision

    if set(projected_cases) != set(decisions_by_case):
        _fail("REFERENCE_FEATURE_CASE_SET")

    verified_records: list[dict[str, Any]] = []
    for case_id in sorted(projected_cases):
        expected_projection, normalized_case_hash = projected_cases[case_id]
        canonical_event_ids = expected_projection["traceability_input_event_ids"]
        observed_projection = _observed_projection(
            decisions_by_case[case_id],
            case_id=case_id,
            canonical_event_ids=canonical_event_ids,
        )
        expected_hash = _canonical_sha256(expected_projection)
        observed_hash = _canonical_sha256(observed_projection)
        if expected_projection != observed_projection or expected_hash != observed_hash:
            _fail("REFERENCE_FEATURE_PROJECTION_MISMATCH")
        verified_records.append(
            {
                "schema_version": "0.2.0",
                "case_id": case_id,
                "normalized_case_sha256": normalized_case_hash,
                "expected_projection_sha256": expected_hash,
                "observed_projection_sha256": observed_hash,
                "matched": True,
            }
        )
    return verified_records
