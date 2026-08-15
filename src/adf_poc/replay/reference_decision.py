"""Separate, read-only source-to-decision recomputation for Phase 2.

This module is deliberately implemented with only the Python standard library.
It does not import the production evidence, feature, model, policy, verifier,
engine, metrics, or action paths.  The result is a same-project, in-process
reference oracle; agreement establishes calculation consistency only, not
source truth, decision efficacy, or organizational independence.

The public API accepts frozen bytes so ambiguous JSON (duplicate members and
non-finite numbers) is rejected before values are materialized.  Successful
results contain hashes and bounded metadata only.  A malformed input or any
stage mismatch raises a stable, sanitized error before a partial result list is
returned.
"""

from __future__ import annotations

from datetime import datetime
import hashlib
import io
import json
import math
import re
from typing import Any, NoReturn


SCHEMA_VERSION = "0.2.0"
ASSURANCE_KIND = "SEPARATE_SOURCE_TO_DECISION_RECOMPUTATION"
RECOMPUTATION_SCOPE = "EVIDENCE_MODEL_POLICY_VERIFIER_READ_ONLY_FINAL"
READ_ONLY_MODES = frozenset({"historical_replay", "shadow_read_only"})

# These limits are deliberately duplicated instead of imported from the
# production replay path.  The reference implementation is an independent
# parser and calculation boundary, so it must enforce its own reviewed resource
# envelope before the JSON decoder materializes attacker-controlled structures.
_MAX_MODEL_BYTES = 64 * 1024 * 1024
_MAX_POLICY_BYTES = 64 * 1024 * 1024
_MAX_JSONL_BYTES = 512 * 1024 * 1024
_MAX_JSONL_LINE_BYTES = 1024 * 1024
_MAX_JSONL_RECORDS = 100_000
_MAX_JSON_NESTING_DEPTH = 128
_MAX_EVENTS_PER_CASE = 10_000
_MAX_UNTRUSTED_TEXT_CHARS = 16_384
_MAX_ATTRIBUTES_BYTES = 256 * 1024
_MAX_TRAINING_METADATA_BYTES = 256 * 1024
_MAX_LIMITATIONS = 256
_MAX_LIMITATIONS_BYTES = 64 * 1024

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
_SOURCE_CONFLICT_SOURCES = frozenset({"network"})
_MAX_FAILED_LOGINS = 1_000_000

_POSITIVE_INDICATORS = frozenset(
    {
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
)
_BENIGN_INDICATORS = frozenset(
    {
        "known_vpn",
        "approved_travel",
        "maintenance_window",
        "service_account_baseline",
        "strong_mfa",
    }
)
_EXPECTED_SOURCES = frozenset(
    {
        "asset_inventory",
        "identity",
        "network",
        "endpoint",
        "threat_intel",
        "change_management",
        "user_context",
    }
)
_INSTRUCTION_PATTERNS = (
    re.compile(r"\bignore\s+(all\s+)?(prior|previous)\b", re.IGNORECASE),
    re.compile(r"\b(system|assistant)\s*:\s*", re.IGNORECASE),
    re.compile(r"\bdo\s+not\s+ask\b", re.IGNORECASE),
    re.compile(r"\bdisable\s+(the\s+)?account\b", re.IGNORECASE),
)

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
_DECISION_FIELDS = frozenset(
    {
        "decision_id",
        "case_id",
        "subject_id",
        "asset_id",
        "asset_criticality",
        "break_glass",
        "created_at",
        "policy_id",
        "policy_version",
        "model_version",
        "execution_mode",
        "original_disposition",
        "final_disposition",
        "counterfactual_actions",
        "compromise_probability",
        "evidence_assessment",
        "model_assessment",
        "proposal",
        "independent_verification",
        "authorization",
        "action_results",
        "post_action_verification",
        "execution_control",
        "latency_ms",
        "traceability",
        "decision_record_hash",
    }
)
_MODEL_FIELDS = frozenset(
    {
        "model_type",
        "version",
        "feature_names",
        "means",
        "scales",
        "weights",
        "intercept",
        "training_metadata",
        "limitations",
    }
)
_POLICY_FIELDS = frozenset(
    {"policy_id", "version", "thresholds", "evidence", "authority", "safety"}
)
_POLICY_THRESHOLD_FIELDS = frozenset(
    {
        "no_action_max_probability",
        "human_escalation_min_probability",
        "autonomous_containment_min_probability",
    }
)
_POLICY_EVIDENCE_FIELDS = frozenset(
    {
        "minimum_quality",
        "minimum_provenance_ratio",
        "minimum_integrity_verified_ratio",
        "minimum_independent_supporting_sources",
        "maximum_missing_expected_sources_for_decision",
        "maximum_conflicts_for_automation",
    }
)
_POLICY_AUTHORITY_FIELDS = frozenset(
    {
        "maximum_asset_criticality_for_automation",
        "break_glass_requires_human",
        "autonomous_actions",
        "human_only_actions",
    }
)
_POLICY_SAFETY_FIELDS = frozenset(
    {
        "poisoned_evidence_blocks_automation",
        "require_independent_verifier",
        "require_rollback_plan",
        "authorization_token_ttl_seconds",
    }
)

_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_SHA256 = re.compile(r"^[a-f0-9]{64}$")
_INTEGRITY_VALUES = frozenset({"verified", "unverified", "failed"})
_DISPOSITIONS = frozenset(
    {"NO_ACTION", "INVESTIGATE", "CONTAIN_REVERSIBLE", "ESCALATE_HUMAN"}
)


class ReferenceDecisionAssuranceError(ValueError):
    """Fail-closed reference error whose message is a stable code only."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


def _fail(code: str) -> NoReturn:
    raise ReferenceDecisionAssuranceError(code)


def _duplicate_safe_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, child in pairs:
        if key in value:
            _fail("REFERENCE_DECISION_DUPLICATE_KEY")
        value[key] = child
    return value


def _parse_float(token: str) -> float:
    value = float(token)
    if not math.isfinite(value):
        _fail("REFERENCE_DECISION_NONFINITE")
    return value


def _reject_constant(_: str) -> None:
    _fail("REFERENCE_DECISION_NONFINITE")


def _json_nesting_depth_exceeded(text: str) -> bool:
    """Check structural depth without counting braces inside JSON strings."""

    depth = 0
    in_string = False
    escaped = False
    for character in text:
        if in_string:
            if escaped:
                escaped = False
            elif character == "\\":
                escaped = True
            elif character == '"':
                in_string = False
            continue
        if character == '"':
            in_string = True
        elif character in "[{":
            depth += 1
            if depth > _MAX_JSON_NESTING_DEPTH:
                return True
        elif character in "]}" and depth:
            depth -= 1
    return False


def _strict_json(raw: bytes, *, document_code: str, max_bytes: int) -> Any:
    if type(raw) is not bytes:
        _fail("REFERENCE_DECISION_INPUT_TYPE")
    if len(raw) > max_bytes:
        _fail("REFERENCE_DECISION_RESOURCE_LIMIT")
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        _fail("REFERENCE_DECISION_ENCODING")
    if _json_nesting_depth_exceeded(text):
        _fail("REFERENCE_DECISION_JSON_NESTING")
    try:
        return json.loads(
            text,
            object_pairs_hook=_duplicate_safe_object,
            parse_float=_parse_float,
            parse_constant=_reject_constant,
        )
    except ReferenceDecisionAssuranceError:
        raise
    except (json.JSONDecodeError, RecursionError, ValueError, OverflowError):
        _fail(document_code)


def _strict_jsonl(raw: bytes, *, record_code: str) -> list[dict[str, Any]]:
    if type(raw) is not bytes:
        _fail("REFERENCE_DECISION_INPUT_TYPE")
    if len(raw) > _MAX_JSONL_BYTES:
        _fail("REFERENCE_DECISION_RESOURCE_LIMIT")
    rows: list[dict[str, Any]] = []
    stream = io.BytesIO(raw)
    while True:
        physical_line = stream.readline(_MAX_JSONL_LINE_BYTES + 1)
        if not physical_line:
            break
        if len(physical_line) > _MAX_JSONL_LINE_BYTES:
            _fail("REFERENCE_DECISION_RESOURCE_LIMIT")
        payload = physical_line.strip()
        if not payload:
            continue
        if len(rows) >= _MAX_JSONL_RECORDS:
            _fail("REFERENCE_DECISION_RESOURCE_LIMIT")
        try:
            text = payload.decode("utf-8")
        except UnicodeDecodeError:
            _fail("REFERENCE_DECISION_ENCODING")
        if _json_nesting_depth_exceeded(text):
            _fail("REFERENCE_DECISION_JSON_NESTING")
        try:
            value = json.loads(
                text,
                object_pairs_hook=_duplicate_safe_object,
                parse_float=_parse_float,
                parse_constant=_reject_constant,
            )
        except ReferenceDecisionAssuranceError:
            raise
        except (json.JSONDecodeError, RecursionError, ValueError, OverflowError):
            _fail(record_code)
        if not isinstance(value, dict):
            _fail(record_code)
        rows.append(value)
    if not rows:
        _fail(record_code)
    return rows


def _canonical_bytes(value: Any) -> bytes:
    try:
        return json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError, RecursionError):
        _fail("REFERENCE_DECISION_CANONICALIZATION")


def _canonical_sha256(value: Any) -> str:
    return hashlib.sha256(_canonical_bytes(value)).hexdigest()


def _source_sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _is_number(value: Any) -> bool:
    return isinstance(value, (int, float)) and not isinstance(value, bool)


def _finite_number(value: Any, *, code: str) -> float:
    if not _is_number(value):
        _fail(code)
    try:
        number = float(value)
    except OverflowError:
        _fail(code)
    if not math.isfinite(number):
        _fail(code)
    return number


def _unit_number(value: Any, *, code: str) -> float:
    number = _finite_number(value, code=code)
    if not 0.0 <= number <= 1.0:
        _fail(code)
    return number


def _exact_integer(
    value: Any,
    *,
    lower: int,
    upper: int,
    code: str,
) -> int:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        _fail(code)
    number = _finite_number(value, code=code)
    if not number.is_integer() or not lower <= number <= upper:
        _fail(code)
    return int(number)


def _identifier(value: Any, *, code: str, allow_empty: bool = False) -> str:
    if not isinstance(value, str):
        _fail(code)
    if allow_empty and value == "":
        return value
    if _IDENTIFIER.fullmatch(value) is None:
        _fail(code)
    return value


def _timestamp(value: Any, *, code: str) -> datetime:
    if not isinstance(value, str):
        _fail(code)
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        _fail(code)
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        _fail(code)
    return parsed


def _string_list(value: Any, *, code: str) -> list[str]:
    if not isinstance(value, list):
        _fail(code)
    checked = [_identifier(child, code=code) for child in value]
    if len(checked) != len(set(checked)):
        _fail(code)
    return checked


def _clamp(value: float) -> float:
    return max(0.0, min(1.0, value))


def _validate_event(
    value: Any,
    *,
    case_id: str,
) -> dict[str, Any]:
    if not isinstance(value, dict) or frozenset(value) != _EVENT_FIELDS:
        _fail("REFERENCE_DECISION_EVENT_SHAPE")
    event_id = _identifier(value.get("event_id"), code="REFERENCE_DECISION_EVENT")
    bound_case = _identifier(value.get("case_id"), code="REFERENCE_DECISION_EVENT")
    if bound_case != case_id:
        _fail("REFERENCE_DECISION_EVENT_BINDING")
    source_type = _identifier(value.get("source_type"), code="REFERENCE_DECISION_EVENT")
    source_instance = _identifier(
        value.get("source_instance"), code="REFERENCE_DECISION_EVENT"
    )
    observed_at = _timestamp(value.get("observed_at"), code="REFERENCE_DECISION_EVENT")
    collected_at = _timestamp(
        value.get("collected_at"), code="REFERENCE_DECISION_EVENT"
    )
    if collected_at < observed_at:
        _fail("REFERENCE_DECISION_EVENT_TIME")
    if value.get("integrity") not in _INTEGRITY_VALUES:
        _fail("REFERENCE_DECISION_EVENT")
    _identifier(
        value.get("provenance_id"),
        code="REFERENCE_DECISION_EVENT",
        allow_empty=True,
    )
    _unit_number(value.get("trust_score"), code="REFERENCE_DECISION_EVENT")
    _string_list(value.get("entity_refs"), code="REFERENCE_DECISION_EVENT")
    attributes = value.get("attributes")
    if not isinstance(attributes, dict):
        _fail("REFERENCE_DECISION_EVENT_SHAPE")
    if len(_canonical_bytes(attributes)) > _MAX_ATTRIBUTES_BYTES:
        _fail("REFERENCE_DECISION_RESOURCE_LIMIT")
    untrusted_text = value.get("untrusted_text")
    if not isinstance(untrusted_text, str):
        _fail("REFERENCE_DECISION_EVENT")
    if len(untrusted_text) > _MAX_UNTRUSTED_TEXT_CHARS:
        _fail("REFERENCE_DECISION_RESOURCE_LIMIT")
    if type(value.get("contains_instructional_content")) is not bool:
        _fail("REFERENCE_DECISION_EVENT")

    for name, allowed_sources in _BOOLEAN_FEATURE_SOURCES.items():
        if name not in attributes:
            continue
        if source_type not in allowed_sources:
            _fail("REFERENCE_DECISION_SOURCE_CONTEXT")
        if type(attributes[name]) is not bool:
            _fail("REFERENCE_DECISION_ATTRIBUTE_TYPE")
    if "failed_logins" in attributes:
        if source_type not in _FAILED_LOGIN_SOURCES:
            _fail("REFERENCE_DECISION_SOURCE_CONTEXT")
        _exact_integer(
            attributes["failed_logins"],
            lower=0,
            upper=_MAX_FAILED_LOGINS,
            code="REFERENCE_DECISION_ATTRIBUTE_TYPE",
        )
    if "source_conflict" in attributes:
        if source_type not in _SOURCE_CONFLICT_SOURCES:
            _fail("REFERENCE_DECISION_SOURCE_CONTEXT")
        if type(attributes["source_conflict"]) is not bool:
            _fail("REFERENCE_DECISION_ATTRIBUTE_TYPE")

    return value


def _validate_case(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict) or frozenset(value) != _CASE_FIELDS:
        _fail("REFERENCE_DECISION_CASE_SHAPE")
    case_id = _identifier(value.get("case_id"), code="REFERENCE_DECISION_CASE")
    _timestamp(value.get("opened_at"), code="REFERENCE_DECISION_CASE")
    _identifier(value.get("subject_id"), code="REFERENCE_DECISION_CASE")
    privilege_level = _identifier(
        value.get("privilege_level"), code="REFERENCE_DECISION_CASE"
    )
    if type(value.get("break_glass")) is not bool:
        _fail("REFERENCE_DECISION_CASE")
    asset_id = _identifier(value.get("asset_id"), code="REFERENCE_DECISION_CASE")
    asset_criticality = _unit_number(
        value.get("asset_criticality"), code="REFERENCE_DECISION_CASE"
    )
    raw_events = value.get("events")
    if not isinstance(raw_events, list) or not raw_events:
        _fail("REFERENCE_DECISION_CASE_SHAPE")
    if len(raw_events) > _MAX_EVENTS_PER_CASE:
        _fail("REFERENCE_DECISION_RESOURCE_LIMIT")
    events = [_validate_event(event, case_id=case_id) for event in raw_events]
    event_ids = [event["event_id"] for event in events]
    if len(event_ids) != len(set(event_ids)):
        _fail("REFERENCE_DECISION_EVENT_DUPLICATE")

    inventory = [event for event in events if event["source_type"] == "asset_inventory"]
    if not inventory:
        _fail("REFERENCE_DECISION_INVENTORY_MISSING")
    required = {"asset_id", "privilege_level", "break_glass", "asset_criticality"}
    for event in inventory:
        attributes = event["attributes"]
        if not required.issubset(attributes):
            _fail("REFERENCE_DECISION_INVENTORY_SHAPE")
        inventory_asset = _identifier(
            attributes["asset_id"], code="REFERENCE_DECISION_INVENTORY_TYPE"
        )
        inventory_privilege = _identifier(
            attributes["privilege_level"], code="REFERENCE_DECISION_INVENTORY_TYPE"
        )
        inventory_break_glass = attributes["break_glass"]
        inventory_criticality = _unit_number(
            attributes["asset_criticality"],
            code="REFERENCE_DECISION_INVENTORY_TYPE",
        )
        if type(inventory_break_glass) is not bool:
            _fail("REFERENCE_DECISION_INVENTORY_TYPE")
        if (
            inventory_asset != asset_id
            or inventory_privilege != privilege_level
            or inventory_break_glass is not value["break_glass"]
            or inventory_criticality != asset_criticality
        ):
            _fail("REFERENCE_DECISION_INVENTORY_BINDING")

    normalized = dict(value)
    normalized["asset_criticality"] = asset_criticality
    normalized["events"] = events
    return normalized


def _validate_model(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict) or frozenset(value) != _MODEL_FIELDS:
        _fail("REFERENCE_DECISION_MODEL_SHAPE")
    if value.get("model_type") != "logistic_regression":
        _fail("REFERENCE_DECISION_MODEL_SHAPE")
    _identifier(value.get("version"), code="REFERENCE_DECISION_MODEL_SHAPE")
    if value.get("feature_names") != list(FEATURE_NAMES):
        _fail("REFERENCE_DECISION_MODEL_FEATURES")
    checked: dict[str, Any] = dict(value)
    for name in ("means", "scales", "weights"):
        array = value.get(name)
        if not isinstance(array, list) or len(array) != len(FEATURE_NAMES):
            _fail("REFERENCE_DECISION_MODEL_SHAPE")
        checked[name] = [
            _finite_number(child, code="REFERENCE_DECISION_MODEL_RANGE")
            for child in array
        ]
    if any(scale <= 0.0 for scale in checked["scales"]):
        _fail("REFERENCE_DECISION_MODEL_RANGE")
    checked["intercept"] = _finite_number(
        value.get("intercept"), code="REFERENCE_DECISION_MODEL_RANGE"
    )
    training_metadata = value.get("training_metadata")
    if not isinstance(training_metadata, dict):
        _fail("REFERENCE_DECISION_MODEL_SHAPE")
    if len(_canonical_bytes(training_metadata)) > _MAX_TRAINING_METADATA_BYTES:
        _fail("REFERENCE_DECISION_RESOURCE_LIMIT")
    limitations = value.get("limitations")
    if not isinstance(limitations, list) or not all(
        isinstance(child, str) for child in limitations
    ):
        _fail("REFERENCE_DECISION_MODEL_SHAPE")
    if (
        len(limitations) > _MAX_LIMITATIONS
        or len(_canonical_bytes(limitations)) > _MAX_LIMITATIONS_BYTES
    ):
        _fail("REFERENCE_DECISION_RESOURCE_LIMIT")
    return checked


def _policy_mapping(
    value: Any,
    *,
    fields: frozenset[str],
    code: str,
) -> dict[str, Any]:
    if not isinstance(value, dict) or frozenset(value) != fields:
        _fail(code)
    return value


def _validate_policy(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict) or frozenset(value) != _POLICY_FIELDS:
        _fail("REFERENCE_DECISION_POLICY_SHAPE")
    _identifier(value.get("policy_id"), code="REFERENCE_DECISION_POLICY_SHAPE")
    _identifier(value.get("version"), code="REFERENCE_DECISION_POLICY_SHAPE")
    thresholds = _policy_mapping(
        value.get("thresholds"),
        fields=_POLICY_THRESHOLD_FIELDS,
        code="REFERENCE_DECISION_POLICY_SHAPE",
    )
    evidence = _policy_mapping(
        value.get("evidence"),
        fields=_POLICY_EVIDENCE_FIELDS,
        code="REFERENCE_DECISION_POLICY_SHAPE",
    )
    authority = _policy_mapping(
        value.get("authority"),
        fields=_POLICY_AUTHORITY_FIELDS,
        code="REFERENCE_DECISION_POLICY_SHAPE",
    )
    safety = _policy_mapping(
        value.get("safety"),
        fields=_POLICY_SAFETY_FIELDS,
        code="REFERENCE_DECISION_POLICY_SHAPE",
    )

    checked = dict(value)
    checked_thresholds = {
        name: _unit_number(thresholds[name], code="REFERENCE_DECISION_POLICY_RANGE")
        for name in _POLICY_THRESHOLD_FIELDS
    }
    if not (
        checked_thresholds["no_action_max_probability"]
        <= checked_thresholds["human_escalation_min_probability"]
        <= checked_thresholds["autonomous_containment_min_probability"]
    ):
        _fail("REFERENCE_DECISION_POLICY_RANGE")
    checked_evidence: dict[str, float | int] = {
        "minimum_quality": _unit_number(
            evidence["minimum_quality"], code="REFERENCE_DECISION_POLICY_RANGE"
        ),
        "minimum_provenance_ratio": _unit_number(
            evidence["minimum_provenance_ratio"],
            code="REFERENCE_DECISION_POLICY_RANGE",
        ),
        "minimum_integrity_verified_ratio": _unit_number(
            evidence["minimum_integrity_verified_ratio"],
            code="REFERENCE_DECISION_POLICY_RANGE",
        ),
        "minimum_independent_supporting_sources": _exact_integer(
            evidence["minimum_independent_supporting_sources"],
            lower=0,
            upper=len(_EXPECTED_SOURCES),
            code="REFERENCE_DECISION_POLICY_RANGE",
        ),
        "maximum_missing_expected_sources_for_decision": _exact_integer(
            evidence["maximum_missing_expected_sources_for_decision"],
            lower=0,
            upper=len(_EXPECTED_SOURCES),
            code="REFERENCE_DECISION_POLICY_RANGE",
        ),
        "maximum_conflicts_for_automation": _exact_integer(
            evidence["maximum_conflicts_for_automation"],
            lower=0,
            upper=1_000_000,
            code="REFERENCE_DECISION_POLICY_RANGE",
        ),
    }
    if type(authority.get("break_glass_requires_human")) is not bool:
        _fail("REFERENCE_DECISION_POLICY_SHAPE")
    autonomous = _string_list(
        authority.get("autonomous_actions"), code="REFERENCE_DECISION_POLICY_SHAPE"
    )
    human_only = _string_list(
        authority.get("human_only_actions"), code="REFERENCE_DECISION_POLICY_SHAPE"
    )
    if set(autonomous) & set(human_only):
        _fail("REFERENCE_DECISION_POLICY_RANGE")
    checked_authority = dict(authority)
    checked_authority["maximum_asset_criticality_for_automation"] = _unit_number(
        authority.get("maximum_asset_criticality_for_automation"),
        code="REFERENCE_DECISION_POLICY_RANGE",
    )
    checked_authority["autonomous_actions"] = autonomous
    checked_authority["human_only_actions"] = human_only
    for name in (
        "poisoned_evidence_blocks_automation",
        "require_independent_verifier",
        "require_rollback_plan",
    ):
        if type(safety.get(name)) is not bool:
            _fail("REFERENCE_DECISION_POLICY_SHAPE")
    _exact_integer(
        safety.get("authorization_token_ttl_seconds"),
        lower=1,
        upper=86_400,
        code="REFERENCE_DECISION_POLICY_RANGE",
    )
    checked["thresholds"] = checked_thresholds
    checked["evidence"] = checked_evidence
    checked["authority"] = checked_authority
    checked["safety"] = dict(safety)
    return checked


def _features(case: dict[str, Any]) -> tuple[dict[str, float], dict[str, list[str]]]:
    values = {name: 0.0 for name in FEATURE_NAMES}
    traces: dict[str, list[str]] = {}
    inventory_ids: list[str] = []
    for event in case["events"]:
        event_id = event["event_id"]
        source_type = event["source_type"]
        attributes = event["attributes"]
        if source_type == "asset_inventory":
            inventory_ids.append(event_id)
        if "failed_logins" in attributes:
            count = _exact_integer(
                attributes["failed_logins"],
                lower=0,
                upper=_MAX_FAILED_LOGINS,
                code="REFERENCE_DECISION_ATTRIBUTE_TYPE",
            )
            values["failed_login_intensity"] = max(
                values["failed_login_intensity"], min(count / 20.0, 1.0)
            )
            traces.setdefault("failed_login_intensity", []).append(event_id)
        for name in _BOOLEAN_FEATURE_SOURCES:
            if name not in attributes:
                continue
            if attributes[name]:
                values[name] = 1.0
            traces.setdefault(name, []).append(event_id)
    values["privilege_global_admin"] = (
        1.0 if case["privilege_level"] == "global_admin" else 0.0
    )
    values["asset_criticality"] = float(case["asset_criticality"])
    traces["privilege_global_admin"] = inventory_ids
    traces["asset_criticality"] = inventory_ids
    return values, traces


def _evidence(case: dict[str, Any]) -> dict[str, Any]:
    events = case["events"]
    if not events:
        _fail("REFERENCE_DECISION_CASE_SHAPE")
    provenance_values: list[float] = []
    integrity_values: list[float] = []
    freshness_values: list[float] = []
    trust_values: list[float] = []
    sources: set[str] = set()
    positive_event_ids: list[str] = []
    benign_event_ids: list[str] = []
    supporting_sources: set[str] = set()
    poisoned_event_ids: list[str] = []
    conflict_count = 0

    for event in events:
        event_id = event["event_id"]
        source_type = event["source_type"]
        attributes = event["attributes"]
        provenance_values.append(1.0 if event["provenance_id"] else 0.0)
        integrity_values.append(1.0 if event["integrity"] == "verified" else 0.0)
        observed = _timestamp(event["observed_at"], code="REFERENCE_DECISION_EVENT")
        collected = _timestamp(event["collected_at"], code="REFERENCE_DECISION_EVENT")
        delay = max(0.0, (collected - observed).total_seconds())
        freshness_values.append(_clamp(1.0 - max(0.0, delay - 300.0) / 6900.0))
        trust_values.append(float(event["trust_score"]))
        sources.add(source_type)

        event_positive = any(
            attributes.get(name) is True for name in _POSITIVE_INDICATORS
        )
        event_benign = any(attributes.get(name) is True for name in _BENIGN_INDICATORS)
        if event_positive:
            positive_event_ids.append(event_id)
            supporting_sources.add(source_type)
        if event_benign:
            benign_event_ids.append(event_id)
        if attributes.get("source_conflict") is True:
            conflict_count += 1
        instructional = event["contains_instructional_content"] or any(
            pattern.search(event["untrusted_text"]) for pattern in _INSTRUCTION_PATTERNS
        )
        if instructional:
            poisoned_event_ids.append(event_id)

    count = len(events)
    provenance_ratio = math.fsum(provenance_values) / count
    integrity_ratio = math.fsum(integrity_values) / count
    freshness_score = math.fsum(freshness_values) / count
    trust_score = math.fsum(trust_values) / count
    diversity_score = _clamp(len(sources) / len(_EXPECTED_SOURCES))
    missing = sorted(_EXPECTED_SOURCES - sources)
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
    quality = _clamp(quality)

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

    return {
        "evidence_quality": round(quality, 6),
        "provenance_valid_ratio": round(provenance_ratio, 6),
        "integrity_verified_ratio": round(integrity_ratio, 6),
        "freshness_score": round(freshness_score, 6),
        "source_diversity_score": round(diversity_score, 6),
        "mean_source_trust": round(trust_score, 6),
        "independent_supporting_sources": len(supporting_sources),
        "positive_event_ids": positive_event_ids,
        "benign_event_ids": benign_event_ids,
        "missing_expected_sources": missing,
        "conflict_count": conflict_count,
        "poisoned_evidence": poisoned,
        "poisoned_event_ids": poisoned_event_ids,
        "reasons": reasons,
    }


def _model_assessment(case: dict[str, Any], model: dict[str, Any]) -> dict[str, Any]:
    feature_values, feature_trace = _features(case)
    contributions: list[float] = []
    for index, name in enumerate(FEATURE_NAMES):
        standardized = (feature_values[name] - model["means"][index]) / model["scales"][
            index
        ]
        contributions.append(standardized * model["weights"][index])
    logit = math.fsum(contributions) + model["intercept"]
    clipped = max(-30.0, min(30.0, logit))
    probability = 1.0 / (1.0 + math.exp(-clipped))
    factor_rows: list[dict[str, Any]] = [
        {
            "feature": name,
            "contribution": round(contribution, 6),
            "value": round(float(feature_values[name]), 6),
        }
        for name, contribution in zip(FEATURE_NAMES, contributions, strict=True)
    ]
    positives = sorted(
        (row for row in factor_rows if row["contribution"] > 0),
        key=lambda row: row["contribution"],
        reverse=True,
    )[:5]
    negatives = sorted(
        (row for row in factor_rows if row["contribution"] < 0),
        key=lambda row: row["contribution"],
    )[:5]
    return {
        "compromise_probability": round(probability, 8),
        "model_version": model["version"],
        "top_positive_factors": positives,
        "top_negative_factors": negatives,
        "feature_values": {
            name: round(float(feature_values[name]), 6) for name in FEATURE_NAMES
        },
        "feature_trace": feature_trace,
    }


def _investigate(
    rationale: list[str], rules: list[str], evidence_ids: list[str]
) -> dict[str, Any]:
    return {
        "disposition": "INVESTIGATE",
        "executable_actions": [],
        "recommended_human_actions": [],
        "investigation_actions": [
            "query_identity_history",
            "query_endpoint_telemetry",
            "validate_change_and_travel_context",
        ],
        "rationale": rationale,
        "policy_rules_applied": rules,
        "evidence_event_ids": evidence_ids,
        "required_authority": "read_only_automation",
        "rollback_plan": {},
    }


def _policy_proposal(
    case: dict[str, Any],
    model: dict[str, Any],
    evidence: dict[str, Any],
    policy: dict[str, Any],
) -> dict[str, Any]:
    probability = model["compromise_probability"]
    thresholds = policy["thresholds"]
    evidence_policy = policy["evidence"]
    authority = policy["authority"]
    safety = policy["safety"]
    severe = any(
        model["feature_values"].get(name, 0.0) >= 1.0
        for name in (
            "credential_dumping",
            "lateral_movement",
            "token_reuse",
            "oauth_grant",
        )
    )
    rationale: list[str] = []
    rules: list[str] = []
    evidence_ids = sorted(
        set(
            evidence["positive_event_ids"]
            + evidence["benign_event_ids"]
            + evidence["poisoned_event_ids"]
        )
    )
    decision_grade = (
        evidence["evidence_quality"] >= evidence_policy["minimum_quality"]
        and evidence["provenance_valid_ratio"]
        >= evidence_policy["minimum_provenance_ratio"]
        and evidence["integrity_verified_ratio"]
        >= evidence_policy["minimum_integrity_verified_ratio"]
        and evidence["conflict_count"]
        <= evidence_policy["maximum_conflicts_for_automation"]
        and len(evidence["missing_expected_sources"])
        <= evidence_policy["maximum_missing_expected_sources_for_decision"]
        and not (
            safety["poisoned_evidence_blocks_automation"]
            and evidence["poisoned_evidence"]
        )
    )
    automation_grade = (
        decision_grade
        and evidence["independent_supporting_sources"]
        >= evidence_policy["minimum_independent_supporting_sources"]
    )

    if evidence["poisoned_evidence"] and safety["poisoned_evidence_blocks_automation"]:
        rules.append("SAFETY-POISON-ABSTAIN")
        rationale.append(
            "Adversarial or instructional content is present in an untrusted source; autonomous action is prohibited."
        )
        return _investigate(rationale, rules, evidence_ids)
    if case["break_glass"] and authority["break_glass_requires_human"]:
        rules.append("AUTH-BREAK-GLASS-HUMAN")
        rationale.append(
            "The subject is a break-glass identity; all containment requires explicit human authorization."
        )
        return {
            "disposition": "ESCALATE_HUMAN",
            "executable_actions": [],
            "recommended_human_actions": [
                "disable_account",
                "revoke_active_sessions",
                "validate_emergency_use",
            ],
            "investigation_actions": [
                "validate_emergency_use",
                "contact_incident_commander",
            ],
            "rationale": rationale,
            "policy_rules_applied": rules,
            "evidence_event_ids": evidence_ids,
            "required_authority": "incident_commander_or_identity_owner",
            "rollback_plan": {},
        }
    if not decision_grade:
        rules.append("EVIDENCE-NOT-DECISION-GRADE")
        rationale.extend(evidence["reasons"])
        rationale.append(
            "The decision firewall abstains until provenance, integrity, completeness, or corroboration is improved."
        )
        return _investigate(rationale, rules, evidence_ids)
    if probability <= thresholds["no_action_max_probability"] and not severe:
        rules.append("RISK-BELOW-NO-ACTION-THRESHOLD")
        rationale.append(
            f"Compromise probability {probability:.3f} is below the no-action threshold and no severe indicator is present."
        )
        return {
            "disposition": "NO_ACTION",
            "executable_actions": [],
            "recommended_human_actions": [],
            "investigation_actions": [],
            "rationale": rationale,
            "policy_rules_applied": rules,
            "evidence_event_ids": evidence_ids,
            "required_authority": "none",
            "rollback_plan": {},
        }
    can_auto_contain = (
        probability >= thresholds["autonomous_containment_min_probability"]
        and case["asset_criticality"]
        <= authority["maximum_asset_criticality_for_automation"]
        and automation_grade
    )
    if can_auto_contain:
        rules.extend(["RISK-AUTO-CONTAIN-THRESHOLD", "AUTH-REVERSIBLE-ACTIONS-ONLY"])
        rationale.append(
            f"Compromise probability {probability:.3f}, evidence quality {evidence['evidence_quality']:.3f}, "
            f"and asset criticality {case['asset_criticality']:.3f} satisfy the reversible-containment policy."
        )
        return {
            "disposition": "CONTAIN_REVERSIBLE",
            "executable_actions": list(authority["autonomous_actions"]),
            "recommended_human_actions": [],
            "investigation_actions": [],
            "rationale": rationale,
            "policy_rules_applied": rules,
            "evidence_event_ids": evidence_ids,
            "required_authority": "deterministic_policy_gate",
            "rollback_plan": {
                "revoke_active_sessions": "restore only through normal reauthentication; no session token is reinstated",
                "force_step_up_auth": "remove temporary step-up requirement after analyst review",
                "increase_monitoring": "return telemetry policy to baseline after closure",
            },
        }
    if probability >= thresholds["human_escalation_min_probability"] or severe:
        rules.append("RISK-HUMAN-ESCALATION")
        if (
            case["asset_criticality"]
            > authority["maximum_asset_criticality_for_automation"]
        ):
            rules.append("AUTH-ASSET-CRITICALITY-HUMAN")
            rationale.append(
                "Asset criticality exceeds the autonomous-action boundary."
            )
        rationale.append(
            f"Compromise probability {probability:.3f} or severe evidence requires human containment authority."
        )
        return {
            "disposition": "ESCALATE_HUMAN",
            "executable_actions": [],
            "recommended_human_actions": [
                "disable_account",
                "revoke_active_sessions",
                "isolate_endpoint",
            ],
            "investigation_actions": [
                "confirm_business_owner",
                "validate_blast_radius",
            ],
            "rationale": rationale,
            "policy_rules_applied": rules,
            "evidence_event_ids": evidence_ids,
            "required_authority": "soc_shift_lead_or_identity_owner",
            "rollback_plan": {},
        }
    rules.append("RISK-UNCERTAIN-INVESTIGATE")
    rationale.append(
        f"Compromise probability {probability:.3f} is not low enough for closure and not high enough for containment."
    )
    return _investigate(rationale, rules, evidence_ids)


def _verification(
    case: dict[str, Any],
    model: dict[str, Any],
    evidence: dict[str, Any],
    proposal: dict[str, Any],
    policy: dict[str, Any],
) -> dict[str, Any]:
    checks: list[dict[str, Any]] = []
    blockers: list[str] = []
    known_event_ids = {event["event_id"] for event in case["events"]}
    autonomous_actions = set(policy["authority"]["autonomous_actions"])
    human_only_actions = set(policy["authority"]["human_only_actions"])

    def check(name: str, passed: bool, detail: str) -> None:
        checks.append({"check": name, "passed": bool(passed), "detail": detail})
        if not passed:
            blockers.append(f"{name}: {detail}")

    check(
        "MODEL-PROBABILITY-RANGE",
        0.0 <= model["compromise_probability"] <= 1.0,
        "Probability must be within [0,1].",
    )
    check(
        "TRACE-EVENTS-EXIST",
        set(proposal["evidence_event_ids"]).issubset(known_event_ids),
        "All cited evidence IDs must exist in the case.",
    )
    traced_ids = {
        event_id for rows in model["feature_trace"].values() for event_id in rows
    }
    check(
        "MODEL-FEATURE-TRACE",
        traced_ids.issubset(known_event_ids),
        "Every model feature trace must resolve to a case event.",
    )
    check(
        "NO-HUMAN-ONLY-EXECUTION",
        not (set(proposal["executable_actions"]) & human_only_actions),
        "Human-only actions cannot appear in the executable action set.",
    )
    check(
        "EXECUTABLE-ACTIONS-ALLOWLISTED",
        set(proposal["executable_actions"]).issubset(autonomous_actions),
        "Executable actions must be on the autonomous allowlist.",
    )
    if proposal["disposition"] == "CONTAIN_REVERSIBLE":
        threshold = policy["thresholds"]["autonomous_containment_min_probability"]
        check(
            "CONTAIN-RISK-THRESHOLD",
            model["compromise_probability"] >= threshold,
            f"Containment requires probability >= {threshold:.2f}.",
        )
        check(
            "CONTAIN-EVIDENCE-QUALITY",
            evidence["evidence_quality"] >= policy["evidence"]["minimum_quality"],
            "Evidence quality must meet the automation threshold.",
        )
        check(
            "CONTAIN-PROVENANCE",
            evidence["provenance_valid_ratio"]
            >= policy["evidence"]["minimum_provenance_ratio"],
            "Evidence provenance ratio is insufficient.",
        )
        check(
            "CONTAIN-INTEGRITY",
            evidence["integrity_verified_ratio"]
            >= policy["evidence"]["minimum_integrity_verified_ratio"],
            "Evidence integrity ratio is insufficient.",
        )
        check(
            "CONTAIN-CORROBORATION",
            evidence["independent_supporting_sources"]
            >= policy["evidence"]["minimum_independent_supporting_sources"],
            "Independent source corroboration is insufficient.",
        )
        check(
            "CONTAIN-NO-CONFLICT",
            evidence["conflict_count"]
            <= policy["evidence"]["maximum_conflicts_for_automation"],
            "Conflicting sources prohibit automation.",
        )
        check(
            "CONTAIN-NO-POISON",
            not evidence["poisoned_evidence"],
            "Instructional or poisoned evidence prohibits automation.",
        )
        check(
            "CONTAIN-NOT-BREAK-GLASS",
            not case["break_glass"],
            "Break-glass identities require human authorization.",
        )
        check(
            "CONTAIN-ASSET-BOUNDARY",
            case["asset_criticality"]
            <= policy["authority"]["maximum_asset_criticality_for_automation"],
            "Asset criticality exceeds the autonomous boundary.",
        )
        check(
            "CONTAIN-ROLLBACK",
            all(
                action in proposal["rollback_plan"]
                for action in proposal["executable_actions"]
            ),
            "Every autonomous action requires a rollback plan.",
        )
        check(
            "CONTAIN-ACTIONS-PRESENT",
            bool(proposal["executable_actions"]),
            "Containment disposition requires at least one executable action.",
        )
    else:
        check(
            "NON-CONTAIN-NO-EXECUTION",
            not proposal["executable_actions"],
            "Non-containment dispositions cannot execute production actions.",
        )
    return {"passed": not blockers, "checks": checks, "blocking_reasons": blockers}


def _downgrade_if_blocked(
    proposal: dict[str, Any], verification: dict[str, Any]
) -> dict[str, Any]:
    if not proposal["executable_actions"] or verification["passed"]:
        return dict(proposal)
    return {
        "disposition": "INVESTIGATE",
        "executable_actions": [],
        "recommended_human_actions": [],
        "investigation_actions": [
            "resolve_independent_verifier_failure",
            "collect_additional_evidence",
        ],
        "rationale": proposal["rationale"]
        + [
            "Independent verification failed; the action proposal was downgraded to investigation."
        ],
        "policy_rules_applied": proposal["policy_rules_applied"]
        + ["FAIL-SAFE-VERIFIER-DOWNGRADE"],
        "evidence_event_ids": proposal["evidence_event_ids"],
        "required_authority": "read_only_automation",
        "rollback_plan": {},
    }


def _read_only_proposal(proposal: dict[str, Any]) -> tuple[dict[str, Any], list[str]]:
    counterfactual_actions = list(proposal["executable_actions"])
    read_only = dict(proposal)
    read_only["executable_actions"] = []
    read_only["required_authority"] = "read_only_observation"
    read_only["rollback_plan"] = {}
    return read_only, counterfactual_actions


def _expected_stages(
    case: dict[str, Any],
    model_config: dict[str, Any],
    policy_config: dict[str, Any],
    execution_mode: str,
) -> dict[str, Any]:
    evidence = _evidence(case)
    model = _model_assessment(case, model_config)
    original_proposal = _policy_proposal(case, model, evidence, policy_config)
    original_disposition = original_proposal["disposition"]
    verifier = _verification(case, model, evidence, original_proposal, policy_config)
    pre_read_only = _downgrade_if_blocked(original_proposal, verifier)
    proposal, counterfactual_actions = _read_only_proposal(pre_read_only)
    policy_surface = {
        "original_disposition": original_disposition,
        "final_disposition": proposal["disposition"],
        "counterfactual_actions": counterfactual_actions,
        "proposal": proposal,
    }
    final_surface = {
        "case_id": case["case_id"],
        "subject_id": case["subject_id"],
        "asset_id": case["asset_id"],
        "asset_criticality": case["asset_criticality"],
        "break_glass": case["break_glass"],
        "policy_id": policy_config["policy_id"],
        "policy_version": policy_config["version"],
        "model_version": model["model_version"],
        "execution_mode": execution_mode,
        "original_disposition": original_disposition,
        "final_disposition": proposal["disposition"],
        "counterfactual_actions": counterfactual_actions,
        "compromise_probability": model["compromise_probability"],
        "evidence_assessment": evidence,
        "model_assessment": model,
        "proposal": proposal,
        "independent_verification": verifier,
        "authorization": {
            "issued": False,
            "token_id": "",
            "decision_hash": "",
            "permitted_actions": [],
            "error": "",
        },
        "action_results": [],
        "post_action_verification": {
            "applicable": False,
            "status": "NOT_APPLICABLE",
            "passed": None,
            "checks": [],
        },
        "execution_control": {
            "mode": execution_mode,
            "read_only": True,
            "status": "SUPPRESSED_READ_ONLY",
            "authorization_attempted": False,
            "broker_invocations": 0,
            "operational_effects": 0,
        },
        "traceability": {
            "input_event_ids": [event["event_id"] for event in case["events"]],
            "cited_evidence_event_ids": proposal["evidence_event_ids"],
            "feature_trace": model["feature_trace"],
        },
    }
    return {
        "evidence": evidence,
        "model": model,
        "policy": policy_surface,
        "verifier": verifier,
        "final_surface": final_surface,
    }


def _observed_stages(
    decision: dict[str, Any], *, case_id: str, execution_mode: str
) -> dict[str, Any]:
    if frozenset(decision) != _DECISION_FIELDS:
        _fail("REFERENCE_DECISION_DECISION_SHAPE")
    observed_case = _identifier(
        decision.get("case_id"), code="REFERENCE_DECISION_DECISION_SHAPE"
    )
    if observed_case != case_id:
        _fail("REFERENCE_DECISION_CASE_SET")
    if decision.get("execution_mode") != execution_mode:
        _fail("REFERENCE_DECISION_MODE")
    _identifier(decision.get("decision_id"), code="REFERENCE_DECISION_DECISION_SHAPE")
    _timestamp(decision.get("created_at"), code="REFERENCE_DECISION_DECISION_SHAPE")
    latency = _finite_number(
        decision.get("latency_ms"), code="REFERENCE_DECISION_DECISION_SHAPE"
    )
    if latency < 0.0:
        _fail("REFERENCE_DECISION_DECISION_SHAPE")
    supplied_hash = decision.get("decision_record_hash")
    if not isinstance(supplied_hash, str) or _SHA256.fullmatch(supplied_hash) is None:
        _fail("REFERENCE_DECISION_RECORD_HASH")
    unhashed = dict(decision)
    del unhashed["decision_record_hash"]
    if _canonical_sha256(unhashed) != supplied_hash:
        _fail("REFERENCE_DECISION_RECORD_HASH")

    evidence = decision.get("evidence_assessment")
    model = decision.get("model_assessment")
    proposal = decision.get("proposal")
    verifier = decision.get("independent_verification")
    traceability = decision.get("traceability")
    for value in (evidence, model, proposal, verifier, traceability):
        if not isinstance(value, dict):
            _fail("REFERENCE_DECISION_DECISION_SHAPE")
    original_disposition = decision.get("original_disposition")
    final_disposition = decision.get("final_disposition")
    if (
        original_disposition not in _DISPOSITIONS
        or final_disposition not in _DISPOSITIONS
    ):
        _fail("REFERENCE_DECISION_DECISION_SHAPE")
    counterfactual = decision.get("counterfactual_actions")
    if not isinstance(counterfactual, list):
        _fail("REFERENCE_DECISION_DECISION_SHAPE")

    policy_surface = {
        "original_disposition": original_disposition,
        "final_disposition": final_disposition,
        "counterfactual_actions": counterfactual,
        "proposal": proposal,
    }
    final_surface = {
        key: decision[key]
        for key in (
            "case_id",
            "subject_id",
            "asset_id",
            "asset_criticality",
            "break_glass",
            "policy_id",
            "policy_version",
            "model_version",
            "execution_mode",
            "original_disposition",
            "final_disposition",
            "counterfactual_actions",
            "compromise_probability",
            "evidence_assessment",
            "model_assessment",
            "proposal",
            "independent_verification",
            "authorization",
            "action_results",
            "post_action_verification",
            "execution_control",
            "traceability",
        )
    }
    return {
        "evidence": evidence,
        "model": model,
        "policy": policy_surface,
        "verifier": verifier,
        "final_surface": final_surface,
    }


def _stage_hashes(stages: dict[str, Any]) -> dict[str, str]:
    return {name: _canonical_sha256(stages[name]) for name in stages}


def _path_hash(stage_hashes: dict[str, str]) -> str:
    return _canonical_sha256(
        [
            {"stage": stage, "sha256": stage_hashes[stage]}
            for stage in ("evidence", "model", "policy", "verifier", "final_surface")
        ]
    )


def _compare_stage(
    name: str,
    expected: dict[str, str],
    observed: dict[str, str],
    code: str,
) -> None:
    if expected[name] != observed[name]:
        _fail(code)


def verify_reference_decision_path(
    *,
    cases_jsonl: bytes,
    decisions_jsonl: bytes,
    model_json: bytes,
    policy_json: bytes,
    expected_execution_mode: str,
) -> list[dict[str, Any]]:
    """Recompute the deterministic read-only decision path from frozen bytes.

    Returned records are sorted by case ID and contain only digests and bounded
    assurance metadata.  Exact agreement means that this separately implemented
    same-project oracle reproduced the recorded calculation.  It does not prove
    that telemetry is true, outcomes are correct, or the model/policy is fit for
    operational use.
    """

    if expected_execution_mode not in READ_ONLY_MODES:
        _fail("REFERENCE_DECISION_MODE")
    raw_cases = _strict_jsonl(cases_jsonl, record_code="REFERENCE_DECISION_CASE_JSONL")
    raw_decisions = _strict_jsonl(
        decisions_jsonl, record_code="REFERENCE_DECISION_DECISION_JSONL"
    )
    raw_model = _strict_json(
        model_json,
        document_code="REFERENCE_DECISION_MODEL_JSON",
        max_bytes=_MAX_MODEL_BYTES,
    )
    raw_policy = _strict_json(
        policy_json,
        document_code="REFERENCE_DECISION_POLICY_JSON",
        max_bytes=_MAX_POLICY_BYTES,
    )
    model = _validate_model(raw_model)
    policy = _validate_policy(raw_policy)

    cases: dict[str, dict[str, Any]] = {}
    for raw_case in raw_cases:
        case = _validate_case(raw_case)
        case_id = case["case_id"]
        if case_id in cases:
            _fail("REFERENCE_DECISION_CASE_DUPLICATE")
        cases[case_id] = case
    decisions: dict[str, dict[str, Any]] = {}
    for decision in raw_decisions:
        case_id = _identifier(
            decision.get("case_id"), code="REFERENCE_DECISION_DECISION_SHAPE"
        )
        if case_id in decisions:
            _fail("REFERENCE_DECISION_DECISION_DUPLICATE")
        decisions[case_id] = decision
    if set(cases) != set(decisions):
        _fail("REFERENCE_DECISION_CASE_SET")

    model_source_sha256 = _source_sha256(model_json)
    policy_source_sha256 = _source_sha256(policy_json)
    prepared: list[dict[str, Any]] = []
    for case_id in sorted(cases):
        case = cases[case_id]
        expected_stages = _expected_stages(case, model, policy, expected_execution_mode)
        observed_stages = _observed_stages(
            decisions[case_id],
            case_id=case_id,
            execution_mode=expected_execution_mode,
        )
        expected_hashes = _stage_hashes(expected_stages)
        observed_hashes = _stage_hashes(observed_stages)
        _compare_stage(
            "evidence",
            expected_hashes,
            observed_hashes,
            "REFERENCE_DECISION_EVIDENCE_MISMATCH",
        )
        _compare_stage(
            "model",
            expected_hashes,
            observed_hashes,
            "REFERENCE_DECISION_MODEL_MISMATCH",
        )
        _compare_stage(
            "policy",
            expected_hashes,
            observed_hashes,
            "REFERENCE_DECISION_POLICY_MISMATCH",
        )
        _compare_stage(
            "verifier",
            expected_hashes,
            observed_hashes,
            "REFERENCE_DECISION_VERIFIER_MISMATCH",
        )
        _compare_stage(
            "final_surface",
            expected_hashes,
            observed_hashes,
            "REFERENCE_DECISION_FINAL_SURFACE_MISMATCH",
        )
        expected_path = _path_hash(expected_hashes)
        observed_path = _path_hash(observed_hashes)
        if expected_path != observed_path:
            _fail("REFERENCE_DECISION_PATH_MISMATCH")
        prepared.append(
            {
                "schema_version": SCHEMA_VERSION,
                "assurance_kind": ASSURANCE_KIND,
                "recomputation_scope": RECOMPUTATION_SCOPE,
                "case_id": case_id,
                "normalized_case_sha256": _canonical_sha256(case),
                "model_source_sha256": model_source_sha256,
                "policy_source_sha256": policy_source_sha256,
                "expected_evidence_sha256": expected_hashes["evidence"],
                "observed_evidence_sha256": observed_hashes["evidence"],
                "expected_model_sha256": expected_hashes["model"],
                "observed_model_sha256": observed_hashes["model"],
                "expected_policy_sha256": expected_hashes["policy"],
                "observed_policy_sha256": observed_hashes["policy"],
                "expected_verifier_sha256": expected_hashes["verifier"],
                "observed_verifier_sha256": observed_hashes["verifier"],
                "expected_final_surface_sha256": expected_hashes["final_surface"],
                "observed_final_surface_sha256": observed_hashes["final_surface"],
                "expected_source_to_decision_sha256": expected_path,
                "observed_source_to_decision_sha256": observed_path,
                "execution_mode": expected_execution_mode,
                "read_only": True,
                "matched": True,
            }
        )
    return prepared


__all__ = [
    "ASSURANCE_KIND",
    "RECOMPUTATION_SCOPE",
    "ReferenceDecisionAssuranceError",
    "verify_reference_decision_path",
]
