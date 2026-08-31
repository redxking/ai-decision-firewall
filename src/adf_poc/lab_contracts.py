from __future__ import annotations

import copy
import hashlib
import hmac
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator
from jsonschema.exceptions import SchemaError

from adf_poc.utils import StrictJSONError, canonical_json, strict_json_loads


SCHEMA_VERSION = "0.4.0"
COMMAND = "LAB_EXECUTION_COMMAND"
RECEIPT = "LAB_EXECUTOR_RECEIPT"
OBSERVATION_REQUEST = "LAB_OBSERVATION_REQUEST"
OBSERVATION = "LAB_OBSERVATION"
MESSAGE_TYPES = frozenset({COMMAND, RECEIPT, OBSERVATION_REQUEST, OBSERVATION})
MAX_MESSAGE_BYTES = 16 * 1024
MAX_JSON_DEPTH = 8
MAX_FUTURE_SKEW = timedelta(seconds=30)
MAX_COMMAND_LIFETIME = timedelta(seconds=120)
MIN_KEY_BYTES = 32
TARGET_ID = "LAB_ENDPOINT_001"

CONTRACT_ROOT = Path(__file__).resolve().parents[2] / "contracts" / "v0.4.0"
SCHEMA_PATHS = {
    COMMAND: CONTRACT_ROOT / "lab-execution-command.schema.json",
    RECEIPT: CONTRACT_ROOT / "lab-executor-receipt.schema.json",
    OBSERVATION_REQUEST: CONTRACT_ROOT / "lab-observation-request.schema.json",
    OBSERVATION: CONTRACT_ROOT / "lab-observation.schema.json",
}
DOMAINS = {
    COMMAND: b"ADF-LAB-IPC\x00v0.4.0\x00COMMAND\x00",
    RECEIPT: b"ADF-LAB-IPC\x00v0.4.0\x00EXECUTOR-RECEIPT\x00",
    OBSERVATION_REQUEST: b"ADF-LAB-IPC\x00v0.4.0\x00OBSERVATION-REQUEST\x00",
    OBSERVATION: b"ADF-LAB-IPC\x00v0.4.0\x00INDEPENDENT-OBSERVATION\x00",
}
OBSERVATION_FACT_FIELDS = (
    "lab_session_id",
    "request_id",
    "decision_id",
    "command_sha256",
    "idempotency_key",
    "target_id",
    "target_boot_id",
    "sequence",
    "beacon_reachable",
    "management_reachable",
    "ruleset_sha256",
    "observed_at",
)


class LabContractError(ValueError):
    """Fail-closed isolated-lab contract error with a stable reason code."""

    def __init__(self, reason_code: str, message: str) -> None:
        self.reason_code = reason_code
        self.code = reason_code
        self.message = message
        super().__init__(f"{reason_code}: {message}")


def _require_message_type(message_type: str) -> None:
    if type(message_type) is not str or message_type not in MESSAGE_TYPES:
        raise LabContractError(
            "LAB_MESSAGE_TYPE_INVALID", "The expected lab message type is unsupported."
        )


def _require_key(key: bytes, *, label: str) -> bytes:
    if type(key) is not bytes or len(key) < MIN_KEY_BYTES:
        raise LabContractError(
            "LAB_KEY_INVALID",
            f"{label} must be an exact bytes value of at least 32 bytes.",
        )
    return key


def validate_lab_channel_keys(*, executor_key: bytes, observer_key: bytes) -> None:
    """Require distinct fixed-purpose command/receipt and observation keys."""

    executor = _require_key(executor_key, label="Executor channel key")
    observer = _require_key(observer_key, label="Observer channel key")
    if hmac.compare_digest(
        hashlib.sha256(executor).digest(), hashlib.sha256(observer).digest()
    ):
        raise LabContractError(
            "LAB_KEY_SEPARATION_INVALID",
            "Executor and observer channels require distinct key material.",
        )


def _json_depth(value: Any) -> int:
    maximum = 0
    pending: list[tuple[Any, int]] = [(value, 1)]
    while pending:
        child, depth = pending.pop()
        maximum = max(maximum, depth)
        if isinstance(child, dict):
            pending.extend((item, depth + 1) for item in child.values())
        elif isinstance(child, list):
            pending.extend((item, depth + 1) for item in child)
    return maximum


def _encoded_size(value: Any) -> int:
    try:
        return len(canonical_json(value).encode("utf-8"))
    except (TypeError, ValueError, OverflowError) as exc:
        raise LabContractError(
            "LAB_JSON_INVALID",
            "Lab messages must contain finite canonical JSON values.",
        ) from exc


def _strict_decode(raw: str | bytes) -> dict[str, Any]:
    if not isinstance(raw, (str, bytes)):
        raise LabContractError(
            "LAB_JSON_INVALID", "Lab message must be JSON text or bytes."
        )
    raw_bytes = raw.encode("utf-8") if isinstance(raw, str) else raw
    if len(raw_bytes) > MAX_MESSAGE_BYTES:
        raise LabContractError(
            "LAB_MESSAGE_TOO_LARGE", "Lab message exceeds the 16 KiB bound."
        )
    try:
        value = strict_json_loads(raw)
    except (StrictJSONError, json.JSONDecodeError, UnicodeError, RecursionError) as exc:
        raise LabContractError(
            "LAB_JSON_INVALID",
            "Lab message is not strict JSON; duplicate members and non-finite numbers are prohibited.",
        ) from exc
    if not isinstance(value, dict):
        raise LabContractError(
            "LAB_MESSAGE_NOT_OBJECT", "Lab message must be an object."
        )
    if _json_depth(value) > MAX_JSON_DEPTH:
        raise LabContractError(
            "LAB_MESSAGE_TOO_DEEP",
            f"Lab message exceeds the {MAX_JSON_DEPTH}-level nesting bound.",
        )
    return value


def _load_schema(message_type: str) -> dict[str, Any]:
    _require_message_type(message_type)
    try:
        raw = SCHEMA_PATHS[message_type].read_bytes()
        if len(raw) > MAX_MESSAGE_BYTES:
            raise ValueError("schema exceeds bound")
        schema = strict_json_loads(raw)
        if not isinstance(schema, dict):
            raise TypeError("schema is not an object")
        Draft202012Validator.check_schema(schema)
        return schema
    except (
        OSError,
        StrictJSONError,
        UnicodeError,
        ValueError,
        TypeError,
        SchemaError,
    ) as exc:
        raise LabContractError(
            "LAB_SCHEMA_INVALID_CONFIGURATION",
            "The selected lab message schema could not be loaded or validated.",
        ) from exc


def _schema_error_message(error: Any) -> str:
    path = ".".join(str(item) for item in error.absolute_path)
    return ((f"{path}: " if path else "") + error.message)[:500]


def _parse_canonical_utc(value: Any) -> datetime:
    if type(value) is not str:
        raise ValueError("timestamp is not text")
    parsed = datetime.fromisoformat(value)
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValueError("timestamp has no offset")
    canonical = parsed.astimezone(timezone.utc).replace(microsecond=0).isoformat()
    if value != canonical:
        raise ValueError("timestamp is not canonical UTC seconds")
    return parsed.astimezone(timezone.utc)


def _validation_time(now: datetime | None) -> datetime:
    value = now or datetime.now(timezone.utc)
    if value.tzinfo is None or value.utcoffset() is None:
        raise LabContractError(
            "LAB_CLOCK_INVALID", "Lab validation clock must include a UTC offset."
        )
    return value.astimezone(timezone.utc)


def _validate_times(
    value: dict[str, Any],
    message_type: str,
    now: datetime | None,
    *,
    allow_expired: bool = False,
) -> None:
    validation_time = _validation_time(now)
    try:
        if message_type in (COMMAND, OBSERVATION_REQUEST):
            issued = _parse_canonical_utc(value["issued_at"])
            expires = _parse_canonical_utc(value["expires_at"])
            if expires <= issued or expires - issued > MAX_COMMAND_LIFETIME:
                raise LabContractError(
                    "LAB_COMMAND_LIFETIME_INVALID",
                    "Request expiry must be after issue and within 120 seconds.",
                )
            if issued > validation_time + MAX_FUTURE_SKEW:
                raise LabContractError(
                    "LAB_TIMESTAMP_FUTURE", "Request issue time exceeds allowed skew."
                )
            if expires <= validation_time and not allow_expired:
                raise LabContractError("LAB_COMMAND_EXPIRED", "Request has expired.")
        elif message_type == RECEIPT:
            executed = _parse_canonical_utc(value["executed_at"])
            recorded = _parse_canonical_utc(value["recorded_at"])
            if executed > recorded:
                raise LabContractError(
                    "LAB_TIMESTAMP_ORDER_INVALID",
                    "Receipt execution cannot occur after receipt recording.",
                )
            if recorded > validation_time + MAX_FUTURE_SKEW:
                raise LabContractError(
                    "LAB_TIMESTAMP_FUTURE", "Receipt time exceeds allowed skew."
                )
        else:
            observed = _parse_canonical_utc(value["observed_at"])
            recorded = _parse_canonical_utc(value["recorded_at"])
            if observed > recorded:
                raise LabContractError(
                    "LAB_TIMESTAMP_ORDER_INVALID",
                    "Observation cannot occur after observation recording.",
                )
            if recorded > validation_time + MAX_FUTURE_SKEW:
                raise LabContractError(
                    "LAB_TIMESTAMP_FUTURE", "Observation time exceeds allowed skew."
                )
    except LabContractError:
        raise
    except (KeyError, TypeError, ValueError, OverflowError) as exc:
        raise LabContractError(
            "LAB_TIMESTAMP_INVALID",
            "Lab timestamps must be canonical UTC date-times at whole-second precision.",
        ) from exc


def observation_facts_sha256(value: dict[str, Any]) -> str:
    try:
        facts = {
            field: copy.deepcopy(value[field]) for field in OBSERVATION_FACT_FIELDS
        }
        payload = canonical_json(facts).encode("utf-8")
    except (KeyError, TypeError, ValueError, OverflowError) as exc:
        raise LabContractError(
            "LAB_OBSERVATION_BINDING_INVALID",
            "Observation facts cannot be canonically bound.",
        ) from exc
    return hashlib.sha256(
        b"ADF-LAB-OBSERVATION-FACTS\x00v0.4.0\x00" + payload
    ).hexdigest()


def validate_lab_message_dict(
    value: dict[str, Any],
    *,
    message_type: str,
    now: datetime | None = None,
    allow_expired: bool = False,
) -> dict[str, Any]:
    """Validate an already decoded message without assigning it trust."""

    _require_message_type(message_type)
    if not isinstance(value, dict):
        raise LabContractError(
            "LAB_MESSAGE_NOT_OBJECT", "Lab message must be an object."
        )
    if _encoded_size(value) > MAX_MESSAGE_BYTES:
        raise LabContractError(
            "LAB_MESSAGE_TOO_LARGE", "Lab message exceeds the 16 KiB bound."
        )
    if _json_depth(value) > MAX_JSON_DEPTH:
        raise LabContractError(
            "LAB_MESSAGE_TOO_DEEP",
            f"Lab message exceeds the {MAX_JSON_DEPTH}-level nesting bound.",
        )
    if "schema_version" in value and value["schema_version"] != SCHEMA_VERSION:
        raise LabContractError(
            "LAB_SCHEMA_VERSION_UNSUPPORTED",
            f"Only lab schema version {SCHEMA_VERSION} is supported.",
        )
    errors = sorted(
        Draft202012Validator(_load_schema(message_type)).iter_errors(value),
        key=lambda error: (
            tuple(str(item) for item in error.absolute_path),
            error.message,
        ),
    )
    if errors:
        raise LabContractError("LAB_SCHEMA_INVALID", _schema_error_message(errors[0]))
    if type(allow_expired) is not bool or (
        allow_expired and message_type not in (COMMAND, OBSERVATION_REQUEST)
    ):
        raise LabContractError(
            "LAB_VALIDATION_MODE_INVALID",
            "Expired-message validation is available only to replay-aware requests.",
        )
    _validate_times(value, message_type, now, allow_expired=allow_expired)

    if message_type == RECEIPT:
        expected = {
            "APPLIED": {(True, "RULESET_APPLIED")},
            "NO_EFFECT": {
                (False, "REJECTED_PRE_EFFECT"),
                (False, "TARGET_UNAVAILABLE_PRE_EFFECT"),
            },
            "PARTIAL": {(True, "PARTIAL_RULESET")},
            "AMBIGUOUS": {(True, "EFFECT_UNCERTAIN")},
        }[value["status"]]
        if (value["effect_possible"], value["reason_code"]) not in expected:
            raise LabContractError(
                "LAB_RECEIPT_OUTCOME_INVALID",
                "Receipt status, effect possibility, and reason code disagree.",
            )
        if value["status"] == "NO_EFFECT":
            expected_poststate = (
                "0" * 64
                if value["reason_code"] == "TARGET_UNAVAILABLE_PRE_EFFECT"
                else value["prestate_sha256"]
            )
            if value["poststate_sha256"] != expected_poststate:
                raise LabContractError(
                    "LAB_RECEIPT_OUTCOME_INVALID",
                    "NO_EFFECT receipt poststate does not match its closed reason.",
                )
        if (
            value["status"] == "APPLIED"
            and value["poststate_sha256"] == value["prestate_sha256"]
        ):
            raise LabContractError(
                "LAB_RECEIPT_OUTCOME_INVALID",
                "APPLIED receipt must bind a changed poststate digest.",
            )
    elif message_type == OBSERVATION:
        expected_digest = observation_facts_sha256(value)
        if not hmac.compare_digest(expected_digest, value["observation_facts_sha256"]):
            raise LabContractError(
                "LAB_OBSERVATION_BINDING_INVALID",
                "Observation facts digest does not match the canonical record.",
            )
    return copy.deepcopy(value)


def _authentication_bytes(value: dict[str, Any], message_type: str) -> bytes:
    payload = copy.deepcopy(value)
    try:
        authentication = payload["authentication"]
        del authentication["mac_sha256"]
    except (KeyError, TypeError) as exc:
        raise LabContractError(
            "LAB_AUTHENTICATION_INVALID", "Lab authentication envelope is incomplete."
        ) from exc
    try:
        return DOMAINS[message_type] + canonical_json(payload).encode("utf-8")
    except (TypeError, ValueError, OverflowError) as exc:
        raise LabContractError(
            "LAB_AUTHENTICATION_INVALID", "Lab authentication payload is not canonical."
        ) from exc


def sign_lab_message(
    unsigned: dict[str, Any],
    *,
    message_type: str,
    key_id: str,
    key: bytes,
    now: datetime | None = None,
) -> dict[str, Any]:
    """Validate and authenticate a new message; never accepts a preexisting MAC."""

    _require_message_type(message_type)
    material = _require_key(key, label="Lab channel key")
    if not isinstance(unsigned, dict) or "authentication" in unsigned:
        raise LabContractError(
            "LAB_SIGNING_INPUT_INVALID",
            "Signing input must be a message object without authentication.",
        )
    candidate = copy.deepcopy(unsigned)
    candidate["authentication"] = {"key_id": key_id, "mac_sha256": "0" * 64}
    validate_lab_message_dict(candidate, message_type=message_type, now=now)
    candidate["authentication"]["mac_sha256"] = hmac.new(
        material, _authentication_bytes(candidate, message_type), hashlib.sha256
    ).hexdigest()
    return candidate


def verify_lab_message_hmac(
    value: dict[str, Any],
    *,
    message_type: str,
    expected_key_id: str,
    key: bytes,
) -> None:
    """Authenticate before callers semantically consume untrusted fields."""

    _require_message_type(message_type)
    material = _require_key(key, label="Lab channel key")
    try:
        authentication = value["authentication"]
        key_id = authentication["key_id"]
        observed = authentication["mac_sha256"]
        if type(key_id) is not str or type(observed) is not str:
            raise TypeError("authentication values are not text")
    except (KeyError, TypeError) as exc:
        raise LabContractError(
            "LAB_AUTHENTICATION_INVALID", "Lab authentication envelope is incomplete."
        ) from exc
    expected = hmac.new(
        material, _authentication_bytes(value, message_type), hashlib.sha256
    ).hexdigest()
    if not (
        hmac.compare_digest(key_id, expected_key_id)
        and hmac.compare_digest(observed, expected)
    ):
        raise LabContractError(
            "LAB_AUTHENTICATION_INVALID", "Lab message authentication failed."
        )


def load_authenticated_lab_message(
    raw: str | bytes,
    *,
    message_type: str,
    expected_key_id: str,
    key: bytes,
    now: datetime | None = None,
    allow_expired: bool = False,
) -> dict[str, Any]:
    """Strict-decode, authenticate, then semantically validate a lab message."""

    value = _strict_decode(raw)
    verify_lab_message_hmac(
        value,
        message_type=message_type,
        expected_key_id=expected_key_id,
        key=key,
    )
    return validate_lab_message_dict(
        value,
        message_type=message_type,
        now=now,
        allow_expired=allow_expired,
    )


def lab_message_sha256(value: dict[str, Any]) -> str:
    """Digest the complete signed message for cross-message correlation."""

    try:
        return hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()
    except (TypeError, ValueError, OverflowError) as exc:
        raise LabContractError(
            "LAB_MESSAGE_DIGEST_INVALID", "Lab message cannot be canonically digested."
        ) from exc


def validate_lab_message_correlation(
    *,
    command: dict[str, Any],
    receipt: dict[str, Any],
    observation: dict[str, Any],
) -> None:
    """Require exact one-command correlation without assigning effect truth."""

    command_digest = lab_message_sha256(command)
    if (
        receipt.get("command_sha256") != command_digest
        or observation.get("command_sha256") != command_digest
    ):
        raise LabContractError(
            "LAB_CORRELATION_INVALID",
            "Receipt and observation must bind the exact signed command.",
        )
    shared = (
        "lab_session_id",
        "request_id",
        "decision_id",
        "idempotency_key",
        "target_id",
        "target_boot_id",
        "sequence",
    )
    for field in shared:
        if receipt.get(field) != command.get(field) or observation.get(
            field
        ) != command.get(field):
            raise LabContractError(
                "LAB_CORRELATION_INVALID",
                f"Command, receipt, and observation disagree on {field}.",
            )
    if receipt.get("authorization_id") != command.get("authorization_id"):
        raise LabContractError(
            "LAB_CORRELATION_INVALID",
            "Receipt does not bind the command authorization.",
        )
    if receipt.get("prestate_sha256") != command.get("prestate_sha256"):
        raise LabContractError(
            "LAB_CORRELATION_INVALID", "Receipt does not bind the command prestate."
        )
    if observation.get("ruleset_sha256") != receipt.get("poststate_sha256"):
        raise LabContractError(
            "LAB_CORRELATION_INVALID",
            "Independent observation does not match the executor poststate digest.",
        )
