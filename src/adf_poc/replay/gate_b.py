"""Fail-closed Gate B preflight for de-identified historical replay.

The Gate B document is an externally governed control input.  This module can
verify its closed structure, time validity, required roles, local artifact
bindings, and code-owned stop conditions.  It cannot prove an approver's
identity or authority, a signature, the truth of a custody statement, or the
effectiveness of de-identification.  Those remain external governance duties.

For historical input, callers must complete this control-document preflight
before opening, hashing, counting, or parsing the case and adjudication files.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
from collections import Counter
from dataclasses import dataclass
from datetime import datetime, timezone
from decimal import Decimal, InvalidOperation
from pathlib import Path
from typing import Any, Mapping, Sequence

from .contracts import (
    ALLOWED_DATA_ORIGINS,
    ALLOWED_REPLAY_MODES,
    CONTRACT_VERSION,
    MAX_CONTROL_DOCUMENT_BYTES,
    MAX_RECORDS_PER_FILE,
    ContractValidationError,
    ManifestValidationError,
    ReplayConfig,
    resolve_confined_path,
)


REQUIRED_APPROVAL_ROLES = frozenset(
    {
        "DATA_OWNER",
        "MISSION_OWNER",
        "SECURITY",
        "PRIVACY_LEGAL",
        "RECORDS_MANAGEMENT",
    }
)
REQUIRED_ARTIFACT_ROLES = frozenset(
    {"SOURCE_MAPPING", "ADJUDICATION_PROTOCOL", "PILOT_PROTOCOL"}
)
ALLOWED_QUALIFICATION_THRESHOLD_CATEGORIES = frozenset(
    {
        "ENCODING",
        "RESOURCE_LIMIT",
        "SYNTAX",
        "STRUCTURE",
        "SEMANTICS",
        "POLICY",
        "DUPLICATE",
    }
)
GATE_B_SNAPSHOT_ROLE_BY_ARTIFACT = {
    "SOURCE_MAPPING": "gate_b_source_mapping",
    "ADJUDICATION_PROTOCOL": "gate_b_adjudication_protocol",
    "PILOT_PROTOCOL": "gate_b_pilot_protocol",
}

_IDENTIFIER_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_SHA256_PATTERN = re.compile(r"^[a-f0-9]{64}$")
_PATH_COMPONENT_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$")
_MAX_TEXT_CHARS = 2048
MAX_CONTROL_JSON_NESTING_DEPTH = 128
MAX_GATE_B_ARTIFACT_BYTES = 2 * 1024 * 1024
MAX_GATE_B_MODEL_POLICY_BYTES = 64 * 1024 * 1024


class GateBValidationError(ContractValidationError):
    """A bounded Gate B control-document or binding failure."""


class GateBStopConditionViolation(GateBValidationError):
    """A predeclared Gate B stop condition was reached before engine use."""


class _DuplicateJSONMember(ValueError):
    """Internal marker for ambiguous control-document JSON."""


def _parse_object_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, child in pairs:
        if key in value:
            raise _DuplicateJSONMember
        value[key] = child
    return value


def _reject_nonstandard_number(_: str) -> None:
    raise ValueError


@dataclass(frozen=True, slots=True)
class ManifestControl:
    """Manifest identity parsed without opening any declared data file."""

    path: Path
    source_sha256: str
    source_bytes: bytes
    dataset_id: str
    data_origin: str
    historical_case_count: int
    intended_mode: str
    cases_record_count: int


@dataclass(frozen=True, slots=True, repr=False)
class GateBArtifactBinding:
    role: str
    path: Path
    sha256: str
    content: bytes


@dataclass(frozen=True, slots=True, repr=False)
class GateBAuthorization:
    """The minimum runtime state retained from an approved Gate B package."""

    path: Path
    source_sha256: str
    source_bytes: bytes
    authorization_id: str
    dataset_id: str
    dataset_manifest_sha256: str
    window_start: datetime
    window_end: datetime
    valid_from: datetime
    expires_at: datetime
    artifacts: tuple[GateBArtifactBinding, ...]
    full_intake_count: int
    sample_count: int
    max_overall_quarantine_rate: Decimal
    max_category_quarantine_rates: tuple[tuple[str, Decimal], ...]
    model_bytes: bytes
    policy_bytes: bytes

    @property
    def artifact_by_role(self) -> dict[str, GateBArtifactBinding]:
        return {artifact.role: artifact for artifact in self.artifacts}

    @property
    def category_thresholds(self) -> dict[str, Decimal]:
        return dict(self.max_category_quarantine_rates)


def validate_gate_b_current(
    authorization: GateBAuthorization,
    *,
    now: datetime | None = None,
) -> None:
    """Require a Gate B authorization to be current at an execution stage."""

    current = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
    if current < authorization.valid_from or current >= authorization.expires_at:
        raise GateBValidationError("Gate B authorization is not currently valid.")


def _read_bounded_regular_file(path: Path, *, label: str, maximum: int) -> bytes:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError:
        raise GateBValidationError(f"Unable to read the bound {label} file.") from None
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
            raise GateBValidationError(
                f"The bound {label} file is not an exclusive regular file."
            )
        if metadata.st_size > maximum:
            raise GateBValidationError(
                f"The bound {label} file exceeds its size limit."
            )
        chunks: list[bytes] = []
        total = 0
        while True:
            chunk = os.read(descriptor, min(1024 * 1024, maximum + 1 - total))
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
            if total > maximum:
                raise GateBValidationError(
                    f"The bound {label} file exceeds its size limit."
                )
        final_metadata = os.fstat(descriptor)
        stable_fields = (
            "st_dev",
            "st_ino",
            "st_size",
            "st_mtime_ns",
            "st_ctime_ns",
            "st_nlink",
        )
        if final_metadata.st_nlink != 1 or any(
            getattr(metadata, field) != getattr(final_metadata, field)
            for field in stable_fields
        ):
            raise GateBValidationError(
                f"The bound {label} file changed while it was read."
            )
        return b"".join(chunks)
    except OSError:
        raise GateBValidationError(f"Unable to read the bound {label} file.") from None
    finally:
        os.close(descriptor)


def _load_bounded_json_object(
    path: Path, *, label: str
) -> tuple[dict[str, Any], str, bytes]:
    raw = _read_bounded_regular_file(
        path,
        label=f"{label} control document",
        maximum=MAX_CONTROL_DOCUMENT_BYTES,
    )
    if len(raw) > MAX_CONTROL_DOCUMENT_BYTES:
        raise GateBValidationError(
            f"The {label} control document exceeds its size limit."
        )
    try:
        text = raw.decode("utf-8")
        if _json_nesting_depth_exceeded(text):
            raise RecursionError
        value = json.loads(
            text,
            object_pairs_hook=_parse_object_pairs,
            parse_constant=_reject_nonstandard_number,
        )
    except RecursionError:
        raise GateBValidationError(
            f"The {label} control document exceeds the JSON nesting limit."
        ) from None
    except (UnicodeError, json.JSONDecodeError, _DuplicateJSONMember, ValueError):
        raise GateBValidationError(
            f"The {label} control document is not valid UTF-8 JSON."
        ) from None
    if not isinstance(value, dict):
        raise GateBValidationError(
            f"The {label} control document must be a JSON object."
        )
    return value, hashlib.sha256(raw).hexdigest(), raw


def _exact_fields(value: Any, required: set[str], label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise GateBValidationError(f"{label} must be an object.")
    missing = sorted(required - set(value))
    unexpected = sorted(set(value) - required)
    if missing:
        raise GateBValidationError(
            f"{label} is missing required fields: {', '.join(missing)}."
        )
    if unexpected:
        raise GateBValidationError(f"{label} contains unsupported fields.")
    return value


def _json_nesting_depth_exceeded(text: str) -> bool:
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
            if depth > MAX_CONTROL_JSON_NESTING_DEPTH:
                return True
        elif character in "]}" and depth:
            depth -= 1
    return False


def _nonempty(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value.strip() or len(value) > _MAX_TEXT_CHARS:
        raise GateBValidationError(f"{label} must be a bounded non-empty string.")
    return value


def _confined_relative_path(value: Any, label: str) -> str:
    candidate = _nonempty(value, label)
    path = Path(candidate)
    if (
        len(candidate) > 512
        or "\\" in candidate
        or candidate != path.as_posix()
        or path.is_absolute()
        or any(part in {"", ".", ".."} for part in path.parts)
        or any(not _PATH_COMPONENT_PATTERN.fullmatch(part) for part in path.parts)
    ):
        raise GateBValidationError(f"{label} must be a confined relative path.")
    return candidate


def _identifier(value: Any, label: str) -> str:
    candidate = _nonempty(value, label)
    if not _IDENTIFIER_PATTERN.fullmatch(candidate):
        raise GateBValidationError(f"{label} must be a canonical identifier.")
    return candidate


def _sha256(value: Any, label: str, *, allow_placeholder: bool = False) -> str:
    if not isinstance(value, str) or not _SHA256_PATTERN.fullmatch(value):
        raise GateBValidationError(f"{label} must be a lowercase SHA-256 digest.")
    if not allow_placeholder and value == "0" * 64:
        raise GateBValidationError(f"{label} cannot use a placeholder digest.")
    return value


def _boolean(value: Any, label: str) -> bool:
    if type(value) is not bool:
        raise GateBValidationError(f"{label} must be a boolean.")
    return value


def _integer(value: Any, label: str, *, minimum: int = 0) -> int:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise GateBValidationError(
            f"{label} must be an integer greater than or equal to {minimum}."
        )
    if isinstance(value, float):
        if not value.is_integer():
            raise GateBValidationError(
                f"{label} must be an integer greater than or equal to {minimum}."
            )
        value = int(value)
    if value < minimum:
        raise GateBValidationError(
            f"{label} must be an integer greater than or equal to {minimum}."
        )
    return value


def _rate(value: Any, label: str) -> Decimal:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise GateBValidationError(f"{label} must be a number in [0, 1].")
    try:
        candidate = Decimal(str(value))
    except (InvalidOperation, ValueError):
        raise GateBValidationError(f"{label} must be a number in [0, 1].") from None
    if not candidate.is_finite() or not Decimal("0") <= candidate <= Decimal("1"):
        raise GateBValidationError(f"{label} must be a finite number in [0, 1].")
    return candidate


def _timestamp(value: Any, label: str) -> datetime:
    if not isinstance(value, str) or not value:
        raise GateBValidationError(
            f"{label} must be an ISO-8601 timestamp with a UTC offset."
        )
    candidate = value[:-1] + "+00:00" if value.endswith(("Z", "z")) else value
    try:
        parsed = datetime.fromisoformat(candidate)
    except ValueError:
        raise GateBValidationError(
            f"{label} must be an ISO-8601 timestamp with a UTC offset."
        ) from None
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise GateBValidationError(f"{label} must include an explicit UTC offset.")
    return parsed.astimezone(timezone.utc)


def _safe_file_bytes_and_digest(
    path: Path, label: str, *, maximum: int
) -> tuple[bytes, str]:
    raw = _read_bounded_regular_file(
        path,
        label=label,
        maximum=maximum,
    )
    return raw, hashlib.sha256(raw).hexdigest()


def load_manifest_control(path: str | Path) -> ManifestControl:
    """Read only manifest control bytes; never open a declared data file."""

    target = Path(path).resolve()
    value, source_sha256, source_bytes = _load_bounded_json_object(
        target, label="dataset manifest"
    )
    required = {
        "schema_version",
        "dataset_id",
        "data_origin",
        "historical_case_count",
        "intended_mode",
        "created_at",
        "attestations",
        "files",
    }
    _exact_fields(value, required, "dataset manifest")
    if value.get("schema_version") != CONTRACT_VERSION:
        raise GateBValidationError("dataset manifest.schema_version is unsupported.")
    dataset_id = _identifier(value.get("dataset_id"), "dataset manifest.dataset_id")
    data_origin = value.get("data_origin")
    if data_origin not in ALLOWED_DATA_ORIGINS:
        raise GateBValidationError("dataset manifest.data_origin is unsupported.")
    historical_case_count = _integer(
        value.get("historical_case_count"), "dataset manifest.historical_case_count"
    )
    intended_mode = value.get("intended_mode")
    if intended_mode not in ALLOWED_REPLAY_MODES:
        raise GateBValidationError("dataset manifest.intended_mode is unsupported.")
    _timestamp(value.get("created_at"), "dataset manifest.created_at")
    files = value.get("files")
    if not isinstance(files, list) or not files:
        raise GateBValidationError("dataset manifest.files must be a non-empty array.")
    roles: set[str] = set()
    declared_paths: set[str] = set()
    cases_record_count: int | None = None
    for index, raw_entry in enumerate(files):
        entry = _exact_fields(
            raw_entry,
            {"role", "path", "sha256", "record_count", "adapter"},
            f"dataset manifest.files[{index}]",
        )
        role = _identifier(entry.get("role"), f"dataset manifest.files[{index}].role")
        if role not in {"cases", "adjudications"} or role in roles:
            raise GateBValidationError(
                "dataset manifest file roles are unsupported or duplicated."
            )
        roles.add(role)
        declared_path = _confined_relative_path(
            entry.get("path"), f"dataset manifest.files[{index}].path"
        )
        if declared_path in declared_paths:
            raise GateBValidationError(
                "dataset manifest file paths must be physically distinct."
            )
        declared_paths.add(declared_path)
        _sha256(
            entry.get("sha256"),
            f"dataset manifest.files[{index}].sha256",
            allow_placeholder=data_origin != "HISTORICAL_DEIDENTIFIED",
        )
        record_count = _integer(
            entry.get("record_count"), f"dataset manifest.files[{index}].record_count"
        )
        if record_count > MAX_RECORDS_PER_FILE:
            raise GateBValidationError("dataset manifest declares too many records.")
        if entry.get("adapter") != "canonical_jsonl_v0.2":
            raise GateBValidationError(
                "dataset manifest declares an unsupported adapter."
            )
        if role == "cases":
            cases_record_count = record_count
    if cases_record_count is None:
        raise GateBValidationError("dataset manifest does not declare the cases role.")
    if data_origin == "HISTORICAL_DEIDENTIFIED":
        if intended_mode != "HISTORICAL_REPLAY":
            raise GateBValidationError("Historical data requires HISTORICAL_REPLAY.")
        if "adjudications" not in roles:
            raise GateBValidationError(
                "Historical replay requires separate adjudications."
            )
        if historical_case_count != cases_record_count:
            raise GateBValidationError(
                "Historical case count must equal the declared cases record count."
            )
    return ManifestControl(
        path=target,
        source_sha256=source_sha256,
        source_bytes=source_bytes,
        dataset_id=dataset_id,
        data_origin=str(data_origin),
        historical_case_count=historical_case_count,
        intended_mode=str(intended_mode),
        cases_record_count=cases_record_count,
    )


def _resolve_bound_artifact(
    *,
    repository_root: Path,
    role: str,
    declared_path: str,
    overrides: Mapping[str, Path] | None,
) -> Path:
    if overrides is not None:
        if role not in overrides:
            raise GateBValidationError(
                f"No snapshotted artifact is available for role {role}."
            )
        path = Path(overrides[role]).resolve()
        if not path.is_file():
            raise GateBValidationError(
                f"The snapshotted {role} artifact is unavailable."
            )
        return path
    declared_path = _confined_relative_path(
        declared_path, f"Gate B {role} artifact path"
    )
    candidate = Path(declared_path)
    if overrides is None and candidate.parts[:2] != ("local", "gate_b"):
        raise GateBValidationError(
            f"The bound {role} artifact must use the restricted local/gate_b root."
        )
    current = repository_root
    for part in candidate.parts:
        current = current / part
        if current.is_symlink():
            raise GateBValidationError(
                f"The bound {role} artifact path cannot use symlinks."
            )
    try:
        return resolve_confined_path(
            repository_root,
            declared_path,
            label=f"Gate B {role} artifact",
            must_exist=True,
        )
    except ManifestValidationError:
        raise GateBValidationError(
            f"The bound {role} artifact path is not confined."
        ) from None


def load_gate_b_authorization(
    path: str | Path,
    *,
    repository_root: str | Path,
    manifest: ManifestControl,
    config: ReplayConfig,
    model_path: str | Path,
    policy_path: str | Path,
    now: datetime | None = None,
    artifact_path_overrides: Mapping[str, Path] | None = None,
) -> GateBAuthorization:
    """Validate an approved Gate B package without touching historical records."""

    target = Path(path).resolve()
    value, source_sha256, source_bytes = _load_bounded_json_object(
        target, label="Gate B authorization"
    )
    top_fields = {
        "schema_version",
        "authorization_id",
        "status",
        "dataset_id",
        "dataset_manifest_sha256",
        "approved_purpose",
        "population_scope",
        "window_start",
        "window_end",
        "valid_from",
        "expires_at",
        "approvals",
        "artifact_bindings",
        "controls",
        "custody",
        "sampling",
        "stop_conditions",
        "adjudication",
        "independent_review",
        "claim_control",
    }
    _exact_fields(value, top_fields, "Gate B authorization")
    if value.get("schema_version") != CONTRACT_VERSION:
        raise GateBValidationError(
            "Gate B authorization.schema_version is unsupported."
        )
    if value.get("status") != "APPROVED":
        raise GateBValidationError("Gate B authorization status is not APPROVED.")
    if manifest.data_origin != "HISTORICAL_DEIDENTIFIED":
        raise GateBValidationError(
            "Gate B authorization is only valid for historical origin."
        )
    if config.execution_mode != "HISTORICAL_REPLAY":
        raise GateBValidationError("Gate B requires HISTORICAL_REPLAY execution mode.")
    if config.record_failure_policy != "QUARANTINE_RECORD":
        raise GateBValidationError("Gate B requires the QUARANTINE_RECORD policy.")

    authorization_id = _identifier(value.get("authorization_id"), "authorization_id")
    dataset_id = _identifier(value.get("dataset_id"), "dataset_id")
    if dataset_id != manifest.dataset_id:
        raise GateBValidationError(
            "Gate B dataset binding does not match the manifest."
        )
    manifest_digest = _sha256(
        value.get("dataset_manifest_sha256"), "dataset_manifest_sha256"
    )
    if manifest_digest != manifest.source_sha256:
        raise GateBValidationError("Gate B manifest digest binding does not match.")
    _nonempty(value.get("approved_purpose"), "approved_purpose")
    _nonempty(value.get("population_scope"), "population_scope")

    window_start = _timestamp(value.get("window_start"), "window_start")
    window_end = _timestamp(value.get("window_end"), "window_end")
    valid_from = _timestamp(value.get("valid_from"), "valid_from")
    expires_at = _timestamp(value.get("expires_at"), "expires_at")
    if not window_start < window_end:
        raise GateBValidationError("Gate B approved window must be non-empty.")
    if not valid_from < expires_at:
        raise GateBValidationError("Gate B validity interval must be non-empty.")
    current = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
    if current < valid_from or current >= expires_at:
        raise GateBValidationError("Gate B authorization is not currently valid.")

    approvals = value.get("approvals")
    if not isinstance(approvals, list) or len(approvals) != len(
        REQUIRED_APPROVAL_ROLES
    ):
        raise GateBValidationError("Gate B requires exactly five approval roles.")
    approval_roles: set[str] = set()
    approval_identities: set[str] = set()
    for index, raw_approval in enumerate(approvals):
        approval = _exact_fields(
            raw_approval,
            {"role", "status", "approver_id", "approval_reference", "approved_at"},
            f"approvals[{index}]",
        )
        role = approval.get("role")
        if role not in REQUIRED_APPROVAL_ROLES or role in approval_roles:
            raise GateBValidationError(
                "Gate B approval roles are incomplete or duplicated."
            )
        approval_roles.add(str(role))
        if approval.get("status") != "APPROVED":
            raise GateBValidationError(f"Gate B approval role {role} is not APPROVED.")
        approver_id = _nonempty(
            approval.get("approver_id"), f"approvals[{index}].approver_id"
        )
        approval_identities.add(approver_id)
        _nonempty(
            approval.get("approval_reference"), f"approvals[{index}].approval_reference"
        )
        approved_at = _timestamp(
            approval.get("approved_at"), f"approvals[{index}].approved_at"
        )
        if approved_at > valid_from:
            raise GateBValidationError(
                f"Gate B approval role {role} postdates valid_from."
            )
    if approval_roles != REQUIRED_APPROVAL_ROLES:
        raise GateBValidationError(
            "Gate B approval roles are incomplete or duplicated."
        )

    bindings = _exact_fields(
        value.get("artifact_bindings"),
        {
            "contract_version",
            "contract_adapter",
            "model_sha256",
            "policy_sha256",
            "artifacts",
        },
        "artifact_bindings",
    )
    if bindings.get("contract_version") != CONTRACT_VERSION:
        raise GateBValidationError("Gate B contract version binding does not match.")
    if bindings.get("contract_adapter") != config.contract_adapter:
        raise GateBValidationError("Gate B contract adapter binding does not match.")
    expected_model_digest = _sha256(bindings.get("model_sha256"), "model_sha256")
    expected_policy_digest = _sha256(bindings.get("policy_sha256"), "policy_sha256")
    model_bytes, model_digest = _safe_file_bytes_and_digest(
        Path(model_path), "model", maximum=MAX_GATE_B_MODEL_POLICY_BYTES
    )
    policy_bytes, policy_digest = _safe_file_bytes_and_digest(
        Path(policy_path), "policy", maximum=MAX_GATE_B_MODEL_POLICY_BYTES
    )
    if model_digest != expected_model_digest:
        raise GateBValidationError("Gate B model digest binding does not match.")
    if policy_digest != expected_policy_digest:
        raise GateBValidationError("Gate B policy digest binding does not match.")
    raw_artifacts = bindings.get("artifacts")
    if not isinstance(raw_artifacts, list) or len(raw_artifacts) != len(
        REQUIRED_ARTIFACT_ROLES
    ):
        raise GateBValidationError(
            "Gate B requires exactly three bound control artifacts."
        )
    parsed_artifacts: list[GateBArtifactBinding] = []
    artifact_roles: set[str] = set()
    for index, raw_artifact in enumerate(raw_artifacts):
        artifact = _exact_fields(
            raw_artifact,
            {"role", "path", "sha256"},
            f"artifact_bindings.artifacts[{index}]",
        )
        role = artifact.get("role")
        if role not in REQUIRED_ARTIFACT_ROLES or role in artifact_roles:
            raise GateBValidationError(
                "Gate B artifact roles are incomplete or duplicated."
            )
        artifact_roles.add(str(role))
        declared_path = _confined_relative_path(
            artifact.get("path"), f"artifact_bindings.artifacts[{index}].path"
        )
        expected_digest = _sha256(
            artifact.get("sha256"), f"artifact_bindings.artifacts[{index}].sha256"
        )
        resolved = _resolve_bound_artifact(
            repository_root=Path(repository_root).resolve(),
            role=str(role),
            declared_path=declared_path,
            overrides=artifact_path_overrides,
        )
        content, actual_digest = _safe_file_bytes_and_digest(
            resolved,
            str(role),
            maximum=MAX_GATE_B_ARTIFACT_BYTES,
        )
        if actual_digest != expected_digest:
            raise GateBValidationError(f"Gate B {role} digest binding does not match.")
        parsed_artifacts.append(
            GateBArtifactBinding(
                role=str(role),
                path=resolved,
                sha256=expected_digest,
                content=content,
            )
        )
    if artifact_roles != REQUIRED_ARTIFACT_ROLES:
        raise GateBValidationError(
            "Gate B artifact roles are incomplete or duplicated."
        )

    controls = _exact_fields(
        value.get("controls"),
        {
            "deidentification_assessment_reference",
            "direct_identifiers_removed",
            "reidentification_risk_reviewed",
            "offline_only",
            "live_feed_connected",
            "action_credentials_present",
            "write_capable_connectors_present",
            "network_egress_disabled",
            "runtime_labels_separated",
            "complete_intake_reporting",
            "restricted_hash_handling",
            "retention_deletion_reference",
            "incident_response_reference",
            "isolation_reference",
            "kill_switch_reference",
        },
        "controls",
    )
    for reference in (
        "deidentification_assessment_reference",
        "retention_deletion_reference",
        "incident_response_reference",
        "isolation_reference",
        "kill_switch_reference",
    ):
        _nonempty(controls.get(reference), f"controls.{reference}")
    required_true = {
        "direct_identifiers_removed",
        "reidentification_risk_reviewed",
        "offline_only",
        "network_egress_disabled",
        "runtime_labels_separated",
        "complete_intake_reporting",
        "restricted_hash_handling",
    }
    required_false = {
        "live_feed_connected",
        "action_credentials_present",
        "write_capable_connectors_present",
    }
    for field in sorted(required_true):
        if _boolean(controls.get(field), f"controls.{field}") is not True:
            raise GateBValidationError(f"Gate B requires controls.{field}=true.")
    for field in sorted(required_false):
        if _boolean(controls.get(field), f"controls.{field}") is not False:
            raise GateBValidationError(f"Gate B requires controls.{field}=false.")

    custody = _exact_fields(
        value.get("custody"),
        {
            "snapshot_reference",
            "custody_record_reference",
            "external_manifest_digest_reference",
            "frozen_at",
            "custodian_id",
        },
        "custody",
    )
    for field in (
        "snapshot_reference",
        "custody_record_reference",
        "external_manifest_digest_reference",
        "custodian_id",
    ):
        _nonempty(custody.get(field), f"custody.{field}")
    frozen_at = _timestamp(custody.get("frozen_at"), "custody.frozen_at")
    if frozen_at < window_end:
        raise GateBValidationError("Gate B custody freeze predates window_end.")
    if frozen_at > valid_from:
        raise GateBValidationError("Gate B custody freeze postdates valid_from.")

    sampling = _exact_fields(
        value.get("sampling"),
        {
            "protocol_reference",
            "predeclared_at",
            "temporal_holdout_start",
            "temporal_holdout_end",
            "full_intake_count",
            "sample_count",
            "selection_method",
            "selection_frozen",
        },
        "sampling",
    )
    _nonempty(sampling.get("protocol_reference"), "sampling.protocol_reference")
    _nonempty(sampling.get("selection_method"), "sampling.selection_method")
    if (
        _boolean(sampling.get("selection_frozen"), "sampling.selection_frozen")
        is not True
    ):
        raise GateBValidationError("Gate B requires sampling.selection_frozen=true.")
    predeclared_at = _timestamp(
        sampling.get("predeclared_at"), "sampling.predeclared_at"
    )
    if predeclared_at > valid_from:
        raise GateBValidationError("Gate B sampling was not frozen before valid_from.")
    holdout_start = _timestamp(
        sampling.get("temporal_holdout_start"), "sampling.temporal_holdout_start"
    )
    holdout_end = _timestamp(
        sampling.get("temporal_holdout_end"), "sampling.temporal_holdout_end"
    )
    if not window_start <= holdout_start < holdout_end <= window_end:
        raise GateBValidationError(
            "Gate B temporal holdout is outside the approved window."
        )
    full_intake_count = _integer(
        sampling.get("full_intake_count"), "sampling.full_intake_count", minimum=1
    )
    sample_count = _integer(
        sampling.get("sample_count"), "sampling.sample_count", minimum=1
    )
    if sample_count > full_intake_count:
        raise GateBValidationError("Gate B sample count exceeds the full intake count.")
    if (
        sample_count != manifest.cases_record_count
        or sample_count != manifest.historical_case_count
    ):
        raise GateBValidationError(
            "Gate B sample count does not match the historical manifest."
        )

    stop = _exact_fields(
        value.get("stop_conditions"),
        {
            "max_overall_quarantine_rate",
            "max_category_quarantine_rates",
            "stop_on_any_fatal",
            "stop_on_unknown_failure",
            "thresholds_frozen",
            "escalation_owner_id",
        },
        "stop_conditions",
    )
    max_overall = _rate(
        stop.get("max_overall_quarantine_rate"),
        "stop_conditions.max_overall_quarantine_rate",
    )
    for field in ("stop_on_any_fatal", "stop_on_unknown_failure", "thresholds_frozen"):
        if _boolean(stop.get(field), f"stop_conditions.{field}") is not True:
            raise GateBValidationError(f"Gate B requires stop_conditions.{field}=true.")
    _nonempty(stop.get("escalation_owner_id"), "stop_conditions.escalation_owner_id")
    category_rows = stop.get("max_category_quarantine_rates")
    if not isinstance(category_rows, list) or not category_rows:
        raise GateBValidationError(
            "Gate B requires category-specific quarantine thresholds."
        )
    category_rates: dict[str, Decimal] = {}
    for index, raw_row in enumerate(category_rows):
        row = _exact_fields(
            raw_row, {"category", "max_rate"}, f"stop_conditions.categories[{index}]"
        )
        category = _identifier(
            row.get("category"), f"stop_conditions.categories[{index}].category"
        )
        if category not in ALLOWED_QUALIFICATION_THRESHOLD_CATEGORIES:
            raise GateBValidationError(
                "Gate B contains an unsupported quarantine threshold category."
            )
        if category in category_rates:
            raise GateBValidationError(
                "Gate B quarantine threshold categories are duplicated."
            )
        category_rates[category] = _rate(
            row.get("max_rate"), f"stop_conditions.categories[{index}].max_rate"
        )

    adjudication = _exact_fields(
        value.get("adjudication"),
        {
            "protocol_reference",
            "minimum_reviewers",
            "runtime_separated",
            "labels_hidden_until_decision",
            "indeterminate_allowed",
            "disagreement_resolution",
        },
        "adjudication",
    )
    _nonempty(adjudication.get("protocol_reference"), "adjudication.protocol_reference")
    _nonempty(
        adjudication.get("disagreement_resolution"),
        "adjudication.disagreement_resolution",
    )
    _integer(
        adjudication.get("minimum_reviewers"),
        "adjudication.minimum_reviewers",
        minimum=2,
    )
    for field in (
        "runtime_separated",
        "labels_hidden_until_decision",
        "indeterminate_allowed",
    ):
        if _boolean(adjudication.get(field), f"adjudication.{field}") is not True:
            raise GateBValidationError(f"Gate B requires adjudication.{field}=true.")

    review = _exact_fields(
        value.get("independent_review"),
        {"status", "reviewer_id", "review_reference", "reviewed_at"},
        "independent_review",
    )
    if review.get("status") != "APPROVED":
        raise GateBValidationError("Gate B independent review is not APPROVED.")
    reviewer_id = _nonempty(review.get("reviewer_id"), "independent_review.reviewer_id")
    if reviewer_id in approval_identities:
        raise GateBValidationError(
            "Gate B independent reviewer must differ from approval identities."
        )
    _nonempty(review.get("review_reference"), "independent_review.review_reference")
    if (
        _timestamp(review.get("reviewed_at"), "independent_review.reviewed_at")
        > valid_from
    ):
        raise GateBValidationError("Gate B independent review postdates valid_from.")

    claim = _exact_fields(
        value.get("claim_control"),
        {
            "claim_owner_id",
            "pause_authority_id",
            "revocation_authority_id",
            "expires_at",
            "revalidation_triggers",
        },
        "claim_control",
    )
    for field in ("claim_owner_id", "pause_authority_id", "revocation_authority_id"):
        _nonempty(claim.get(field), f"claim_control.{field}")
    if _timestamp(claim.get("expires_at"), "claim_control.expires_at") != expires_at:
        raise GateBValidationError(
            "Gate B claim-control expiry does not match authorization expiry."
        )
    triggers = claim.get("revalidation_triggers")
    if not isinstance(triggers, list) or not triggers:
        raise GateBValidationError("Gate B requires revalidation triggers.")
    normalized_triggers = [
        _nonempty(item, "claim_control.revalidation_triggers[]") for item in triggers
    ]
    if len(set(normalized_triggers)) != len(normalized_triggers):
        raise GateBValidationError("Gate B revalidation triggers must be unique.")

    return GateBAuthorization(
        path=target,
        source_sha256=source_sha256,
        source_bytes=source_bytes,
        authorization_id=authorization_id,
        dataset_id=dataset_id,
        dataset_manifest_sha256=manifest_digest,
        window_start=window_start,
        window_end=window_end,
        valid_from=valid_from,
        expires_at=expires_at,
        artifacts=tuple(sorted(parsed_artifacts, key=lambda item: item.role)),
        full_intake_count=full_intake_count,
        sample_count=sample_count,
        max_overall_quarantine_rate=max_overall,
        max_category_quarantine_rates=tuple(sorted(category_rates.items())),
        model_bytes=model_bytes,
        policy_bytes=policy_bytes,
    )


def validate_accepted_case_window(
    authorization: GateBAuthorization, records: Sequence[Mapping[str, Any]]
) -> None:
    """Reject a complete pilot when any accepted case exceeds approved time scope."""

    for record in records:
        opened_at = _timestamp(record.get("opened_at"), "accepted case.opened_at")
        if not authorization.window_start <= opened_at < authorization.window_end:
            raise GateBStopConditionViolation(
                "An accepted case falls outside the approved Gate B time window."
            )


def evaluate_qualification_stop_conditions(
    authorization: GateBAuthorization,
    qualification_records: Sequence[Mapping[str, Any]],
) -> dict[str, Any]:
    """Evaluate complete-intake and quarantine gates before engine invocation."""

    input_count = len(qualification_records)
    if input_count != authorization.sample_count:
        raise GateBStopConditionViolation(
            "Qualification input count does not match the approved Gate B sample count."
        )
    accepted_count = 0
    rejected_count = 0
    rejection_categories: Counter[str] = Counter()
    for row in qualification_records:
        status = row.get("status")
        if status == "ACCEPTED":
            accepted_count += 1
            continue
        if status != "QUARANTINED":
            raise GateBStopConditionViolation(
                "Qualification contains an unknown Gate B accounting status."
            )
        category = row.get("error_category")
        if not isinstance(category, str) or not _IDENTIFIER_PATTERN.fullmatch(category):
            raise GateBStopConditionViolation(
                "Qualification contains an invalid Gate B rejection category."
            )
        rejected_count += 1
        rejection_categories[category] += 1
    if input_count != accepted_count + rejected_count:
        raise GateBStopConditionViolation(
            "Gate B qualification accounting is incomplete."
        )
    denominator = Decimal(input_count)
    overall = Decimal(rejected_count) / denominator
    if overall > authorization.max_overall_quarantine_rate:
        raise GateBStopConditionViolation(
            "The overall quarantine rate exceeds the approved Gate B threshold."
        )
    thresholds = authorization.category_thresholds
    observed: dict[str, Decimal] = {}
    for category, count in sorted(rejection_categories.items()):
        if category not in ALLOWED_QUALIFICATION_THRESHOLD_CATEGORIES:
            raise GateBStopConditionViolation(
                "Qualification contains an unsupported Gate B rejection category."
            )
        if category not in thresholds:
            raise GateBStopConditionViolation(
                "No approved Gate B threshold exists for an observed rejection category."
            )
        rate = Decimal(count) / denominator
        observed[category] = rate
        if rate > thresholds[category]:
            raise GateBStopConditionViolation(
                f"The {category} quarantine rate exceeds its approved Gate B threshold."
            )
    return {
        "authorization_id": authorization.authorization_id,
        "status": "APPROVED",
        "expires_at": authorization.expires_at.isoformat().replace("+00:00", "Z"),
        "required_approval_roles": len(REQUIRED_APPROVAL_ROLES),
        "bindings_verified": True,
        "stop_conditions_passed": True,
        "full_intake_count": authorization.full_intake_count,
        "sample_count": authorization.sample_count,
        "input_records": input_count,
        "accepted_records": accepted_count,
        "quarantined_records": rejected_count,
        "overall_quarantine_rate": float(overall),
        "category_quarantine_rates": {
            category: float(rate) for category, rate in sorted(observed.items())
        },
    }


__all__ = [
    "GATE_B_SNAPSHOT_ROLE_BY_ARTIFACT",
    "ALLOWED_QUALIFICATION_THRESHOLD_CATEGORIES",
    "REQUIRED_APPROVAL_ROLES",
    "REQUIRED_ARTIFACT_ROLES",
    "GateBArtifactBinding",
    "GateBAuthorization",
    "GateBStopConditionViolation",
    "GateBValidationError",
    "ManifestControl",
    "MAX_CONTROL_JSON_NESTING_DEPTH",
    "MAX_GATE_B_ARTIFACT_BYTES",
    "MAX_GATE_B_MODEL_POLICY_BYTES",
    "evaluate_qualification_stop_conditions",
    "load_gate_b_authorization",
    "load_manifest_control",
    "validate_accepted_case_window",
]
