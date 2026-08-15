from __future__ import annotations

import hashlib
import io
import json
import math
import re
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Iterable, TextIO


CONTRACT_VERSION = "0.2.0"
MAX_CONTROL_DOCUMENT_BYTES = 1024 * 1024
MAX_JSONL_LINE_BYTES = 1024 * 1024
MAX_RECORDS_PER_FILE = 100_000
MAX_EVENTS_PER_CASE = 10_000
MAX_UNTRUSTED_TEXT_CHARS = 16_384
MAX_ATTRIBUTES_BYTES = 256 * 1024
MAX_DECLARED_FILE_BYTES = 512 * 1024 * 1024
ALLOWED_REPLAY_MODES = frozenset({"HISTORICAL_REPLAY", "SHADOW_READ_ONLY"})
RECORD_FAILURE_POLICIES = frozenset({"FAIL_DATASET", "QUARANTINE_RECORD"})
ALLOWED_DISPOSITIONS = frozenset(
    {"NO_ACTION", "INVESTIGATE", "CONTAIN_REVERSIBLE", "ESCALATE_HUMAN"}
)
ALLOWED_DATA_ORIGINS = frozenset(
    {"SYNTHETIC_FIXTURE", "HISTORICAL_DEIDENTIFIED", "SHADOW_TELEMETRY_DEIDENTIFIED"}
)
FORBIDDEN_RUNTIME_LABEL_KEYS = frozenset(
    {
        "adjudication",
        "adjudicated_disposition",
        "compromised",
        "expected_disposition",
        "ground_truth",
        "ground_truth_label",
        "is_malicious",
        "label",
        "labels",
        "malicious",
        "outcome_label",
        "scenario",
    }
)

_IDENTIFIER_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_SHA256_PATTERN = re.compile(r"^[a-f0-9]{64}$")


class ContractValidationError(ValueError):
    """Raised when a Phase 2 record violates the canonical data contract."""


class ManifestValidationError(ContractValidationError):
    """Raised when a dataset manifest or one of its declared files is invalid."""


class ReplayConfigurationError(ContractValidationError):
    """Raised when replay configuration would permit an unsupported or unsafe run."""


@dataclass(frozen=True, slots=True)
class ManifestFile:
    role: str
    path: str
    sha256: str
    record_count: int
    adapter: str
    resolved_path: Path


@dataclass(frozen=True, slots=True)
class ReplayManifest:
    schema_version: str
    dataset_id: str
    data_origin: str
    historical_case_count: int
    intended_mode: str
    created_at: str
    attestations: dict[str, Any]
    files: tuple[ManifestFile, ...]
    path: Path
    source_sha256: str

    def file_for_role(self, role: str, *, required: bool = True) -> ManifestFile | None:
        matches = [entry for entry in self.files if entry.role == role]
        if len(matches) > 1:
            raise ManifestValidationError(
                f"Manifest declares role {role!r} more than once."
            )
        if not matches:
            if required:
                raise ManifestValidationError(
                    f"Manifest does not declare required role {role!r}."
                )
            return None
        return matches[0]


@dataclass(frozen=True, slots=True)
class ReplayConfig:
    schema_version: str
    execution_mode: str
    live_actions_enabled: bool
    dataset_manifest: str
    model_path: str
    policy_path: str
    output_dir: str
    contract_adapter: str
    deterministic_outputs: bool
    zero_effects_required: bool
    record_failure_policy: str
    gate_b_authorization: str | None
    path: Path
    source_sha256: str

    @classmethod
    def load(cls, path: str | Path) -> "ReplayConfig":
        target = Path(path).resolve()
        value, source_sha256 = _load_json_object_with_digest(
            target, "replay configuration"
        )
        required = {
            "schema_version",
            "execution_mode",
            "live_actions_enabled",
            "dataset_manifest",
            "model_path",
            "policy_path",
            "output_dir",
            "contract_adapter",
            "deterministic_outputs",
            "zero_effects_required",
        }
        allowed = required | {"record_failure_policy", "gate_b_authorization"}
        missing = sorted(required - set(value))
        unexpected = sorted(set(value) - allowed)
        if missing:
            raise ReplayConfigurationError(
                "replay configuration is missing required fields: "
                + ", ".join(missing)
                + "."
            )
        if unexpected:
            raise ReplayConfigurationError(
                "replay configuration contains unsupported fields: "
                + ", ".join(unexpected)
                + "."
            )
        _require_version(value.get("schema_version"), "replay configuration")
        mode = value.get("execution_mode")
        if mode not in ALLOWED_REPLAY_MODES:
            allowed_modes = ", ".join(sorted(ALLOWED_REPLAY_MODES))
            raise ReplayConfigurationError(
                f"execution_mode must be one of {allowed_modes}; received {mode!r}."
            )
        if value.get("live_actions_enabled") is not False:
            raise ReplayConfigurationError(
                "live_actions_enabled must be exactly false."
            )
        if value.get("contract_adapter") != "canonical_jsonl_v0.2":
            raise ReplayConfigurationError(
                "contract_adapter must be 'canonical_jsonl_v0.2' for the Phase 2 starter."
            )
        if value.get("deterministic_outputs") is not True:
            raise ReplayConfigurationError(
                "deterministic_outputs must be exactly true."
            )
        if value.get("zero_effects_required") is not True:
            raise ReplayConfigurationError(
                "zero_effects_required must be exactly true."
            )
        record_failure_policy = value.get("record_failure_policy", "FAIL_DATASET")
        if record_failure_policy not in RECORD_FAILURE_POLICIES:
            raise ReplayConfigurationError(
                "record_failure_policy must be FAIL_DATASET or QUARANTINE_RECORD."
            )
        if record_failure_policy == "QUARANTINE_RECORD" and mode != "HISTORICAL_REPLAY":
            raise ReplayConfigurationError(
                "QUARANTINE_RECORD is limited to offline HISTORICAL_REPLAY; "
                "shadow input remains fail-dataset."
            )
        for name in ("dataset_manifest", "model_path", "policy_path", "output_dir"):
            _require_nonempty_string(value.get(name), f"replay configuration.{name}")
            if Path(str(value[name])).is_absolute():
                raise ReplayConfigurationError(
                    f"{name} must be a repository-relative path."
                )
        normalized = dict(value)
        normalized["record_failure_policy"] = record_failure_policy
        gate_b_authorization = value.get("gate_b_authorization")
        if gate_b_authorization is not None:
            _require_nonempty_string(
                gate_b_authorization,
                "replay configuration.gate_b_authorization",
            )
            gate_b_path = Path(str(gate_b_authorization))
            if (
                "\\" in str(gate_b_authorization)
                or str(gate_b_authorization) != gate_b_path.as_posix()
                or gate_b_path.is_absolute()
                or any(part in {"", ".", ".."} for part in gate_b_path.parts)
            ):
                raise ReplayConfigurationError(
                    "gate_b_authorization must be a confined repository-relative path."
                )
        normalized["gate_b_authorization"] = gate_b_authorization
        return cls(path=target, source_sha256=source_sha256, **normalized)

    def resolve_paths(self, repository_root: str | Path) -> dict[str, Path]:
        root = Path(repository_root).resolve()
        resolved = {
            "dataset_manifest": resolve_confined_path(
                root, self.dataset_manifest, label="dataset_manifest", must_exist=True
            ),
            "model_path": resolve_confined_path(
                root, self.model_path, label="model_path", must_exist=True
            ),
            "policy_path": resolve_confined_path(
                root, self.policy_path, label="policy_path", must_exist=True
            ),
            "output_dir": resolve_confined_path(
                root, self.output_dir, label="output_dir", must_exist=False
            ),
        }
        if resolved["output_dir"] == root:
            raise ReplayConfigurationError("output_dir cannot be the repository root.")
        if self.gate_b_authorization is not None:
            if Path(self.gate_b_authorization).parts[:2] != ("local", "gate_b"):
                raise ReplayConfigurationError(
                    "gate_b_authorization must use the restricted local/gate_b root."
                )
            unresolved = root / self.gate_b_authorization
            current = root
            for part in Path(self.gate_b_authorization).parts:
                if part in {"", ".", ".."}:
                    raise ReplayConfigurationError(
                        "gate_b_authorization path is not confined."
                    )
                current = current / part
                if current.is_symlink():
                    raise ReplayConfigurationError(
                        "gate_b_authorization path cannot use symlinks."
                    )
            if unresolved.is_symlink():
                raise ReplayConfigurationError(
                    "gate_b_authorization path cannot use symlinks."
                )
            try:
                resolved["gate_b_authorization"] = resolve_confined_path(
                    root,
                    self.gate_b_authorization,
                    label="gate_b_authorization",
                    must_exist=True,
                )
            except ManifestValidationError:
                raise ReplayConfigurationError(
                    "gate_b_authorization is unavailable or not confined."
                ) from None
        return resolved


def _load_json_object(path: Path, label: str) -> dict[str, Any]:
    value, _ = _load_json_object_with_digest(path, label)
    return value


def _load_json_object_with_digest(path: Path, label: str) -> tuple[dict[str, Any], str]:
    try:
        raw = path.read_bytes()
        if len(raw) > MAX_CONTROL_DOCUMENT_BYTES:
            raise ContractValidationError(
                f"{label} exceeds the {MAX_CONTROL_DOCUMENT_BYTES}-byte control-document limit."
            )
        value = json.loads(
            raw.decode("utf-8"), object_pairs_hook=_reject_duplicate_json_pairs
        )
    except _DuplicateJSONMember:
        raise ContractValidationError(
            f"{label} contains duplicate JSON object members."
        ) from None
    except (OSError, UnicodeError, json.JSONDecodeError):
        raise ContractValidationError(f"Unable to read {label}.") from None
    if not isinstance(value, dict):
        raise ContractValidationError(f"{label} must be a JSON object.")
    return value, hashlib.sha256(raw).hexdigest()


def _require_exact_fields(value: dict[str, Any], allowed: set[str], label: str) -> None:
    missing = sorted(allowed - set(value))
    unexpected = sorted(set(value) - allowed)
    if missing:
        raise ContractValidationError(
            f"{label} is missing required fields: {', '.join(missing)}."
        )
    if unexpected:
        raise ContractValidationError(
            f"{label} contains unsupported fields: {', '.join(unexpected)}."
        )


def _require_version(value: Any, label: str) -> None:
    if value != CONTRACT_VERSION:
        raise ContractValidationError(
            f"{label}.schema_version must be {CONTRACT_VERSION!r}; received {value!r}."
        )


def _require_nonempty_string(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ContractValidationError(f"{label} must be a non-empty string.")
    return value


def _require_identifier(value: Any, label: str) -> str:
    candidate = _require_nonempty_string(value, label)
    if not _IDENTIFIER_PATTERN.fullmatch(candidate):
        raise ContractValidationError(
            f"{label} must match {_IDENTIFIER_PATTERN.pattern}; received {candidate!r}."
        )
    return candidate


def _require_boolean(value: Any, label: str) -> bool:
    if type(value) is not bool:
        raise ContractValidationError(f"{label} must be a boolean.")
    return value


def _require_unit_interval(value: Any, label: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ContractValidationError(f"{label} must be numeric.")
    try:
        candidate = float(value)
    except OverflowError:
        raise ContractValidationError(
            f"{label} must be finite and within [0, 1]."
        ) from None
    if not math.isfinite(candidate) or not 0.0 <= candidate <= 1.0:
        raise ContractValidationError(f"{label} must be finite and within [0, 1].")
    return candidate


def parse_timestamp(value: Any, label: str) -> datetime:
    candidate = _require_nonempty_string(value, label)
    try:
        parsed = datetime.fromisoformat(candidate.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ContractValidationError(
            f"{label} must be an ISO-8601 timestamp."
        ) from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ContractValidationError(f"{label} must include an explicit UTC offset.")
    return parsed


def detect_runtime_label_leakage(value: Any, path: str = "case") -> list[str]:
    leaks: list[str] = []
    if isinstance(value, dict):
        for key, child in value.items():
            child_path = f"{path}.{key}"
            if str(key).lower() in FORBIDDEN_RUNTIME_LABEL_KEYS:
                leaks.append(child_path)
            leaks.extend(detect_runtime_label_leakage(child, child_path))
    elif isinstance(value, list):
        for index, child in enumerate(value):
            leaks.extend(detect_runtime_label_leakage(child, f"{path}[{index}]"))
    return leaks


def validate_case_record(record: dict[str, Any]) -> None:
    if not isinstance(record, dict):
        raise ContractValidationError("Replay case record must be a JSON object.")
    leaks = detect_runtime_label_leakage(record)
    if leaks:
        raise ContractValidationError(
            "Runtime label leakage is prohibited; forbidden fields found at "
            + ", ".join(leaks)
        )
    required = {
        "schema_version",
        "case_id",
        "opened_at",
        "subject_id",
        "privilege_level",
        "break_glass",
        "asset_id",
        "asset_criticality",
        "events",
    }
    _require_exact_fields(record, required, "replay case")
    _require_version(record.get("schema_version"), "replay case")
    case_id = _require_identifier(record.get("case_id"), "replay case.case_id")
    parse_timestamp(record.get("opened_at"), "replay case.opened_at")
    _require_identifier(record.get("subject_id"), "replay case.subject_id")
    _require_identifier(record.get("asset_id"), "replay case.asset_id")
    _require_identifier(record.get("privilege_level"), "replay case.privilege_level")
    break_glass = _require_boolean(record.get("break_glass"), "replay case.break_glass")
    criticality = _require_unit_interval(
        record.get("asset_criticality"), "replay case.asset_criticality"
    )
    events = record.get("events")
    if not isinstance(events, list) or not events:
        raise ContractValidationError("replay case.events must be a non-empty array.")
    if len(events) > MAX_EVENTS_PER_CASE:
        raise ContractValidationError(
            f"replay case.events exceeds the {MAX_EVENTS_PER_CASE}-event limit."
        )

    event_ids: set[str] = set()
    inventory_events: list[dict[str, Any]] = []
    for index, event in enumerate(events):
        label = f"replay case.events[{index}]"
        _validate_event_record(event, label, case_id)
        event_id = str(event["event_id"])
        if event_id in event_ids:
            raise ContractValidationError(
                f"Duplicate event_id {event_id!r} within case {case_id!r}."
            )
        event_ids.add(event_id)
        if event["source_type"] == "asset_inventory":
            inventory_events.append(event)

    if not inventory_events:
        raise ContractValidationError(
            f"Case {case_id!r} requires at least one asset_inventory event."
        )
    for event in inventory_events:
        attributes = event["attributes"]
        if "break_glass" not in attributes or "asset_criticality" not in attributes:
            raise ContractValidationError(
                "asset_inventory attributes must include break_glass and asset_criticality."
            )
        inventory_break_glass = _require_boolean(
            attributes["break_glass"], "asset_inventory.attributes.break_glass"
        )
        inventory_criticality = _require_unit_interval(
            attributes["asset_criticality"],
            "asset_inventory.attributes.asset_criticality",
        )
        if inventory_break_glass is not break_glass:
            raise ContractValidationError(
                "Canonical break_glass must equal asset_inventory.attributes.break_glass."
            )
        if not math.isclose(
            inventory_criticality, criticality, rel_tol=0.0, abs_tol=1e-12
        ):
            raise ContractValidationError(
                "Canonical asset_criticality must equal "
                "asset_inventory.attributes.asset_criticality."
            )
        if "asset_id" in attributes and attributes["asset_id"] != record["asset_id"]:
            raise ContractValidationError(
                "Canonical asset_id must equal asset_inventory.attributes.asset_id when present."
            )


def _validate_event_record(event: Any, label: str, case_id: str) -> None:
    if not isinstance(event, dict):
        raise ContractValidationError(f"{label} must be a JSON object.")
    required = {
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
    _require_exact_fields(event, required, label)
    _require_identifier(event.get("event_id"), f"{label}.event_id")
    event_case_id = _require_identifier(event.get("case_id"), f"{label}.case_id")
    if event_case_id != case_id:
        raise ContractValidationError(
            f"{label}.case_id {event_case_id!r} does not match parent case {case_id!r}."
        )
    _require_identifier(event.get("source_type"), f"{label}.source_type")
    _require_identifier(event.get("source_instance"), f"{label}.source_instance")
    observed = parse_timestamp(event.get("observed_at"), f"{label}.observed_at")
    collected = parse_timestamp(event.get("collected_at"), f"{label}.collected_at")
    if collected < observed:
        raise ContractValidationError(
            f"{label}.collected_at cannot precede observed_at."
        )
    if event.get("integrity") not in {"verified", "unverified", "failed"}:
        raise ContractValidationError(
            f"{label}.integrity must be verified, unverified, or failed."
        )
    provenance_id = event.get("provenance_id")
    if not isinstance(provenance_id, str):
        raise ContractValidationError(f"{label}.provenance_id must be a string.")
    if provenance_id:
        _require_identifier(provenance_id, f"{label}.provenance_id")
    _require_unit_interval(event.get("trust_score"), f"{label}.trust_score")
    entity_refs = event.get("entity_refs")
    if not isinstance(entity_refs, list):
        raise ContractValidationError(f"{label}.entity_refs must be an array.")
    seen_refs: set[str] = set()
    for reference in entity_refs:
        parsed = _require_identifier(reference, f"{label}.entity_refs[]")
        if parsed in seen_refs:
            raise ContractValidationError(
                f"{label}.entity_refs contains duplicate {parsed!r}."
            )
        seen_refs.add(parsed)
    if not isinstance(event.get("attributes"), dict):
        raise ContractValidationError(f"{label}.attributes must be a JSON object.")
    attributes_size = len(
        json.dumps(
            event["attributes"], separators=(",", ":"), ensure_ascii=True
        ).encode("utf-8")
    )
    if attributes_size > MAX_ATTRIBUTES_BYTES:
        raise ContractValidationError(
            f"{label}.attributes exceeds the {MAX_ATTRIBUTES_BYTES}-byte limit."
        )
    if not isinstance(event.get("untrusted_text"), str):
        raise ContractValidationError(f"{label}.untrusted_text must be a string.")
    if len(event["untrusted_text"]) > MAX_UNTRUSTED_TEXT_CHARS:
        raise ContractValidationError(
            f"{label}.untrusted_text exceeds the {MAX_UNTRUSTED_TEXT_CHARS}-character limit."
        )
    _require_boolean(
        event.get("contains_instructional_content"),
        f"{label}.contains_instructional_content",
    )


def validate_case_records(records: Iterable[dict[str, Any]]) -> list[dict[str, Any]]:
    materialized = list(records)
    case_ids: set[str] = set()
    event_ids: set[str] = set()
    for record in materialized:
        validate_case_record(record)
        case_id = str(record["case_id"])
        if case_id in case_ids:
            raise ContractValidationError(
                f"Duplicate case_id {case_id!r} across the case file."
            )
        case_ids.add(case_id)
        for event in record["events"]:
            event_id = str(event["event_id"])
            if event_id in event_ids:
                raise ContractValidationError(
                    f"Duplicate event_id {event_id!r} across the case file."
                )
            event_ids.add(event_id)
    return materialized


def validate_adjudication_record(record: dict[str, Any]) -> None:
    if not isinstance(record, dict):
        raise ContractValidationError("Replay adjudication must be a JSON object.")
    required = {
        "schema_version",
        "adjudication_id",
        "case_id",
        "adjudicated_at",
        "adjudicator_role",
        "adjudicated_disposition",
        "compromised",
        "confidence",
        "rationale_codes",
    }
    _require_exact_fields(record, required, "replay adjudication")
    _require_version(record.get("schema_version"), "replay adjudication")
    _require_identifier(
        record.get("adjudication_id"), "replay adjudication.adjudication_id"
    )
    _require_identifier(record.get("case_id"), "replay adjudication.case_id")
    parse_timestamp(record.get("adjudicated_at"), "replay adjudication.adjudicated_at")
    _require_identifier(
        record.get("adjudicator_role"), "replay adjudication.adjudicator_role"
    )
    if record.get("adjudicated_disposition") not in ALLOWED_DISPOSITIONS:
        raise ContractValidationError(
            "replay adjudication.adjudicated_disposition is not a supported disposition."
        )
    _require_boolean(record.get("compromised"), "replay adjudication.compromised")
    _require_unit_interval(record.get("confidence"), "replay adjudication.confidence")
    rationale_codes = record.get("rationale_codes")
    if not isinstance(rationale_codes, list) or not rationale_codes:
        raise ContractValidationError(
            "replay adjudication.rationale_codes must be a non-empty array."
        )
    parsed_codes = [
        _require_identifier(code, "replay adjudication.rationale_codes[]")
        for code in rationale_codes
    ]
    if len(parsed_codes) != len(set(parsed_codes)):
        raise ContractValidationError(
            "replay adjudication.rationale_codes cannot contain duplicates."
        )


def validate_adjudication_records(
    records: Iterable[dict[str, Any]], *, known_case_ids: set[str] | None = None
) -> list[dict[str, Any]]:
    materialized = list(records)
    adjudication_ids: set[str] = set()
    adjudicated_case_ids: set[str] = set()
    for record in materialized:
        validate_adjudication_record(record)
        adjudication_id = str(record["adjudication_id"])
        case_id = str(record["case_id"])
        if adjudication_id in adjudication_ids:
            raise ContractValidationError(
                f"Duplicate adjudication_id {adjudication_id!r}."
            )
        if case_id in adjudicated_case_ids:
            raise ContractValidationError(
                f"Case {case_id!r} has multiple adjudications."
            )
        if known_case_ids is not None and case_id not in known_case_ids:
            raise ContractValidationError(
                f"Adjudication {adjudication_id!r} references unknown case {case_id!r}."
            )
        adjudication_ids.add(adjudication_id)
        adjudicated_case_ids.add(case_id)
    return materialized


def _load_jsonl_text(handle: TextIO, *, label: str) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    line_number = 0
    while True:
        line = handle.readline(MAX_JSONL_LINE_BYTES + 1)
        if not line:
            break
        line_number += 1
        if len(line.encode("utf-8")) > MAX_JSONL_LINE_BYTES:
            raise ContractValidationError(
                f"{label} line {line_number} exceeds the "
                f"{MAX_JSONL_LINE_BYTES}-byte limit."
            )
        if not line.strip():
            continue
        try:
            value = json.loads(line, object_pairs_hook=_reject_duplicate_json_pairs)
        except _DuplicateJSONMember:
            raise ContractValidationError(
                f"{label} line {line_number} contains duplicate JSON object members."
            ) from None
        except json.JSONDecodeError as exc:
            raise ContractValidationError(
                f"{label} line {line_number} is not valid JSON: {exc}"
            ) from exc
        if not isinstance(value, dict):
            raise ContractValidationError(
                f"{label} line {line_number} must be a JSON object."
            )
        rows.append(value)
        if len(rows) > MAX_RECORDS_PER_FILE:
            raise ContractValidationError(
                f"{label} exceeds the {MAX_RECORDS_PER_FILE}-record limit."
            )
    return rows


class _DuplicateJSONMember(ValueError):
    """Internal marker for ambiguous duplicate JSON object members."""


def _reject_duplicate_json_pairs(
    pairs: list[tuple[str, Any]],
) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, child in pairs:
        if key in value:
            raise _DuplicateJSONMember
        value[key] = child
    return value


def load_jsonl_objects(path: str | Path, *, label: str) -> list[dict[str, Any]]:
    target = Path(path)
    try:
        with target.open("r", encoding="utf-8") as handle:
            return _load_jsonl_text(handle, label=label)
    except (OSError, UnicodeError) as exc:
        raise ContractValidationError(
            f"Unable to read {label} at {target}: {exc}"
        ) from exc


def load_jsonl_bytes(content: bytes, *, label: str) -> list[dict[str, Any]]:
    """Load bounded JSON objects from already-custodied JSONL bytes.

    The text wrapper deliberately uses the same UTF-8 decoding, universal-newline
    behavior, line bound, object requirement, and record bound as
    :func:`load_jsonl_objects`.  This entry point lets a caller validate bytes
    obtained through a descriptor-bound channel without reopening a pathname.
    """

    if not isinstance(content, bytes):
        raise TypeError("content must be bytes.")
    try:
        with io.BytesIO(content) as raw_handle:
            with io.TextIOWrapper(raw_handle, encoding="utf-8") as handle:
                return _load_jsonl_text(handle, label=label)
    except UnicodeError as exc:
        raise ContractValidationError(
            f"Unable to read {label} from byte content: {exc}"
        ) from exc


def resolve_confined_path(
    root: str | Path,
    relative_path: str | Path,
    *,
    label: str,
    must_exist: bool,
) -> Path:
    root_path = Path(root).resolve()
    candidate = Path(relative_path)
    if candidate.is_absolute():
        raise ManifestValidationError(f"{label} must be relative to its allowed root.")
    resolved = (root_path / candidate).resolve()
    try:
        resolved.relative_to(root_path)
    except ValueError as exc:
        raise ManifestValidationError(f"{label} escapes its allowed root.") from exc
    if must_exist and (not resolved.exists() or not resolved.is_file()):
        raise ManifestValidationError(f"{label} does not resolve to a file.")
    return resolved


def sha256_file(path: str | Path) -> str:
    digest = hashlib.sha256()
    with Path(path).open("rb") as handle:
        while chunk := handle.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def count_jsonl_records(path: str | Path) -> int:
    """Count bounded nonblank records without parsing evaluator-only content.

    Case syntax and semantics are validated by the runtime adapter before engine
    invocation. Adjudication syntax and semantics are deliberately deferred until
    after read-only decisions have closed, so the pre-run integrity pass only
    verifies bytes, line bounds, and record count.
    """

    count = 0
    try:
        with Path(path).open("r", encoding="utf-8") as handle:
            line_number = 0
            while True:
                line = handle.readline(MAX_JSONL_LINE_BYTES + 1)
                if not line:
                    break
                line_number += 1
                if len(line.encode("utf-8")) > MAX_JSONL_LINE_BYTES:
                    raise ManifestValidationError(
                        f"Declared JSONL file {path} line {line_number} exceeds the "
                        f"{MAX_JSONL_LINE_BYTES}-byte limit."
                    )
                if not line.strip():
                    continue
                count += 1
                if count > MAX_RECORDS_PER_FILE:
                    raise ManifestValidationError(
                        f"Declared JSONL file {path} exceeds the "
                        f"{MAX_RECORDS_PER_FILE}-record limit."
                    )
    except (OSError, UnicodeError) as exc:
        raise ManifestValidationError(
            f"Unable to count declared JSONL records at {path}: {exc}"
        ) from exc
    return count


def load_and_validate_manifest(
    path: str | Path,
    *,
    expected_source_sha256: str | None = None,
    defer_adjudication_content_validation: bool = False,
) -> ReplayManifest:
    target = Path(path).resolve()
    value, source_sha256 = _load_json_object_with_digest(target, "dataset manifest")
    if expected_source_sha256 is not None and source_sha256 != expected_source_sha256:
        raise ManifestValidationError(
            "Dataset manifest changed after control-document preflight."
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
    _require_exact_fields(value, required, "dataset manifest")
    _require_version(value.get("schema_version"), "dataset manifest")
    dataset_id = _require_identifier(
        value.get("dataset_id"), "dataset manifest.dataset_id"
    )
    data_origin = value.get("data_origin")
    if data_origin not in ALLOWED_DATA_ORIGINS:
        raise ManifestValidationError(
            f"dataset manifest.data_origin must be one of {sorted(ALLOWED_DATA_ORIGINS)}."
        )
    historical_case_count = value.get("historical_case_count")
    if (
        isinstance(historical_case_count, bool)
        or not isinstance(historical_case_count, int)
        or historical_case_count < 0
    ):
        raise ManifestValidationError(
            "dataset manifest.historical_case_count must be a non-negative integer."
        )
    if data_origin in {"SYNTHETIC_FIXTURE", "SHADOW_TELEMETRY_DEIDENTIFIED"}:
        if historical_case_count != 0:
            raise ManifestValidationError(
                f"{data_origin} requires historical_case_count=0."
            )
    intended_mode = value.get("intended_mode")
    if intended_mode not in ALLOWED_REPLAY_MODES:
        raise ManifestValidationError(
            f"dataset manifest.intended_mode must be one of {sorted(ALLOWED_REPLAY_MODES)}."
        )
    parse_timestamp(value.get("created_at"), "dataset manifest.created_at")
    attestations = value.get("attestations")
    _validate_attestations(attestations, intended_mode)
    assert isinstance(attestations, dict)
    raw_files = value.get("files")
    if not isinstance(raw_files, list) or not raw_files:
        raise ManifestValidationError(
            "dataset manifest.files must be a non-empty array."
        )

    manifest_root = target.parent
    parsed_files: list[ManifestFile] = []
    roles: set[str] = set()
    paths: set[Path] = set()
    for index, entry in enumerate(raw_files):
        label = f"dataset manifest.files[{index}]"
        if not isinstance(entry, dict):
            raise ManifestValidationError(f"{label} must be an object.")
        _require_exact_fields(
            entry, {"role", "path", "sha256", "record_count", "adapter"}, label
        )
        role = _require_identifier(entry.get("role"), f"{label}.role")
        if role not in {"cases", "adjudications"}:
            raise ManifestValidationError(f"{label}.role {role!r} is unsupported.")
        if role in roles:
            raise ManifestValidationError(f"Manifest role {role!r} is duplicated.")
        relative_path = _require_nonempty_string(entry.get("path"), f"{label}.path")
        resolved = resolve_confined_path(
            manifest_root, relative_path, label=f"{label}.path", must_exist=True
        )
        if resolved in paths:
            raise ManifestValidationError(
                f"Manifest path {relative_path!r} is duplicated."
            )
        defer_content = (
            defer_adjudication_content_validation and role == "adjudications"
        )
        if not defer_content and resolved.stat().st_size > MAX_DECLARED_FILE_BYTES:
            raise ManifestValidationError(
                f"Manifest path {relative_path!r} exceeds the "
                f"{MAX_DECLARED_FILE_BYTES}-byte file limit."
            )
        declared_digest = entry.get("sha256")
        if not isinstance(declared_digest, str) or not _SHA256_PATTERN.fullmatch(
            declared_digest
        ):
            raise ManifestValidationError(
                f"{label}.sha256 must be a lowercase SHA-256 digest."
            )
        record_count = entry.get("record_count")
        if (
            isinstance(record_count, bool)
            or not isinstance(record_count, int)
            or not 0 <= record_count <= MAX_RECORDS_PER_FILE
        ):
            raise ManifestValidationError(
                f"{label}.record_count must be an integer within "
                f"[0, {MAX_RECORDS_PER_FILE}]."
            )
        adapter = entry.get("adapter")
        if adapter != "canonical_jsonl_v0.2":
            raise ManifestValidationError(
                f"{label}.adapter must be 'canonical_jsonl_v0.2'."
            )
        if not defer_content:
            actual_digest = sha256_file(resolved)
            if actual_digest != declared_digest:
                raise ManifestValidationError(
                    f"SHA-256 mismatch for {relative_path}: declared {declared_digest}, "
                    f"actual {actual_digest}."
                )
            actual_count = count_jsonl_records(resolved)
            if actual_count != record_count:
                raise ManifestValidationError(
                    f"Record-count mismatch for {relative_path}: declared {record_count}, "
                    f"actual {actual_count}."
                )
        parsed_files.append(
            ManifestFile(
                role=role,
                path=relative_path,
                sha256=declared_digest,
                record_count=record_count,
                adapter=adapter,
                resolved_path=resolved,
            )
        )
        roles.add(role)
        paths.add(resolved)

    if "cases" not in roles:
        raise ManifestValidationError("Manifest requires a cases file.")
    if intended_mode == "HISTORICAL_REPLAY" and "adjudications" not in roles:
        raise ManifestValidationError(
            "HISTORICAL_REPLAY requires a physically separate adjudications file."
        )
    cases_entry = next(entry for entry in parsed_files if entry.role == "cases")
    if data_origin == "HISTORICAL_DEIDENTIFIED":
        if historical_case_count != cases_entry.record_count:
            raise ManifestValidationError(
                "HISTORICAL_DEIDENTIFIED requires historical_case_count to equal the "
                "declared cases-file record count."
            )
    return ReplayManifest(
        schema_version=CONTRACT_VERSION,
        dataset_id=dataset_id,
        data_origin=str(data_origin),
        historical_case_count=historical_case_count,
        intended_mode=str(intended_mode),
        created_at=str(value["created_at"]),
        attestations=dict(attestations),
        files=tuple(parsed_files),
        path=target,
        source_sha256=source_sha256,
    )


def _validate_attestations(value: Any, intended_mode: str) -> None:
    if not isinstance(value, dict):
        raise ManifestValidationError(
            "dataset manifest.attestations must be an object."
        )
    required = {
        "approved_for_replay",
        "approval_reference",
        "deidentified",
        "deidentification_method",
        "direct_identifiers_present",
        "attested_by",
        "attested_at",
    }
    _require_exact_fields(value, required, "dataset manifest.attestations")
    approved = _require_boolean(
        value.get("approved_for_replay"),
        "dataset manifest.attestations.approved_for_replay",
    )
    deidentified = _require_boolean(
        value.get("deidentified"), "dataset manifest.attestations.deidentified"
    )
    direct_identifiers = _require_boolean(
        value.get("direct_identifiers_present"),
        "dataset manifest.attestations.direct_identifiers_present",
    )
    _require_nonempty_string(
        value.get("approval_reference"),
        "dataset manifest.attestations.approval_reference",
    )
    _require_nonempty_string(
        value.get("deidentification_method"),
        "dataset manifest.attestations.deidentification_method",
    )
    _require_identifier(
        value.get("attested_by"), "dataset manifest.attestations.attested_by"
    )
    parse_timestamp(
        value.get("attested_at"), "dataset manifest.attestations.attested_at"
    )
    if direct_identifiers:
        raise ManifestValidationError(
            "direct_identifiers_present must be false for all Phase 2 replay/shadow inputs."
        )
    if not approved:
        raise ManifestValidationError(
            f"{intended_mode} requires approved_for_replay=true."
        )
    if intended_mode == "HISTORICAL_REPLAY" and not deidentified:
        raise ManifestValidationError("HISTORICAL_REPLAY requires deidentified=true.")
    if not deidentified:
        raise ManifestValidationError(
            "Phase 2 inputs must be attested as deidentified."
        )
