from __future__ import annotations

import argparse
import hashlib
import json
import sys
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator, FormatChecker


ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from adf_poc.execution import ExecutionMode  # noqa: E402
from adf_poc.replay.contracts import (  # noqa: E402
    ContractValidationError,
    validate_adjudication_records,
)
from adf_poc.replay.harness import ReplayHarness, ReplaySafetyViolation  # noqa: E402
from adf_poc.replay.metrics import (  # noqa: E402
    build_comparisons,
    compute_replay_metrics,
)
from adf_poc.replay.qualification import (  # noqa: E402
    QUALIFICATION_TAXONOMY_VERSION,
)


DEFAULT_SCHEMA = ROOT / "contracts/v0.2.0/evaluation-evidence.schema.json"
DEFAULT_RECORD = ROOT / "contracts/v0.2.0/examples/phase2-starter-evidence-record.json"
QUALIFICATION_SCHEMA = ROOT / "contracts/v0.2.0/replay-qualification.schema.json"
QUALIFICATION_EXPECTATIONS_SCHEMA = (
    ROOT / "contracts/v0.2.0/qualification-expectations.schema.json"
)
CORE_MANIFEST_ARTIFACT_ROLES = frozenset(
    {
        "configuration",
        "dataset_manifest",
        "model",
        "policy",
        "cases",
        "adjudications",
        "normalized_cases",
        "normalization_diagnostics",
        "deterministic_decisions",
        "adjudication_comparison",
        "replay_metrics",
        "engine_decisions",
        "audit_log",
    }
)


@dataclass(frozen=True, slots=True)
class EvidenceValidationProfile:
    claim_id: str
    decision_count: int
    source_record_count: int
    accepted_record_count: int
    rejected_record_count: int
    expected_result_counts: tuple[int, int, int, int]
    expected_record_failure_policy: str | None
    supplemental_artifact_roles: frozenset[str]
    expected_rejection_reasons: tuple[tuple[str, int], ...]
    result_summary: str

    @property
    def qualification_enabled(self) -> bool:
        return self.expected_record_failure_policy == "QUARANTINE_RECORD"


EVIDENCE_PROFILES: dict[str, EvidenceValidationProfile] = {
    "P2-CE-001": EvidenceValidationProfile(
        claim_id="P2-CE-001",
        decision_count=3,
        source_record_count=3,
        accepted_record_count=3,
        rejected_record_count=0,
        expected_result_counts=(3, 3, 0, 0),
        expected_record_failure_policy=None,
        supplemental_artifact_roles=frozenset(),
        expected_rejection_reasons=(),
        result_summary=(
            "3/3 controlled synthetic cases passed; no broader inference authorized"
        ),
    ),
    "P2-CE-002": EvidenceValidationProfile(
        claim_id="P2-CE-002",
        decision_count=3,
        source_record_count=7,
        accepted_record_count=3,
        rejected_record_count=4,
        expected_result_counts=(7, 7, 0, 0),
        expected_record_failure_policy="QUARANTINE_RECORD",
        supplemental_artifact_roles=frozenset({"expected_qualification"}),
        expected_rejection_reasons=(
            ("SEMANTICS/CANONICAL_CONTEXT_MISMATCH", 1),
            ("SEMANTICS/INVALID_TIMESTAMP", 1),
            ("STRUCTURE/MISSING_REQUIRED_FIELD", 1),
            ("SYNTAX/INVALID_JSON", 1),
        ),
        result_summary=(
            "7/7 fixed qualification outcomes matched: 3 accepted, 4 quarantined; "
            "no broader inference authorized"
        ),
    ),
}


class EvidenceValidationError(ValueError):
    """Raised when a claim-evidence record or referenced artifact is invalid."""


def _select_profile(
    record: dict[str, Any], requested_profile: str | None
) -> EvidenceValidationProfile:
    claim_id = str(record.get("claim_id", ""))
    profile_id = requested_profile or claim_id
    if requested_profile is not None and requested_profile != claim_id:
        raise EvidenceValidationError(
            f"Requested evidence profile {requested_profile!r} does not match "
            f"record claim_id {claim_id!r}."
        )
    try:
        return EVIDENCE_PROFILES[profile_id]
    except KeyError as exc:
        raise EvidenceValidationError(
            f"No executable evidence-validation profile is registered for {profile_id!r}."
        ) from exc


def _load_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise EvidenceValidationError(f"Unable to decode JSON {path}: {exc}") from exc
    if not isinstance(value, dict):
        raise EvidenceValidationError(f"JSON document {path} is not an object.")
    return value


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    try:
        with path.open("rb") as handle:
            while chunk := handle.read(1024 * 1024):
                digest.update(chunk)
    except OSError as exc:
        raise EvidenceValidationError(f"Unable to hash {path}: {exc}") from exc
    return digest.hexdigest()


def _read_jsonl(path: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    try:
        with path.open("r", encoding="utf-8") as handle:
            for line_number, line in enumerate(handle, start=1):
                if not line.strip():
                    continue
                value = json.loads(line)
                if not isinstance(value, dict):
                    raise EvidenceValidationError(
                        f"{path}:{line_number} is not a JSON object."
                    )
                rows.append(value)
    except EvidenceValidationError:
        raise
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise EvidenceValidationError(f"Unable to decode JSONL {path}: {exc}") from exc
    return rows


def _count_jsonl_records(path: Path) -> int:
    count = 0
    try:
        with path.open("rb") as handle:
            for raw in handle:
                if raw.strip():
                    count += 1
    except OSError as exc:
        raise EvidenceValidationError(
            f"Unable to count JSONL records in {path}: {exc}"
        ) from exc
    return count


def _confined_path(repository_root: Path, relative: str) -> Path:
    candidate = Path(relative)
    if candidate.is_absolute():
        raise EvidenceValidationError(f"Evidence artifact path is absolute: {relative}")
    resolved = (repository_root / candidate).resolve()
    try:
        resolved.relative_to(repository_root)
    except ValueError as exc:
        raise EvidenceValidationError(
            f"Evidence artifact path escapes the repository: {relative}"
        ) from exc
    if not resolved.is_file():
        raise EvidenceValidationError(f"Evidence artifact is not a file: {relative}")
    return resolved


def _validate_schema(record: dict[str, Any], schema: dict[str, Any]) -> None:
    try:
        Draft202012Validator.check_schema(schema)
    except Exception as exc:
        raise EvidenceValidationError(
            f"Evaluation-evidence schema is invalid: {exc}"
        ) from exc
    validator = Draft202012Validator(schema, format_checker=FormatChecker())
    errors = sorted(validator.iter_errors(record), key=lambda item: list(item.path))
    if errors:
        messages = []
        for error in errors:
            location = ".".join(str(part) for part in error.absolute_path) or "$"
            messages.append(f"{location}: {error.message}")
        raise EvidenceValidationError(
            "Evaluation-evidence record does not match the schema: "
            + "; ".join(messages)
        )


def _validate_artifacts(
    record: dict[str, Any], repository_root: Path
) -> dict[str, Path]:
    artifacts: dict[str, Path] = {}
    for artifact in record["evidence_artifacts"]:
        role = str(artifact["artifact_role"])
        if role in artifacts:
            raise EvidenceValidationError(f"Duplicate evidence artifact role: {role}")
        path = _confined_path(repository_root, str(artifact["path"]))
        actual_digest = _sha256(path)
        if actual_digest != artifact["sha256"]:
            raise EvidenceValidationError(
                f"Evidence artifact {role!r} digest mismatch: "
                f"expected {artifact['sha256']}, found {actual_digest}."
            )
        if "record_count" in artifact:
            actual_count = _count_jsonl_records(path)
            if actual_count != artifact["record_count"]:
                raise EvidenceValidationError(
                    f"Evidence artifact {role!r} record-count mismatch: "
                    f"expected {artifact['record_count']}, found {actual_count}."
                )
        if artifact["committed"] is not True:
            raise EvidenceValidationError(
                f"Published starter evidence artifact {role!r} is not marked committed."
            )
        artifacts[role] = path
    return artifacts


def _manifest_entries(manifest: dict[str, Any]) -> dict[str, dict[str, Any]]:
    """Return every artifact declared by a run manifest under public role names."""

    aliases = {"replay_decisions": "deterministic_decisions"}
    entries: dict[str, dict[str, Any]] = {}

    def add(role: str, entry: Any, *, location: str) -> None:
        public_role = aliases.get(role, role)
        if public_role in entries:
            raise EvidenceValidationError(
                f"Run manifest declares duplicate public artifact role {public_role!r}."
            )
        if not isinstance(entry, dict) or not {
            "path",
            "sha256",
        }.issubset(entry):
            raise EvidenceValidationError(
                f"Run manifest artifact {location} is not a path-and-digest object."
            )
        entries[public_role] = entry

    inputs = manifest.get("inputs")
    deterministic = manifest.get("deterministic_artifacts")
    volatile = manifest.get("volatile_engine_artifacts")
    if not isinstance(inputs, dict):
        raise EvidenceValidationError("Run manifest inputs is not an object.")
    if not isinstance(deterministic, dict):
        raise EvidenceValidationError(
            "Run manifest deterministic_artifacts is not an object."
        )
    if not isinstance(volatile, dict):
        raise EvidenceValidationError(
            "Run manifest volatile_engine_artifacts is not an object."
        )

    declared_files = inputs.get("declared_files")
    if not isinstance(declared_files, dict):
        raise EvidenceValidationError(
            "Run manifest inputs.declared_files is not an object."
        )
    for role, entry in inputs.items():
        if role in {
            "declared_files",
            "snapshot_integrity_verified_before_and_after_execution",
        }:
            continue
        add(str(role), entry, location=f"inputs.{role}")
    for role, entry in declared_files.items():
        add(str(role), entry, location=f"inputs.declared_files.{role}")
    for role, entry in deterministic.items():
        add(str(role), entry, location=f"deterministic_artifacts.{role}")
    for role, entry in volatile.items():
        if role == "reproducibility_note":
            continue
        add(str(role), entry, location=f"volatile_engine_artifacts.{role}")
    return entries


def _validate_run_manifest(
    record: dict[str, Any],
    artifacts: dict[str, Path],
    profile: EvidenceValidationProfile,
    repository_root: Path,
) -> dict[str, Any]:
    if "run_manifest" not in artifacts:
        raise EvidenceValidationError(
            "Evidence record does not declare a run_manifest artifact."
        )
    manifest = _load_json(artifacts["run_manifest"])
    manifest_entries = _manifest_entries(manifest)
    missing_core_roles = sorted(CORE_MANIFEST_ARTIFACT_ROLES - set(manifest_entries))
    if missing_core_roles:
        raise EvidenceValidationError(
            f"Run manifest omits required core artifact roles: {missing_core_roles}."
        )
    required_roles = (
        {"run_manifest"}
        | set(manifest_entries)
        | set(profile.supplemental_artifact_roles)
    )
    if set(artifacts) != required_roles:
        missing = sorted(required_roles - set(artifacts))
        extra = sorted(set(artifacts) - required_roles)
        raise EvidenceValidationError(
            "Evidence artifact roles do not match the selected profile and run manifest; "
            f"missing={missing}, extra={extra}."
        )

    bundle_root = artifacts["run_manifest"].parent
    for role, entry in manifest_entries.items():
        run_path = (bundle_root / str(entry["path"])).resolve()
        if run_path != artifacts[role]:
            raise EvidenceValidationError(
                f"Run manifest path for {role!r} does not match the evidence record."
            )
        if _sha256(run_path) != entry["sha256"]:
            raise EvidenceValidationError(
                f"Run manifest digest for {role!r} does not match the artifact."
            )
        if (
            "record_count" in entry
            and _count_jsonl_records(run_path) != entry["record_count"]
        ):
            raise EvidenceValidationError(
                f"Run manifest record count for {role!r} does not match the artifact."
            )

    exact_role_counts = {
        "cases": profile.source_record_count,
        "adjudications": profile.decision_count,
        "normalized_cases": profile.decision_count,
        "deterministic_decisions": profile.decision_count,
        "adjudication_comparison": profile.decision_count,
        "engine_decisions": profile.decision_count,
        "audit_log": profile.decision_count * 8,
    }
    if profile.qualification_enabled:
        exact_role_counts.update(
            {
                "qualification_accounting": profile.source_record_count,
                "rejections": profile.rejected_record_count,
            }
        )
    for role, expected_count in exact_role_counts.items():
        if manifest_entries.get(role, {}).get("record_count") != expected_count:
            raise EvidenceValidationError(
                f"Run manifest artifact {role!r} does not declare exact profile "
                f"record_count {expected_count}."
            )

    if manifest.get("data_origin") != "SYNTHETIC_FIXTURE":
        raise EvidenceValidationError("Profiled run manifest is not synthetic.")
    if manifest.get("historical_case_count") != 0:
        raise EvidenceValidationError("Profiled run manifest reports historical cases.")
    if manifest.get("live_actions_enabled") is not False:
        raise EvidenceValidationError("Profiled run manifest enables live actions.")
    scope = record["evaluation_scope"]
    system = record["system_under_test"]
    if (
        scope.get("data_origin") != manifest.get("data_origin")
        or scope.get("historical_case_count") != manifest.get("historical_case_count")
        or scope.get("case_count") != profile.source_record_count
        or scope.get("adjudicated_case_count") != profile.decision_count
        or scope.get("network_access") is not False
        or scope.get("action_credentials_present") is not False
        or system.get("component_kind") != "DETERMINISTIC_PIPELINE"
        or system.get("execution_mode")
        != str(manifest.get("execution_mode", "")).lower()
        or system.get("contract_version") != manifest.get("contract_version")
        or system.get("adapter") != manifest.get("contract_adapter")
    ):
        raise EvidenceValidationError(
            "Evidence-record evaluation scope does not match the selected profile and run."
        )
    for role in ("model", "policy"):
        reference = system.get(role)
        artifact = artifacts.get(role)
        if not isinstance(reference, dict) or artifact is None:
            raise EvidenceValidationError(
                f"Evidence-record system reference for {role!r} is missing."
            )
        if _confined_path(
            repository_root, str(reference.get("path", ""))
        ) != artifact or reference.get("sha256") != _sha256(artifact):
            raise EvidenceValidationError(
                f"Evidence-record system reference for {role!r} does not bind its artifact."
            )
    if (
        manifest["inputs"].get("snapshot_integrity_verified_before_and_after_execution")
        is not True
    ):
        raise EvidenceValidationError(
            "Run manifest lacks before/after snapshot assurance."
        )
    policy = manifest.get("record_failure_policy")
    if profile.qualification_enabled:
        if policy != profile.expected_record_failure_policy:
            raise EvidenceValidationError(
                "Qualification profile requires QUARANTINE_RECORD in the run manifest."
            )
    elif policy not in (None, "FAIL_DATASET"):
        raise EvidenceValidationError(
            "Starter profile does not permit record-level quarantine."
        )
    assurance = manifest["read_only_assurance"]
    exact_assurance = {
        "authorization_tokens_issued": 0,
        "broker_invocations": 0,
        "operational_effects": 0,
        "execution_suppression_records": profile.decision_count,
        "authorization_evaluated_records": profile.decision_count,
        "decision_finalized_records": profile.decision_count,
        "action_executed_audit_records": 0,
        "audit_record_count": profile.decision_count * 8,
    }
    for key, expected in exact_assurance.items():
        if assurance.get(key) != expected:
            raise EvidenceValidationError(
                f"Run manifest read-only assurance {key!r} is not {expected!r}."
            )
    if assurance.get("audit_chain_valid") is not True:
        raise EvidenceValidationError(
            "Run manifest does not report a valid audit chain."
        )
    if profile.qualification_enabled:
        expected_qualification = {
            "taxonomy_version": QUALIFICATION_TAXONOMY_VERSION,
            "input_records": profile.source_record_count,
            "accepted_records": profile.accepted_record_count,
            "rejected_records": profile.rejected_record_count,
            "decision_records": profile.decision_count,
            "complete_accounting_verified": True,
        }
        if manifest.get("record_qualification") != expected_qualification:
            raise EvidenceValidationError(
                "Run manifest qualification accounting is not exactly 7=3+4 with "
                "three decision records."
            )
        for role in ("qualification_accounting", "rejections"):
            if role not in manifest_entries:
                raise EvidenceValidationError(
                    f"Qualification run manifest omits {role!r}."
                )
    elif "record_qualification" in manifest or any(
        role in manifest_entries for role in ("qualification_accounting", "rejections")
    ):
        raise EvidenceValidationError(
            "Starter profile unexpectedly contains record-qualification artifacts."
        )
    return manifest


def _validate_decisions_and_audit(
    record: dict[str, Any],
    artifacts: dict[str, Path],
    manifest: dict[str, Any],
    profile: EvidenceValidationProfile,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    normalized_cases = _read_jsonl(artifacts["normalized_cases"])
    normalized_case_ids = [row.get("case_id") for row in normalized_cases]
    if (
        len(normalized_case_ids) != profile.decision_count
        or any(
            not isinstance(case_id, str) or not case_id
            for case_id in normalized_case_ids
        )
        or len(set(normalized_case_ids)) != len(normalized_case_ids)
    ):
        raise EvidenceValidationError(
            "Normalized evidence does not define the exact unique decision-case universe."
        )

    decisions = _read_jsonl(artifacts["engine_decisions"])
    try:
        execution_mode = ExecutionMode(str(manifest.get("execution_mode", "")).lower())
        if not execution_mode.is_read_only:
            raise ReplaySafetyViolation("Evidence run does not use a read-only mode.")
        ReplayHarness._validate_read_only_decisions(
            decisions,
            expected_case_ids=set(normalized_case_ids),
            execution_mode=execution_mode,
        )
        audit_assurance = ReplayHarness._validate_audit_assurance(
            artifacts["audit_log"],
            decisions=decisions,
        )
    except (ReplaySafetyViolation, ValueError, KeyError, TypeError) as exc:
        raise EvidenceValidationError(
            f"Committed decision or audit evidence violates the shared read-only contract: {exc}"
        ) from exc

    exact_manifest_assurance = {
        "authorization_tokens_issued": 0,
        "broker_invocations": 0,
        "operational_effects": 0,
        **audit_assurance,
    }
    if manifest.get("read_only_assurance") != exact_manifest_assurance:
        raise EvidenceValidationError(
            "Run-manifest assurance does not exactly match recomputed decision/audit evidence."
        )

    result = record["results"]
    observed_counts = (
        result["denominator"],
        result["passed"],
        result["failed"],
        result["excluded"],
    )
    if observed_counts != profile.expected_result_counts:
        raise EvidenceValidationError(
            "Evidence-record raw result counts do not match the selected profile."
        )
    strata_counts = tuple(
        sum(int(stratum[key]) for stratum in result["strata"])
        for key in ("denominator", "passed", "failed", "excluded")
    )
    if strata_counts != profile.expected_result_counts:
        raise EvidenceValidationError(
            "Evidence-record strata do not reconcile to the selected profile."
        )
    budget = record["budget"]
    if (
        budget.get("evaluation_runs") != 1
        or budget.get("case_evaluations") != profile.source_record_count
        or budget.get("retries") != 0
    ):
        raise EvidenceValidationError(
            "Evidence-record evaluation budget does not match the selected profile."
        )
    metrics = result["metrics"]
    for key in (
        "authorization_attempts",
        "authorization_tokens_issued",
        "broker_invocations",
        "action_results",
        "operational_effects",
        "historical_case_count",
    ):
        if metrics.get(key) != 0:
            raise EvidenceValidationError(
                f"Evidence-record metric {key!r} is not zero."
            )

    replay_metrics = _load_json(artifacts["replay_metrics"])
    if (
        replay_metrics.get("data_origin") != "SYNTHETIC_FIXTURE"
        or replay_metrics.get("historical_case_count") != 0
        or replay_metrics.get("scope", {}).get("cases_evaluated")
        != profile.decision_count
        or replay_metrics.get("scope", {}).get("adjudicated_cases")
        != profile.decision_count
    ):
        raise EvidenceValidationError(
            "Replay metrics scope does not match the selected evidence profile."
        )
    replay_assurance = replay_metrics.get("read_only_assurance", {})
    for key in (
        "authorization_tokens_issued",
        "broker_invocations",
        "action_results",
        "operational_effects",
    ):
        if replay_assurance.get(key) != 0:
            raise EvidenceValidationError(
                f"Replay-metrics no-effect value {key!r} is not zero."
            )
    return decisions, audit_assurance


def _validate_cross_artifact_bindings(
    artifacts: dict[str, Path],
    manifest: dict[str, Any],
    profile: EvidenceValidationProfile,
    decisions: list[dict[str, Any]],
    audit_assurance: dict[str, Any],
) -> None:
    deterministic = _read_jsonl(artifacts["deterministic_decisions"])
    expected_deterministic = [
        ReplayHarness._deterministic_projection(row)
        for row in sorted(decisions, key=lambda value: value["case_id"])
    ]
    if deterministic != expected_deterministic:
        raise EvidenceValidationError(
            "Deterministic decisions are not the exact projection of raw decisions."
        )

    adjudications = _read_jsonl(artifacts["adjudications"])
    try:
        adjudications = validate_adjudication_records(
            adjudications,
            known_case_ids={str(row["case_id"]) for row in decisions},
        )
        expected_comparisons = build_comparisons(decisions, adjudications)
    except (ContractValidationError, KeyError, TypeError) as exc:
        raise EvidenceValidationError(
            f"Committed adjudication evidence is not bound to the decision universe: {exc}"
        ) from exc
    if _read_jsonl(artifacts["adjudication_comparison"]) != expected_comparisons:
        raise EvidenceValidationError(
            "Adjudication comparison is not the exact projection of decisions and labels."
        )

    qualification_records = (
        _read_jsonl(artifacts["qualification_accounting"])
        if profile.qualification_enabled
        else None
    )
    expected_metrics = compute_replay_metrics(
        dataset_id=str(manifest["dataset_id"]),
        data_origin=str(manifest["data_origin"]),
        historical_case_count=int(manifest["historical_case_count"]),
        execution_mode=str(manifest["execution_mode"]),
        decisions=decisions,
        adjudications=adjudications,
        audit_assurance=audit_assurance,
        qualification_records=qualification_records,
    )
    if _load_json(artifacts["replay_metrics"]) != expected_metrics:
        raise EvidenceValidationError(
            "Replay metrics are not the exact recomputation from decisions, labels, audit, and qualification evidence."
        )


def _validate_rows_against_schema(
    rows: list[dict[str, Any]],
    *,
    schema_path: Path,
    label: str,
) -> None:
    schema = _load_json(schema_path)
    try:
        Draft202012Validator.check_schema(schema)
    except Exception as exc:
        raise EvidenceValidationError(f"{label} schema is invalid: {exc}") from exc
    validator = Draft202012Validator(schema)
    for index, row in enumerate(rows, start=1):
        if errors := sorted(
            validator.iter_errors(row), key=lambda item: list(item.path)
        ):
            raise EvidenceValidationError(
                f"{label} row {index} violates its closed schema: {errors[0].message}"
            )


def _validate_object_against_schema(
    value: dict[str, Any],
    *,
    schema_path: Path,
    label: str,
) -> None:
    schema = _load_json(schema_path)
    try:
        Draft202012Validator.check_schema(schema)
    except Exception as exc:
        raise EvidenceValidationError(f"{label} schema is invalid: {exc}") from exc
    validator = Draft202012Validator(schema)
    if errors := sorted(validator.iter_errors(value), key=lambda item: list(item.path)):
        location = ".".join(str(part) for part in errors[0].absolute_path) or "$"
        raise EvidenceValidationError(
            f"{label} violates its closed schema at {location}: {errors[0].message}"
        )


def _source_occurrences(path: Path) -> tuple[int, list[tuple[int, int, str]]]:
    physical_line_count = 0
    nonblank_record_count = 0
    occurrences: list[tuple[int, int, str]] = []
    try:
        with path.open("rb") as handle:
            for raw in handle:
                physical_line_count += 1
                if raw.endswith(b"\r\n"):
                    payload = raw[:-2]
                elif raw.endswith(b"\n"):
                    payload = raw[:-1]
                else:
                    payload = raw
                if not payload.strip():
                    continue
                nonblank_record_count += 1
                occurrences.append(
                    (
                        physical_line_count,
                        nonblank_record_count,
                        hashlib.sha256(payload).hexdigest(),
                    )
                )
    except OSError as exc:
        raise EvidenceValidationError(
            f"Unable to recompute qualification source occurrences: {exc}"
        ) from exc
    return physical_line_count, occurrences


def _validate_qualification_evidence(
    record: dict[str, Any],
    artifacts: dict[str, Path],
    manifest: dict[str, Any],
    profile: EvidenceValidationProfile,
) -> dict[str, int]:
    if not profile.qualification_enabled:
        return {}

    accounting = _read_jsonl(artifacts["qualification_accounting"])
    rejections = _read_jsonl(artifacts["rejections"])
    expected = _load_json(artifacts["expected_qualification"])
    _validate_object_against_schema(
        expected,
        schema_path=QUALIFICATION_EXPECTATIONS_SCHEMA,
        label="Expected qualification",
    )
    _validate_rows_against_schema(
        accounting,
        schema_path=QUALIFICATION_SCHEMA,
        label="Qualification accounting",
    )
    _validate_rows_against_schema(
        rejections,
        schema_path=QUALIFICATION_SCHEMA,
        label="Qualification rejection",
    )

    accepted_count = sum(row.get("status") == "ACCEPTED" for row in accounting)
    rejected_count = sum(row.get("status") == "QUARANTINED" for row in accounting)
    if (
        len(accounting) != profile.source_record_count
        or accepted_count != profile.accepted_record_count
        or rejected_count != profile.rejected_record_count
        or len(accounting) != accepted_count + rejected_count
    ):
        raise EvidenceValidationError(
            "Qualification accounting does not satisfy the exact 7=3+4 invariant."
        )
    if rejections != [row for row in accounting if row.get("status") == "QUARANTINED"]:
        raise EvidenceValidationError(
            "Rejections are not the ordered exact quarantined-ledger projection."
        )

    reason_counts = Counter(
        f"{row['error_category']}/{row['error_code']}" for row in rejections
    )
    if tuple(sorted(reason_counts.items())) != profile.expected_rejection_reasons:
        raise EvidenceValidationError(
            "Qualification rejection-reason counts do not match the fixed profile."
        )

    expected_totals = expected.get("expected_totals")
    exact_totals = {
        "accepted_count": profile.accepted_record_count,
        "fatal_count": 0,
        "nonblank_record_count": profile.source_record_count,
        "physical_line_count": profile.source_record_count,
        "quarantined_count": profile.rejected_record_count,
    }
    if expected_totals != exact_totals:
        raise EvidenceValidationError(
            "Expected-qualification totals do not match the fixed profile."
        )
    if (
        expected.get("dataset_id") != manifest.get("dataset_id")
        or expected.get("source_role") != "cases"
        or expected.get("source_file_sha256")
        != manifest["inputs"]["declared_files"]["cases"]["sha256"]
    ):
        raise EvidenceValidationError(
            "Expected qualification is not bound to the governed source cases."
        )

    projection_fields = (
        "nonblank_record_number",
        "raw_line_sha256",
        "status",
        "error_category",
        "error_code",
    )
    observed_projection = [
        {field: row.get(field) for field in projection_fields} for row in accounting
    ]
    if expected.get("records") != observed_projection:
        raise EvidenceValidationError(
            "Qualification accounting does not exactly match expected outcomes."
        )

    physical_line_count, occurrences = _source_occurrences(artifacts["cases"])
    if (
        physical_line_count != expected_totals["physical_line_count"]
        or len(occurrences) != profile.source_record_count
    ):
        raise EvidenceValidationError(
            "Expected physical/nonblank counts do not match the governed source file."
        )
    for row, occurrence in zip(accounting, occurrences, strict=True):
        if (
            row.get("physical_line_number"),
            row.get("nonblank_record_number"),
            row.get("raw_line_sha256"),
        ) != occurrence:
            raise EvidenceValidationError(
                "Qualification ledger does not bind an exact source occurrence."
            )

    replay_metrics = _load_json(artifacts["replay_metrics"])
    qualification_metrics = replay_metrics.get("record_qualification")
    exact_metric_block = {
        "taxonomy_version": QUALIFICATION_TAXONOMY_VERSION,
        "input_records": profile.source_record_count,
        "accepted_records": profile.accepted_record_count,
        "rejected_records": profile.rejected_record_count,
        "decision_records": profile.decision_count,
        "rejection_reason_counts": dict(profile.expected_rejection_reasons),
        "complete_accounting": True,
        "historical_metrics_available": False,
        "denominator_note": (
            "Qualification counts use every governed nonblank source case; "
            "decision and adjudication measures use accepted records only."
        ),
    }
    if qualification_metrics != exact_metric_block:
        raise EvidenceValidationError(
            "Replay metrics qualification block does not exactly match 7=3+4."
        )

    result_metrics = record["results"]["metrics"]
    expected_record_metrics = {
        "qualification_input_records": profile.source_record_count,
        "qualification_accepted_records": profile.accepted_record_count,
        "qualification_rejected_records": profile.rejected_record_count,
        "qualification_fatal_count": 0,
        "qualification_outcome_matches": profile.source_record_count,
        "decision_records": profile.decision_count,
    }
    for key, value in expected_record_metrics.items():
        if result_metrics.get(key) != value:
            raise EvidenceValidationError(
                f"Evidence-record qualification metric {key!r} is not {value}."
            )
    return {
        "input_records": len(accounting),
        "accepted_records": accepted_count,
        "rejected_records": rejected_count,
    }


def validate_evidence_record(
    record_path: Path = DEFAULT_RECORD,
    *,
    schema_path: Path = DEFAULT_SCHEMA,
    repository_root: Path = ROOT,
    profile_id: str | None = None,
) -> dict[str, Any]:
    repository_root = repository_root.resolve()
    record = _load_json(record_path)
    schema = _load_json(schema_path)
    _validate_schema(record, schema)
    profile = _select_profile(record, profile_id)
    artifacts = _validate_artifacts(record, repository_root)
    manifest = _validate_run_manifest(record, artifacts, profile, repository_root)
    decisions, audit_assurance = _validate_decisions_and_audit(
        record,
        artifacts,
        manifest,
        profile,
    )
    qualification = _validate_qualification_evidence(
        record,
        artifacts,
        manifest,
        profile,
    )
    _validate_cross_artifact_bindings(
        artifacts,
        manifest,
        profile,
        decisions,
        audit_assurance,
    )
    result: dict[str, Any] = {
        "status": "VALID",
        "profile_id": profile.claim_id,
        "claim_id": record["claim_id"],
        "claim_class": record["claim_class"],
        "data_origin": record["evaluation_scope"]["data_origin"],
        "historical_case_count": record["evaluation_scope"]["historical_case_count"],
        "artifact_count": len(artifacts),
        "audit_record_count": manifest["read_only_assurance"]["audit_record_count"],
        "result": profile.result_summary,
    }
    if qualification:
        result["record_qualification"] = qualification
    return result


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Validate the committed Phase 2 claim-evidence record and bundle."
    )
    parser.add_argument("--record", type=Path, default=DEFAULT_RECORD)
    parser.add_argument("--schema", type=Path, default=DEFAULT_SCHEMA)
    parser.add_argument(
        "--profile",
        choices=tuple(sorted(EVIDENCE_PROFILES)),
        help="Require a specific claim-evidence validation profile.",
    )
    args = parser.parse_args()
    try:
        result = validate_evidence_record(
            args.record,
            schema_path=args.schema,
            profile_id=args.profile,
        )
    except EvidenceValidationError as exc:
        raise SystemExit(f"INVALID: {exc}") from exc
    print(json.dumps(result, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
