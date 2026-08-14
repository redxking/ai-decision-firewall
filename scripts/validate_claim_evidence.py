from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator, FormatChecker


ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from adf_poc.audit import AuditLogger  # noqa: E402


DEFAULT_SCHEMA = ROOT / "contracts/v0.2.0/evaluation-evidence.schema.json"
DEFAULT_RECORD = (
    ROOT
    / "contracts/v0.2.0/examples/phase2-starter-evidence-record.json"
)


class EvidenceValidationError(ValueError):
    """Raised when a claim-evidence record or referenced artifact is invalid."""


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
        raise EvidenceValidationError(f"Evaluation-evidence schema is invalid: {exc}") from exc
    validator = Draft202012Validator(schema, format_checker=FormatChecker())
    errors = sorted(validator.iter_errors(record), key=lambda item: list(item.path))
    if errors:
        messages = []
        for error in errors:
            location = ".".join(str(part) for part in error.absolute_path) or "$"
            messages.append(f"{location}: {error.message}")
        raise EvidenceValidationError(
            "Evaluation-evidence record does not match the schema: " + "; ".join(messages)
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
            actual_count = len(_read_jsonl(path))
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
    inputs = manifest["inputs"]
    deterministic = manifest["deterministic_artifacts"]
    volatile = manifest["volatile_engine_artifacts"]
    return {
        "configuration": inputs["configuration"],
        "dataset_manifest": inputs["dataset_manifest"],
        "model": inputs["model"],
        "policy": inputs["policy"],
        "cases": inputs["declared_files"]["cases"],
        "adjudications": inputs["declared_files"]["adjudications"],
        "normalized_cases": deterministic["normalized_cases"],
        "normalization_diagnostics": deterministic["normalization_diagnostics"],
        "deterministic_decisions": deterministic["replay_decisions"],
        "adjudication_comparison": deterministic["adjudication_comparison"],
        "replay_metrics": deterministic["replay_metrics"],
        "engine_decisions": volatile["engine_decisions"],
        "audit_log": volatile["audit_log"],
    }


def _validate_run_manifest(
    record: dict[str, Any], artifacts: dict[str, Path]
) -> dict[str, Any]:
    required_roles = {
        "run_manifest",
        "configuration",
        "dataset_manifest",
        "model",
        "policy",
        "cases",
        "adjudications",
        "normalized_cases",
        "normalization_diagnostics",
        "engine_decisions",
        "deterministic_decisions",
        "audit_log",
        "adjudication_comparison",
        "replay_metrics",
    }
    if set(artifacts) != required_roles:
        missing = sorted(required_roles - set(artifacts))
        extra = sorted(set(artifacts) - required_roles)
        raise EvidenceValidationError(
            f"Evidence artifact roles do not match the starter bundle; missing={missing}, extra={extra}."
        )

    manifest = _load_json(artifacts["run_manifest"])
    bundle_root = artifacts["run_manifest"].parent
    for role, entry in _manifest_entries(manifest).items():
        run_path = (bundle_root / str(entry["path"])).resolve()
        if run_path != artifacts[role]:
            raise EvidenceValidationError(
                f"Run manifest path for {role!r} does not match the evidence record."
            )
        if _sha256(run_path) != entry["sha256"]:
            raise EvidenceValidationError(
                f"Run manifest digest for {role!r} does not match the artifact."
            )
        if "record_count" in entry and len(_read_jsonl(run_path)) != entry["record_count"]:
            raise EvidenceValidationError(
                f"Run manifest record count for {role!r} does not match the artifact."
            )

    if manifest.get("data_origin") != "SYNTHETIC_FIXTURE":
        raise EvidenceValidationError("Starter run manifest is not synthetic.")
    if manifest.get("historical_case_count") != 0:
        raise EvidenceValidationError("Starter run manifest reports historical cases.")
    if manifest.get("live_actions_enabled") is not False:
        raise EvidenceValidationError("Starter run manifest enables live actions.")
    if manifest["inputs"].get(
        "snapshot_integrity_verified_before_and_after_execution"
    ) is not True:
        raise EvidenceValidationError("Run manifest lacks before/after snapshot assurance.")
    assurance = manifest["read_only_assurance"]
    exact_assurance = {
        "authorization_tokens_issued": 0,
        "broker_invocations": 0,
        "operational_effects": 0,
        "execution_suppression_records": 3,
        "authorization_evaluated_records": 3,
        "decision_finalized_records": 3,
        "action_executed_audit_records": 0,
        "audit_record_count": 24,
    }
    for key, expected in exact_assurance.items():
        if assurance.get(key) != expected:
            raise EvidenceValidationError(
                f"Run manifest read-only assurance {key!r} is not {expected!r}."
            )
    if assurance.get("audit_chain_valid") is not True:
        raise EvidenceValidationError("Run manifest does not report a valid audit chain.")
    return manifest


def _validate_decisions_and_audit(
    record: dict[str, Any], artifacts: dict[str, Path]
) -> None:
    decisions = _read_jsonl(artifacts["engine_decisions"])
    if len(decisions) != 3:
        raise EvidenceValidationError("Starter evidence does not contain three decisions.")
    expected_authorization = {
        "issued": False,
        "token_id": "",
        "decision_hash": "",
        "permitted_actions": [],
        "error": "",
    }
    expected_post_action = {
        "applicable": False,
        "status": "NOT_APPLICABLE",
        "passed": None,
        "checks": [],
    }
    for decision in decisions:
        if decision.get("authorization") != expected_authorization:
            raise EvidenceValidationError("A starter decision retains authorization state.")
        if decision.get("action_results") != []:
            raise EvidenceValidationError("A starter decision contains action results.")
        if decision.get("post_action_verification") != expected_post_action:
            raise EvidenceValidationError(
                "A starter decision misrepresents post-action verification."
            )
        control = decision.get("execution_control", {})
        if (
            control.get("authorization_attempted") is not False
            or control.get("broker_invocations") != 0
            or control.get("operational_effects") != 0
        ):
            raise EvidenceValidationError("A starter decision violates the no-effect contract.")

    audit_valid, audit_errors = AuditLogger.verify(artifacts["audit_log"])
    if not audit_valid:
        raise EvidenceValidationError(
            "Committed audit chain is invalid: " + "; ".join(audit_errors)
        )
    audit_rows = _read_jsonl(artifacts["audit_log"])
    counts: dict[str, int] = {}
    for row in audit_rows:
        record_type = str(row.get("record_type", ""))
        counts[record_type] = counts.get(record_type, 0) + 1
    for record_type in ("EXECUTION_SUPPRESSED", "AUTHORIZATION_EVALUATED", "DECISION_FINALIZED"):
        if counts.get(record_type) != 3:
            raise EvidenceValidationError(
                f"Committed audit does not contain three {record_type} records."
            )
    for record_type in ("ACTION_EXECUTED", "ACTION_REJECTED", "POST_ACTION_VERIFIED"):
        if counts.get(record_type, 0) != 0:
            raise EvidenceValidationError(
                f"Committed audit contains prohibited {record_type} evidence."
            )

    result = record["results"]
    if (result["denominator"], result["passed"], result["failed"], result["excluded"]) != (
        3,
        3,
        0,
        0,
    ):
        raise EvidenceValidationError("Evidence-record raw result counts are not 3/3/0/0.")
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
            raise EvidenceValidationError(f"Evidence-record metric {key!r} is not zero.")


def validate_evidence_record(
    record_path: Path = DEFAULT_RECORD,
    *,
    schema_path: Path = DEFAULT_SCHEMA,
    repository_root: Path = ROOT,
) -> dict[str, Any]:
    repository_root = repository_root.resolve()
    record = _load_json(record_path)
    schema = _load_json(schema_path)
    _validate_schema(record, schema)
    artifacts = _validate_artifacts(record, repository_root)
    manifest = _validate_run_manifest(record, artifacts)
    _validate_decisions_and_audit(record, artifacts)
    return {
        "status": "VALID",
        "claim_id": record["claim_id"],
        "claim_class": record["claim_class"],
        "data_origin": record["evaluation_scope"]["data_origin"],
        "historical_case_count": record["evaluation_scope"]["historical_case_count"],
        "artifact_count": len(artifacts),
        "audit_record_count": manifest["read_only_assurance"]["audit_record_count"],
        "result": "3/3 controlled synthetic cases passed; no broader inference authorized",
    }


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Validate the committed Phase 2 claim-evidence record and bundle."
    )
    parser.add_argument("--record", type=Path, default=DEFAULT_RECORD)
    parser.add_argument("--schema", type=Path, default=DEFAULT_SCHEMA)
    args = parser.parse_args()
    try:
        result = validate_evidence_record(args.record, schema_path=args.schema)
    except EvidenceValidationError as exc:
        raise SystemExit(f"INVALID: {exc}") from exc
    print(json.dumps(result, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
