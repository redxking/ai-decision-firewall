from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
import sys
from collections import Counter
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
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
from adf_poc.replay.reference_features import (  # noqa: E402
    ReferenceFeatureAssuranceError,
    verify_reference_feature_projections,
)


DEFAULT_SCHEMA = ROOT / "contracts/v0.2.0/evaluation-evidence.schema.json"
DEFAULT_RECORD = ROOT / "contracts/v0.2.0/examples/phase2-starter-evidence-record.json"
LEGACY_REPLAY_RECORD_FINGERPRINTS = {
    (
        ROOT / "contracts/v0.2.0/examples/phase2-starter-evidence-record.json"
    ).resolve(): "b349c30fd654f8b3b09286e07a7008efe9b73e8b2ad20dd7b88f68f9123b2f4f",
    (
        ROOT / "contracts/v0.2.0/examples/phase2-qualification-evidence-record.json"
    ).resolve(): "c2a623f878ba9654c893e14fa54373ca9b4bd4e1c6c118661f86d360a4a9c4fd",
}
QUALIFICATION_SCHEMA = ROOT / "contracts/v0.2.0/replay-qualification.schema.json"
QUALIFICATION_EXPECTATIONS_SCHEMA = (
    ROOT / "contracts/v0.2.0/qualification-expectations.schema.json"
)
GATE_B_CAMPAIGN_SCHEMA = ROOT / "contracts/v0.2.0/gate-b-ce2-campaign.schema.json"
GATE_B_CAMPAIGN_PLAN = ROOT / "config/gate_b_ce2_campaign_plan.json"
GATE_B_CAMPAIGN_ID = "P2-CE-003-GATE-B-SYNTHETIC"
GATE_B_CAMPAIGN_SEED = 20260814
GATE_B_CANARY = "P2-CE-003-EPHEMERAL-AUTHORIZATION-CANARY"
GATE_B_CAMPAIGN_MAX_BYTES = 256 * 1024
GATE_B_CAMPAIGN_SOURCE_PATHS = {
    "CAMPAIGN_GENERATOR": "scripts/generate_gate_b_ce2_campaign.py",
    "CAMPAIGN_PLAN": "config/gate_b_ce2_campaign_plan.json",
    "CAMPAIGN_SCHEMA": "contracts/v0.2.0/gate-b-ce2-campaign.schema.json",
    "CLAIM_VALIDATOR": "scripts/validate_claim_evidence.py",
    "GATE_B_IMPLEMENTATION": "src/adf_poc/replay/gate_b.py",
    "REPLAY_CONTRACTS_IMPLEMENTATION": "src/adf_poc/replay/contracts.py",
    "REPLAY_HARNESS_IMPLEMENTATION": "src/adf_poc/replay/harness.py",
    "GATE_B_AUTHORIZATION_SCHEMA": "contracts/v0.2.0/gate-b-authorization.schema.json",
    "STARTER_MANIFEST": "data/phase2_starter/manifest.json",
    "STARTER_CASES": "data/phase2_starter/cases.jsonl",
    "STARTER_ADJUDICATIONS": "data/phase2_starter/adjudications.jsonl",
    "QUALIFICATION_MANIFEST": "data/phase2_qualification/manifest.json",
    "QUALIFICATION_CASES": "data/phase2_qualification/cases.jsonl",
    "QUALIFICATION_ADJUDICATIONS": "data/phase2_qualification/adjudications.jsonl",
    "MODEL": "outputs/baseline/model.json",
    "POLICY": "config/policy.json",
}
FEATURE_ASSURANCE_CAMPAIGN_SCHEMA = (
    ROOT / "contracts/v0.2.0/feature-assurance-ce2-campaign.schema.json"
)
FEATURE_ASSURANCE_CAMPAIGN_PLAN = (
    ROOT / "config/feature_assurance_ce2_campaign_plan.json"
)
FEATURE_ASSURANCE_CAMPAIGN_ID = "P2-CE-004-FEATURE-ASSURANCE-SYNTHETIC"
FEATURE_ASSURANCE_CAMPAIGN_SEED = 20260815
FEATURE_ASSURANCE_CAMPAIGN_MAX_BYTES = 256 * 1024


def _feature_assurance_source_paths() -> dict[str, str]:
    package_paths: dict[str, str] = {}
    for path in sorted((ROOT / "src/adf_poc").rglob("*.py")):
        relative = str(path.relative_to(ROOT))
        role = "ADF_" + re.sub(r"[^A-Za-z0-9]+", "_", relative).strip("_").upper()
        package_paths[role] = relative
    return {
        "CAMPAIGN_GENERATOR": "scripts/generate_feature_assurance_ce2_campaign.py",
        "CAMPAIGN_PLAN": "config/feature_assurance_ce2_campaign_plan.json",
        "CAMPAIGN_SCHEMA": (
            "contracts/v0.2.0/feature-assurance-ce2-campaign.schema.json"
        ),
        "CLAIM_VALIDATOR": "scripts/validate_claim_evidence.py",
        "EVIDENCE_SCHEMA": "contracts/v0.2.0/evaluation-evidence.schema.json",
        "EVIDENCE_TEMPLATE": (
            "contracts/v0.2.0/examples/phase2-qualification-evidence-record.json"
        ),
        "QUALIFICATION_SCHEMA": ("contracts/v0.2.0/replay-qualification.schema.json"),
        "REFERENCE_ASSURANCE_SCHEMA": (
            "contracts/v0.2.0/reference-feature-assurance.schema.json"
        ),
        "REPLAY_CASE_SCHEMA": "contracts/v0.2.0/replay-case.schema.json",
        "PROJECT_METADATA": "pyproject.toml",
        "DEPENDENCY_DECLARATIONS": "requirements.txt",
        **package_paths,
    }


FEATURE_ASSURANCE_CAMPAIGN_SOURCE_PATHS = _feature_assurance_source_paths()
FEATURE_ASSURANCE_SUPPORTED_WORDING = (
    "Across two complete executions of P2-CE-004's fixed 16-attempt synthetic "
    "campaign and exact bound source/configuration, all 32 attempt observations "
    "matched the 16 commit-frozen, project-controlled expected outcomes (16/16 "
    "per run): each run produced eight clean qualification and reference-projection "
    "matches, four typed or source-unauthorized modeled signals quarantined before "
    "production projection, and four locally rehashed projection mutations blocked "
    "by the separately implemented in-process reference projector. The two sanitized "
    "result ledgers were "
    "byte-identical. Within the scoped campaign calls, no model, policy, verifier, "
    "decision-engine, authorization, broker, target-effect, or operational-effect "
    "boundary was reached; this is project-controlled SELF-reviewed synthetic CE-2 "
    "evidence only."
)
GATE_B_SUPPORTED_WORDING = (
    "Across two complete executions of P2-CE-003's fixed 16-attempt synthetic "
    "campaign and exact bound source/configuration, all 32 attempt observations "
    "matched the 16 commit-frozen, project-controlled expected outcomes (16/16 "
    "in each run): each run produced one test-only validate-only pass, 14 "
    "structural blocks with no governed payload-role access observed by the "
    "declared Path/os.open instrumentation during the harness invocation, and "
    "one quarantine-threshold block "
    "after qualification but before the decision engine. The two sanitized "
    "result ledgers were byte-identical; across both runs, no decision-engine, "
    "authorization, broker, or target-effect boundary was reached during an "
    "instrumented harness invocation, and no completed run manifest, decision "
    "artifact, or audit artifact was observed."
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
    profile_kind: str = "REPLAY"

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
    "P2-CE-003": EvidenceValidationProfile(
        claim_id="P2-CE-003",
        decision_count=0,
        source_record_count=16,
        accepted_record_count=1,
        rejected_record_count=15,
        expected_result_counts=(32, 32, 0, 0),
        expected_record_failure_policy=None,
        supplemental_artifact_roles=frozenset(),
        expected_rejection_reasons=(),
        result_summary=(
            "32/32 observations across two complete executions of 16 fixed "
            "synthetic Gate B outcomes matched; no broader inference authorized"
        ),
        profile_kind="GATE_B_CAMPAIGN",
    ),
    "P2-CE-004": EvidenceValidationProfile(
        claim_id="P2-CE-004",
        decision_count=0,
        source_record_count=16,
        accepted_record_count=12,
        rejected_record_count=4,
        expected_result_counts=(32, 32, 0, 0),
        expected_record_failure_policy=None,
        supplemental_artifact_roles=frozenset(),
        expected_rejection_reasons=(
            ("SEMANTICS/INVALID_BOOLEAN", 1),
            ("SEMANTICS/INVALID_TYPE", 1),
            ("SEMANTICS/UNAUTHORIZED_MODELED_SIGNAL", 2),
        ),
        result_summary=(
            "32/32 observations across two complete executions of 16 fixed "
            "synthetic feature-assurance outcomes matched; no broader inference "
            "authorized"
        ),
        profile_kind="FEATURE_ASSURANCE_CAMPAIGN",
    ),
}


class EvidenceValidationError(ValueError):
    """Raised when a claim-evidence record or referenced artifact is invalid."""


class _DuplicateJSONMember(ValueError):
    """Internal marker for ambiguous evidence JSON."""


def _reject_duplicate_json_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, child in pairs:
        if key in value:
            raise _DuplicateJSONMember
        value[key] = child
    return value


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
        value = json.loads(
            path.read_text(encoding="utf-8"),
            object_pairs_hook=_reject_duplicate_json_pairs,
        )
    except (OSError, UnicodeError, json.JSONDecodeError, _DuplicateJSONMember) as exc:
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
                value = json.loads(
                    line,
                    object_pairs_hook=_reject_duplicate_json_pairs,
                )
                if not isinstance(value, dict):
                    raise EvidenceValidationError(
                        f"{path}:{line_number} is not a JSON object."
                    )
                rows.append(value)
    except EvidenceValidationError:
        raise
    except (
        OSError,
        UnicodeError,
        json.JSONDecodeError,
        _DuplicateJSONMember,
    ) as exc:
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
    if "reference_feature_assurance" in manifest_entries:
        exact_role_counts["reference_feature_assurance"] = profile.decision_count
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
    if "reference_feature_assurance" in manifest_entries:
        for key in (
            "reference_feature_cases_checked",
            "reference_feature_cases_matched",
        ):
            if assurance.get(key) != profile.decision_count:
                raise EvidenceValidationError(
                    f"Run manifest read-only assurance {key!r} is not "
                    f"{profile.decision_count!r}."
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
            expected_case_ids={
                case_id for case_id in normalized_case_ids if isinstance(case_id, str)
            },
            execution_mode=execution_mode,
        )
        audit_assurance = ReplayHarness._validate_audit_assurance(
            artifacts["audit_log"],
            decisions=decisions,
            autonomous_actions=ReplayHarness._autonomous_actions_from_policy_bytes(
                artifacts["policy"].read_bytes()
            ),
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
    if "reference_feature_assurance" in artifacts:
        try:
            expected_reference_records = verify_reference_feature_projections(
                normalized_cases,
                decisions,
            )
        except ReferenceFeatureAssuranceError as exc:
            raise EvidenceValidationError(
                "Committed feature-projection evidence violates the reference contract."
            ) from exc
        observed_reference_records = _read_jsonl(
            artifacts["reference_feature_assurance"]
        )
        if observed_reference_records != expected_reference_records:
            raise EvidenceValidationError(
                "Committed reference feature evidence does not match recomputation."
            )
        exact_manifest_assurance.update(
            {
                "reference_feature_cases_checked": profile.decision_count,
                "reference_feature_cases_matched": profile.decision_count,
            }
        )
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
    reference_feature_records = (
        _read_jsonl(artifacts["reference_feature_assurance"])
        if "reference_feature_assurance" in artifacts
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
        reference_feature_records=reference_feature_records,
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


def _validate_gate_b_campaign_object(
    value: dict[str, Any],
    *,
    schema: dict[str, Any],
    label: str,
) -> None:
    validator = Draft202012Validator(schema)
    errors = sorted(validator.iter_errors(value), key=lambda item: list(item.path))
    if errors:
        location = ".".join(str(part) for part in errors[0].absolute_path) or "$"
        raise EvidenceValidationError(
            f"{label} violates the closed Gate B campaign schema at {location}."
        )


def _git_blob_digest(
    repository_root: Path,
    *,
    commit: str,
    relative_path: str,
) -> str:
    try:
        completed = subprocess.run(
            ["git", "show", f"{commit}:{relative_path}"],
            cwd=repository_root,
            check=False,
            capture_output=True,
            timeout=10,
        )
    except (OSError, subprocess.SubprocessError):
        raise EvidenceValidationError(
            "Unable to verify the Gate B campaign implementation commit."
        ) from None
    if completed.returncode != 0:
        raise EvidenceValidationError(
            "Gate B campaign source binding is absent from the implementation commit."
        )
    return hashlib.sha256(completed.stdout).hexdigest()


def _git_commit_timestamp(repository_root: Path, *, commit: str) -> datetime:
    try:
        completed = subprocess.run(
            ["git", "show", "-s", "--format=%cI", commit],
            cwd=repository_root,
            check=False,
            capture_output=True,
            timeout=10,
            text=True,
        )
    except (OSError, subprocess.SubprocessError):
        raise EvidenceValidationError(
            "Unable to verify the Gate B campaign commit timestamp."
        ) from None
    if completed.returncode != 0:
        raise EvidenceValidationError(
            "Gate B campaign implementation commit is unavailable."
        )
    try:
        return datetime.fromisoformat(completed.stdout.strip()).astimezone(timezone.utc)
    except ValueError:
        raise EvidenceValidationError(
            "Gate B campaign implementation commit timestamp is invalid."
        ) from None


def _expected_gate_b_result(
    expected: dict[str, Any],
    observed: dict[str, Any],
) -> bool:
    zero_fields = (
        "engine_calls",
        "authorization_attempts",
        "authorization_tokens_issued",
        "broker_invocations",
        "target_effect_calls",
        "action_results",
        "operational_effects",
        "completed_run_manifests",
        "decision_artifacts",
        "audit_artifacts",
    )
    return (
        observed.get("sequence") == expected.get("sequence")
        and observed.get("attempt_id") == expected.get("attempt_id")
        and observed.get("fixture") == expected.get("fixture")
        and observed.get("operation") == expected.get("operation")
        and observed.get("mutation_id") == expected.get("mutation_id")
        and observed.get("expected_outcome") == expected.get("expected_outcome")
        and observed.get("observed_outcome") == expected.get("expected_outcome")
        and observed.get("error_class") == expected.get("expected_error_class")
        and observed.get("accessed_payload_roles")
        == expected.get("expected_accessed_payload_roles")
        and all(observed.get(field) == 0 for field in zero_fields)
    )


def _validate_gate_b_campaign_evidence(
    record: dict[str, Any],
    artifacts: dict[str, Path],
    profile: EvidenceValidationProfile,
    repository_root: Path,
) -> dict[str, Any]:
    exact_artifact_roles = {
        "campaign_profile",
        "campaign_results_run1",
        "campaign_results_run2",
        "campaign_summary",
        "campaign_plan",
        "campaign_schema",
    }
    if set(artifacts) != exact_artifact_roles:
        raise EvidenceValidationError(
            "Gate B campaign evidence does not contain the exact six artifact roles."
        )
    if artifacts["campaign_schema"] != GATE_B_CAMPAIGN_SCHEMA.resolve():
        raise EvidenceValidationError(
            "Gate B campaign evidence does not bind the canonical campaign schema."
        )
    if artifacts["campaign_plan"] != GATE_B_CAMPAIGN_PLAN.resolve():
        raise EvidenceValidationError(
            "Gate B campaign evidence does not bind the canonical campaign plan."
        )
    for role, path in artifacts.items():
        maximum = 512 * 1024 if role == "campaign_schema" else GATE_B_CAMPAIGN_MAX_BYTES
        try:
            size = path.stat().st_size
        except OSError:
            raise EvidenceValidationError(
                "Gate B campaign evidence artifact is unavailable."
            ) from None
        if size > maximum:
            raise EvidenceValidationError(
                "Gate B campaign evidence artifact exceeds its public size bound."
            )

    schema = _load_json(artifacts["campaign_schema"])
    try:
        Draft202012Validator.check_schema(schema)
    except Exception:
        raise EvidenceValidationError("Gate B campaign schema is invalid.") from None
    plan = _load_json(GATE_B_CAMPAIGN_PLAN)
    campaign_profile = _load_json(artifacts["campaign_profile"])
    campaign_results_run1 = _read_jsonl(artifacts["campaign_results_run1"])
    campaign_results_run2 = _read_jsonl(artifacts["campaign_results_run2"])
    campaign_summary = _load_json(artifacts["campaign_summary"])
    _validate_gate_b_campaign_object(plan, schema=schema, label="Campaign plan")
    _validate_gate_b_campaign_object(
        campaign_profile,
        schema=schema,
        label="Campaign profile",
    )
    _validate_gate_b_campaign_object(
        campaign_summary,
        schema=schema,
        label="Campaign summary",
    )
    for row in campaign_results_run1 + campaign_results_run2:
        _validate_gate_b_campaign_object(row, schema=schema, label="Campaign result")

    if (
        campaign_profile.get("campaign_id") != GATE_B_CAMPAIGN_ID
        or campaign_profile.get("claim_id") != profile.claim_id
        or campaign_profile.get("campaign_seed") != GATE_B_CAMPAIGN_SEED
        or campaign_profile.get("campaign_plan_sha256") != _sha256(GATE_B_CAMPAIGN_PLAN)
        or campaign_summary.get("runtime_fingerprint")
        != campaign_profile.get("runtime_fingerprint")
        or campaign_profile.get("design") != plan.get("design")
        or campaign_profile.get("configuration_binding")
        != plan.get("configuration_binding")
        or campaign_profile.get("budget") != plan.get("budget")
        or campaign_profile.get("expected_attempts") != plan.get("expected_attempts")
    ):
        raise EvidenceValidationError(
            "Gate B campaign profile does not exactly bind the commit-frozen plan."
        )
    design = campaign_profile["design"]
    if design != {
        "actual_historical_records": 0,
        "attempt_order_frozen": True,
        "data_origin": "SYNTHETIC_FIXTURE",
        "execution_authority": "NONE",
        "result_capture": "SANITIZED_ENUMERATED_FIELDS_ONLY",
        "simulated_runtime_origin": "HISTORICAL_DEIDENTIFIED",
        "stored_approval_package": False,
        "stored_historical_data": False,
    }:
        raise EvidenceValidationError("Gate B campaign origin boundary is not exact.")

    implementation_commit = campaign_profile.get("implementation_commit")
    if not isinstance(implementation_commit, str) or not re.fullmatch(
        r"[0-9a-f]{40}", implementation_commit
    ):
        raise EvidenceValidationError(
            "Gate B campaign profile lacks an exact implementation commit."
        )
    evaluated_at = campaign_profile.get("evaluated_at")
    if (
        not isinstance(evaluated_at, str)
        or not re.fullmatch(
            r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z",
            evaluated_at,
        )
        or campaign_summary.get("evaluated_at") != evaluated_at
        or record.get("evaluated_at") != evaluated_at
        or record.get("review", {}).get("reviewed_at") != evaluated_at
    ):
        raise EvidenceValidationError(
            "Gate B campaign evaluation timestamp binding is not exact."
        )
    try:
        evaluated_time = datetime.fromisoformat(
            evaluated_at[:-1] + "+00:00"
        ).astimezone(timezone.utc)
    except ValueError:
        raise EvidenceValidationError(
            "Gate B campaign evaluation timestamp is invalid."
        ) from None
    expected_expiry = (
        (evaluated_time + timedelta(days=90)).isoformat().replace("+00:00", "Z")
    )
    if evaluated_time > datetime.now(timezone.utc) + timedelta(minutes=5):
        raise EvidenceValidationError(
            "Gate B campaign evaluation timestamp is later than the validation clock."
        )
    if evaluated_time < _git_commit_timestamp(
        repository_root,
        commit=implementation_commit,
    ):
        raise EvidenceValidationError(
            "Gate B campaign evaluation predates its implementation commit."
        )
    if record.get("review", {}).get("claim_expires_at") != expected_expiry:
        raise EvidenceValidationError(
            "Gate B campaign claim expiry is not derived from the evaluation timestamp."
        )
    source_reference = str(record["system_under_test"].get("source_reference", ""))
    exact_commit_phrase = f"Git commit {implementation_commit} "
    exact_commit_url = (
        "https://github.com/redxking/ai-decision-firewall/commit/"
        + implementation_commit
    )
    referenced_commits = set(
        re.findall(r"(?<![0-9a-f])[0-9a-f]{40}(?![0-9a-f])", source_reference)
    )
    if (
        exact_commit_phrase not in source_reference
        or exact_commit_url not in source_reference
        or referenced_commits != {implementation_commit}
    ):
        raise EvidenceValidationError(
            "Evidence source_reference does not bind the campaign implementation commit."
        )

    bindings = campaign_profile.get("source_bindings")
    if not isinstance(bindings, list) or len(bindings) != len(
        GATE_B_CAMPAIGN_SOURCE_PATHS
    ):
        raise EvidenceValidationError(
            "Gate B campaign source-binding count is invalid."
        )
    bound_roles: set[str] = set()
    for binding in bindings:
        role = str(binding.get("role"))
        if role in bound_roles or role not in GATE_B_CAMPAIGN_SOURCE_PATHS:
            raise EvidenceValidationError(
                "Gate B campaign source-binding role set is invalid."
            )
        bound_roles.add(role)
        expected_relative = GATE_B_CAMPAIGN_SOURCE_PATHS[role]
        if binding.get("path") != expected_relative:
            raise EvidenceValidationError(
                "Gate B campaign source-binding path is not canonical."
            )
        expected_digest = binding.get("sha256")
        # P2-CE-003 is immutable historical evidence.  Validate its recorded
        # bytes against the exact Git object named by the evidence, rather than
        # against a later checkout whose implementation is expected to evolve.
        # The closed role/path registry above and git-show failure handling keep
        # this fail-closed when the commit or a bound blob is unavailable.
        if expected_digest != _git_blob_digest(
            repository_root,
            commit=implementation_commit,
            relative_path=expected_relative,
        ):
            raise EvidenceValidationError(
                "Gate B campaign source bytes do not match the implementation commit."
            )
    if bound_roles != set(GATE_B_CAMPAIGN_SOURCE_PATHS):
        raise EvidenceValidationError(
            "Gate B campaign source-binding roles are incomplete."
        )

    expected_attempts = campaign_profile["expected_attempts"]
    if len(expected_attempts) != 16 or any(
        len(rows) != 16 for rows in (campaign_results_run1, campaign_results_run2)
    ):
        raise EvidenceValidationError(
            "Gate B campaign does not contain exactly two complete 16-attempt runs."
        )
    for rows in (campaign_results_run1, campaign_results_run2):
        for expected, observed in zip(expected_attempts, rows, strict=True):
            recomputed = _expected_gate_b_result(expected, observed)
            if observed.get("matched") is not recomputed or not recomputed:
                raise EvidenceValidationError(
                    "Gate B campaign result does not match its exact commit-frozen attempt."
                )

    profile_bytes = artifacts["campaign_profile"].read_bytes()
    result_run1_bytes = artifacts["campaign_results_run1"].read_bytes()
    result_run2_bytes = artifacts["campaign_results_run2"].read_bytes()
    if result_run1_bytes != result_run2_bytes:
        raise EvidenceValidationError(
            "Gate B campaign result ledgers are not byte-identical."
        )
    summary_bindings = campaign_summary.get("artifact_bindings")
    if summary_bindings != {
        "campaign_profile_sha256": hashlib.sha256(profile_bytes).hexdigest(),
        "campaign_results_run1_sha256": hashlib.sha256(result_run1_bytes).hexdigest(),
        "campaign_results_run2_sha256": hashlib.sha256(result_run2_bytes).hexdigest(),
    }:
        raise EvidenceValidationError(
            "Gate B campaign summary does not bind the exact profile and both results."
        )
    if campaign_summary.get(
        "implementation_commit"
    ) != implementation_commit or campaign_summary.get(
        "campaign_plan_sha256"
    ) != campaign_profile.get(
        "campaign_plan_sha256"
    ):
        raise EvidenceValidationError(
            "Gate B campaign summary source binding is not exact."
        )
    campaign_results = campaign_results_run1 + campaign_results_run2
    prepayload = [
        row
        for row in campaign_results
        if row["expected_outcome"] == "BLOCKED_PREPAYLOAD"
    ]
    observed_pass = sum(
        row["observed_outcome"] == "PASS_TEST_ONLY" for row in campaign_results
    )
    observed_post = sum(
        row["observed_outcome"] == "BLOCKED_POSTQUALIFICATION_PREENGINE"
        for row in campaign_results
    )
    zero_fields = (
        "engine_calls",
        "authorization_attempts",
        "authorization_tokens_issued",
        "broker_invocations",
        "target_effect_calls",
        "action_results",
        "operational_effects",
        "completed_run_manifests",
        "decision_artifacts",
        "audit_artifacts",
    )
    expected_summary = {
        "raw_outcomes": {
            "denominator": 32,
            "matched": 32,
            "mismatched": 0,
            "excluded": 0,
            "observed_pass_test_only": observed_pass,
            "observed_blocked": 32 - observed_pass,
        },
        "stage_outcomes": {
            "pass_test_only": observed_pass,
            "blocked_prepayload": len(prepayload),
            "blocked_postqualification_preengine": observed_post,
        },
        "assurance": {
            "prepayload_attempts": len(prepayload),
            "prepayload_attempts_with_payload_access": sum(
                bool(row["accessed_payload_roles"]) for row in prepayload
            ),
            **{
                field: sum(int(row[field]) for row in campaign_results)
                for field in zero_fields
            },
        },
        "repeatability": {
            "evaluation_runs": 2,
            "attempts_per_run": 16,
            "total_attempt_executions": 32,
            "byte_identical_result_ledgers": True,
        },
    }
    for field, value in expected_summary.items():
        if campaign_summary.get(field) != value:
            raise EvidenceValidationError(
                "Gate B campaign summary does not exactly recompute from result rows."
            )
    if campaign_summary.get("evidence_boundary") != {
        "stored_approval_package": False,
        "stored_historical_data": False,
        "review_type": "SELF",
        "supported_claim_class": "CONTROLLED_BEHAVIOR",
    }:
        raise EvidenceValidationError("Gate B campaign evidence boundary is invalid.")

    serialized_public_bundle = b"\n".join(
        (
            profile_bytes,
            result_run1_bytes,
            result_run2_bytes,
            artifacts["campaign_summary"].read_bytes(),
        )
    )
    prohibited_public_tokens = (
        GATE_B_CANARY.encode("utf-8"),
        b'"approved_purpose"',
        b'"approver_id"',
        b'"approval_reference"',
        b'"authorization_id"',
        b'"case_id"',
        b'"exception_text"',
        b'"raw_payload"',
        b'"payload_excerpt"',
    )
    if any(token in serialized_public_bundle for token in prohibited_public_tokens):
        raise EvidenceValidationError(
            "Gate B public campaign artifacts contain prohibited ephemeral content."
        )
    serialized_record = json.dumps(record, sort_keys=True).encode("utf-8")
    if any(token in serialized_record for token in prohibited_public_tokens):
        raise EvidenceValidationError(
            "Gate B evidence record contains prohibited ephemeral content."
        )

    scope = record["evaluation_scope"]
    budget = record["budget"]
    result = record["results"]
    if (
        record.get("claim_class") != "CONTROLLED_BEHAVIOR"
        or record.get("claim_status") != "OBSERVED"
        or scope.get("data_origin") != "SYNTHETIC_FIXTURE"
        or scope.get("historical_case_count") != 0
        or scope.get("case_count") != 0
        or scope.get("adjudicated_case_count") != 0
        or scope.get("time_window")
        != f"One fixed deterministic campaign recorded at {evaluated_at}."
        or scope.get("network_access") is not True
        or scope.get("action_credentials_present") is not False
        or budget.get("evaluation_runs") != 2
        or budget.get("case_evaluations") != 0
        or budget.get("retries") != 0
        or (
            result["denominator"],
            result["passed"],
            result["failed"],
            result["excluded"],
        )
        != (32, 32, 0, 0)
        or record.get("supported_wording") != GATE_B_SUPPORTED_WORDING
        or record.get("review", {}).get("review_type") != "SELF"
        or record.get("review", {}).get("reviewer_role")
        != "automated project-controlled evidence self-check"
    ):
        raise EvidenceValidationError(
            "Gate B evidence record does not preserve the exact CE-2 reporting boundary."
        )
    runtime = campaign_profile["runtime_fingerprint"]
    expected_dependency_access = (
        "Bound evaluation runtime: "
        f"{runtime['python_implementation']} {runtime['python_version']}; "
        f"jsonschema {runtime['jsonschema_version']}; "
        f"NumPy {runtime['numpy_version']}; "
        f"{runtime['platform_system']} {runtime['platform_release']} "
        f"{runtime['platform_machine']}. Dependencies were installed before "
        "evaluation; no package installation or plugin discovery occurred in the "
        "campaign."
    )
    if (
        record.get("evaluation_environment", {}).get("dependency_access")
        != expected_dependency_access
    ):
        raise EvidenceValidationError(
            "Gate B evidence record does not bind the recorded evaluation runtime."
        )
    result_metrics = result["metrics"]
    exact_metrics = {
        "unique_scenarios": 16,
        "evaluation_runs": 2,
        "total_attempt_executions": 32,
        "byte_identical_result_ledgers": True,
        "pass_test_only": 2,
        "blocked_prepayload": 28,
        "blocked_postqualification_preengine": 2,
        "prepayload_attempts_with_payload_access": 0,
        "engine_calls": 0,
        "authorization_attempts": 0,
        "authorization_tokens_issued": 0,
        "broker_invocations": 0,
        "target_effect_calls": 0,
        "action_results": 0,
        "operational_effects": 0,
        "completed_run_manifests": 0,
        "decision_artifacts": 0,
        "audit_artifacts": 0,
        "historical_case_count": 0,
    }
    if result_metrics != exact_metrics:
        raise EvidenceValidationError("Gate B evidence-record metrics are not exact.")
    strata = result.get("strata")
    if strata != [
        {
            "name": "RUN_1",
            "denominator": 16,
            "passed": 16,
            "failed": 0,
            "excluded": 0,
        },
        {
            "name": "RUN_2",
            "denominator": 16,
            "passed": 16,
            "failed": 0,
            "excluded": 0,
        },
    ]:
        raise EvidenceValidationError("Gate B evidence strata do not reconcile.")
    model_binding = next(row for row in bindings if row["role"] == "MODEL")
    policy_binding = next(row for row in bindings if row["role"] == "POLICY")
    if record["system_under_test"].get("model") != {
        "path": model_binding["path"],
        "sha256": model_binding["sha256"],
    } or record["system_under_test"].get("policy") != {
        "path": policy_binding["path"],
        "sha256": policy_binding["sha256"],
    }:
        raise EvidenceValidationError(
            "Gate B evidence model or policy binding drifted."
        )
    prohibited = " ".join(record.get("prohibited_inferences", [])).lower()
    for phrase in (
        "real organizational",
        "de-identification",
        "historical data",
        "zero governed payload reads",
        "production ready",
        "agentic misalignment",
        "zero risk",
        "independent replication",
    ):
        if phrase not in prohibited:
            raise EvidenceValidationError(
                "Gate B evidence record omits a required prohibited inference."
            )
    return {
        "status": "VALID",
        "profile_id": profile.claim_id,
        "claim_id": record["claim_id"],
        "claim_class": record["claim_class"],
        "data_origin": scope["data_origin"],
        "historical_case_count": scope["historical_case_count"],
        "artifact_count": len(artifacts),
        "audit_record_count": 0,
        "implementation_commit": implementation_commit,
        "result": profile.result_summary,
        "campaign_outcomes": {
            "unique_scenarios": 16,
            "evaluation_runs": 2,
            "denominator": 32,
            "pass_test_only": 2,
            "blocked_prepayload": 28,
            "blocked_postqualification_preengine": 2,
            "byte_identical_result_ledgers": True,
        },
    }


def _validate_feature_assurance_campaign_evidence(
    record: dict[str, Any],
    artifacts: dict[str, Path],
    profile: EvidenceValidationProfile,
    repository_root: Path,
) -> dict[str, Any]:
    """Validate the exact commit-bound P2-CE-004 CE-2 campaign bundle."""

    exact_roles = {
        "campaign_profile",
        "campaign_results_run1",
        "campaign_results_run2",
        "campaign_summary",
        "campaign_plan",
        "campaign_schema",
    }
    if set(artifacts) != exact_roles:
        raise EvidenceValidationError(
            "Feature-assurance campaign evidence does not contain the exact six roles."
        )
    if artifacts["campaign_schema"] != FEATURE_ASSURANCE_CAMPAIGN_SCHEMA.resolve():
        raise EvidenceValidationError(
            "Feature-assurance evidence does not bind the canonical campaign schema."
        )
    if artifacts["campaign_plan"] != FEATURE_ASSURANCE_CAMPAIGN_PLAN.resolve():
        raise EvidenceValidationError(
            "Feature-assurance evidence does not bind the canonical campaign plan."
        )
    for role, path in artifacts.items():
        maximum = (
            512 * 1024
            if role == "campaign_schema"
            else FEATURE_ASSURANCE_CAMPAIGN_MAX_BYTES
        )
        try:
            size = path.stat().st_size
        except OSError:
            raise EvidenceValidationError(
                "Feature-assurance campaign artifact is unavailable."
            ) from None
        if size > maximum:
            raise EvidenceValidationError(
                "Feature-assurance campaign artifact exceeds its public size bound."
            )

    schema = _load_json(artifacts["campaign_schema"])
    try:
        Draft202012Validator.check_schema(schema)
    except Exception:
        raise EvidenceValidationError(
            "Feature-assurance campaign schema is invalid."
        ) from None
    validator = Draft202012Validator(schema)

    def validate_closed(value: dict[str, Any], label: str) -> None:
        errors = sorted(validator.iter_errors(value), key=lambda item: list(item.path))
        if errors:
            location = ".".join(str(part) for part in errors[0].absolute_path) or "$"
            raise EvidenceValidationError(
                f"{label} violates the closed feature-assurance schema at {location}."
            )

    plan = _load_json(FEATURE_ASSURANCE_CAMPAIGN_PLAN)
    campaign_profile = _load_json(artifacts["campaign_profile"])
    results_run1 = _read_jsonl(artifacts["campaign_results_run1"])
    results_run2 = _read_jsonl(artifacts["campaign_results_run2"])
    campaign_summary = _load_json(artifacts["campaign_summary"])
    validate_closed(plan, "Campaign plan")
    validate_closed(campaign_profile, "Campaign profile")
    validate_closed(campaign_summary, "Campaign summary")
    for row in results_run1 + results_run2:
        validate_closed(row, "Campaign result")

    if (
        campaign_profile.get("campaign_id") != FEATURE_ASSURANCE_CAMPAIGN_ID
        or campaign_profile.get("claim_id") != profile.claim_id
        or campaign_profile.get("campaign_seed") != FEATURE_ASSURANCE_CAMPAIGN_SEED
        or campaign_profile.get("campaign_plan_sha256")
        != _sha256(FEATURE_ASSURANCE_CAMPAIGN_PLAN)
        or campaign_profile.get("design") != plan.get("design")
        or campaign_profile.get("configuration_binding")
        != plan.get("configuration_binding")
        or campaign_profile.get("budget") != plan.get("budget")
        or campaign_profile.get("expected_attempts") != plan.get("expected_attempts")
        or campaign_summary.get("runtime_fingerprint")
        != campaign_profile.get("runtime_fingerprint")
    ):
        raise EvidenceValidationError(
            "Feature-assurance profile does not exactly bind the frozen plan."
        )
    exact_design = {
        "actual_historical_records": 0,
        "attempt_order_frozen": True,
        "data_origin": "SYNTHETIC_FIXTURE",
        "execution_authority": "NONE",
        "failure_policy": "ABORT_WITHOUT_EVIDENCE_NO_RETRY",
        "input_authorization": "FIXED_GENERATED_SCENARIOS_ONLY",
        "network_capability_status": "UNVERIFIED_AVAILABLE_CAPABILITY",
        "output_authorization": "SANITIZED_ENUMERATED_METADATA_ONLY",
        "result_capture": "NO_RAW_CASE_OR_PROJECTION_CONTENT",
        "stored_approval_package": False,
        "stored_historical_data": False,
    }
    if campaign_profile.get("design") != exact_design:
        raise EvidenceValidationError(
            "Feature-assurance campaign origin and authority boundary is not exact."
        )
    exact_configuration = {
        "campaign_mode": "SYNTHETIC_FEATURE_ASSURANCE",
        "decision_engine_enabled": False,
        "live_actions_enabled": False,
        "projection_authority": "READ_ONLY_LOCAL_COMPARISON",
        "qualification_api": "qualify_case_bytes",
        "reference_projection_api": "verify_reference_feature_projections",
        "schema_version": "0.2.0",
        "zero_effects_required": True,
    }
    if (
        campaign_profile.get("configuration_binding", {}).get("configuration")
        != exact_configuration
    ):
        raise EvidenceValidationError(
            "Feature-assurance campaign configuration is not fail-closed."
        )

    implementation_commit = campaign_profile.get("implementation_commit")
    if not isinstance(implementation_commit, str) or not re.fullmatch(
        r"[0-9a-f]{40}", implementation_commit
    ):
        raise EvidenceValidationError(
            "Feature-assurance campaign lacks an exact implementation commit."
        )
    evaluated_at = campaign_profile.get("evaluated_at")
    if (
        not isinstance(evaluated_at, str)
        or not re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z", evaluated_at)
        or campaign_summary.get("evaluated_at") != evaluated_at
        or record.get("evaluated_at") != evaluated_at
        or record.get("review", {}).get("reviewed_at") != evaluated_at
    ):
        raise EvidenceValidationError(
            "Feature-assurance evaluation timestamp binding is not exact."
        )
    try:
        evaluated_time = datetime.fromisoformat(
            evaluated_at[:-1] + "+00:00"
        ).astimezone(timezone.utc)
    except ValueError:
        raise EvidenceValidationError(
            "Feature-assurance evaluation timestamp is invalid."
        ) from None
    if evaluated_time > datetime.now(timezone.utc) + timedelta(minutes=5):
        raise EvidenceValidationError(
            "Feature-assurance evaluation timestamp is later than validation time."
        )
    if evaluated_time < _git_commit_timestamp(
        repository_root, commit=implementation_commit
    ):
        raise EvidenceValidationError(
            "Feature-assurance evaluation predates its implementation commit."
        )
    expected_expiry = (
        (evaluated_time + timedelta(days=90)).isoformat().replace("+00:00", "Z")
    )
    if record.get("review", {}).get("claim_expires_at") != expected_expiry:
        raise EvidenceValidationError(
            "Feature-assurance claim expiry is not derived from evaluation time."
        )

    source_reference = str(record["system_under_test"].get("source_reference", ""))
    commit_url = (
        "https://github.com/redxking/ai-decision-firewall/commit/"
        + implementation_commit
    )
    referenced_commits = set(
        re.findall(r"(?<![0-9a-f])[0-9a-f]{40}(?![0-9a-f])", source_reference)
    )
    if (
        f"Git commit {implementation_commit} " not in source_reference
        or commit_url not in source_reference
        or referenced_commits != {implementation_commit}
    ):
        raise EvidenceValidationError(
            "Feature-assurance source_reference does not bind one exact commit."
        )

    bindings = campaign_profile.get("source_bindings")
    if not isinstance(bindings, list) or len(bindings) != len(
        FEATURE_ASSURANCE_CAMPAIGN_SOURCE_PATHS
    ):
        raise EvidenceValidationError(
            "Feature-assurance source-binding count is invalid."
        )
    bound_roles: set[str] = set()
    for binding in bindings:
        role = str(binding.get("role"))
        if role in bound_roles or role not in FEATURE_ASSURANCE_CAMPAIGN_SOURCE_PATHS:
            raise EvidenceValidationError(
                "Feature-assurance source-binding role set is invalid."
            )
        bound_roles.add(role)
        relative = FEATURE_ASSURANCE_CAMPAIGN_SOURCE_PATHS[role]
        if binding.get("path") != relative:
            raise EvidenceValidationError(
                "Feature-assurance source-binding path is not canonical."
            )
        current = _confined_path(repository_root, relative)
        digest = binding.get("sha256")
        if digest != _sha256(current) or digest != _git_blob_digest(
            repository_root,
            commit=implementation_commit,
            relative_path=relative,
        ):
            raise EvidenceValidationError(
                "Feature-assurance sources do not match the implementation commit."
            )
    if bound_roles != set(FEATURE_ASSURANCE_CAMPAIGN_SOURCE_PATHS):
        raise EvidenceValidationError(
            "Feature-assurance source-binding roles are incomplete."
        )

    if len(campaign_profile.get("expected_attempts", [])) != 16 or any(
        len(rows) != 16 for rows in (results_run1, results_run2)
    ):
        raise EvidenceValidationError(
            "Feature-assurance evidence must contain two complete 16-attempt runs."
        )

    # Re-execute the frozen evaluator.  This rejects a coherent rewrite of both
    # ledgers plus summary hashes; ledger agreement alone is not sufficient.
    try:
        from scripts.generate_feature_assurance_ce2_campaign import (
            _jsonl_bytes as feature_jsonl_bytes,
            build_summary as build_feature_summary,
            run_campaign as run_feature_campaign,
        )

        recomputed_run1 = run_feature_campaign(campaign_profile)
        recomputed_run2 = run_feature_campaign(campaign_profile)
        recomputed_run1_bytes = feature_jsonl_bytes(recomputed_run1)
        recomputed_run2_bytes = feature_jsonl_bytes(recomputed_run2)
    except Exception as exc:
        raise EvidenceValidationError(
            "Feature-assurance campaign could not be freshly re-executed."
        ) from exc
    committed_profile_bytes = artifacts["campaign_profile"].read_bytes()
    committed_run1_bytes = artifacts["campaign_results_run1"].read_bytes()
    committed_run2_bytes = artifacts["campaign_results_run2"].read_bytes()
    if (
        committed_run1_bytes != recomputed_run1_bytes
        or committed_run2_bytes != recomputed_run2_bytes
        or committed_run1_bytes != committed_run2_bytes
    ):
        raise EvidenceValidationError(
            "Feature-assurance ledgers do not match fresh frozen-plan execution."
        )
    recomputed_summary = build_feature_summary(
        committed_profile_bytes,
        committed_run1_bytes,
        committed_run2_bytes,
        recomputed_run1,
        recomputed_run2,
        evaluated_at=evaluated_at,
    )
    if campaign_summary != recomputed_summary:
        raise EvidenceValidationError(
            "Feature-assurance summary does not exactly recompute from the ledgers."
        )

    public_bundle = b"\n".join(
        (
            committed_profile_bytes,
            committed_run1_bytes,
            committed_run2_bytes,
            artifacts["campaign_summary"].read_bytes(),
        )
    )
    prohibited_tokens = (
        b'"case_id"',
        b'"events"',
        b'"feature_trace"',
        b'"feature_values"',
        b'"subject_id"',
        b'"untrusted_text"',
        b'"raw_payload"',
        b'"exception_text"',
    )
    if any(token in public_bundle for token in prohibited_tokens):
        raise EvidenceValidationError(
            "Feature-assurance public artifacts contain prohibited raw content."
        )

    scope = record["evaluation_scope"]
    budget = record["budget"]
    result = record["results"]
    if (
        record.get("claim_class") != "CONTROLLED_BEHAVIOR"
        or record.get("claim_status") != "OBSERVED"
        or scope.get("data_origin") != "SYNTHETIC_FIXTURE"
        or scope.get("historical_case_count") != 0
        or scope.get("case_count") != 32
        or scope.get("adjudicated_case_count") != 0
        or scope.get("network_access") is not True
        or scope.get("action_credentials_present") is not False
        or budget.get("evaluation_runs") != 2
        or budget.get("case_evaluations") != 32
        or budget.get("retries") != 0
        or (
            result.get("denominator"),
            result.get("passed"),
            result.get("failed"),
            result.get("excluded"),
        )
        != (32, 32, 0, 0)
        or record.get("supported_wording") != FEATURE_ASSURANCE_SUPPORTED_WORDING
        or record.get("review", {}).get("review_type") != "SELF"
        or record.get("review", {}).get("reviewer_role")
        != "automated project-controlled evidence self-check"
    ):
        raise EvidenceValidationError(
            "Feature-assurance record does not preserve its exact CE-2 boundary."
        )
    runtime = campaign_profile["runtime_fingerprint"]
    expected_dependency_access = (
        "Bound evaluation runtime: "
        f"{runtime['python_implementation']} {runtime['python_version']}; "
        f"jsonschema {runtime['jsonschema_version']}; "
        f"NumPy {runtime['numpy_version']}; "
        f"{runtime['platform_system']} {runtime['platform_release']} "
        f"{runtime['platform_machine']}. Dependencies were installed before "
        "evaluation; no package installation or plugin discovery occurred."
    )
    if (
        record.get("evaluation_environment", {}).get("dependency_access")
        != expected_dependency_access
    ):
        raise EvidenceValidationError(
            "Feature-assurance record does not bind the sanitized runtime."
        )

    exact_metrics = {
        "unique_scenarios": 16,
        "evaluation_runs": 2,
        "total_attempt_executions": 32,
        "byte_identical_result_ledgers": True,
        "clean_projection_matches": 16,
        "qualification_quarantines": 8,
        "reference_projection_blocks": 8,
        "qualification_calls": 32,
        "qualification_input_records": 32,
        "qualification_accepted_records": 24,
        "qualification_rejected_records": 8,
        "production_projector_calls": 24,
        "reference_projector_calls": 24,
        "local_rehashes": 8,
        "model_calls": 0,
        "policy_calls": 0,
        "verifier_calls": 0,
        "engine_calls": 0,
        "authorization_attempts": 0,
        "broker_invocations": 0,
        "target_effect_calls": 0,
        "operational_effects": 0,
        "decision_artifact_write_calls": 0,
        "audit_artifact_write_calls": 0,
        "run_manifest_write_calls": 0,
        "historical_case_count": 0,
    }
    if result.get("metrics") != exact_metrics:
        raise EvidenceValidationError(
            "Feature-assurance evidence metrics are not exact."
        )
    if result.get("strata") != [
        {"name": "RUN_1", "denominator": 16, "passed": 16, "failed": 0, "excluded": 0},
        {"name": "RUN_2", "denominator": 16, "passed": 16, "failed": 0, "excluded": 0},
    ]:
        raise EvidenceValidationError(
            "Feature-assurance result strata do not reconcile."
        )

    bindings_by_role = {row["role"]: row for row in bindings}
    production = bindings_by_role["ADF_SRC_ADF_POC_FEATURES_PY"]
    reference = bindings_by_role["ADF_SRC_ADF_POC_REPLAY_REFERENCE_FEATURES_PY"]
    if record["system_under_test"].get("model") != {
        "path": production["path"],
        "sha256": production["sha256"],
    } or record["system_under_test"].get("policy") != {
        "path": reference["path"],
        "sha256": reference["sha256"],
    }:
        raise EvidenceValidationError(
            "Feature-assurance record projector bindings drifted."
        )

    prohibited = " ".join(record.get("prohibited_inferences", [])).lower()
    for phrase in (
        "historical or live",
        "approval",
        "privacy",
        "os-level",
        "network nonuse",
        "production ready",
        "agentic misalignment",
        "zero risk",
        "independent replication",
        "exhaustive",
        "statistical",
    ):
        if phrase not in prohibited:
            raise EvidenceValidationError(
                "Feature-assurance record omits a required prohibited inference."
            )

    return {
        "status": "VALID",
        "profile_id": profile.claim_id,
        "claim_id": record["claim_id"],
        "claim_class": record["claim_class"],
        "data_origin": scope["data_origin"],
        "historical_case_count": 0,
        "artifact_count": len(artifacts),
        "audit_record_count": 0,
        "implementation_commit": implementation_commit,
        "result": profile.result_summary,
        "campaign_outcomes": {
            "unique_scenarios": 16,
            "evaluation_runs": 2,
            "denominator": 32,
            "clean_projection_matches": 16,
            "qualification_quarantines": 8,
            "reference_projection_blocks": 8,
            "byte_identical_result_ledgers": True,
        },
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
    if profile.profile_kind == "GATE_B_CAMPAIGN":
        return _validate_gate_b_campaign_evidence(
            record,
            artifacts,
            profile,
            repository_root,
        )
    if profile.profile_kind == "FEATURE_ASSURANCE_CAMPAIGN":
        return _validate_feature_assurance_campaign_evidence(
            record,
            artifacts,
            profile,
            repository_root,
        )
    record_resolved = record_path.resolve()
    legacy_digest = LEGACY_REPLAY_RECORD_FINGERPRINTS.get(record_resolved)
    exact_legacy_replay_record = (
        legacy_digest is not None
        and profile.claim_id in {"P2-CE-001", "P2-CE-002"}
        and _sha256(record_resolved) == legacy_digest
    )
    if (
        "reference_feature_assurance" not in artifacts
        and not exact_legacy_replay_record
    ):
        raise EvidenceValidationError(
            "Nonlegacy replay evidence requires reference_feature_assurance."
        )
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
