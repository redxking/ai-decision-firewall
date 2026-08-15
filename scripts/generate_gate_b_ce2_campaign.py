from __future__ import annotations

import argparse
import copy
import hashlib
import importlib.metadata
import json
import os
import platform
import re
import shutil
import subprocess
import sys
import tempfile
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Callable, Iterator
from unittest.mock import patch

from jsonschema import Draft202012Validator


ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from adf_poc.replay import ReplayHarness  # noqa: E402
from adf_poc.actions import (  # noqa: E402
    ActionBroker,
    AuthorizationGate,
    SimulatedIdentityProvider,
)
from adf_poc.replay.gate_b import (  # noqa: E402
    GateBStopConditionViolation,
    GateBValidationError,
)
from adf_poc.replay.contracts import sha256_file  # noqa: E402


CAMPAIGN_ID = "P2-CE-003-GATE-B-SYNTHETIC"
CLAIM_ID = "P2-CE-003"
CAMPAIGN_SCHEMA_VERSION = "1.0.0"
CAMPAIGN_SEED = 20260814
CAMPAIGN_SCHEMA = ROOT / "contracts/v0.2.0/gate-b-ce2-campaign.schema.json"
CAMPAIGN_PLAN = ROOT / "config/gate_b_ce2_campaign_plan.json"
EVIDENCE_SCHEMA = ROOT / "contracts/v0.2.0/evaluation-evidence.schema.json"
EVIDENCE_TEMPLATE = (
    ROOT / "contracts/v0.2.0/examples/phase2-qualification-evidence-record.json"
)
DEFAULT_OUTPUT_DIR = ROOT / "evidence/phase2_gate_b_ce2"
DEFAULT_RECORD_PATH = (
    ROOT / "contracts/v0.2.0/examples/phase2-gate-b-ce2-evidence-record.json"
)
IMPLEMENTATION_COMMIT_PATTERN = re.compile(r"^[0-9a-f]{40}$")
CANONICAL_UTC_PATTERN = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")
SENSITIVE_CANARY = "P2-CE-003-EPHEMERAL-AUTHORIZATION-CANARY"


class CampaignGenerationError(RuntimeError):
    """Raised when the fixed campaign cannot produce its commit-frozen result."""


class _DuplicateJSONMember(ValueError):
    """Internal marker for ambiguous generated-control JSON."""


def _reject_duplicate_json_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, child in pairs:
        if key in value:
            raise _DuplicateJSONMember
        value[key] = child
    return value


FIXTURE_CONFIGURATION: dict[str, Any] = {
    "schema_version": "0.2.0",
    "execution_mode": "HISTORICAL_REPLAY",
    "live_actions_enabled": False,
    "dataset_manifest": "data/campaign/manifest.json",
    "model_path": "outputs/baseline/model.json",
    "policy_path": "config/policy.json",
    "output_dir": "outputs/replay/gate_b_ce2_campaign",
    "contract_adapter": "canonical_jsonl_v0.2",
    "deterministic_outputs": True,
    "zero_effects_required": True,
    "record_failure_policy": "QUARANTINE_RECORD",
    "gate_b_authorization": "local/gate_b/gate_b_authorization.json",
}


EXPECTED_ATTEMPTS: tuple[dict[str, Any], ...] = (
    {
        "sequence": 1,
        "attempt_id": "GB-POS-001",
        "fixture": "STARTER_VALID",
        "operation": "VALIDATE_ONLY",
        "mutation_id": "NONE",
        "expected_outcome": "PASS_TEST_ONLY",
        "expected_error_class": "NONE",
        "expected_accessed_payload_roles": ["adjudications", "cases"],
    },
    {
        "sequence": 2,
        "attempt_id": "GB-NEG-001",
        "fixture": "STARTER_VALID",
        "operation": "RUN",
        "mutation_id": "STATUS_DRAFT",
        "expected_outcome": "BLOCKED_PREPAYLOAD",
        "expected_error_class": "GateBValidationError",
        "expected_accessed_payload_roles": [],
    },
    {
        "sequence": 3,
        "attempt_id": "GB-NEG-002",
        "fixture": "STARTER_VALID",
        "operation": "RUN",
        "mutation_id": "MISSING_APPROVAL_ROLE",
        "expected_outcome": "BLOCKED_PREPAYLOAD",
        "expected_error_class": "GateBValidationError",
        "expected_accessed_payload_roles": [],
    },
    {
        "sequence": 4,
        "attempt_id": "GB-NEG-003",
        "fixture": "STARTER_VALID",
        "operation": "RUN",
        "mutation_id": "DUPLICATE_APPROVAL_ROLE",
        "expected_outcome": "BLOCKED_PREPAYLOAD",
        "expected_error_class": "GateBValidationError",
        "expected_accessed_payload_roles": [],
    },
    {
        "sequence": 5,
        "attempt_id": "GB-NEG-004",
        "fixture": "STARTER_VALID",
        "operation": "RUN",
        "mutation_id": "MANIFEST_DIGEST_MISMATCH",
        "expected_outcome": "BLOCKED_PREPAYLOAD",
        "expected_error_class": "GateBValidationError",
        "expected_accessed_payload_roles": [],
    },
    {
        "sequence": 6,
        "attempt_id": "GB-NEG-005",
        "fixture": "STARTER_VALID",
        "operation": "RUN",
        "mutation_id": "MODEL_DIGEST_MISMATCH",
        "expected_outcome": "BLOCKED_PREPAYLOAD",
        "expected_error_class": "GateBValidationError",
        "expected_accessed_payload_roles": [],
    },
    {
        "sequence": 7,
        "attempt_id": "GB-NEG-006",
        "fixture": "STARTER_VALID",
        "operation": "RUN",
        "mutation_id": "POLICY_DIGEST_MISMATCH",
        "expected_outcome": "BLOCKED_PREPAYLOAD",
        "expected_error_class": "GateBValidationError",
        "expected_accessed_payload_roles": [],
    },
    {
        "sequence": 8,
        "attempt_id": "GB-NEG-007",
        "fixture": "STARTER_VALID",
        "operation": "RUN",
        "mutation_id": "CONTROL_ARTIFACT_DIGEST_MISMATCH",
        "expected_outcome": "BLOCKED_PREPAYLOAD",
        "expected_error_class": "GateBValidationError",
        "expected_accessed_payload_roles": [],
    },
    {
        "sequence": 9,
        "attempt_id": "GB-NEG-008",
        "fixture": "STARTER_VALID",
        "operation": "RUN",
        "mutation_id": "ACTION_CREDENTIALS_PRESENT",
        "expected_outcome": "BLOCKED_PREPAYLOAD",
        "expected_error_class": "GateBValidationError",
        "expected_accessed_payload_roles": [],
    },
    {
        "sequence": 10,
        "attempt_id": "GB-NEG-009",
        "fixture": "STARTER_VALID",
        "operation": "RUN",
        "mutation_id": "LIVE_FEED_CONNECTED",
        "expected_outcome": "BLOCKED_PREPAYLOAD",
        "expected_error_class": "GateBValidationError",
        "expected_accessed_payload_roles": [],
    },
    {
        "sequence": 11,
        "attempt_id": "GB-NEG-010",
        "fixture": "STARTER_VALID",
        "operation": "RUN",
        "mutation_id": "WRITE_CONNECTOR_PRESENT",
        "expected_outcome": "BLOCKED_PREPAYLOAD",
        "expected_error_class": "GateBValidationError",
        "expected_accessed_payload_roles": [],
    },
    {
        "sequence": 12,
        "attempt_id": "GB-NEG-011",
        "fixture": "STARTER_VALID",
        "operation": "RUN",
        "mutation_id": "NETWORK_EGRESS_ENABLED",
        "expected_outcome": "BLOCKED_PREPAYLOAD",
        "expected_error_class": "GateBValidationError",
        "expected_accessed_payload_roles": [],
    },
    {
        "sequence": 13,
        "attempt_id": "GB-NEG-012",
        "fixture": "STARTER_VALID",
        "operation": "RUN",
        "mutation_id": "AUTHORIZATION_EXPIRED",
        "expected_outcome": "BLOCKED_PREPAYLOAD",
        "expected_error_class": "GateBValidationError",
        "expected_accessed_payload_roles": [],
    },
    {
        "sequence": 14,
        "attempt_id": "GB-NEG-013",
        "fixture": "STARTER_VALID",
        "operation": "RUN",
        "mutation_id": "REVIEWER_NOT_INDEPENDENT",
        "expected_outcome": "BLOCKED_PREPAYLOAD",
        "expected_error_class": "GateBValidationError",
        "expected_accessed_payload_roles": [],
    },
    {
        "sequence": 15,
        "attempt_id": "GB-NEG-014",
        "fixture": "STARTER_VALID",
        "operation": "RUN",
        "mutation_id": "CUSTODY_FREEZE_PREDATES_WINDOW",
        "expected_outcome": "BLOCKED_PREPAYLOAD",
        "expected_error_class": "GateBValidationError",
        "expected_accessed_payload_roles": [],
    },
    {
        "sequence": 16,
        "attempt_id": "GB-NEG-015",
        "fixture": "QUALIFICATION_THRESHOLD",
        "operation": "RUN",
        "mutation_id": "QUARANTINE_THRESHOLD_EXCEEDED",
        "expected_outcome": "BLOCKED_POSTQUALIFICATION_PREENGINE",
        "expected_error_class": "GateBStopConditionViolation",
        "expected_accessed_payload_roles": ["adjudications", "cases"],
    },
)


SOURCE_BINDING_PATHS: tuple[tuple[str, str], ...] = (
    ("CAMPAIGN_GENERATOR", "scripts/generate_gate_b_ce2_campaign.py"),
    ("CAMPAIGN_PLAN", "config/gate_b_ce2_campaign_plan.json"),
    ("CAMPAIGN_SCHEMA", "contracts/v0.2.0/gate-b-ce2-campaign.schema.json"),
    ("CLAIM_VALIDATOR", "scripts/validate_claim_evidence.py"),
    ("GATE_B_IMPLEMENTATION", "src/adf_poc/replay/gate_b.py"),
    ("REPLAY_CONTRACTS_IMPLEMENTATION", "src/adf_poc/replay/contracts.py"),
    ("REPLAY_HARNESS_IMPLEMENTATION", "src/adf_poc/replay/harness.py"),
    (
        "GATE_B_AUTHORIZATION_SCHEMA",
        "contracts/v0.2.0/gate-b-authorization.schema.json",
    ),
    ("STARTER_MANIFEST", "data/phase2_starter/manifest.json"),
    ("STARTER_CASES", "data/phase2_starter/cases.jsonl"),
    ("STARTER_ADJUDICATIONS", "data/phase2_starter/adjudications.jsonl"),
    ("QUALIFICATION_MANIFEST", "data/phase2_qualification/manifest.json"),
    ("QUALIFICATION_CASES", "data/phase2_qualification/cases.jsonl"),
    (
        "QUALIFICATION_ADJUDICATIONS",
        "data/phase2_qualification/adjudications.jsonl",
    ),
    ("MODEL", "outputs/baseline/model.json"),
    ("POLICY", "config/policy.json"),
)


def _json_bytes(value: Any) -> bytes:
    return (json.dumps(value, indent=2, sort_keys=True) + "\n").encode("utf-8")


def _jsonl_bytes(rows: list[dict[str, Any]]) -> bytes:
    return "".join(
        json.dumps(row, separators=(",", ":"), sort_keys=True) + "\n" for row in rows
    ).encode("utf-8")


def _canonical_digest(value: Any) -> str:
    payload = json.dumps(value, separators=(",", ":"), sort_keys=True).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def _canonical_utc(value: str) -> datetime:
    if not CANONICAL_UTC_PATTERN.fullmatch(value):
        raise CampaignGenerationError(
            "--evaluated-at must use canonical UTC form YYYY-MM-DDTHH:MM:SSZ."
        )
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError:
        raise CampaignGenerationError(
            "--evaluated-at is not a valid timestamp."
        ) from None
    parsed = parsed.astimezone(timezone.utc)
    if parsed > datetime.now(timezone.utc) + timedelta(minutes=5):
        raise CampaignGenerationError(
            "--evaluated-at cannot be later than the current clock plus five minutes."
        )
    return parsed


def _sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _write_bytes(path: Path, payload: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(payload)


def _write_json(path: Path, value: Any) -> None:
    _write_bytes(path, _json_bytes(value))


def _load_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(
            path.read_text(encoding="utf-8"),
            object_pairs_hook=_reject_duplicate_json_pairs,
        )
    except (OSError, UnicodeError, json.JSONDecodeError, _DuplicateJSONMember):
        raise CampaignGenerationError(
            "Campaign control JSON is unavailable or ambiguous."
        ) from None
    if not isinstance(value, dict):
        raise CampaignGenerationError(f"Expected an object in {path}.")
    return value


def _source_bindings() -> list[dict[str, str]]:
    bindings: list[dict[str, str]] = []
    for role, relative in SOURCE_BINDING_PATHS:
        path = ROOT / relative
        if not path.is_file():
            raise CampaignGenerationError(
                f"Missing required campaign source: {relative}"
            )
        bindings.append({"role": role, "path": relative, "sha256": sha256_file(path)})
    return bindings


def _runtime_fingerprint() -> dict[str, str]:
    """Return the sanitized interpreter and library identity used for evaluation."""

    try:
        jsonschema_version = importlib.metadata.version("jsonschema")
        numpy_version = importlib.metadata.version("numpy")
    except importlib.metadata.PackageNotFoundError:
        raise CampaignGenerationError(
            "Required campaign dependency metadata is unavailable."
        ) from None
    return {
        "python_implementation": platform.python_implementation(),
        "python_version": platform.python_version(),
        "jsonschema_version": jsonschema_version,
        "numpy_version": numpy_version,
        "platform_system": platform.system(),
        "platform_release": platform.release(),
        "platform_machine": platform.machine(),
    }


def _require_clean_generation_commit(implementation_commit: str) -> None:
    """Require evidence generation to start from the exact clean frozen commit."""

    try:
        head = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=ROOT,
            check=False,
            capture_output=True,
            text=True,
            timeout=10,
        )
        status = subprocess.run(
            ["git", "status", "--porcelain", "--untracked-files=all"],
            cwd=ROOT,
            check=False,
            capture_output=True,
            text=True,
            timeout=10,
        )
    except (OSError, subprocess.SubprocessError):
        raise CampaignGenerationError(
            "Campaign generation could not verify its Git checkout."
        ) from None
    if (
        head.returncode != 0
        or head.stdout.strip() != implementation_commit
        or status.returncode != 0
        or status.stdout.strip()
    ):
        raise CampaignGenerationError(
            "Campaign generation requires the exact clean implementation commit."
        )


def load_and_validate_plan() -> dict[str, Any]:
    plan = _load_json(CAMPAIGN_PLAN)
    _validate_campaign_artifact(plan)
    if (
        plan.get("configuration_binding", {}).get("configuration")
        != FIXTURE_CONFIGURATION
    ):
        raise CampaignGenerationError(
            "Campaign plan configuration is not the fixed configuration."
        )
    if plan["configuration_binding"]["canonical_sha256"] != _canonical_digest(
        FIXTURE_CONFIGURATION
    ):
        raise CampaignGenerationError("Campaign plan configuration digest is stale.")
    if plan.get("expected_attempts") != [
        copy.deepcopy(row) for row in EXPECTED_ATTEMPTS
    ]:
        raise CampaignGenerationError(
            "Campaign plan attempts do not match the code-owned registry."
        )
    expected_public_roles = {
        "STARTER_MANIFEST",
        "STARTER_CASES",
        "STARTER_ADJUDICATIONS",
        "QUALIFICATION_MANIFEST",
        "QUALIFICATION_CASES",
        "QUALIFICATION_ADJUDICATIONS",
        "MODEL",
        "POLICY",
    }
    observed_roles: set[str] = set()
    for binding in plan.get("public_input_bindings", []):
        role = str(binding.get("role"))
        if role in observed_roles:
            raise CampaignGenerationError(
                "Campaign plan contains a duplicate public-input role."
            )
        observed_roles.add(role)
        expected_path = dict(SOURCE_BINDING_PATHS).get(role)
        if expected_path is None or binding.get("path") != expected_path:
            raise CampaignGenerationError(
                "Campaign plan public-input path binding is invalid."
            )
        if sha256_file(ROOT / expected_path) != binding.get("sha256"):
            raise CampaignGenerationError("Campaign plan public-input digest is stale.")
    if observed_roles != expected_public_roles:
        raise CampaignGenerationError(
            "Campaign plan public-input role set is incomplete."
        )
    return plan


def build_profile(implementation_commit: str, evaluated_at: str) -> dict[str, Any]:
    if not IMPLEMENTATION_COMMIT_PATTERN.fullmatch(implementation_commit):
        raise CampaignGenerationError(
            "An exact lowercase 40-character implementation commit is required."
        )
    plan = load_and_validate_plan()
    _canonical_utc(evaluated_at)
    return {
        "artifact_kind": "CAMPAIGN_PROFILE",
        "schema_version": CAMPAIGN_SCHEMA_VERSION,
        "campaign_id": CAMPAIGN_ID,
        "claim_id": CLAIM_ID,
        "campaign_seed": CAMPAIGN_SEED,
        "implementation_commit": implementation_commit,
        "evaluated_at": evaluated_at,
        "campaign_plan_sha256": sha256_file(CAMPAIGN_PLAN),
        "runtime_fingerprint": _runtime_fingerprint(),
        "design": copy.deepcopy(plan["design"]),
        "source_bindings": _source_bindings(),
        "configuration_binding": copy.deepcopy(plan["configuration_binding"]),
        "budget": copy.deepcopy(plan["budget"]),
        "expected_attempts": copy.deepcopy(plan["expected_attempts"]),
    }


def _copy_fixture(repository_root: Path, fixture: str) -> tuple[Path, Path, Path]:
    source_name = (
        "phase2_starter" if fixture == "STARTER_VALID" else "phase2_qualification"
    )
    source = ROOT / "data" / source_name
    target = repository_root / "data/campaign"
    shutil.copytree(source, target)
    shutil.copytree(ROOT / "contracts", repository_root / "contracts")
    (repository_root / "config").mkdir(parents=True)
    (repository_root / "outputs/baseline").mkdir(parents=True)
    shutil.copyfile(ROOT / "config/policy.json", repository_root / "config/policy.json")
    shutil.copyfile(
        ROOT / "outputs/baseline/model.json",
        repository_root / "outputs/baseline/model.json",
    )

    manifest_path = target / "manifest.json"
    manifest = _load_json(manifest_path)
    case_count = next(
        int(entry["record_count"])
        for entry in manifest["files"]
        if entry["role"] == "cases"
    )
    manifest["data_origin"] = "HISTORICAL_DEIDENTIFIED"
    manifest["historical_case_count"] = case_count
    _write_json(manifest_path, manifest)

    config_path = repository_root / "config/campaign.json"
    _write_json(config_path, FIXTURE_CONFIGURATION)
    return manifest_path, target / "cases.jsonl", target / "adjudications.jsonl"


def _base_authorization(repository_root: Path, manifest_path: Path) -> dict[str, Any]:
    controls = repository_root / "local/gate_b"
    controls.mkdir(parents=True)
    artifact_paths = {
        "SOURCE_MAPPING": controls / "source_mapping.csv",
        "ADJUDICATION_PROTOCOL": controls / "adjudication_protocol.md",
        "PILOT_PROTOCOL": controls / "pilot_protocol.md",
    }
    artifact_paths["SOURCE_MAPPING"].write_text(
        "source_field,canonical_field\nsynthetic,synthetic\n", encoding="utf-8"
    )
    artifact_paths["ADJUDICATION_PROTOCOL"].write_text(
        "# Synthetic test-only adjudication protocol\n", encoding="utf-8"
    )
    artifact_paths["PILOT_PROTOCOL"].write_text(
        "# Synthetic test-only pilot protocol\n", encoding="utf-8"
    )
    manifest = _load_json(manifest_path)
    sample_count = int(manifest["historical_case_count"])
    model_path = repository_root / "outputs/baseline/model.json"
    policy_path = repository_root / "config/policy.json"
    return {
        "schema_version": "0.2.0",
        "authorization_id": "SYNTHETIC-TEST-ONLY-GATE-B",
        "status": "APPROVED",
        "dataset_id": manifest["dataset_id"],
        "dataset_manifest_sha256": sha256_file(manifest_path),
        "approved_purpose": f"Synthetic structural-control campaign only; {SENSITIVE_CANARY}.",
        "population_scope": "Project-controlled public synthetic fixture only.",
        "window_start": "2026-08-01T00:00:00Z",
        "window_end": "2026-08-02T00:00:00Z",
        "valid_from": "2026-08-10T00:00:00Z",
        "expires_at": "2099-01-01T00:00:00Z",
        "approvals": [
            {
                "role": role,
                "status": "APPROVED",
                "approver_id": f"synthetic-test-{role.lower()}",
                "approval_reference": f"synthetic-reference-{role.lower()}-{SENSITIVE_CANARY}",
                "approved_at": "2026-08-09T00:00:00Z",
            }
            for role in (
                "DATA_OWNER",
                "MISSION_OWNER",
                "SECURITY",
                "PRIVACY_LEGAL",
                "RECORDS_MANAGEMENT",
            )
        ],
        "artifact_bindings": {
            "contract_version": "0.2.0",
            "contract_adapter": "canonical_jsonl_v0.2",
            "model_sha256": sha256_file(model_path),
            "policy_sha256": sha256_file(policy_path),
            "artifacts": [
                {
                    "role": role,
                    "path": str(path.relative_to(repository_root)),
                    "sha256": sha256_file(path),
                }
                for role, path in artifact_paths.items()
            ],
        },
        "controls": {
            "deidentification_assessment_reference": "synthetic-test-assessment",
            "direct_identifiers_removed": True,
            "reidentification_risk_reviewed": True,
            "offline_only": True,
            "live_feed_connected": False,
            "action_credentials_present": False,
            "write_capable_connectors_present": False,
            "network_egress_disabled": True,
            "runtime_labels_separated": True,
            "complete_intake_reporting": True,
            "restricted_hash_handling": True,
            "retention_deletion_reference": "synthetic-test-retention",
            "incident_response_reference": "synthetic-test-incident",
            "isolation_reference": "synthetic-test-isolation",
            "kill_switch_reference": "synthetic-test-kill-switch",
        },
        "custody": {
            "snapshot_reference": "synthetic-test-snapshot",
            "custody_record_reference": "synthetic-test-custody",
            "external_manifest_digest_reference": "synthetic-test-external-digest",
            "frozen_at": "2026-08-09T00:00:00Z",
            "custodian_id": "synthetic-test-custodian",
        },
        "sampling": {
            "protocol_reference": "synthetic-test-sampling",
            "predeclared_at": "2026-08-09T00:00:00Z",
            "temporal_holdout_start": "2026-08-01T00:00:00Z",
            "temporal_holdout_end": "2026-08-01T23:59:59Z",
            "full_intake_count": sample_count,
            "sample_count": sample_count,
            "selection_method": "Complete fixed synthetic fixture.",
            "selection_frozen": True,
        },
        "stop_conditions": {
            "max_overall_quarantine_rate": 0,
            "max_category_quarantine_rates": [
                {"category": "SYNTAX", "max_rate": 0},
                {"category": "STRUCTURE", "max_rate": 0},
                {"category": "SEMANTICS", "max_rate": 0},
                {"category": "RESOURCE_LIMIT", "max_rate": 0},
            ],
            "stop_on_any_fatal": True,
            "stop_on_unknown_failure": True,
            "thresholds_frozen": True,
            "escalation_owner_id": "synthetic-test-escalation-owner",
        },
        "adjudication": {
            "protocol_reference": "synthetic-test-adjudication",
            "minimum_reviewers": 2,
            "runtime_separated": True,
            "labels_hidden_until_decision": True,
            "indeterminate_allowed": True,
            "disagreement_resolution": "Synthetic test-only majority rule.",
        },
        "independent_review": {
            "status": "APPROVED",
            "reviewer_id": "synthetic-test-reviewer",
            "review_reference": "synthetic-test-review",
            "reviewed_at": "2026-08-09T00:00:00Z",
        },
        "claim_control": {
            "claim_owner_id": "synthetic-test-claim-owner",
            "pause_authority_id": "synthetic-test-pause-owner",
            "revocation_authority_id": "synthetic-test-revocation-owner",
            "expires_at": "2099-01-01T00:00:00Z",
            "revalidation_triggers": [
                "Any bound source, model, policy, or protocol change",
                "Any incident or discovered validation gap",
            ],
        },
    }


def _apply_mutation(authorization: dict[str, Any], mutation_id: str) -> None:
    if mutation_id in {"NONE", "QUARANTINE_THRESHOLD_EXCEEDED"}:
        return
    if mutation_id == "STATUS_DRAFT":
        authorization["status"] = "DRAFT"
    elif mutation_id == "MISSING_APPROVAL_ROLE":
        authorization["approvals"].pop()
    elif mutation_id == "DUPLICATE_APPROVAL_ROLE":
        authorization["approvals"][-1]["role"] = authorization["approvals"][0]["role"]
    elif mutation_id == "MANIFEST_DIGEST_MISMATCH":
        authorization["dataset_manifest_sha256"] = "1" * 64
    elif mutation_id == "MODEL_DIGEST_MISMATCH":
        authorization["artifact_bindings"]["model_sha256"] = "1" * 64
    elif mutation_id == "POLICY_DIGEST_MISMATCH":
        authorization["artifact_bindings"]["policy_sha256"] = "1" * 64
    elif mutation_id == "CONTROL_ARTIFACT_DIGEST_MISMATCH":
        authorization["artifact_bindings"]["artifacts"][0]["sha256"] = "1" * 64
    elif mutation_id == "ACTION_CREDENTIALS_PRESENT":
        authorization["controls"]["action_credentials_present"] = True
    elif mutation_id == "LIVE_FEED_CONNECTED":
        authorization["controls"]["live_feed_connected"] = True
    elif mutation_id == "WRITE_CONNECTOR_PRESENT":
        authorization["controls"]["write_capable_connectors_present"] = True
    elif mutation_id == "NETWORK_EGRESS_ENABLED":
        authorization["controls"]["network_egress_disabled"] = False
    elif mutation_id == "AUTHORIZATION_EXPIRED":
        authorization["expires_at"] = "2026-08-14T00:00:00Z"
        authorization["claim_control"]["expires_at"] = "2026-08-14T00:00:00Z"
    elif mutation_id == "REVIEWER_NOT_INDEPENDENT":
        authorization["independent_review"]["reviewer_id"] = authorization["approvals"][
            0
        ]["approver_id"]
    elif mutation_id == "CUSTODY_FREEZE_PREDATES_WINDOW":
        authorization["custody"]["frozen_at"] = "2026-07-31T00:00:00Z"
    else:
        raise CampaignGenerationError(f"Unsupported mutation: {mutation_id}")


@contextmanager
def _observe_payload_roles(
    cases_path: Path,
    adjudications_path: Path,
) -> Iterator[set[str]]:
    governed = {
        cases_path.resolve(): "cases",
        adjudications_path.resolve(): "adjudications",
    }
    accessed: set[str] = set()
    original_os_open = os.open
    original_path_open = Path.open
    original_read_text = Path.read_text
    original_read_bytes = Path.read_bytes

    def observe(value: Any) -> None:
        try:
            resolved = Path(value).resolve()
        except (TypeError, ValueError, OSError):
            return
        role = governed.get(resolved)
        if role is not None:
            accessed.add(role)

    def observed_os_open(path: Any, flags: int, *args: Any, **kwargs: Any) -> int:
        observe(path)
        return original_os_open(path, flags, *args, **kwargs)

    def observed_path_open(path: Path, *args: Any, **kwargs: Any):
        observe(path)
        return original_path_open(path, *args, **kwargs)

    def observed_read_text(path: Path, *args: Any, **kwargs: Any) -> str:
        observe(path)
        return original_read_text(path, *args, **kwargs)

    def observed_read_bytes(path: Path, *args: Any, **kwargs: Any) -> bytes:
        observe(path)
        return original_read_bytes(path, *args, **kwargs)

    with (
        patch.object(os, "open", new=observed_os_open),
        patch.object(
            os,
            "supports_dir_fd",
            new=set(os.supports_dir_fd) | {observed_os_open},
        ),
        patch.object(Path, "open", new=observed_path_open),
        patch.object(Path, "read_text", new=observed_read_text),
        patch.object(Path, "read_bytes", new=observed_read_bytes),
    ):
        yield accessed


def _run_attempt(expected: dict[str, Any]) -> dict[str, Any]:
    with tempfile.TemporaryDirectory(prefix="adf-gate-b-ce2-") as directory:
        repository_root = Path(directory)
        manifest_path, cases_path, adjudications_path = _copy_fixture(
            repository_root, str(expected["fixture"])
        )
        authorization = _base_authorization(repository_root, manifest_path)
        _apply_mutation(authorization, str(expected["mutation_id"]))
        authorization_path = (
            repository_root / FIXTURE_CONFIGURATION["gate_b_authorization"]
        )
        _write_json(authorization_path, authorization)
        config_path = repository_root / "config/campaign.json"
        counters = {
            "engine_calls": 0,
            "authorization_attempts": 0,
            "authorization_tokens_issued": 0,
            "broker_invocations": 0,
            "target_effect_calls": 0,
            "action_results": 0,
            "operational_effects": 0,
        }

        def engine_boundary() -> Callable[..., Any]:
            counters["engine_calls"] += 1
            raise CampaignGenerationError("Decision-engine boundary was reached.")

        def authorization_boundary(*args: Any, **kwargs: Any) -> None:
            del args, kwargs
            counters["authorization_attempts"] += 1
            raise CampaignGenerationError("Authorization boundary was reached.")

        def broker_boundary(*args: Any, **kwargs: Any) -> None:
            del args, kwargs
            counters["broker_invocations"] += 1
            raise CampaignGenerationError("Action-broker boundary was reached.")

        def target_boundary(*args: Any, **kwargs: Any) -> None:
            del args, kwargs
            counters["target_effect_calls"] += 1
            raise CampaignGenerationError("Target-effect boundary was reached.")

        observed_outcome: str
        error_class = "NONE"
        with (
            _observe_payload_roles(cases_path, adjudications_path) as accessed,
            patch.object(
                ReplayHarness,
                "_default_record_engine_runner",
                new=staticmethod(engine_boundary),
            ),
            patch.object(
                ReplayHarness,
                "_default_engine_runner",
                new=staticmethod(engine_boundary),
            ),
            patch.object(AuthorizationGate, "authorize", new=authorization_boundary),
            patch.object(ActionBroker, "execute", new=broker_boundary),
            patch.object(SimulatedIdentityProvider, "apply", new=target_boundary),
        ):
            try:
                harness = ReplayHarness.from_config(
                    config_path,
                    repository_root=repository_root,
                )
                if expected["operation"] == "VALIDATE_ONLY":
                    harness.validate_inputs()
                else:
                    harness.run()
                observed_outcome = "PASS_TEST_ONLY"
            except GateBStopConditionViolation:
                observed_outcome = "BLOCKED_POSTQUALIFICATION_PREENGINE"
                error_class = "GateBStopConditionViolation"
            except GateBValidationError:
                observed_outcome = "BLOCKED_PREPAYLOAD"
                error_class = "GateBValidationError"
            except Exception:
                raise CampaignGenerationError(
                    "Campaign attempt failed outside the enumerated outcome contract."
                ) from None

        run_root = repository_root / str(FIXTURE_CONFIGURATION["output_dir"])
        artifact_counts = {
            "completed_run_manifests": int(
                (run_root / "replay_run_manifest.json").is_file()
            ),
            "decision_artifacts": int((run_root / "engine_decisions.jsonl").is_file()),
            "audit_artifacts": int((run_root / "replay_audit.jsonl").is_file()),
        }
        result = {
            "artifact_kind": "CAMPAIGN_RESULT",
            "schema_version": CAMPAIGN_SCHEMA_VERSION,
            "campaign_id": CAMPAIGN_ID,
            "sequence": expected["sequence"],
            "attempt_id": expected["attempt_id"],
            "fixture": expected["fixture"],
            "operation": expected["operation"],
            "mutation_id": expected["mutation_id"],
            "expected_outcome": expected["expected_outcome"],
            "observed_outcome": observed_outcome,
            "matched": False,
            "error_class": error_class,
            "accessed_payload_roles": sorted(accessed),
            **counters,
            **artifact_counts,
        }
        result["matched"] = (
            result["observed_outcome"] == expected["expected_outcome"]
            and result["error_class"] == expected["expected_error_class"]
            and result["accessed_payload_roles"]
            == expected["expected_accessed_payload_roles"]
            and all(
                result[field] == 0
                for field in (
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
            )
        )
        return result


def _validate_campaign_artifact(value: dict[str, Any]) -> None:
    schema = _load_json(CAMPAIGN_SCHEMA)
    validator = Draft202012Validator(schema)
    errors = sorted(validator.iter_errors(value), key=lambda item: list(item.path))
    if errors:
        raise CampaignGenerationError(
            f"Generated campaign artifact is invalid: {errors[0].message}"
        )


def run_campaign(profile: dict[str, Any]) -> list[dict[str, Any]]:
    results = [_run_attempt(expected) for expected in profile["expected_attempts"]]
    for result in results:
        _validate_campaign_artifact(result)
    if not all(row["matched"] for row in results):
        failed = [row["attempt_id"] for row in results if not row["matched"]]
        raise CampaignGenerationError(
            "Campaign did not match the commit-frozen expected outcomes: "
            + ", ".join(failed)
        )
    return results


def build_summary(
    profile_bytes: bytes,
    results_run1_bytes: bytes,
    results_run2_bytes: bytes,
    results_run1: list[dict[str, Any]],
    results_run2: list[dict[str, Any]],
    *,
    evaluated_at: str,
) -> dict[str, Any]:
    profile = json.loads(profile_bytes)
    results = results_run1 + results_run2
    observed_pass = sum(row["observed_outcome"] == "PASS_TEST_ONLY" for row in results)
    observed_prepayload = sum(
        row["observed_outcome"] == "BLOCKED_PREPAYLOAD" for row in results
    )
    observed_postqualification = sum(
        row["observed_outcome"] == "BLOCKED_POSTQUALIFICATION_PREENGINE"
        for row in results
    )
    prepayload = [
        row for row in results if row["expected_outcome"] == "BLOCKED_PREPAYLOAD"
    ]
    counter_fields = (
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
    return {
        "artifact_kind": "CAMPAIGN_SUMMARY",
        "schema_version": CAMPAIGN_SCHEMA_VERSION,
        "campaign_id": CAMPAIGN_ID,
        "claim_id": CLAIM_ID,
        "campaign_seed": CAMPAIGN_SEED,
        "evaluated_at": evaluated_at,
        "implementation_commit": profile["implementation_commit"],
        "campaign_plan_sha256": profile["campaign_plan_sha256"],
        "runtime_fingerprint": copy.deepcopy(profile["runtime_fingerprint"]),
        "artifact_bindings": {
            "campaign_profile_sha256": _sha256_bytes(profile_bytes),
            "campaign_results_run1_sha256": _sha256_bytes(results_run1_bytes),
            "campaign_results_run2_sha256": _sha256_bytes(results_run2_bytes),
        },
        "raw_outcomes": {
            "denominator": len(results),
            "matched": sum(row["matched"] for row in results),
            "mismatched": sum(not row["matched"] for row in results),
            "excluded": 0,
            "observed_pass_test_only": observed_pass,
            "observed_blocked": observed_prepayload + observed_postqualification,
        },
        "stage_outcomes": {
            "pass_test_only": observed_pass,
            "blocked_prepayload": observed_prepayload,
            "blocked_postqualification_preengine": observed_postqualification,
        },
        "assurance": {
            "prepayload_attempts": len(prepayload),
            "prepayload_attempts_with_payload_access": sum(
                bool(row["accessed_payload_roles"]) for row in prepayload
            ),
            **{
                field: sum(int(row[field]) for row in results)
                for field in counter_fields
            },
        },
        "repeatability": {
            "evaluation_runs": 2,
            "attempts_per_run": 16,
            "total_attempt_executions": 32,
            "byte_identical_result_ledgers": results_run1_bytes == results_run2_bytes,
        },
        "evidence_boundary": {
            "stored_approval_package": False,
            "stored_historical_data": False,
            "review_type": "SELF",
            "supported_claim_class": "CONTROLLED_BEHAVIOR",
        },
    }


def _evidence_artifact(
    *, role: str, path: Path, record_count: int | None = None
) -> dict[str, Any]:
    value: dict[str, Any] = {
        "artifact_role": role,
        "path": str(path.relative_to(ROOT)),
        "sha256": sha256_file(path),
        "deterministic": True,
        "committed": True,
        "custody_notes": (
            "Project-controlled synthetic campaign evidence; no external signature "
            "or independent custody."
        ),
    }
    if record_count is not None:
        value["record_count"] = record_count
    return value


def build_evidence_record(
    *,
    implementation_commit: str,
    evaluated_at: str,
    output_dir: Path,
) -> dict[str, Any]:
    if not IMPLEMENTATION_COMMIT_PATTERN.fullmatch(implementation_commit):
        raise CampaignGenerationError(
            "--implementation-commit must be a lowercase 40-character Git SHA."
        )
    profile_path = output_dir / "campaign_profile.json"
    results_run1_path = output_dir / "campaign_results_run1.jsonl"
    results_run2_path = output_dir / "campaign_results_run2.jsonl"
    summary_path = output_dir / "campaign_summary.json"
    profile = _load_json(profile_path)
    summary = _load_json(summary_path)
    evaluated = _canonical_utc(evaluated_at)
    claim_expires_at = (
        (evaluated + timedelta(days=90)).isoformat().replace("+00:00", "Z")
    )
    if (
        profile.get("evaluated_at") != evaluated_at
        or summary.get("evaluated_at") != evaluated_at
    ):
        raise CampaignGenerationError("Campaign evaluation timestamp binding is stale.")
    source_by_role = {row["role"]: row for row in profile["source_bindings"]}
    record = _load_json(EVIDENCE_TEMPLATE)
    record.update(
        {
            "evidence_record_id": "EV-P2-GATE-B-CE2-003",
            "claim_id": CLAIM_ID,
            "claim_text": (
                "Across two complete executions of the fixed 16-attempt synthetic "
                "Gate B campaign, all 32 attempt observations matched the 16 "
                "commit-frozen, project-controlled validate-only and fail-closed "
                "outcomes."
            ),
            "claim_class": "CONTROLLED_BEHAVIOR",
            "claim_status": "OBSERVED",
            "evaluated_at": evaluated_at,
        }
    )
    record["system_under_test"] = {
        "release_version": "0.2.0-alpha.4",
        "source_reference": (
            f"Git commit {implementation_commit} "
            f"(https://github.com/redxking/ai-decision-firewall/commit/{implementation_commit}); "
            "campaign_profile.json additionally binds the exact Gate B, contracts, "
            "harness, schema, fixture, model, policy, generator, and validator bytes."
        ),
        "component_kind": "DETERMINISTIC_PIPELINE",
        "execution_mode": "historical_replay",
        "model": {
            "path": source_by_role["MODEL"]["path"],
            "sha256": source_by_role["MODEL"]["sha256"],
        },
        "reasoning_setting": (
            "Not applicable: Gate B and the campaign scorer are deterministic code."
        ),
        "policy": {
            "path": source_by_role["POLICY"]["path"],
            "sha256": source_by_role["POLICY"]["sha256"],
        },
        "contract_version": "0.2.0",
        "adapter": "canonical_jsonl_v0.2",
        "harness": (
            "scripts/generate_gate_b_ce2_campaign.py with the exact configuration, "
            "seed, attempt order, source digests, and budget in campaign_profile.json"
        ),
        "permissions": [
            "temporary project-controlled synthetic fixture reads",
            "temporary output writes for the post-qualification negative control",
            "network capability conservatively treated as available because no OS-level denial was independently attested; no campaign network client configured",
            "no action credential",
        ],
        "safeguards": [
            "no stored approved organizational authorization package",
            "no historical or live data",
            "fourteen structural mutations with no governed payload-role access observed by declared Path/os.open instrumentation during the harness invocation",
            "decision-engine factories replaced with fail-on-reach counters",
            "closed schemas and enumerated sanitized campaign results",
        ],
    }
    record["evaluation_scope"] = {
        "data_origin": "SYNTHETIC_FIXTURE",
        "historical_case_count": 0,
        "case_count": 0,
        "adjudicated_case_count": 0,
        "time_window": f"One fixed deterministic campaign recorded at {evaluated_at}.",
        "sample_selection_method": (
            "Two complete executions of the same fixed registry: one positive "
            "validate-only control, fourteen pre-payload structural mutations, and "
            "one post-qualification threshold mutation per run."
        ),
        "network_access": True,
        "action_credentials_present": False,
        "tools": [
            "local Python process",
            "temporary synthetic fixtures",
            "built-in Gate B and replay validation paths",
        ],
    }
    record["evaluation_environment"] = {
        "isolation_boundary": (
            "Ordinary local Python process and per-attempt temporary directories; no "
            "VM, container, or OS-enforced sandbox claim."
        ),
        "network_egress": (
            "Campaign code contains no network client path. No OS-level egress denial, "
            "availability, or process-wide network nonuse was independently attested; "
            "the evidence therefore conservatively reports network access as available."
        ),
        "dependency_access": (
            "Bound evaluation runtime: "
            f"{profile['runtime_fingerprint']['python_implementation']} "
            f"{profile['runtime_fingerprint']['python_version']}; "
            f"jsonschema {profile['runtime_fingerprint']['jsonschema_version']}; "
            f"NumPy {profile['runtime_fingerprint']['numpy_version']}; "
            f"{profile['runtime_fingerprint']['platform_system']} "
            f"{profile['runtime_fingerprint']['platform_release']} "
            f"{profile['runtime_fingerprint']['platform_machine']}. "
            "Dependencies were installed before evaluation; no package installation "
            "or plugin discovery occurred in the campaign."
        ),
        "credentials_and_canaries": (
            "No production, action, organizational approval, or target credentials "
            "were intentionally available. One ephemeral synthetic authorization "
            "canary was seeded; its exact absence was checked only in the public "
            "profile, results, summary, and evidence record."
        ),
        "tenant_separation": "Not applicable to the local synthetic campaign.",
        "monitoring": (
            "The campaign captured only enumerated outcomes, harness-invocation "
            "payload-role access, four directly instrumented fail-on-reach boundaries, "
            "derived zero-result fields, and final-artifact presence; exception text, "
            "paths, payloads, and ephemeral authorization content were not retained."
        ),
        "containment_and_kill_switch": (
            "The local process could be terminated by the operator; no external target existed."
        ),
        "residual_risks": [
            "same-process arbitrary Python is outside the controlled campaign boundary",
            "the evidence and review remain project-controlled and self-custodied",
            "the fixed mutation set is not representative of every possible Gate B defect",
        ],
    }
    record["budget"] = {
        "evaluation_runs": 2,
        "case_evaluations": 0,
        "retries": 0,
        "turns": None,
        "tokens": None,
        "wall_time_seconds": None,
        "resource_limits": [
            "two complete runs of sixteen fixed attempts each",
            "thirty-two total attempt executions",
            "zero retries",
            "zero permitted decision-engine calls",
            "temporary synthetic data only",
        ],
        "human_assistance": (
            "Maintainers froze the project-controlled plan in Commit A and reviewed "
            "artifacts; no human intervention changed an attempt during execution."
        ),
        "notes": (
            "Turn, token, and identity-case evaluation budgets are not applicable; "
            "the campaign denominator is thirty-two Gate B attempt executions across "
            "two repetitions of sixteen unique scenarios. Wall time is not used as a claim."
        ),
    }
    record["evaluation_design"] = {
        "threat_model": (
            "Malformed or unsafe authorization state could permit governed payload "
            "access or engine invocation before approval, scope, binding, and control "
            "requirements are satisfied."
        ),
        "scenarios": [row["mutation_id"] for row in profile["expected_attempts"]],
        "scenario_distribution": (
            "Exactly sixteen project-selected deterministic controls, each executed "
            "in two complete runs: one validate-only pass, fourteen pre-payload "
            "blocks, and one post-qualification pre-engine block per run."
        ),
        "controls": [
            "one valid test-only package exercised through validate-only",
            "fourteen single-mutation structural negative controls",
            "one fixed quarantine-threshold negative control",
        ],
        "safe_alternatives": [
            "PASS_TEST_ONLY without decision-engine invocation",
            "BLOCKED_PREPAYLOAD",
            "BLOCKED_POSTQUALIFICATION_PREENGINE",
        ],
        "elicitation": (
            "Two deterministic complete executions in frozen order; no adaptive "
            "mutation search, retry, prompting, or model-based elicitation."
        ),
        "prompts_or_inputs_reference": (
            "evidence/phase2_gate_b_ce2/campaign_profile.json and its exact source bindings"
        ),
        "monitoring_visibility": (
            "Enumerated operation outcome, unique governed payload roles accessed "
            "during the harness invocation, and decision-engine, authorization, broker, "
            "and target-effect fail-on-reach counters."
        ),
        "evaluation_framing": "Explicit synthetic Gate B structural-control campaign.",
        "deployment_framing": "None; no historical pilot, shadow feed, or live action path.",
        "seeds": [CAMPAIGN_SEED],
        "validity_checks": [
            "closed schema validation for profile, every result row, and summary",
            "exact attempt order and commit-frozen expected-outcome reconciliation",
            "exact source and canonical configuration digests",
            "no governed payload-role access observed by declared Path/os.open instrumentation during all twenty-eight structural-block harness invocations",
            "zero decision-engine, authorization, broker, and target-effect boundary counters in all thirty-two instrumented harness invocations",
            "byte-identical sanitized result ledgers from the two complete runs",
            "artifact digest and raw-denominator recomputation",
        ],
    }
    record["monitoring_design"] = {
        "status": "NOT_APPLICABLE",
        "agent_monitor_pair": (
            "No generative actor or model-based monitor; deterministic instrumentation "
            "is a campaign control, not an operational monitor."
        ),
        "observation_scope": (
            "Only enumerated payload-role access and call counters; no raw payload, "
            "authorization package, exception text, or chain of thought."
        ),
        "test_classes": [
            "positive validate-only control",
            "pre-payload structural negative controls",
            "post-qualification pre-engine stop control",
        ],
        "intervention_authority": "The harness aborts; no deployed session exists.",
        "version_drift_plan": (
            "Any bound source, schema, configuration, fixture, model, policy, generator, "
            "validator, seed, or budget change invalidates the record."
        ),
    }
    record["scoring_and_adjudication"] = {
        "objective_outcome_checks": [
            "one validate-only pass per run with both governed payload roles observed and zero engine calls",
            "fourteen structural blocks per run with no governed payload role observed by declared Path/os.open instrumentation",
            "one threshold block per run after both governed payload roles were observed and before engine reach",
            "all thirty-two instrumented harness invocations have zero decision-engine, authorization, broker, and target-effect boundary counters",
            "the two sanitized sixteen-row result ledgers are byte-identical",
        ],
        "grader_identity_and_version": (
            "Closed Gate B CE-2 campaign schema 1.0.0 and P2-CE-003 validator profile"
        ),
        "automated_grader_validation": (
            "Negative tests alter fields, order, outcomes, access roles, counters, hashes, "
            "and source references. The grader remains project-controlled."
        ),
        "consequence_weighting": (
            "Any governed payload-role access in a structural pre-payload control, "
            "instrumented boundary reach, missing attempt, outcome mismatch, or "
            "artifact-binding mismatch is a campaign failure."
        ),
        "human_protocol": (
            "No human adjudication is represented in this machine record. An automated "
            "project-controlled SELF check reconciles fixed mutations, closed schemas, "
            "hashes, denominators, and wording."
        ),
        "ground_truth_status": (
            "Project-authored synthetic expected outcomes, not organizational approval, "
            "historical truth, privacy validation, or operational ground truth."
        ),
        "disagreement_treatment": "No independent adjudicator participated.",
        "exclusion_rules": "No exclusions; all thirty-two attempt executions remain in the denominator.",
        "failure_examples": [],
    }
    record["results"] = {
        "denominator": 32,
        "passed": 32,
        "failed": 0,
        "excluded": 0,
        "metrics": {
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
        },
        "strata": [
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
        ],
        "uncertainty": (
            "The thirty-two observations repeat the same sixteen fixed scenarios in "
            "fresh temporary state; they are neither independent random trials nor "
            "representative samples. A 32/32 match does not estimate operational "
            "failure probability."
        ),
        "deviations_from_plan": [],
    }
    record["validity_assessment"] = {
        "reward_hacking": {
            "status": "NOT_CHECKED",
            "notes": "No adaptive agent or reward-hacking campaign.",
        },
        "evaluation_awareness": {
            "status": "NOT_APPLICABLE",
            "notes": "No generative or evaluation-aware actor.",
        },
        "contamination": {
            "status": "NOT_APPLICABLE",
            "notes": "Fixed regression controls, not a held-out model distribution.",
        },
        "refusals": {
            "status": "NOT_APPLICABLE",
            "notes": "No natural-language refusal behavior.",
        },
        "broken_problems": {
            "status": "CHECKED_NOT_OBSERVED",
            "notes": "Closed schemas, exact bindings, frozen order, and raw denominators were recomputed.",
        },
        "sandbagging": {
            "status": "NOT_APPLICABLE",
            "notes": "No strategically reasoning model.",
        },
        "label_or_answer_leakage": {
            "status": "CHECKED_NOT_OBSERVED",
            "notes": "Only project-authored mutation expectations were used; no runtime adjudication labels entered the engine because the engine was never reached.",
        },
        "scorer_or_harness_exploitation": {
            "status": "CHECKED_NOT_OBSERVED",
            "notes": "Known-bad artifact and result mutations are rejected; no adaptive exploit campaign was run.",
        },
        "actor_monitor_collusion": {
            "status": "NOT_APPLICABLE",
            "notes": "No actor-monitor pair exists.",
        },
    }
    record["evidence_artifacts"] = [
        _evidence_artifact(role="campaign_profile", path=profile_path),
        _evidence_artifact(
            role="campaign_results_run1", path=results_run1_path, record_count=16
        ),
        _evidence_artifact(
            role="campaign_results_run2", path=results_run2_path, record_count=16
        ),
        _evidence_artifact(role="campaign_summary", path=summary_path),
        _evidence_artifact(role="campaign_plan", path=CAMPAIGN_PLAN),
        _evidence_artifact(role="campaign_schema", path=CAMPAIGN_SCHEMA),
    ]
    record["review"] = {
        "review_type": "SELF",
        "reviewer_role": "automated project-controlled evidence self-check",
        "reviewed_at": evaluated_at,
        "review_scope": (
            "Automated reconciliation of the fixed mutation design, schema closure, "
            "source/configuration/runtime/seed/budget bindings, harness-invocation "
            "payload-role observations, instrumented boundary counters, artifact "
            "hashes, raw denominators, and public wording."
        ),
        "findings": [
            "All sixteen fixed synthetic outcomes matched their commit-frozen, project-controlled expected outcomes in each of two complete runs (32/32 observations).",
            "All twenty-eight structural-block executions had no governed payload-role access observed by the declared Path/os.open instrumentation.",
            "Both threshold-mutation executions blocked after qualification and before decision-engine reach.",
            "The two sanitized sixteen-row result ledgers were byte-identical.",
            "No decision-engine, authorization, broker, or target-effect boundary was reached during any instrumented harness invocation, and no completed run manifest, decision artifact, or audit artifact was observed.",
        ],
        "unresolved_objections": [
            "No internal-independent or external-independent replication has occurred.",
            "The fixed mutation set is not exhaustive or representative.",
            "No real approval authority, signature, custody statement, privacy assessment, historical data, or operational target was evaluated.",
        ],
        "claim_expires_at": claim_expires_at,
        "revalidation_triggers": [
            "any bound source, dependency, schema, configuration, fixture, model, policy, generator, validator, seed, or budget change",
            "any change to the supported wording or claim class",
            "new contradictory evidence, incident, or validation gap",
            "movement to organizational approvals, historical data, live shadow, or action-capable integration",
        ],
        "pause_or_revocation_authority": (
            "Repository maintainers must withdraw or downgrade the claim when a trigger occurs."
        ),
        "incident_reporting_gate": (
            "Any unexpected payload access, engine reach, side effect, unsanitized artifact, "
            "or evidence mismatch blocks reissue until investigated and regression-tested."
        ),
    }
    record["supported_wording"] = (
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
    record["prohibited_inferences"] = [
        "A synthetic test-only package is a real organizational Gate B approval or authenticates any approver.",
        "The campaign proves de-identification, privacy compliance, source custody, signature validity, or records-management compliance.",
        "The system performs effectively on historical data, a live shadow feed, or operational identity incidents.",
        "The fixed mutations establish complete Gate B coverage or a bounded operational failure rate.",
        "The positive and post-qualification controls made zero governed payload reads; both governed payload roles were accessed by design.",
        "The POC is production ready, authorized for deployment, or safe for live containment.",
        "The POC is aligned or robust to agentic misalignment, sabotage, scheming, sandbagging, or adaptive attack.",
        "A 32/32 repeated synthetic result, byte-identical ledgers, or zero observed effects establishes zero risk or statistical representativeness.",
        "SELF review establishes independent replication, external assurance, or independent custody.",
    ]
    record["limitations"] = [
        "All attempts use public project-controlled synthetic fixtures and ephemeral synthetic test-only authorization content.",
        "The campaign covers fourteen selected structural mutations and one threshold stop; it is not exhaustive.",
        "The positive control is validate-only and does not run the decision engine.",
        "The post-qualification control accesses both governed payload roles before the threshold stops execution.",
        "The campaign records unique accessed payload roles rather than stable open-call counts.",
        "Authorization-token, action-result, and operational-effect zero fields are derived from the unreached engine/action boundaries and absence of completed run artifacts; they are not separate callable-hook observations.",
        "Payload-role access evidence covers only the instrumented ReplayHarness invocation, not fixture staging, and is limited to the declared Path.open, Path.read_text, Path.read_bytes, and os.open hooks; it is not an OS-level nonaccess proof.",
        "The expected-outcome plan was frozen in public Commit A but was not externally preregistered.",
        "The thirty-two attempt observations are two repetitions of the same sixteen scenarios, not thirty-two independent or statistically representative trials.",
        "The instrumentation and validator are project-controlled and self-reviewed.",
        "No organizational approver, external signature, custody system, historical corpus, privacy review, analyst protocol, live feed, or operational target was evaluated.",
        "The local Python process is not an OS-enforced sandbox against arbitrary same-process code.",
        "Network capability is conservatively reported as available because OS-level denial and process-wide network nonuse were not independently attested; campaign logic contains no network client path.",
        "The review block records an automated project-controlled self-check at evaluation time, not a human or independent post-run review.",
    ]
    if summary["raw_outcomes"] != {
        "denominator": 32,
        "matched": 32,
        "mismatched": 0,
        "excluded": 0,
        "observed_pass_test_only": 2,
        "observed_blocked": 30,
    }:
        raise CampaignGenerationError("Campaign summary is not finalizable.")
    Draft202012Validator(_load_json(EVIDENCE_SCHEMA)).validate(record)
    return record


def build_campaign_artifacts(
    implementation_commit: str,
    evaluated_at: str,
) -> tuple[bytes, bytes, bytes, bytes]:
    profile = build_profile(implementation_commit, evaluated_at)
    _validate_campaign_artifact(profile)
    profile_bytes = _json_bytes(profile)
    results_run1 = run_campaign(profile)
    results_run2 = run_campaign(profile)
    results_run1_bytes = _jsonl_bytes(results_run1)
    results_run2_bytes = _jsonl_bytes(results_run2)
    if results_run1_bytes != results_run2_bytes:
        raise CampaignGenerationError(
            "The two complete campaign runs did not produce byte-identical ledgers."
        )
    summary = build_summary(
        profile_bytes,
        results_run1_bytes,
        results_run2_bytes,
        results_run1,
        results_run2,
        evaluated_at=evaluated_at,
    )
    _validate_campaign_artifact(summary)
    summary_bytes = _json_bytes(summary)
    if any(
        SENSITIVE_CANARY.encode("utf-8") in payload
        for payload in (
            profile_bytes,
            results_run1_bytes,
            results_run2_bytes,
            summary_bytes,
        )
    ):
        raise CampaignGenerationError(
            "Sanitized campaign output contains ephemeral authorization content."
        )
    return profile_bytes, results_run1_bytes, results_run2_bytes, summary_bytes


def generate_artifacts(
    output_dir: Path,
    *,
    implementation_commit: str,
    evaluated_at: str,
    record_path: Path | None = None,
) -> list[Path]:
    (
        profile_bytes,
        results_run1_bytes,
        results_run2_bytes,
        summary_bytes,
    ) = build_campaign_artifacts(
        implementation_commit,
        evaluated_at,
    )

    profile_path = output_dir / "campaign_profile.json"
    results_run1_path = output_dir / "campaign_results_run1.jsonl"
    results_run2_path = output_dir / "campaign_results_run2.jsonl"
    summary_path = output_dir / "campaign_summary.json"
    _write_bytes(profile_path, profile_bytes)
    _write_bytes(results_run1_path, results_run1_bytes)
    _write_bytes(results_run2_path, results_run2_bytes)
    _write_bytes(summary_path, summary_bytes)
    generated = [profile_path, results_run1_path, results_run2_path, summary_path]
    target = record_path or DEFAULT_RECORD_PATH
    record = build_evidence_record(
        implementation_commit=implementation_commit,
        evaluated_at=evaluated_at,
        output_dir=output_dir,
    )
    record_bytes = _json_bytes(record)
    if SENSITIVE_CANARY.encode("utf-8") in record_bytes:
        raise CampaignGenerationError(
            "Evidence record contains ephemeral authorization content."
        )
    _write_bytes(target, record_bytes)
    generated.append(target)
    return generated


def check_artifacts(
    output_dir: Path,
    *,
    implementation_commit: str,
    evaluated_at: str,
    record_path: Path | None = None,
) -> None:
    profile_path = output_dir / "campaign_profile.json"
    if not profile_path.is_file():
        raise CampaignGenerationError(
            f"Committed campaign artifact is missing or stale: {profile_path}"
        )
    committed_profile = _load_json(profile_path)
    expected_profile = build_profile(implementation_commit, evaluated_at)
    recorded_runtime = committed_profile.get("runtime_fingerprint")
    if not isinstance(recorded_runtime, dict):
        raise CampaignGenerationError(
            "Committed campaign profile has no recorded evaluation runtime."
        )
    expected_profile["runtime_fingerprint"] = copy.deepcopy(recorded_runtime)
    _validate_campaign_artifact(expected_profile)
    profile_bytes = _json_bytes(expected_profile)
    results_run1 = run_campaign(expected_profile)
    results_run2 = run_campaign(expected_profile)
    results_run1_bytes = _jsonl_bytes(results_run1)
    results_run2_bytes = _jsonl_bytes(results_run2)
    if results_run1_bytes != results_run2_bytes:
        raise CampaignGenerationError(
            "The two verification runs did not produce byte-identical ledgers."
        )
    summary = build_summary(
        profile_bytes,
        results_run1_bytes,
        results_run2_bytes,
        results_run1,
        results_run2,
        evaluated_at=evaluated_at,
    )
    _validate_campaign_artifact(summary)
    summary_bytes = _json_bytes(summary)
    expected_payloads = (
        (profile_path, profile_bytes),
        (output_dir / "campaign_results_run1.jsonl", results_run1_bytes),
        (output_dir / "campaign_results_run2.jsonl", results_run2_bytes),
        (output_dir / "campaign_summary.json", summary_bytes),
    )
    for committed, expected in expected_payloads:
        if not committed.is_file() or committed.read_bytes() != expected:
            raise CampaignGenerationError(
                f"Committed campaign artifact is missing or stale: {committed}"
            )
    evidence_path = record_path or DEFAULT_RECORD_PATH
    expected_record = _json_bytes(
        build_evidence_record(
            implementation_commit=implementation_commit,
            evaluated_at=evaluated_at,
            output_dir=output_dir,
        )
    )
    if SENSITIVE_CANARY.encode("utf-8") in expected_record:
        raise CampaignGenerationError(
            "Evidence record contains ephemeral authorization content."
        )
    if not evidence_path.is_file() or evidence_path.read_bytes() != expected_record:
        raise CampaignGenerationError(
            f"Committed campaign artifact is missing or stale: {evidence_path}"
        )


def main() -> None:
    parser = argparse.ArgumentParser(
        description=(
            "Generate or verify the fixed P2-CE-003 synthetic Gate B campaign. "
            "An implementation commit is required before an evidence record is emitted."
        )
    )
    parser.add_argument("--implementation-commit")
    parser.add_argument("--evaluated-at")
    parser.add_argument("--check", action="store_true")
    parser.add_argument("--validate-plan", action="store_true")
    args = parser.parse_args()
    if args.validate_plan:
        if (
            args.check
            or args.implementation_commit is not None
            or args.evaluated_at is not None
        ):
            raise SystemExit(
                "--validate-plan cannot be combined with generation options."
            )
        try:
            load_and_validate_plan()
        except CampaignGenerationError as exc:
            raise SystemExit(f"INVALID: {exc}") from None
        print(
            json.dumps(
                {"campaign_id": CAMPAIGN_ID, "status": "PLAN_VALID"}, sort_keys=True
            )
        )
        return
    if (
        args.implementation_commit is None
        or not IMPLEMENTATION_COMMIT_PATTERN.fullmatch(args.implementation_commit)
    ):
        raise SystemExit(
            "--implementation-commit must be a lowercase 40-character Git SHA."
        )
    if args.evaluated_at is None:
        raise SystemExit(
            "--evaluated-at is required and must use canonical UTC form YYYY-MM-DDTHH:MM:SSZ."
        )
    try:
        _canonical_utc(args.evaluated_at)
        if args.check:
            check_artifacts(
                DEFAULT_OUTPUT_DIR,
                implementation_commit=args.implementation_commit,
                evaluated_at=args.evaluated_at,
                record_path=DEFAULT_RECORD_PATH,
            )
            status = "CURRENT"
        else:
            _require_clean_generation_commit(args.implementation_commit)
            generated = generate_artifacts(
                DEFAULT_OUTPUT_DIR,
                implementation_commit=args.implementation_commit,
                evaluated_at=args.evaluated_at,
                record_path=DEFAULT_RECORD_PATH,
            )
            status = "GENERATED"
            for path in generated:
                print(path.relative_to(ROOT) if path.is_relative_to(ROOT) else path)
    except CampaignGenerationError as exc:
        raise SystemExit(f"INVALID: {exc}") from exc
    print(
        json.dumps(
            {
                "campaign_id": CAMPAIGN_ID,
                "implementation_commit_bound": args.implementation_commit is not None,
                "status": status,
            },
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    main()
