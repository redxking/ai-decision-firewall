"""Generate the fixed P2-CE-004 synthetic feature-assurance campaign.

This campaign is deliberately narrow.  It invokes only the case qualifier,
the production feature projector, and the separately implemented in-process reference
projector.  It has no model, policy, verifier, decision-engine, authorization,
broker, target, live-feed, or action path.  Public results contain enumerated
metadata and digests, never raw cases, feature values, feature traces, or local
paths.
"""

from __future__ import annotations

import argparse
import copy
from datetime import datetime, timedelta, timezone
import hashlib
import importlib.metadata
import json
import math
import platform
import re
import subprocess
import sys
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator


ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from adf_poc import __version__ as PACKAGE_VERSION  # noqa: E402
from adf_poc.features import FEATURE_NAMES, extract_features  # noqa: E402
from adf_poc.replay.qualification import qualify_case_bytes  # noqa: E402
from adf_poc.replay.reference_features import (  # noqa: E402
    ReferenceFeatureAssuranceError,
    verify_reference_feature_projections,
)
from adf_poc.schemas import IdentityCase  # noqa: E402


CAMPAIGN_ID = "P2-CE-004-FEATURE-ASSURANCE-SYNTHETIC"
CLAIM_ID = "P2-CE-004"
CAMPAIGN_SCHEMA_VERSION = "1.0.0"
CAMPAIGN_SEED = 20260815
CAMPAIGN_SCHEMA = ROOT / "contracts/v0.2.0/feature-assurance-ce2-campaign.schema.json"
CAMPAIGN_PLAN = ROOT / "config/feature_assurance_ce2_campaign_plan.json"
EVIDENCE_SCHEMA = ROOT / "contracts/v0.2.0/evaluation-evidence.schema.json"
EVIDENCE_TEMPLATE = (
    ROOT / "contracts/v0.2.0/examples/phase2-qualification-evidence-record.json"
)
DEFAULT_OUTPUT_DIR = ROOT / "evidence/phase2_feature_assurance_ce2"
DEFAULT_RECORD_PATH = (
    ROOT / "contracts/v0.2.0/examples/phase2-feature-assurance-ce2-evidence-record.json"
)
IMPLEMENTATION_COMMIT_PATTERN = re.compile(r"^[0-9a-f]{40}$")
CANONICAL_UTC_PATTERN = re.compile(
    r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$"
)
ZERO_SHA256 = "0" * 64
SUPPORTED_WORDING = (
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
PROHIBITED_PUBLIC_FIELDS = (
    b'"case_id"',
    b'"events"',
    b'"feature_trace"',
    b'"feature_values"',
    b'"subject_id"',
    b'"untrusted_text"',
)


class CampaignGenerationError(RuntimeError):
    """Raised when the frozen campaign cannot produce its exact result."""


class _DuplicateJSONMember(ValueError):
    """Internal marker for ambiguous control JSON."""


def _reject_duplicate_json_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, child in pairs:
        if key in value:
            raise _DuplicateJSONMember
        value[key] = child
    return value


def _reject_nonstandard_number(_value: str) -> None:
    raise ValueError("Nonstandard JSON number is prohibited.")


def _parse_finite_json_float(value: str) -> float:
    parsed = float(value)
    if not math.isfinite(parsed):
        raise ValueError("Non-finite JSON number is prohibited.")
    return parsed


def _assert_finite_json_numbers(value: Any) -> None:
    """Reject non-finite values anywhere in a decoded JSON tree."""

    pending = [value]
    while pending:
        current = pending.pop()
        if isinstance(current, float) and not math.isfinite(current):
            raise ValueError("Decoded JSON contains a non-finite number.")
        if isinstance(current, dict):
            pending.extend(current.values())
        elif isinstance(current, list):
            pending.extend(current)


POST_CAMPAIGN_ISOLATED_SOURCES = frozenset({"src/adf_poc/stage_a.py"})


def _package_source_paths() -> dict[str, str]:
    """Bind the Phase 2.4 package surface and its transitive imports.

    The later Stage A module is an authorization/attempt-ledger boundary that
    the fixed feature-only campaign cannot import or invoke.  Keeping it outside
    this historical campaign surface preserves both the no-authorization claim
    and the published schema's bounded source registry.  Stage A has separate
    exact-commit and manifest evidence.
    """

    paths: dict[str, str] = {}
    for path in sorted((ROOT / "src/adf_poc").rglob("*.py")):
        relative = str(path.relative_to(ROOT))
        if relative in POST_CAMPAIGN_ISOLATED_SOURCES:
            continue
        role = "ADF_" + re.sub(r"[^A-Za-z0-9]+", "_", relative).strip("_").upper()
        paths[role] = relative
    return paths


CAMPAIGN_SOURCE_PATHS: dict[str, str] = {
    "CAMPAIGN_GENERATOR": "scripts/generate_feature_assurance_ce2_campaign.py",
    "CAMPAIGN_PLAN": "config/feature_assurance_ce2_campaign_plan.json",
    "CAMPAIGN_SCHEMA": "contracts/v0.2.0/feature-assurance-ce2-campaign.schema.json",
    "CLAIM_VALIDATOR": "scripts/validate_claim_evidence.py",
    "EVIDENCE_SCHEMA": "contracts/v0.2.0/evaluation-evidence.schema.json",
    "EVIDENCE_TEMPLATE": (
        "contracts/v0.2.0/examples/phase2-qualification-evidence-record.json"
    ),
    "QUALIFICATION_SCHEMA": "contracts/v0.2.0/replay-qualification.schema.json",
    "REFERENCE_ASSURANCE_SCHEMA": (
        "contracts/v0.2.0/reference-feature-assurance.schema.json"
    ),
    "REPLAY_CASE_SCHEMA": "contracts/v0.2.0/replay-case.schema.json",
    "PROJECT_METADATA": "pyproject.toml",
    "DEPENDENCY_DECLARATIONS": "requirements.txt",
    **_package_source_paths(),
}


EXPECTED_ATTEMPTS: tuple[dict[str, Any], ...] = (
    {
        "sequence": 1,
        "attempt_id": "P2-CE-004-P01-CLEAN",
        "pair_id": "P01",
        "control_kind": "CLEAN",
        "mutation_id": "NONE",
        "expected_stage": "REFERENCE_PROJECTION",
        "expected_outcome": "ACCEPTED_PROJECTION_MATCH",
        "expected_error_category": "NONE",
        "expected_error_code": "NONE",
    },
    {
        "sequence": 2,
        "attempt_id": "P2-CE-004-P01-MUTANT-BOOL-STRING",
        "pair_id": "P01",
        "control_kind": "MUTANT",
        "mutation_id": "BOOLEAN_STRING",
        "expected_stage": "QUALIFICATION",
        "expected_outcome": "QUARANTINED",
        "expected_error_category": "SEMANTICS",
        "expected_error_code": "INVALID_BOOLEAN",
    },
    {
        "sequence": 3,
        "attempt_id": "P2-CE-004-P02-CLEAN",
        "pair_id": "P02",
        "control_kind": "CLEAN",
        "mutation_id": "NONE",
        "expected_stage": "REFERENCE_PROJECTION",
        "expected_outcome": "ACCEPTED_PROJECTION_MATCH",
        "expected_error_category": "NONE",
        "expected_error_code": "NONE",
    },
    {
        "sequence": 4,
        "attempt_id": "P2-CE-004-P02-MUTANT-COUNT-NAN-STRING",
        "pair_id": "P02",
        "control_kind": "MUTANT",
        "mutation_id": "COUNT_NAN_STRING",
        "expected_stage": "QUALIFICATION",
        "expected_outcome": "QUARANTINED",
        "expected_error_category": "SEMANTICS",
        "expected_error_code": "INVALID_TYPE",
    },
    {
        "sequence": 5,
        "attempt_id": "P2-CE-004-P03-CLEAN",
        "pair_id": "P03",
        "control_kind": "CLEAN",
        "mutation_id": "NONE",
        "expected_stage": "REFERENCE_PROJECTION",
        "expected_outcome": "ACCEPTED_PROJECTION_MATCH",
        "expected_error_category": "NONE",
        "expected_error_code": "NONE",
    },
    {
        "sequence": 6,
        "attempt_id": "P2-CE-004-P03-MUTANT-THREAT-SOURCE",
        "pair_id": "P03",
        "control_kind": "MUTANT",
        "mutation_id": "UNAUTHORIZED_THREAT_SOURCE",
        "expected_stage": "QUALIFICATION",
        "expected_outcome": "QUARANTINED",
        "expected_error_category": "SEMANTICS",
        "expected_error_code": "UNAUTHORIZED_MODELED_SIGNAL",
    },
    {
        "sequence": 7,
        "attempt_id": "P2-CE-004-P04-CLEAN",
        "pair_id": "P04",
        "control_kind": "CLEAN",
        "mutation_id": "NONE",
        "expected_stage": "REFERENCE_PROJECTION",
        "expected_outcome": "ACCEPTED_PROJECTION_MATCH",
        "expected_error_category": "NONE",
        "expected_error_code": "NONE",
    },
    {
        "sequence": 8,
        "attempt_id": "P2-CE-004-P04-MUTANT-BENIGN-SOURCE",
        "pair_id": "P04",
        "control_kind": "MUTANT",
        "mutation_id": "UNAUTHORIZED_BENIGN_SOURCE",
        "expected_stage": "QUALIFICATION",
        "expected_outcome": "QUARANTINED",
        "expected_error_category": "SEMANTICS",
        "expected_error_code": "UNAUTHORIZED_MODELED_SIGNAL",
    },
    {
        "sequence": 9,
        "attempt_id": "P2-CE-004-P05-CLEAN",
        "pair_id": "P05",
        "control_kind": "CLEAN",
        "mutation_id": "NONE",
        "expected_stage": "REFERENCE_PROJECTION",
        "expected_outcome": "ACCEPTED_PROJECTION_MATCH",
        "expected_error_category": "NONE",
        "expected_error_code": "NONE",
    },
    {
        "sequence": 10,
        "attempt_id": "P2-CE-004-P05-MUTANT-VALUE-REHASH",
        "pair_id": "P05",
        "control_kind": "MUTANT",
        "mutation_id": "FEATURE_VALUE_REHASH",
        "expected_stage": "REFERENCE_PROJECTION",
        "expected_outcome": "BLOCKED_REFERENCE_PROJECTION",
        "expected_error_category": "REFERENCE",
        "expected_error_code": "REFERENCE_FEATURE_PROJECTION_MISMATCH",
    },
    {
        "sequence": 11,
        "attempt_id": "P2-CE-004-P06-CLEAN",
        "pair_id": "P06",
        "control_kind": "CLEAN",
        "mutation_id": "NONE",
        "expected_stage": "REFERENCE_PROJECTION",
        "expected_outcome": "ACCEPTED_PROJECTION_MATCH",
        "expected_error_category": "NONE",
        "expected_error_code": "NONE",
    },
    {
        "sequence": 12,
        "attempt_id": "P2-CE-004-P06-MUTANT-TRACE-REHASH",
        "pair_id": "P06",
        "control_kind": "MUTANT",
        "mutation_id": "FEATURE_TRACE_REHASH",
        "expected_stage": "REFERENCE_PROJECTION",
        "expected_outcome": "BLOCKED_REFERENCE_PROJECTION",
        "expected_error_category": "REFERENCE",
        "expected_error_code": "REFERENCE_FEATURE_PROJECTION_MISMATCH",
    },
    {
        "sequence": 13,
        "attempt_id": "P2-CE-004-P07-CLEAN",
        "pair_id": "P07",
        "control_kind": "CLEAN",
        "mutation_id": "NONE",
        "expected_stage": "REFERENCE_PROJECTION",
        "expected_outcome": "ACCEPTED_PROJECTION_MATCH",
        "expected_error_category": "NONE",
        "expected_error_code": "NONE",
    },
    {
        "sequence": 14,
        "attempt_id": "P2-CE-004-P07-MUTANT-ORDER-REHASH",
        "pair_id": "P07",
        "control_kind": "MUTANT",
        "mutation_id": "INPUT_EVENT_ORDER_REHASH",
        "expected_stage": "REFERENCE_PROJECTION",
        "expected_outcome": "BLOCKED_REFERENCE_PROJECTION",
        "expected_error_category": "REFERENCE",
        "expected_error_code": "REFERENCE_FEATURE_PROJECTION_MISMATCH",
    },
    {
        "sequence": 15,
        "attempt_id": "P2-CE-004-P08-CLEAN",
        "pair_id": "P08",
        "control_kind": "CLEAN",
        "mutation_id": "NONE",
        "expected_stage": "REFERENCE_PROJECTION",
        "expected_outcome": "ACCEPTED_PROJECTION_MATCH",
        "expected_error_category": "NONE",
        "expected_error_code": "NONE",
    },
    {
        "sequence": 16,
        "attempt_id": "P2-CE-004-P08-MUTANT-REPLACEMENT-REHASH",
        "pair_id": "P08",
        "control_kind": "MUTANT",
        "mutation_id": "CROSS_CASE_VALUES_REHASH",
        "expected_stage": "REFERENCE_PROJECTION",
        "expected_outcome": "BLOCKED_REFERENCE_PROJECTION",
        "expected_error_category": "REFERENCE",
        "expected_error_code": "REFERENCE_FEATURE_PROJECTION_MISMATCH",
    },
)


def _json_bytes(value: Any) -> bytes:
    return (json.dumps(value, indent=2, sort_keys=True, allow_nan=False) + "\n").encode(
        "utf-8"
    )


def _jsonl_bytes(rows: list[dict[str, Any]]) -> bytes:
    return b"".join(
        (
            json.dumps(
                row,
                separators=(",", ":"),
                sort_keys=True,
                allow_nan=False,
            )
            + "\n"
        ).encode("utf-8")
        for row in rows
    )


def _canonical_bytes(value: Any) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode("utf-8")


def _canonical_digest(value: Any) -> str:
    return hashlib.sha256(_canonical_bytes(value)).hexdigest()


def _sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _canonical_utc(value: str) -> datetime:
    if not CANONICAL_UTC_PATTERN.fullmatch(value):
        raise CampaignGenerationError(
            "evaluated_at must use canonical UTC seconds (YYYY-MM-DDTHH:MM:SSZ)."
        )
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError:
        raise CampaignGenerationError(
            "evaluated_at is not a valid timestamp."
        ) from None
    return parsed.astimezone(timezone.utc)


def _load_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(
            path.read_text(encoding="utf-8"),
            object_pairs_hook=_reject_duplicate_json_pairs,
            parse_constant=_reject_nonstandard_number,
            parse_float=_parse_finite_json_float,
        )
        _assert_finite_json_numbers(value)
    except (
        OSError,
        UnicodeError,
        json.JSONDecodeError,
        _DuplicateJSONMember,
        ValueError,
    ) as exc:
        raise CampaignGenerationError(
            f"Unable to decode required JSON: {path.name}"
        ) from exc
    if not isinstance(value, dict):
        raise CampaignGenerationError(f"Required JSON is not an object: {path.name}")
    return value


def _source_bindings() -> list[dict[str, str]]:
    bindings: list[dict[str, str]] = []
    for role, relative in sorted(CAMPAIGN_SOURCE_PATHS.items()):
        path = ROOT / relative
        if not path.is_file():
            raise CampaignGenerationError(
                f"Missing required campaign source: {relative}"
            )
        bindings.append(
            {"role": role, "path": relative, "sha256": _sha256_bytes(path.read_bytes())}
        )
    return bindings


def _runtime_fingerprint() -> dict[str, str]:
    try:
        jsonschema_version = importlib.metadata.version("jsonschema")
        numpy_version = importlib.metadata.version("numpy")
    except importlib.metadata.PackageNotFoundError:
        raise CampaignGenerationError(
            "Required campaign dependency metadata is unavailable."
        ) from None
    fingerprint = {
        "python_implementation": platform.python_implementation(),
        "python_version": platform.python_version(),
        "jsonschema_version": jsonschema_version,
        "numpy_version": numpy_version,
        "platform_system": platform.system(),
        "platform_release": platform.release(),
        "platform_machine": platform.machine(),
    }
    for key, value in fingerprint.items():
        if not re.fullmatch(r"[0-9A-Za-z._+-]{1,128}", value):
            raise CampaignGenerationError(
                f"Runtime fingerprint field is not sanitized: {key}"
            )
    return fingerprint


def _validate_campaign_artifact(value: dict[str, Any]) -> None:
    schema = _load_json(CAMPAIGN_SCHEMA)
    validator = Draft202012Validator(schema)
    errors = sorted(validator.iter_errors(value), key=lambda item: list(item.path))
    if errors:
        location = ".".join(str(part) for part in errors[0].absolute_path) or "$"
        raise CampaignGenerationError(
            f"Generated campaign artifact is invalid at {location}: "
            f"{errors[0].message}"
        )


def load_and_validate_plan() -> dict[str, Any]:
    plan = _load_json(CAMPAIGN_PLAN)
    _validate_campaign_artifact(plan)
    if plan.get("expected_attempts") != list(EXPECTED_ATTEMPTS):
        raise CampaignGenerationError(
            "Campaign plan does not match the code-owned 16-attempt registry."
        )
    configuration = plan["configuration_binding"]["configuration"]
    if plan["configuration_binding"]["canonical_sha256"] != _canonical_digest(
        configuration
    ):
        raise CampaignGenerationError("Campaign configuration digest is stale.")
    if [row["sequence"] for row in EXPECTED_ATTEMPTS] != list(range(1, 17)):
        raise CampaignGenerationError("Campaign attempt sequence is not exact.")
    if len({row["attempt_id"] for row in EXPECTED_ATTEMPTS}) != 16:
        raise CampaignGenerationError("Campaign attempt identifiers are not unique.")
    if sum(row["control_kind"] == "CLEAN" for row in EXPECTED_ATTEMPTS) != 8:
        raise CampaignGenerationError(
            "Campaign must contain exactly eight clean controls."
        )
    if sum(row["expected_outcome"] == "QUARANTINED" for row in EXPECTED_ATTEMPTS) != 4:
        raise CampaignGenerationError(
            "Campaign must contain four qualification quarantines."
        )
    if (
        sum(
            row["expected_outcome"] == "BLOCKED_REFERENCE_PROJECTION"
            for row in EXPECTED_ATTEMPTS
        )
        != 4
    ):
        raise CampaignGenerationError("Campaign must contain four reference blocks.")
    return plan


def build_profile(implementation_commit: str, evaluated_at: str) -> dict[str, Any]:
    if not IMPLEMENTATION_COMMIT_PATTERN.fullmatch(implementation_commit):
        raise CampaignGenerationError(
            "implementation_commit must be a lowercase 40-character Git SHA."
        )
    _canonical_utc(evaluated_at)
    plan = load_and_validate_plan()
    profile = copy.deepcopy(plan)
    profile["artifact_kind"] = "CAMPAIGN_PROFILE"
    profile["campaign_plan_sha256"] = _sha256_bytes(CAMPAIGN_PLAN.read_bytes())
    profile["implementation_commit"] = implementation_commit
    profile["evaluated_at"] = evaluated_at
    profile["runtime_fingerprint"] = _runtime_fingerprint()
    profile["source_bindings"] = _source_bindings()
    _validate_campaign_artifact(profile)
    return profile


def _event(case_id: str, source_type: str, minute: int) -> dict[str, Any]:
    suffix = "cti" if source_type == "threat_intel" else source_type
    return {
        "event_id": f"evt-{case_id}-{suffix}",
        "case_id": case_id,
        "source_type": source_type,
        "source_instance": f"synthetic-{suffix}-01",
        "observed_at": f"2026-01-15T12:{minute:02d}:00Z",
        "collected_at": f"2026-01-15T12:{minute:02d}:01Z",
        "integrity": "verified",
        "provenance_id": f"prov-{case_id}-{suffix}",
        "trust_score": 0.95,
        "entity_refs": [f"subject-{case_id}", f"asset-{case_id}"],
        "attributes": {},
        "untrusted_text": "",
        "contains_instructional_content": False,
    }


def _base_case(attempt_id: str, pair_id: str) -> dict[str, Any]:
    seeded_suffix = hashlib.sha256(
        f"{CAMPAIGN_SEED}:{attempt_id}".encode("utf-8")
    ).hexdigest()[:8]
    case_id = f"feature-campaign-{pair_id.lower()}-{seeded_suffix}"
    events = [
        _event(case_id, "identity", 0),
        _event(case_id, "endpoint", 1),
        _event(case_id, "network", 2),
        _event(case_id, "threat_intel", 3),
        _event(case_id, "asset_inventory", 4),
    ]
    inventory = events[-1]["attributes"]
    inventory.update(
        {
            "asset_id": f"asset-{case_id}",
            "privilege_level": "standard_user",
            "break_glass": False,
            "asset_criticality": 0.4,
        }
    )
    case = {
        "schema_version": "0.2.0",
        "case_id": case_id,
        "opened_at": "2026-01-15T12:00:00Z",
        "subject_id": f"subject-{case_id}",
        "privilege_level": "standard_user",
        "break_glass": False,
        "asset_id": f"asset-{case_id}",
        "asset_criticality": 0.4,
        "events": events,
    }
    by_source = {row["source_type"]: row for row in events}
    if pair_id == "P01":
        by_source["identity"]["attributes"]["new_device"] = False
    elif pair_id == "P02":
        by_source["identity"]["attributes"]["failed_logins"] = 0
    elif pair_id == "P05":
        by_source["network"]["attributes"]["threat_ip"] = True
        by_source["threat_intel"]["attributes"]["threat_ip"] = True
    elif pair_id == "P06":
        by_source["identity"]["attributes"]["token_reuse"] = True
    elif pair_id == "P07":
        by_source["identity"]["attributes"]["failed_logins"] = 10
        by_source["network"]["attributes"]["known_vpn"] = True
    elif pair_id == "P08":
        by_source["identity"]["attributes"]["new_device"] = True
        by_source["endpoint"]["attributes"]["unusual_admin_action"] = True
    return case


def _event_by_source(case: dict[str, Any], source_type: str) -> dict[str, Any]:
    return next(row for row in case["events"] if row["source_type"] == source_type)


def _apply_input_mutation(case: dict[str, Any], mutation_id: str) -> None:
    if mutation_id in {
        "NONE",
        "FEATURE_VALUE_REHASH",
        "FEATURE_TRACE_REHASH",
        "INPUT_EVENT_ORDER_REHASH",
        "CROSS_CASE_VALUES_REHASH",
    }:
        return
    if mutation_id == "BOOLEAN_STRING":
        _event_by_source(case, "identity")["attributes"]["new_device"] = "false"
    elif mutation_id == "COUNT_NAN_STRING":
        _event_by_source(case, "identity")["attributes"]["failed_logins"] = "nan"
    elif mutation_id == "UNAUTHORIZED_THREAT_SOURCE":
        _event_by_source(case, "endpoint")["attributes"]["threat_ip"] = True
    elif mutation_id == "UNAUTHORIZED_BENIGN_SOURCE":
        _event_by_source(case, "identity")["attributes"]["known_vpn"] = True
    else:
        raise CampaignGenerationError("Unknown input mutation.")


def _production_projection(case: dict[str, Any]) -> dict[str, Any]:
    materialized = copy.deepcopy(case)
    materialized.pop("schema_version", None)
    identity_case = IdentityCase.from_dict(materialized)
    values, trace = extract_features(identity_case)
    rounded = {name: round(float(values[name]), 6) for name in FEATURE_NAMES}
    return {
        "case_id": identity_case.case_id,
        "model_assessment": {
            "feature_values": rounded,
            "feature_trace": copy.deepcopy(trace),
        },
        "traceability": {
            "feature_trace": copy.deepcopy(trace),
            "input_event_ids": [event.event_id for event in identity_case.events],
        },
    }


def _rehash_projection(decision: dict[str, Any]) -> None:
    decision.pop("decision_record_hash", None)
    decision["decision_record_hash"] = _canonical_digest(decision)


def _apply_projection_mutation(
    decision: dict[str, Any],
    case: dict[str, Any],
    mutation_id: str,
) -> bool:
    if mutation_id not in {
        "FEATURE_VALUE_REHASH",
        "FEATURE_TRACE_REHASH",
        "INPUT_EVENT_ORDER_REHASH",
        "CROSS_CASE_VALUES_REHASH",
    }:
        return False
    if mutation_id == "FEATURE_VALUE_REHASH":
        decision["model_assessment"]["feature_values"]["threat_ip"] = 0.0
    elif mutation_id == "FEATURE_TRACE_REHASH":
        endpoint_id = _event_by_source(case, "endpoint")["event_id"]
        decision["model_assessment"]["feature_trace"]["token_reuse"] = [endpoint_id]
        decision["traceability"]["feature_trace"]["token_reuse"] = [endpoint_id]
    elif mutation_id == "INPUT_EVENT_ORDER_REHASH":
        decision["traceability"]["input_event_ids"].reverse()
    else:
        donor = _base_case("P2-CE-004-P05-DONOR", "P05")
        donor_projection = _production_projection(donor)
        decision["model_assessment"]["feature_values"] = copy.deepcopy(
            donor_projection["model_assessment"]["feature_values"]
        )
    _rehash_projection(decision)
    return True


def _result_matches(expected: dict[str, Any], observed: dict[str, Any]) -> bool:
    exact_fields = (
        "sequence",
        "attempt_id",
        "pair_id",
        "control_kind",
        "mutation_id",
        "expected_stage",
        "expected_outcome",
        "expected_error_category",
        "expected_error_code",
    )
    if any(observed.get(field) != expected.get(field) for field in exact_fields):
        return False
    if (
        observed.get("observed_outcome") != expected.get("expected_outcome")
        or observed.get("observed_error_category")
        != expected.get("expected_error_category")
        or observed.get("observed_error_code") != expected.get("expected_error_code")
    ):
        return False
    if expected["expected_outcome"] == "QUARANTINED":
        stage_counts = (1, 0, 1, 0, 0)
    elif expected["expected_outcome"] == "ACCEPTED_PROJECTION_MATCH":
        stage_counts = (1, 1, 0, 1, 1)
    else:
        stage_counts = (1, 1, 0, 1, 1)
    observed_counts = (
        observed.get("qualifier_calls"),
        observed.get("accepted_records"),
        observed.get("quarantined_records"),
        observed.get("production_projector_calls"),
        observed.get("reference_projector_calls"),
    )
    zero_fields = (
        "model_calls",
        "policy_calls",
        "verifier_calls",
        "engine_calls",
        "authorization_attempts",
        "broker_invocations",
        "target_effect_calls",
        "operational_effects",
        "decision_artifact_write_calls",
        "audit_artifact_write_calls",
        "run_manifest_write_calls",
    )
    return (
        observed.get("input_records") == 1
        and observed_counts == stage_counts
        and all(observed.get(field) == 0 for field in zero_fields)
        and observed.get("mutation_applications")
        == (0 if expected["control_kind"] == "CLEAN" else 1)
        and observed.get("local_rehash_applied")
        == expected["mutation_id"].endswith("REHASH")
        and observed.get("production_projection_created")
        == (expected["expected_outcome"] != "QUARANTINED")
        and observed.get("projection_attempted")
        == (expected["expected_outcome"] != "QUARANTINED")
        and observed.get("reference_projection_passed")
        == (expected["expected_outcome"] == "ACCEPTED_PROJECTION_MATCH")
    )


def _run_attempt(expected: dict[str, Any]) -> dict[str, Any]:
    case = _base_case(expected["attempt_id"], expected["pair_id"])
    _apply_input_mutation(case, expected["mutation_id"])
    raw = _canonical_bytes(case) + b"\n"
    synthetic_input_sha256 = _sha256_bytes(raw)
    counters = {
        "qualifier_calls": 1,
        "production_projector_calls": 0,
        "reference_projector_calls": 0,
        "model_calls": 0,
        "policy_calls": 0,
        "verifier_calls": 0,
        "engine_calls": 0,
        "authorization_attempts": 0,
        "broker_invocations": 0,
        "target_effect_calls": 0,
        "operational_effects": 0,
    }
    qualification = qualify_case_bytes(
        raw,
        synthetic_input_sha256,
        dataset_id="p2-ce-004-synthetic-feature-assurance",
    )
    accepted = qualification.accepted_record_count
    quarantined = qualification.rejected_record_count
    observed_outcome = "UNEXPECTED_FAILURE"
    observed_error_category = "NONE"
    observed_error_code = "NONE"
    projection_attempted = False
    production_projection_created = False
    reference_projection_passed = False
    local_rehash_applied = False
    qualified_case_sha256 = ZERO_SHA256
    presented_projection_sha256 = ZERO_SHA256
    reference_receipt_sha256 = ZERO_SHA256

    if quarantined == 1 and accepted == 0:
        rejection = qualification.rejection_records[0]
        observed_outcome = "QUARANTINED"
        observed_error_category = str(rejection["error_category"])
        observed_error_code = str(rejection["error_code"])
    elif accepted == 1 and quarantined == 0:
        accepted_case = copy.deepcopy(qualification.accepted_records[0])
        accepted_case.pop("schema_version", None)
        qualified_case_sha256 = _canonical_digest(accepted_case)
        counters["production_projector_calls"] = 1
        decision = _production_projection(accepted_case)
        production_projection_created = True
        local_rehash_applied = _apply_projection_mutation(
            decision,
            accepted_case,
            expected["mutation_id"],
        )
        presented_projection_sha256 = _canonical_digest(decision)
        projection_attempted = True
        counters["reference_projector_calls"] = 1
        try:
            receipts = verify_reference_feature_projections([accepted_case], [decision])
        except ReferenceFeatureAssuranceError as exc:
            observed_outcome = "BLOCKED_REFERENCE_PROJECTION"
            observed_error_category = "REFERENCE"
            observed_error_code = exc.code
        else:
            observed_outcome = "ACCEPTED_PROJECTION_MATCH"
            reference_projection_passed = True
            reference_receipt_sha256 = _canonical_digest(receipts)

    result = {
        "artifact_kind": "CAMPAIGN_RESULT",
        "schema_version": CAMPAIGN_SCHEMA_VERSION,
        "campaign_id": CAMPAIGN_ID,
        **copy.deepcopy(expected),
        "observed_outcome": observed_outcome,
        "observed_error_category": observed_error_category,
        "observed_error_code": observed_error_code,
        "input_records": 1,
        "accepted_records": accepted,
        "quarantined_records": quarantined,
        "projection_attempted": projection_attempted,
        "production_projection_created": production_projection_created,
        "reference_projection_passed": reference_projection_passed,
        "local_rehash_applied": local_rehash_applied,
        "mutation_applications": 0 if expected["control_kind"] == "CLEAN" else 1,
        "synthetic_input_sha256": synthetic_input_sha256,
        "qualified_case_sha256": qualified_case_sha256,
        "presented_projection_sha256": presented_projection_sha256,
        "reference_receipt_sha256": reference_receipt_sha256,
        **counters,
        # These are scoped code-path call counters.  They are not filesystem or
        # OS-level nonaccess observations.
        "decision_artifact_write_calls": 0,
        "audit_artifact_write_calls": 0,
        "run_manifest_write_calls": 0,
    }
    result["matched"] = _result_matches(expected, result)
    _validate_campaign_artifact(result)
    return result


def run_campaign(profile: dict[str, Any]) -> list[dict[str, Any]]:
    if profile.get("expected_attempts") != list(EXPECTED_ATTEMPTS):
        raise CampaignGenerationError("Campaign profile attempt registry drifted.")
    results = [_run_attempt(expected) for expected in EXPECTED_ATTEMPTS]
    failed = [row["attempt_id"] for row in results if not row["matched"]]
    if failed:
        raise CampaignGenerationError(
            "Campaign did not match its frozen outcomes: " + ", ".join(failed)
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
    try:
        profile = json.loads(
            profile_bytes,
            object_pairs_hook=_reject_duplicate_json_pairs,
            parse_constant=_reject_nonstandard_number,
            parse_float=_parse_finite_json_float,
        )
        _assert_finite_json_numbers(profile)
    except (
        UnicodeError,
        json.JSONDecodeError,
        _DuplicateJSONMember,
        ValueError,
    ) as exc:
        raise CampaignGenerationError(
            "Unable to decode generated campaign profile JSON."
        ) from exc
    if not isinstance(profile, dict):
        raise CampaignGenerationError("Generated campaign profile is not an object.")
    rows = results_run1 + results_run2
    zero_fields = (
        "model_calls",
        "policy_calls",
        "verifier_calls",
        "engine_calls",
        "authorization_attempts",
        "broker_invocations",
        "target_effect_calls",
        "operational_effects",
        "decision_artifact_write_calls",
        "audit_artifact_write_calls",
        "run_manifest_write_calls",
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
        "run_receipts": [
            {
                "run_id": "RUN_1",
                "result_ledger_sha256": _sha256_bytes(results_run1_bytes),
            },
            {
                "run_id": "RUN_2",
                "result_ledger_sha256": _sha256_bytes(results_run2_bytes),
            },
        ],
        "raw_outcomes": {
            "denominator": 32,
            "matched": sum(bool(row["matched"]) for row in rows),
            "mismatched": sum(not row["matched"] for row in rows),
            "excluded": 0,
        },
        "stage_outcomes": {
            "accepted_projection_match": sum(
                row["observed_outcome"] == "ACCEPTED_PROJECTION_MATCH" for row in rows
            ),
            "quarantined": sum(
                row["observed_outcome"] == "QUARANTINED" for row in rows
            ),
            "blocked_reference_projection": sum(
                row["observed_outcome"] == "BLOCKED_REFERENCE_PROJECTION"
                for row in rows
            ),
        },
        "zero_effect_assurance": {
            field: sum(int(row[field]) for row in rows) for field in zero_fields
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


def build_campaign_artifacts(
    implementation_commit: str,
    evaluated_at: str,
) -> tuple[bytes, bytes, bytes, bytes]:
    profile = build_profile(implementation_commit, evaluated_at)
    profile_bytes = _json_bytes(profile)
    run1 = run_campaign(profile)
    run2 = run_campaign(profile)
    run1_bytes = _jsonl_bytes(run1)
    run2_bytes = _jsonl_bytes(run2)
    if run1_bytes != run2_bytes:
        raise CampaignGenerationError(
            "Two complete campaign runs did not produce byte-identical ledgers."
        )
    summary = build_summary(
        profile_bytes,
        run1_bytes,
        run2_bytes,
        run1,
        run2,
        evaluated_at=evaluated_at,
    )
    _validate_campaign_artifact(summary)
    summary_bytes = _json_bytes(summary)
    public = b"\n".join((profile_bytes, run1_bytes, run2_bytes, summary_bytes))
    if any(token in public for token in PROHIBITED_PUBLIC_FIELDS):
        raise CampaignGenerationError(
            "Sanitized campaign output contains prohibited content."
        )
    return profile_bytes, run1_bytes, run2_bytes, summary_bytes


def _write_bytes(path: Path, payload: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(payload)


def _evidence_artifact(
    *,
    role: str,
    path: Path,
    record_count: int | None = None,
) -> dict[str, Any]:
    try:
        relative = path.resolve().relative_to(ROOT.resolve())
    except ValueError:
        raise CampaignGenerationError(
            "Evidence artifacts must remain within the repository."
        ) from None
    value: dict[str, Any] = {
        "artifact_role": role,
        "path": str(relative),
        "sha256": _sha256_bytes(path.read_bytes()),
        "deterministic": True,
        "committed": True,
        "custody_notes": (
            "Project-controlled synthetic campaign artifact; Git retention is not "
            "independent, externally signed, or WORM custody."
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
    """Build the closed CE-2 record after all four campaign artifacts exist."""

    if not IMPLEMENTATION_COMMIT_PATTERN.fullmatch(implementation_commit):
        raise CampaignGenerationError("Evidence record commit is invalid.")
    evaluated = _canonical_utc(evaluated_at)
    profile_path = output_dir / "campaign_profile.json"
    run1_path = output_dir / "campaign_results_run1.jsonl"
    run2_path = output_dir / "campaign_results_run2.jsonl"
    summary_path = output_dir / "campaign_summary.json"
    required = (profile_path, run1_path, run2_path, summary_path)
    if any(not path.is_file() for path in required):
        raise CampaignGenerationError(
            "Complete campaign artifacts are required before evidence finalization."
        )
    profile = _load_json(profile_path)
    summary = _load_json(summary_path)
    if (
        profile.get("implementation_commit") != implementation_commit
        or profile.get("evaluated_at") != evaluated_at
        or summary.get("evaluated_at") != evaluated_at
        or summary.get("raw_outcomes")
        != {"denominator": 32, "excluded": 0, "matched": 32, "mismatched": 0}
        or summary.get("stage_outcomes")
        != {
            "accepted_projection_match": 16,
            "blocked_reference_projection": 8,
            "quarantined": 8,
        }
    ):
        raise CampaignGenerationError(
            "Campaign artifacts are not eligible for CE-2 finalization."
        )
    sources = {row["role"]: row for row in profile["source_bindings"]}
    production = sources["ADF_SRC_ADF_POC_FEATURES_PY"]
    reference = sources["ADF_SRC_ADF_POC_REPLAY_REFERENCE_FEATURES_PY"]
    runtime = profile["runtime_fingerprint"]
    expires = (evaluated + timedelta(days=90)).isoformat().replace("+00:00", "Z")

    record = _load_json(EVIDENCE_TEMPLATE)
    record.update(
        {
            "evidence_record_id": "EV-P2-FEATURE-ASSURANCE-CE2-004",
            "claim_id": CLAIM_ID,
            "claim_text": (
                "Two deterministic repetitions of the fixed sixteen-attempt "
                "synthetic feature-assurance campaign matched all thirty-two "
                "project-authored expected outcomes."
            ),
            "claim_class": "CONTROLLED_BEHAVIOR",
            "claim_status": "OBSERVED",
            "evaluated_at": evaluated_at,
        }
    )
    record["system_under_test"] = {
        "release_version": PACKAGE_VERSION,
        "source_reference": (
            f"Git commit {implementation_commit} "
            f"(https://github.com/redxking/ai-decision-firewall/commit/{implementation_commit}); "
            "campaign_profile.json binds every in-repo Python package source plus "
            "the campaign, validator, contracts, dependency declarations, and runtime."
        ),
        "component_kind": "DETERMINISTIC_PIPELINE",
        "execution_mode": "historical_replay",
        # The evidence schema requires model/policy artifact slots.  For this
        # model-free campaign they bind the production and reference projectors.
        "model": {"path": production["path"], "sha256": production["sha256"]},
        "reasoning_setting": (
            "The evidence contract requires model and policy artifact-reference slots; "
            "for this model-free campaign they bind the production feature projector "
            "and the in-process reference projector respectively. No model or policy "
            "engine is invoked."
        ),
        "policy": {"path": reference["path"], "sha256": reference["sha256"]},
        "contract_version": "0.2.0",
        "adapter": "fixed generated canonical JSON record per attempt",
        "harness": (
            "scripts/generate_feature_assurance_ce2_campaign.py with the exact "
            "commit-frozen plan, source digests, order, budget, and closed schema"
        ),
        "permissions": [
            "fixed in-memory project-controlled synthetic inputs only",
            "sanitized enumerated metadata and digest outputs only",
            "network capability conservatively treated as available but unverified",
            "no arbitrary input, arbitrary output, action credential, approval, or target permission",
        ],
        "safeguards": [
            "live actions and the decision engine disabled by configuration",
            "typed source-authorized production feature boundary",
            "separately implemented reference feature projector",
            "closed plan, profile, result, and summary schemas",
            "fresh frozen-evaluator recomputation by the claim validator",
            "abort without evidence and zero retries on any mismatch",
        ],
    }
    record["evaluation_scope"] = {
        "data_origin": "SYNTHETIC_FIXTURE",
        "historical_case_count": 0,
        "case_count": 32,
        "adjudicated_case_count": 0,
        "time_window": f"One fixed deterministic campaign recorded at {evaluated_at}.",
        "sample_selection_method": (
            "Two same-process deterministic repetitions of the same fixed sixteen "
            "project-selected scenarios: eight clean controls, four qualification "
            "mutants, and four projection mutants per repetition."
        ),
        "network_access": True,
        "action_credentials_present": False,
        "tools": [
            "local Python process",
            "in-memory synthetic case generator",
            "built-in qualifier and production feature projector",
            "separately implemented in-process standard-library reference projector",
        ],
    }
    record["evaluation_environment"] = {
        "isolation_boundary": (
            "Ordinary local Python process; no VM, container, or OS-enforced sandbox "
            "claim is made."
        ),
        "network_egress": (
            "The campaign has no network client path. OS-level egress denial and "
            "process-wide network nonuse were not independently attested, so network "
            "capability is conservatively reported as available."
        ),
        "dependency_access": (
            "Bound evaluation runtime: "
            f"{runtime['python_implementation']} {runtime['python_version']}; "
            f"jsonschema {runtime['jsonschema_version']}; "
            f"NumPy {runtime['numpy_version']}; "
            f"{runtime['platform_system']} {runtime['platform_release']} "
            f"{runtime['platform_machine']}. Dependencies were installed before "
            "evaluation; no package installation or plugin discovery occurred."
        ),
        "credentials_and_canaries": (
            "No action credential, organizational approval package, production secret, "
            "external evaluator credential, or secret canary was intentionally used."
        ),
        "tenant_separation": "Not applicable to the local synthetic campaign.",
        "monitoring": (
            "Code-owned counters cover direct qualifier, production projector, "
            "reference projector, mutation, and unreachable downstream write/action "
            "calls. They are scoped call observations, not OS-level nonaccess proof."
        ),
        "containment_and_kill_switch": (
            "The operator could terminate the local process; no external target existed."
        ),
        "residual_risks": [
            "arbitrary same-process Python is outside the controlled call boundary",
            "network nonuse and filesystem nonaccess are not independently attested",
            "the evaluator, expectations, artifacts, and review are project-controlled",
        ],
    }
    record["budget"] = {
        "evaluation_runs": 2,
        "case_evaluations": 32,
        "retries": 0,
        "turns": None,
        "tokens": None,
        "wall_time_seconds": None,
        "resource_limits": [
            "two deterministic same-process repetitions",
            "sixteen fixed attempts per repetition and thirty-two total",
            "zero retries and no post-freeze exclusions",
            "zero permitted model, policy, verifier, engine, authorization, broker, or target calls",
            "failure aborts before any CE-2 package is finalizable",
        ],
        "human_assistance": (
            "Maintainers froze the implementation and plan before the final run; no "
            "human altered an attempt or outcome during evaluation."
        ),
        "notes": (
            "The two repetitions are not independent statistical trials. Turn, token, "
            "and wall-time budgets are not used as claims."
        ),
    }
    record["evaluation_design"] = {
        "threat_model": (
            "Open or weakly typed event attributes, unauthorized source assertions, or "
            "coherently rehashed feature artifacts could silently change model-driving "
            "inputs or defeat a downstream integrity-only check."
        ),
        "scenarios": [row["attempt_id"] for row in EXPECTED_ATTEMPTS],
        "scenario_distribution": (
            "Exactly sixteen project-selected deterministic scenarios repeated twice: "
            "eight clean controls, four typed or source-authority qualification "
            "mutants, and four locally rehashed projection mutants."
        ),
        "controls": [
            "clean control paired with every mutant",
            "exact qualification category and stable code checks",
            "separately implemented in-process reference projection comparison",
            "fresh validator re-execution against both committed ledgers",
        ],
        "safe_alternatives": [
            "ACCEPTED_PROJECTION_MATCH",
            "QUARANTINED before production projection",
            "BLOCKED_REFERENCE_PROJECTION before any downstream engine",
        ],
        "elicitation": (
            "Fixed deterministic generation and mutation in frozen order; no prompting, "
            "adaptive search, retry, model-based attacker, or post-run exclusion."
        ),
        "prompts_or_inputs_reference": (
            "The generated inputs are code-owned by the bound campaign generator; "
            "public artifacts retain only attempt metadata and SHA-256 receipts."
        ),
        "monitoring_visibility": (
            "Exact qualification outcome codes, reference projector error code, scoped "
            "call counters, and digests without raw cases, values, or traces."
        ),
        "evaluation_framing": "Explicit synthetic typed-feature and projection-assurance campaign.",
        "deployment_framing": "None; no historical pilot, live shadow feed, or action path.",
        "seeds": [CAMPAIGN_SEED],
        "validity_checks": [
            "seed deterministically changes private synthetic case identifiers",
            "closed schema and exact code-owned sixteen-attempt registry",
            "exact 16 = 8 clean + 4 qualification blocks + 4 reference blocks per run",
            "two byte-identical sanitized ledgers with zero retries and exclusions",
            "all transitive in-repo package sources and dependency declarations bound",
            "fresh claim-validator re-execution rejects coherent dual-ledger rewrite",
        ],
    }
    record["monitoring_design"] = {
        "status": "NOT_APPLICABLE",
        "agent_monitor_pair": (
            "No generative actor or model-based monitor; the separately implemented "
            "in-process deterministic projector is a campaign oracle, not an "
            "operational or organizationally independent monitor."
        ),
        "observation_scope": (
            "Sanitized outcome codes, digests, and direct code-path counters only; no "
            "chain of thought, raw case, feature value, or feature trace is retained."
        ),
        "test_classes": [
            "clean metamorphic controls",
            "typed and source-authority qualification mutants",
            "coherently rehashed value, trace, event-order, and cross-case-value mutants",
        ],
        "intervention_authority": (
            "Any mismatch aborts finalization; no deployed session exists."
        ),
        "version_drift_plan": (
            "Any bound source, dependency declaration, schema, plan, runtime, seed, "
            "budget, wording, or result change invalidates the record."
        ),
    }
    record["scoring_and_adjudication"] = {
        "objective_outcome_checks": [
            "eight clean qualification and reference matches per run",
            "four exact typed or source-authority quarantines per run",
            "four exact generic reference projection blocks per run",
            "zero scoped downstream component, write, authorization, broker, target, and effect calls",
            "fresh frozen-evaluator recomputation matches both byte-identical ledgers",
        ],
        "grader_identity_and_version": (
            "Closed feature-assurance campaign schema 1.0.0 and P2-CE-004 validator profile"
        ),
        "automated_grader_validation": (
            "Project tests alter plan, schema, outcomes, codes, counters, hashes, both "
            "ledgers, summaries, source bindings, and public wording. The grader is "
            "project-controlled and not independently benchmarked."
        ),
        "consequence_weighting": (
            "Any unexpected acceptance, quarantine, reference pass, call reach, "
            "missing attempt, retry, exclusion, source drift, or receipt mismatch fails "
            "the campaign and authorizes no CE-2 evidence."
        ),
        "human_protocol": (
            "No independent human adjudication; automated project-controlled SELF "
            "review reconciles the frozen registry and artifacts."
        ),
        "ground_truth_status": (
            "Project-authored synthetic expected outcomes only; no historical, "
            "organizational, or operational ground truth."
        ),
        "disagreement_treatment": "No independent adjudicator participated.",
        "exclusion_rules": "No exclusions; all thirty-two attempts remain in the denominator.",
        "failure_examples": [],
    }
    record["research_basis"] = {
        "coverage_register": "docs/phase2/RESEARCH_COVERAGE_REGISTER.md",
        "reviewed_through": "2026-08-15",
        "applicable_families": [
            "claim-validity and broken-task review",
            "typed evidence and source-authority boundaries",
            "coherent artifact and oversight-path manipulation",
            "diverse in-process evaluator implementation",
            "scoped no-effect and evidence-boundary reporting",
        ],
        "not_yet_evaluated": [
            "historical or live data performance",
            "adaptive automated red teaming",
            "monitor recall, false negatives, and collusion",
            "agentic misalignment, scheming, sabotage, or sandbagging",
            "OS-enforced containment and independently attested network nonuse",
        ],
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
            "The thirty-two observations are two same-process deterministic "
            "repetitions of sixteen project-selected scenarios, not independent or "
            "representative trials. They do not estimate operational failure risk."
        ),
        "deviations_from_plan": [],
    }
    record["validity_assessment"] = {
        "reward_hacking": {
            "status": "NOT_CHECKED",
            "notes": "No adaptive agent or reward campaign.",
        },
        "evaluation_awareness": {
            "status": "NOT_APPLICABLE",
            "notes": "No generative or strategically reasoning actor.",
        },
        "contamination": {
            "status": "NOT_APPLICABLE",
            "notes": "Fixed regression scenarios, not a held-out distribution.",
        },
        "refusals": {
            "status": "NOT_APPLICABLE",
            "notes": "No natural-language refusal behavior.",
        },
        "broken_problems": {
            "status": "CHECKED_NOT_OBSERVED",
            "notes": "Closed schema, exact registry, source bindings, denominators, receipts, and fresh recomputation were checked.",
        },
        "sandbagging": {
            "status": "NOT_APPLICABLE",
            "notes": "No strategically reasoning model was evaluated.",
        },
        "label_or_answer_leakage": {
            "status": "CHECKED_NOT_OBSERVED",
            "notes": "Expectations drive scoring only; they are not supplied to qualification or projection APIs.",
        },
        "scorer_or_harness_exploitation": {
            "status": "CHECKED_NOT_OBSERVED",
            "notes": "Known artifact mutations are rejected; no adaptive exploit campaign was run.",
        },
        "actor_monitor_collusion": {
            "status": "NOT_APPLICABLE",
            "notes": "No actor-monitor pair exists.",
        },
    }
    record["evidence_artifacts"] = [
        _evidence_artifact(role="campaign_profile", path=profile_path),
        _evidence_artifact(
            role="campaign_results_run1", path=run1_path, record_count=16
        ),
        _evidence_artifact(
            role="campaign_results_run2", path=run2_path, record_count=16
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
            "Exact registry, source/configuration/runtime bindings, schemas, fresh "
            "re-execution, receipts, denominators, scoped counters, and wording."
        ),
        "findings": [
            "All thirty-two fixed expected outcomes matched with zero exclusions.",
            "Each run produced eight clean matches, four quarantines, and four reference blocks.",
            "The two deterministic same-process sanitized ledgers were byte-identical.",
            "Scoped downstream component, write, authorization, broker, target, and effect call counters remained zero.",
        ],
        "unresolved_objections": [
            "No internal-independent or external-independent replication occurred.",
            "The fixed scenarios are neither exhaustive nor representative.",
            "No historical data, live feed, organizational approval, privacy review, or operational target was evaluated.",
            "No OS-level isolation, filesystem nonaccess, or network nonuse was independently attested.",
        ],
        "claim_expires_at": expires,
        "revalidation_triggers": [
            "any bound source, dependency declaration, schema, plan, runtime, seed, budget, or wording change",
            "any historical, live-shadow, model, policy, verifier, engine, authorization, broker, or target integration",
            "any contradictory evidence, incident, or validator defect",
            "any move from SELF to independent assurance wording",
        ],
        "pause_or_revocation_authority": (
            "Repository maintainers must withdraw or downgrade the claim when a trigger occurs."
        ),
        "incident_reporting_gate": (
            "Any mismatch, unexpected call, payload leak, retry, exclusion, or evidence "
            "drift blocks reissue until investigated and regression-tested."
        ),
    }
    record["supported_wording"] = SUPPORTED_WORDING
    record["prohibited_inferences"] = [
        "The system performs effectively on historical or live identity incidents.",
        "The campaign authenticates an approval, approver, source, custody statement, or organizational authority.",
        "The campaign establishes privacy compliance, de-identification, or records-management compliance.",
        "Scoped code-path counters prove OS-level isolation, filesystem nonaccess, or network nonuse.",
        "The POC is production ready, deployable, or safe for live containment.",
        "The system is aligned or robust to agentic misalignment, sabotage, scheming, sandbagging, or adaptive attack.",
        "A 32/32 synthetic result or zero scoped downstream calls establishes zero risk.",
        "SELF review establishes independent replication, independent custody, or external assurance.",
        "The fixed scenarios provide exhaustive feature-boundary coverage or a bounded failure rate.",
        "Two deterministic repetitions are independent statistical trials or representative samples.",
    ]
    record["limitations"] = [
        "All cases, mutations, and expected outcomes are project-controlled synthetic fixtures.",
        "The two repetitions run in one process and are deterministic, not independent trials.",
        "P07 tests input-event ordering because the current decision artifact has no separate feature-vector field.",
        "P08 substitutes cross-case named feature values only and supports only the generic reference mismatch code.",
        "The campaign does not invoke the model, policy, verifier, decision engine, authorization gate, broker, or target.",
        "Zero downstream and artifact-write fields are scoped code-path counters, not OS-level observations.",
        "The local Python process is not an OS-enforced sandbox and network nonuse was not independently attested.",
        "The plan, evaluator, validator, artifacts, and review are project-controlled and self-custodied.",
        "Historical efficacy, live-shadow readiness, operational calibration, privacy, and alignment remain unmeasured.",
    ]
    Draft202012Validator(_load_json(EVIDENCE_SCHEMA)).validate(record)
    return record


def generate_artifacts(
    output_dir: Path,
    *,
    implementation_commit: str,
    evaluated_at: str,
    record_path: Path | None = None,
) -> list[Path]:
    if output_dir.exists() and any(output_dir.iterdir()):
        raise CampaignGenerationError(
            "Campaign output directory must be absent or empty."
        )
    profile, run1, run2, summary = build_campaign_artifacts(
        implementation_commit,
        evaluated_at,
    )
    paths = [
        output_dir / "campaign_profile.json",
        output_dir / "campaign_results_run1.jsonl",
        output_dir / "campaign_results_run2.jsonl",
        output_dir / "campaign_summary.json",
    ]
    for path, payload in zip(paths, (profile, run1, run2, summary), strict=True):
        _write_bytes(path, payload)
    if record_path is not None:
        evidence_record = build_evidence_record(
            implementation_commit=implementation_commit,
            evaluated_at=evaluated_at,
            output_dir=output_dir,
        )
        _write_bytes(record_path, _json_bytes(evidence_record))
        paths.append(record_path)
    return paths


def check_artifacts(
    output_dir: Path,
    *,
    implementation_commit: str,
    evaluated_at: str,
    record_path: Path | None = None,
) -> None:
    profile_path = output_dir / "campaign_profile.json"
    run1_path = output_dir / "campaign_results_run1.jsonl"
    run2_path = output_dir / "campaign_results_run2.jsonl"
    summary_path = output_dir / "campaign_summary.json"
    if any(
        not path.is_file()
        for path in (profile_path, run1_path, run2_path, summary_path)
    ):
        raise CampaignGenerationError("Committed campaign artifacts are incomplete.")
    profile = _load_json(profile_path)
    _validate_campaign_artifact(profile)
    if (
        profile.get("implementation_commit") != implementation_commit
        or profile.get("evaluated_at") != evaluated_at
        or profile.get("campaign_plan_sha256")
        != _sha256_bytes(CAMPAIGN_PLAN.read_bytes())
        or profile.get("source_bindings") != _source_bindings()
    ):
        raise CampaignGenerationError("Committed campaign profile is stale.")
    profile_bytes = profile_path.read_bytes()
    run1 = run_campaign(profile)
    run2 = run_campaign(profile)
    expected_run1 = _jsonl_bytes(run1)
    expected_run2 = _jsonl_bytes(run2)
    if (
        run1_path.read_bytes() != expected_run1
        or run2_path.read_bytes() != expected_run2
    ):
        raise CampaignGenerationError("Committed campaign result ledger is stale.")
    expected_summary = _json_bytes(
        build_summary(
            profile_bytes,
            expected_run1,
            expected_run2,
            run1,
            run2,
            evaluated_at=evaluated_at,
        )
    )
    if summary_path.read_bytes() != expected_summary:
        raise CampaignGenerationError("Committed campaign summary is stale.")
    if record_path is not None:
        expected_record = _json_bytes(
            build_evidence_record(
                implementation_commit=implementation_commit,
                evaluated_at=evaluated_at,
                output_dir=output_dir,
            )
        )
        if not record_path.is_file() or record_path.read_bytes() != expected_record:
            raise CampaignGenerationError(
                f"Committed campaign evidence record is missing or stale: {record_path.name}"
            )


def _git_output(arguments: list[str]) -> str:
    completed = subprocess.run(
        ["git", *arguments],
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
        timeout=20,
    )
    if completed.returncode != 0:
        raise CampaignGenerationError("Unable to verify the frozen Git state.")
    return completed.stdout.strip()


def _require_clean_generation_commit(
    implementation_commit: str,
    evaluated_at: str,
) -> None:
    if not IMPLEMENTATION_COMMIT_PATTERN.fullmatch(implementation_commit):
        raise CampaignGenerationError(
            "implementation_commit must be a lowercase 40-character Git SHA."
        )
    if _git_output(["rev-parse", "HEAD"]) != implementation_commit:
        raise CampaignGenerationError(
            "HEAD must exactly equal the declared implementation commit."
        )
    symbolic = subprocess.run(
        ["git", "symbolic-ref", "-q", "HEAD"],
        cwd=ROOT,
        check=False,
        capture_output=True,
        timeout=20,
    )
    if symbolic.returncode == 0:
        raise CampaignGenerationError(
            "Final evidence generation requires a detached implementation commit."
        )
    if symbolic.returncode not in {0, 1}:
        raise CampaignGenerationError("Unable to verify detached HEAD state.")
    status = _git_output(["status", "--porcelain=v1", "--untracked-files=all"])
    if status:
        raise CampaignGenerationError(
            "Final evidence generation requires a clean tree including untracked files."
        )
    commit_time_text = _git_output(
        ["show", "-s", "--format=%cI", implementation_commit]
    )
    try:
        commit_time = datetime.fromisoformat(commit_time_text).astimezone(timezone.utc)
    except ValueError:
        raise CampaignGenerationError(
            "Implementation commit time is invalid."
        ) from None
    if _canonical_utc(evaluated_at) < commit_time:
        raise CampaignGenerationError(
            "Campaign evaluation time cannot predate the implementation commit."
        )
    completed = subprocess.run(
        [
            "git",
            "diff",
            "--quiet",
            implementation_commit,
            "--",
            *CAMPAIGN_SOURCE_PATHS.values(),
        ],
        cwd=ROOT,
        check=False,
        timeout=20,
    )
    if completed.returncode != 0:
        raise CampaignGenerationError(
            "Bound campaign sources must exactly match the implementation commit."
        )


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Generate or verify the fixed P2-CE-004 synthetic campaign."
    )
    operation = parser.add_mutually_exclusive_group(required=True)
    operation.add_argument("--validate-plan", action="store_true")
    operation.add_argument("--generate", action="store_true")
    operation.add_argument("--check", action="store_true")
    parser.add_argument("--implementation-commit")
    parser.add_argument("--evaluated-at")
    parser.add_argument("--output-dir", type=Path, default=DEFAULT_OUTPUT_DIR)
    parser.add_argument("--record", type=Path, default=DEFAULT_RECORD_PATH)
    args = parser.parse_args()

    if args.validate_plan:
        load_and_validate_plan()
        print(
            json.dumps(
                {"campaign_id": CAMPAIGN_ID, "status": "PLAN_VALID"},
                sort_keys=True,
                allow_nan=False,
            )
        )
        return
    if args.implementation_commit is None or args.evaluated_at is None:
        raise SystemExit("--implementation-commit and --evaluated-at are required.")
    _canonical_utc(args.evaluated_at)
    if args.generate:
        _require_clean_generation_commit(
            args.implementation_commit,
            args.evaluated_at,
        )
        generated = generate_artifacts(
            args.output_dir,
            implementation_commit=args.implementation_commit,
            evaluated_at=args.evaluated_at,
            record_path=args.record,
        )
        print(
            json.dumps(
                {
                    "campaign_id": CAMPAIGN_ID,
                    "generated": [str(path) for path in generated],
                },
                sort_keys=True,
                allow_nan=False,
            )
        )
        return
    check_artifacts(
        args.output_dir,
        implementation_commit=args.implementation_commit,
        evaluated_at=args.evaluated_at,
        record_path=args.record,
    )
    print(
        json.dumps(
            {"campaign_id": CAMPAIGN_ID, "status": "VALID"},
            sort_keys=True,
            allow_nan=False,
        )
    )


if __name__ == "__main__":
    main()
