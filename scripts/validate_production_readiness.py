from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import dataclass
from datetime import date
from pathlib import Path, PurePosixPath
from typing import Any, NoReturn


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_REQUIREMENTS = ROOT / "config" / "production_readiness_requirements.json"
MAX_DOCUMENT_BYTES = 1024 * 1024

SCHEMA_VERSION = "adf-production-readiness-0.1.0"
TOP_LEVEL_FIELDS = frozenset(
    {
        "schema_version",
        "as_of",
        "baseline_commit",
        "candidate_label",
        "declared_status",
        "requirements",
    }
)
ROW_FIELDS = frozenset(
    {
        "requirement_id",
        "domain_id",
        "domain",
        "requirement",
        "mandatory",
        "acceptance_criteria",
        "accountable_owner",
        "owner_acceptance",
        "current_state",
        "evidence_artifacts",
        "remaining_gate",
        "release_gate",
        "prohibited_inference",
    }
)

DOMAIN_NAMES = {
    "01": "Mission and operational requirements",
    "02": "Supported and prohibited use cases",
    "03": "Identity authentication authorization and human authority",
    "04": "Evidence provenance freshness integrity and source independence",
    "05": "Model performance calibration abstention drift and promotion governance",
    "06": "Policy correctness and policy-change control",
    "07": "Durable replay prevention and idempotency",
    "08": "Broker and target-adapter isolation",
    "09": "Independent post-action observation",
    "10": "Failure handling reconciliation rollback and recovery",
    "11": "Audit durability authenticity retention and external custody",
    "12": "Availability concurrency scaling and disaster recovery",
    "13": "Security architecture and threat-model closure",
    "14": "Privacy data governance records management and legal constraints",
    "15": "Deployment configuration secrets key management and supply-chain controls",
    "16": "Monitoring alerting incident response and operational runbooks",
    "17": "Verification validation red teaming and operational acceptance",
    "18": "Release rollback upgrade and decommissioning procedures",
}
EXPECTED_REQUIREMENT_IDS = tuple(
    f"PR-{domain_id}-{sequence:03d}"
    for domain_id in DOMAIN_NAMES
    for sequence in (1, 2)
)
EXPECTED_REQUIREMENT_ID_SET = frozenset(EXPECTED_REQUIREMENT_IDS)

ALLOWED_EVIDENCE_STATES = frozenset(
    {
        "NOT_IMPLEMENTED",
        "IMPLEMENTED",
        "UNIT_TESTED",
        "INTEGRATION_TESTED",
        "SYNTHETIC_MECHANISM_EVALUATED",
        "HISTORICALLY_EVALUATED",
        "NON_PRODUCTION_VALIDATED",
        "PILOT_ACCEPTED",
        "PRODUCTION_AUTHORIZED",
        "OPERATIONALLY_EFFECTIVE",
        "EXTERNAL_APPROVAL_REQUIRED",
    }
)
ALLOWED_OWNER_ACCEPTANCE = frozenset(
    {"NOT_RECORDED", "REJECTED", "CONDITIONALLY_ACCEPTED", "ACCEPTED"}
)
ALLOWED_DECLARED_STATUS = frozenset({"BLOCKED", "READY"})
ALLOWED_CANDIDATE_LABELS = frozenset(
    {"PRODUCTION_DEVELOPMENT_CANDIDATE", "PRODUCTION_READY_CANDIDATE"}
)
NO_EVIDENCE_STATES = frozenset({"NOT_IMPLEMENTED", "EXTERNAL_APPROVAL_REQUIRED"})
READY_EVIDENCE_STATE = "OPERATIONALLY_EFFECTIVE"
READY_OWNER_ACCEPTANCE = "ACCEPTED"
NO_REMAINING_GATE = "NONE"

REQUIREMENT_ID_RE = re.compile(r"^PR-(0[1-9]|1[0-8])-[0-9]{3}$")
COMMIT_RE = re.compile(r"^[0-9a-f]{40}$")
CONTROL_ID_RE = re.compile(r"^[A-Z][A-Z0-9_]{2,127}$")


class ReadinessValidationError(ValueError):
    """Raised when the production-readiness document is malformed or unsafe."""


@dataclass(frozen=True, slots=True)
class ReadinessReport:
    derived_status: str
    domain_count: int
    requirement_count: int
    blocking_requirement_ids: tuple[str, ...]

    def to_dict(self) -> dict[str, object]:
        return {
            "structurally_valid": True,
            "derived_status": self.derived_status,
            "domain_count": self.domain_count,
            "requirement_count": self.requirement_count,
            "blocking_requirement_ids": list(self.blocking_requirement_ids),
        }


def _raise(message: str) -> NoReturn:
    raise ReadinessValidationError(message)


def _reject_constant(value: str) -> NoReturn:
    _raise(f"non-finite JSON constant is prohibited: {value}")


def _object_without_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, member in pairs:
        if key in value:
            _raise(f"duplicate JSON member is prohibited: {key}")
        value[key] = member
    return value


def load_readiness_document(path: Path) -> dict[str, Any]:
    """Strictly decode one bounded JSON readiness document."""

    path = path.resolve(strict=True)
    if not path.is_file():
        _raise(f"readiness document is not a regular file: {path}")
    payload = path.read_bytes()
    if len(payload) > MAX_DOCUMENT_BYTES:
        _raise(
            "readiness document exceeds the maximum size of "
            f"{MAX_DOCUMENT_BYTES} bytes"
        )
    try:
        decoded = payload.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ReadinessValidationError("readiness document is not UTF-8") from exc
    try:
        document = json.loads(
            decoded,
            object_pairs_hook=_object_without_duplicate_keys,
            parse_constant=_reject_constant,
        )
    except ReadinessValidationError:
        raise
    except json.JSONDecodeError as exc:
        raise ReadinessValidationError(
            f"invalid JSON at line {exc.lineno}, column {exc.colno}: {exc.msg}"
        ) from exc
    if not isinstance(document, dict):
        _raise("readiness document root must be an object")
    return document


def _require_exact_fields(
    value: dict[str, Any], expected: frozenset[str], label: str
) -> None:
    actual = set(value)
    missing = sorted(expected - actual)
    unknown = sorted(actual - expected)
    if missing or unknown:
        fragments = []
        if missing:
            fragments.append(f"missing fields {missing}")
        if unknown:
            fragments.append(f"unknown fields {unknown}")
        _raise(f"{label} has " + " and ".join(fragments))


def _require_nonempty_string(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value or value != value.strip():
        _raise(f"{label} must be a nonempty string without surrounding whitespace")
    if "\x00" in value:
        _raise(f"{label} contains a prohibited NUL character")
    return value


def _validate_artifact_path(raw_path: Any, repo_root: Path, label: str) -> str:
    value = _require_nonempty_string(raw_path, label)
    if "\\" in value:
        _raise(f"{label} must use repository-relative POSIX separators")
    relative = PurePosixPath(value)
    if relative.is_absolute() or any(part in {"", ".", ".."} for part in relative.parts):
        _raise(f"{label} must be a canonical repository-relative path")

    candidate = repo_root.joinpath(*relative.parts)
    cursor = repo_root
    for part in relative.parts:
        cursor = cursor / part
        if cursor.is_symlink():
            _raise(f"{label} must not traverse a symbolic link: {value}")
    try:
        resolved = candidate.resolve(strict=True)
        resolved.relative_to(repo_root)
    except (FileNotFoundError, RuntimeError, ValueError) as exc:
        raise ReadinessValidationError(
            f"{label} does not resolve to an existing repository path: {value}"
        ) from exc
    return value


def _validate_row(row: Any, index: int, repo_root: Path) -> dict[str, Any]:
    label = f"requirements[{index}]"
    if not isinstance(row, dict):
        _raise(f"{label} must be an object")
    _require_exact_fields(row, ROW_FIELDS, label)

    requirement_id = _require_nonempty_string(
        row["requirement_id"], f"{label}.requirement_id"
    )
    match = REQUIREMENT_ID_RE.fullmatch(requirement_id)
    if match is None:
        _raise(f"{label}.requirement_id has an invalid format: {requirement_id}")
    domain_id = _require_nonempty_string(row["domain_id"], f"{label}.domain_id")
    if domain_id not in DOMAIN_NAMES:
        _raise(f"{label}.domain_id is not one of 01 through 18: {domain_id}")
    if match.group(1) != domain_id:
        _raise(
            f"{label}.requirement_id domain {match.group(1)} does not match "
            f"domain_id {domain_id}"
        )
    domain = _require_nonempty_string(row["domain"], f"{label}.domain")
    if domain != DOMAIN_NAMES[domain_id]:
        _raise(
            f"{label}.domain must equal the controlled name for domain {domain_id}"
        )

    for field in (
        "requirement",
        "acceptance_criteria",
        "remaining_gate",
        "prohibited_inference",
    ):
        _require_nonempty_string(row[field], f"{label}.{field}")

    if row["mandatory"] is not True:
        _raise(f"{label}.mandatory must be true for the frozen production baseline")

    owner = _require_nonempty_string(
        row["accountable_owner"], f"{label}.accountable_owner"
    )
    if CONTROL_ID_RE.fullmatch(owner) is None or owner in {
        "TBD",
        "UNKNOWN",
        "NOT_ASSIGNED",
        "NONE",
    }:
        _raise(f"{label}.accountable_owner is not a valid accountable role identifier")

    owner_acceptance = _require_nonempty_string(
        row["owner_acceptance"], f"{label}.owner_acceptance"
    )
    if owner_acceptance not in ALLOWED_OWNER_ACCEPTANCE:
        _raise(
            f"{label}.owner_acceptance must be one of "
            f"{sorted(ALLOWED_OWNER_ACCEPTANCE)}"
        )

    current_state = _require_nonempty_string(
        row["current_state"], f"{label}.current_state"
    )
    if current_state not in ALLOWED_EVIDENCE_STATES:
        _raise(
            f"{label}.current_state must be one of {sorted(ALLOWED_EVIDENCE_STATES)}"
        )

    release_gate = _require_nonempty_string(
        row["release_gate"], f"{label}.release_gate"
    )
    if CONTROL_ID_RE.fullmatch(release_gate) is None:
        _raise(f"{label}.release_gate is not a valid gate identifier")

    artifacts = row["evidence_artifacts"]
    if not isinstance(artifacts, list):
        _raise(f"{label}.evidence_artifacts must be an array")
    if len(artifacts) > 64:
        _raise(f"{label}.evidence_artifacts exceeds 64 entries")
    validated_artifacts = [
        _validate_artifact_path(
            artifact, repo_root, f"{label}.evidence_artifacts[{artifact_index}]"
        )
        for artifact_index, artifact in enumerate(artifacts)
    ]
    if len(set(validated_artifacts)) != len(validated_artifacts):
        _raise(f"{label}.evidence_artifacts contains duplicate paths")
    if current_state not in NO_EVIDENCE_STATES and not validated_artifacts:
        _raise(
            f"{label}.evidence_artifacts must not be empty for state {current_state}"
        )

    if current_state == READY_EVIDENCE_STATE:
        if owner_acceptance != READY_OWNER_ACCEPTANCE:
            _raise(
                f"{label} cannot claim {READY_EVIDENCE_STATE} without owner "
                f"acceptance {READY_OWNER_ACCEPTANCE}"
            )
        if row["remaining_gate"] != NO_REMAINING_GATE:
            _raise(
                f"{label}.remaining_gate must be {NO_REMAINING_GATE} for a "
                "operationally-effective row"
            )

    return row


def validate_readiness_document(
    document: dict[str, Any], *, repo_root: Path = ROOT
) -> ReadinessReport:
    """Validate the frozen readiness baseline and derive its release status."""

    if not isinstance(document, dict):
        _raise("readiness document root must be an object")
    _require_exact_fields(document, TOP_LEVEL_FIELDS, "document")

    if document["schema_version"] != SCHEMA_VERSION:
        _raise(f"document.schema_version must equal {SCHEMA_VERSION}")
    as_of = _require_nonempty_string(document["as_of"], "document.as_of")
    try:
        parsed_date = date.fromisoformat(as_of)
    except ValueError as exc:
        raise ReadinessValidationError("document.as_of must be an ISO date") from exc
    if parsed_date.isoformat() != as_of:
        _raise("document.as_of must use canonical YYYY-MM-DD form")

    baseline_commit = _require_nonempty_string(
        document["baseline_commit"], "document.baseline_commit"
    )
    if COMMIT_RE.fullmatch(baseline_commit) is None:
        _raise("document.baseline_commit must be a 40-character lowercase Git SHA")

    candidate_label = _require_nonempty_string(
        document["candidate_label"], "document.candidate_label"
    )
    if candidate_label not in ALLOWED_CANDIDATE_LABELS:
        _raise(
            "document.candidate_label must be one of "
            f"{sorted(ALLOWED_CANDIDATE_LABELS)}"
        )
    declared_status = _require_nonempty_string(
        document["declared_status"], "document.declared_status"
    )
    if declared_status not in ALLOWED_DECLARED_STATUS:
        _raise(
            f"document.declared_status must be one of {sorted(ALLOWED_DECLARED_STATUS)}"
        )

    raw_requirements = document["requirements"]
    if not isinstance(raw_requirements, list):
        _raise("document.requirements must be an array")

    normalized_root = repo_root.resolve(strict=True)
    rows = [
        _validate_row(row, index, normalized_root)
        for index, row in enumerate(raw_requirements)
    ]
    ids = [row["requirement_id"] for row in rows]
    if len(set(ids)) != len(ids):
        _raise("document.requirements contains duplicate requirement_id values")
    actual_id_set = frozenset(ids)
    if actual_id_set != EXPECTED_REQUIREMENT_ID_SET:
        missing = sorted(EXPECTED_REQUIREMENT_ID_SET - actual_id_set)
        unknown = sorted(actual_id_set - EXPECTED_REQUIREMENT_ID_SET)
        fragments = []
        if missing:
            fragments.append(f"missing frozen requirements {missing}")
        if unknown:
            fragments.append(f"unknown requirements {unknown}")
        _raise("document.requirements has " + " and ".join(fragments))
    if tuple(ids) != EXPECTED_REQUIREMENT_IDS:
        _raise("document.requirements must use the controlled requirement order")

    domain_ids = {row["domain_id"] for row in rows}
    expected_domain_ids = set(DOMAIN_NAMES)
    if domain_ids != expected_domain_ids:
        missing = sorted(expected_domain_ids - domain_ids)
        unknown = sorted(domain_ids - expected_domain_ids)
        _raise(
            "document must contain exactly domains 01 through 18; "
            f"missing={missing}, unknown={unknown}"
        )
    for domain_id in DOMAIN_NAMES:
        count = sum(row["domain_id"] == domain_id for row in rows)
        if count != 2:
            _raise(f"domain {domain_id} must contain exactly two frozen requirements")

    blocking_ids = tuple(
        row["requirement_id"]
        for row in rows
        if not (
            row["mandatory"] is True
            and row["current_state"] == READY_EVIDENCE_STATE
            and row["owner_acceptance"] == READY_OWNER_ACCEPTANCE
            and row["remaining_gate"] == NO_REMAINING_GATE
            and bool(row["evidence_artifacts"])
        )
    )
    derived_status = "BLOCKED" if blocking_ids else "READY"
    if declared_status != derived_status:
        _raise(
            f"declared status {declared_status} does not match derived status "
            f"{derived_status}"
        )
    expected_label = (
        "PRODUCTION_READY_CANDIDATE"
        if derived_status == "READY"
        else "PRODUCTION_DEVELOPMENT_CANDIDATE"
    )
    if candidate_label != expected_label:
        _raise(
            f"candidate label {candidate_label} does not match derived status; "
            f"expected {expected_label}"
        )

    return ReadinessReport(
        derived_status=derived_status,
        domain_count=len(domain_ids),
        requirement_count=len(rows),
        blocking_requirement_ids=blocking_ids,
    )


def validate_readiness_file(
    path: Path = DEFAULT_REQUIREMENTS, *, repo_root: Path = ROOT
) -> ReadinessReport:
    return validate_readiness_document(
        load_readiness_document(path),
        repo_root=repo_root,
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Strictly validate the frozen production-readiness requirements and "
            "derive READY or BLOCKED."
        )
    )
    parser.add_argument("--config", type=Path, default=DEFAULT_REQUIREMENTS)
    parser.add_argument("--repo-root", type=Path, default=ROOT)
    args = parser.parse_args(argv)

    try:
        report = validate_readiness_file(args.config, repo_root=args.repo_root)
    except (ReadinessValidationError, FileNotFoundError) as exc:
        print(
            json.dumps(
                {
                    "structurally_valid": False,
                    "derived_status": "INVALID",
                    "error": str(exc),
                },
                sort_keys=True,
            ),
            file=sys.stderr,
        )
        return 1

    print(json.dumps(report.to_dict(), sort_keys=True))
    return 0 if report.derived_status == "READY" else 2


if __name__ == "__main__":
    raise SystemExit(main())
