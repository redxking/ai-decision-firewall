from __future__ import annotations

import argparse
import copy
import hashlib
import json
import os
import secrets
import stat
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterator


ROOT = Path(__file__).resolve().parents[1]
SOURCE_DIR = ROOT / "data" / "phase2_starter"
TARGET_DIR = ROOT / "data" / "phase2_qualification"
CONFIG_PATH = ROOT / "config" / "phase2_qualification.json"
VERSION = "0.2.0"

REVIEWED_SOURCE_DIGESTS = {
    "cases.jsonl": "2224e8fdebeec512880f89b43889195bdefa66389eee7ca70ac4370f1000d3d5",
    "adjudications.jsonl": "9fbfba2f1e7f39aa26817f5956cc065434114d4cfe478e16dd478e5ae774a079",
}
TARGET_DATA_FILES = frozenset(
    {"cases.jsonl", "adjudications.jsonl", "manifest.json", "expected_qualification.json"}
)

EXPECTED_OUTCOMES = (
    ("ACCEPTED", "", ""),
    ("ACCEPTED", "", ""),
    ("ACCEPTED", "", ""),
    ("QUARANTINED", "SYNTAX", "INVALID_JSON"),
    ("QUARANTINED", "STRUCTURE", "MISSING_REQUIRED_FIELD"),
    ("QUARANTINED", "SEMANTICS", "INVALID_TIMESTAMP"),
    ("QUARANTINED", "SEMANTICS", "CANONICAL_CONTEXT_MISMATCH"),
)


def _canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def _pretty_json_bytes(value: Any) -> bytes:
    return (json.dumps(value, indent=2, sort_keys=True) + "\n").encode("utf-8")


def _sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _assert_repository_path(path: Path, *, label: str) -> None:
    """Reject path aliases that can escape or redirect the reviewed repository tree."""

    try:
        relative = path.relative_to(ROOT)
    except ValueError as exc:
        raise ValueError(f"{label} is outside the repository root: {path}.") from exc
    resolved = path.resolve(strict=False)
    try:
        resolved.relative_to(ROOT)
    except ValueError as exc:
        raise ValueError(f"{label} resolves outside the repository root: {path}.") from exc

    cursor = ROOT
    for component in relative.parts:
        cursor = cursor / component
        if cursor.is_symlink():
            raise ValueError(f"{label} traverses a symbolic link: {cursor}.")


def _directory_flags() -> int:
    if not hasattr(os, "O_DIRECTORY") or not hasattr(os, "O_NOFOLLOW"):
        raise ValueError(
            "Secure fixture maintenance requires O_DIRECTORY and O_NOFOLLOW support."
        )
    return os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)


@contextmanager
def _open_repository_parent(path: Path, *, create: bool) -> Iterator[int]:
    """Hold no-follow directory descriptors from ROOT through the target parent."""

    _assert_repository_path(path, label="Qualification fixture path")
    relative_parent = path.parent.relative_to(ROOT)
    descriptors: list[int] = []
    try:
        descriptors.append(os.open(ROOT, _directory_flags()))
        for component in relative_parent.parts:
            parent_fd = descriptors[-1]
            try:
                child_fd = os.open(component, _directory_flags(), dir_fd=parent_fd)
            except FileNotFoundError:
                if not create:
                    raise
                try:
                    os.mkdir(component, mode=0o755, dir_fd=parent_fd)
                except FileExistsError:
                    pass
                child_fd = os.open(component, _directory_flags(), dir_fd=parent_fd)
            descriptors.append(child_fd)
        yield descriptors[-1]
    finally:
        for descriptor in reversed(descriptors):
            os.close(descriptor)


def _secure_read(path: Path) -> bytes:
    """Read one regular, unaliased repository file through held directory FDs."""

    try:
        with _open_repository_parent(path, create=False) as parent_fd:
            descriptor = os.open(
                path.name,
                os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0),
                dir_fd=parent_fd,
            )
            try:
                metadata = os.fstat(descriptor)
                if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
                    raise ValueError(f"Refusing aliased or non-regular fixture file {path}.")
                chunks: list[bytes] = []
                while chunk := os.read(descriptor, 1024 * 1024):
                    chunks.append(chunk)
                return b"".join(chunks)
            finally:
                os.close(descriptor)
    except ValueError:
        raise
    except OSError as exc:
        raise ValueError(f"Unable to securely read fixture file {path}: {exc}.") from exc


def _secure_write(path: Path, content: bytes, *, overwrite: bool) -> None:
    """Atomically install bytes beneath ROOT without following mutable path aliases."""

    temporary_name = f".phase2-fixture-{os.getpid()}-{secrets.token_hex(8)}.tmp"
    with _open_repository_parent(path, create=True) as parent_fd:
        try:
            existing = os.stat(path.name, dir_fd=parent_fd, follow_symlinks=False)
        except FileNotFoundError:
            existing = None
        if existing is not None:
            if not stat.S_ISREG(existing.st_mode) or existing.st_nlink != 1:
                raise ValueError(f"Refusing aliased or non-regular fixture target {path}.")
            if not overwrite:
                raise ValueError(f"Refusing to overwrite reviewed fixture target {path}.")

        installed = False
        try:
            descriptor = os.open(
                temporary_name,
                os.O_WRONLY
                | os.O_CREAT
                | os.O_EXCL
                | os.O_NOFOLLOW
                | getattr(os, "O_CLOEXEC", 0),
                0o644,
                dir_fd=parent_fd,
            )
            try:
                view = memoryview(content)
                while view:
                    written = os.write(descriptor, view)
                    if written <= 0:
                        raise OSError("short write while installing fixture artifact")
                    view = view[written:]
                os.fsync(descriptor)
            finally:
                os.close(descriptor)

            if overwrite:
                os.replace(
                    temporary_name,
                    path.name,
                    src_dir_fd=parent_fd,
                    dst_dir_fd=parent_fd,
                )
            else:
                os.link(
                    temporary_name,
                    path.name,
                    src_dir_fd=parent_fd,
                    dst_dir_fd=parent_fd,
                    follow_symlinks=False,
                )
                os.unlink(temporary_name, dir_fd=parent_fd)
            installed = True
        finally:
            if not installed:
                try:
                    os.unlink(temporary_name, dir_fd=parent_fd)
                except FileNotFoundError:
                    pass


def _nonblank_lines(raw: bytes, *, label: str) -> list[str]:
    try:
        lines = raw.decode("utf-8").splitlines()
    except UnicodeDecodeError as exc:
        raise ValueError(f"{label} is not valid UTF-8.") from exc
    return [line for line in lines if line.strip()]


def _load_reviewed_controls(filename: str) -> tuple[list[str], list[dict[str, Any]]]:
    path = SOURCE_DIR / filename
    _assert_repository_path(path, label="Reviewed fixture source")
    raw = _secure_read(path)
    actual_digest = _sha256_bytes(raw)
    expected_digest = REVIEWED_SOURCE_DIGESTS[filename]
    if actual_digest != expected_digest:
        raise ValueError(
            f"Refusing to generate from changed starter control {path}: "
            f"expected {expected_digest}, received {actual_digest}."
        )
    lines = _nonblank_lines(raw, label=str(path))
    if len(lines) != 3:
        raise ValueError(f"Reviewed starter control {path} must contain exactly 3 records.")
    records: list[dict[str, Any]] = []
    for record_number, line in enumerate(lines, start=1):
        try:
            value = json.loads(line)
        except json.JSONDecodeError as exc:
            raise ValueError(
                f"Reviewed starter control {path} record {record_number} is invalid JSON."
            ) from exc
        if not isinstance(value, dict):
            raise ValueError(
                f"Reviewed starter control {path} record {record_number} is not an object."
            )
        records.append(value)
    return lines, records


def _remap_case(
    source: dict[str, Any],
    *,
    case_id: str,
    subject_id: str,
    asset_id: str,
) -> dict[str, Any]:
    record = copy.deepcopy(source)
    record["case_id"] = case_id
    record["subject_id"] = subject_id
    record["asset_id"] = asset_id
    for index, event in enumerate(record["events"], start=1):
        event["case_id"] = case_id
        event["event_id"] = f"evt-{case_id}-{index:02d}"
        event["provenance_id"] = f"prov-{case_id}-{index:02d}"
        event["entity_refs"] = [subject_id, asset_id]
        if event["source_type"] == "asset_inventory":
            event["attributes"]["asset_id"] = asset_id
    return record


def _build_case_lines(
    valid_lines: list[str], valid_cases: list[dict[str, Any]]
) -> list[str]:
    source = valid_cases[0]

    malformed = _remap_case(
        source,
        case_id="phase2-quarantine-malformed-json-001",
        subject_id="pseudonym-quarantine-user-001",
        asset_id="pseudonym-quarantine-asset-001",
    )
    # The final object delimiter is intentionally absent. This is the sole defect
    # on physical/nonblank record 4 and must remain malformed fixture data.
    malformed_line = _canonical_json(malformed)[:-1]

    missing_required = _remap_case(
        source,
        case_id="phase2-quarantine-missing-required-001",
        subject_id="pseudonym-quarantine-user-002",
        asset_id="pseudonym-quarantine-asset-002",
    )
    del missing_required["subject_id"]

    invalid_timestamp = _remap_case(
        source,
        case_id="phase2-quarantine-invalid-timestamp-001",
        subject_id="pseudonym-quarantine-user-003",
        asset_id="pseudonym-quarantine-asset-003",
    )
    invalid_timestamp["opened_at"] = "2026-08-01T12:00:00"

    canonical_mismatch = _remap_case(
        source,
        case_id="phase2-quarantine-context-mismatch-001",
        subject_id="pseudonym-quarantine-user-004",
        asset_id="pseudonym-quarantine-asset-004",
    )
    canonical_mismatch["asset_criticality"] = 0.43

    return valid_lines + [
        malformed_line,
        _canonical_json(missing_required),
        _canonical_json(invalid_timestamp),
        _canonical_json(canonical_mismatch),
    ]


def _jsonl_bytes(lines: list[str]) -> bytes:
    return ("\n".join(lines) + "\n").encode("utf-8")


def _build_expected_qualification(cases_bytes: bytes) -> dict[str, Any]:
    lines = _nonblank_lines(cases_bytes, label="generated qualification cases")
    records = []
    for record_number, (line, outcome) in enumerate(
        zip(lines, EXPECTED_OUTCOMES, strict=True), start=1
    ):
        status, error_category, error_code = outcome
        records.append(
            {
                "nonblank_record_number": record_number,
                "raw_line_sha256": _sha256_bytes(line.encode("utf-8")),
                "status": status,
                "error_category": error_category,
                "error_code": error_code,
            }
        )
    return {
        "schema_version": VERSION,
        "dataset_id": "adf-phase2-qualification-synthetic",
        "source_role": "cases",
        "source_file_sha256": _sha256_bytes(cases_bytes),
        "expected_totals": {
            "physical_line_count": 7,
            "nonblank_record_count": 7,
            "accepted_count": 3,
            "quarantined_count": 4,
            "fatal_count": 0,
        },
        "records": records,
    }


def _build_artifacts() -> dict[Path, bytes]:
    valid_case_lines, valid_cases = _load_reviewed_controls("cases.jsonl")
    valid_adjudication_lines, _ = _load_reviewed_controls("adjudications.jsonl")

    case_lines = _build_case_lines(valid_case_lines, valid_cases)
    cases_bytes = _jsonl_bytes(case_lines)
    adjudications_bytes = _jsonl_bytes(valid_adjudication_lines)

    manifest = {
        "schema_version": VERSION,
        "dataset_id": "adf-phase2-qualification-synthetic",
        "data_origin": "SYNTHETIC_FIXTURE",
        "historical_case_count": 0,
        "intended_mode": "HISTORICAL_REPLAY",
        "created_at": "2026-08-14T00:00:00+00:00",
        "attestations": {
            "approved_for_replay": True,
            "approval_reference": "SYNTHETIC-QUALIFICATION-FIXTURE-NO-EXTERNAL-DATA",
            "deidentified": True,
            "deidentification_method": "synthetic-by-construction",
            "direct_identifiers_present": False,
            "attested_by": "phase2-qualification-fixture-generator",
            "attested_at": "2026-08-14T00:00:00+00:00",
        },
        "files": [
            {
                "role": "cases",
                "path": "cases.jsonl",
                "sha256": _sha256_bytes(cases_bytes),
                "record_count": len(_nonblank_lines(cases_bytes, label="cases.jsonl")),
                "adapter": "canonical_jsonl_v0.2",
            },
            {
                "role": "adjudications",
                "path": "adjudications.jsonl",
                "sha256": _sha256_bytes(adjudications_bytes),
                "record_count": len(
                    _nonblank_lines(adjudications_bytes, label="adjudications.jsonl")
                ),
                "adapter": "canonical_jsonl_v0.2",
            },
        ],
    }
    expected = _build_expected_qualification(cases_bytes)
    config = {
        "schema_version": VERSION,
        "execution_mode": "HISTORICAL_REPLAY",
        "live_actions_enabled": False,
        "dataset_manifest": "data/phase2_qualification/manifest.json",
        "model_path": "outputs/baseline/model.json",
        "policy_path": "config/policy.json",
        "output_dir": "outputs/replay/phase2_qualification",
        "contract_adapter": "canonical_jsonl_v0.2",
        "deterministic_outputs": True,
        "zero_effects_required": True,
        "record_failure_policy": "QUARANTINE_RECORD",
    }
    return {
        TARGET_DIR / "cases.jsonl": cases_bytes,
        TARGET_DIR / "adjudications.jsonl": adjudications_bytes,
        TARGET_DIR / "manifest.json": _pretty_json_bytes(manifest),
        TARGET_DIR / "expected_qualification.json": _pretty_json_bytes(expected),
        CONFIG_PATH: _pretty_json_bytes(config),
    }


def _validate_artifacts(artifacts: dict[Path, bytes]) -> None:
    cases_bytes = artifacts[TARGET_DIR / "cases.jsonl"]
    adjudications_bytes = artifacts[TARGET_DIR / "adjudications.jsonl"]
    case_lines = _nonblank_lines(cases_bytes, label="generated cases.jsonl")
    adjudication_lines = _nonblank_lines(
        adjudications_bytes, label="generated adjudications.jsonl"
    )
    if len(case_lines) != 7 or len(adjudication_lines) != 3:
        raise AssertionError("Qualification fixture must contain 7 case rows and 3 adjudications.")

    for index in range(3):
        json.loads(case_lines[index])
    try:
        json.loads(case_lines[3])
    except json.JSONDecodeError:
        pass
    else:
        raise AssertionError("Qualification record 4 must be malformed JSON.")

    missing_required = json.loads(case_lines[4])
    invalid_timestamp = json.loads(case_lines[5])
    canonical_mismatch = json.loads(case_lines[6])
    if "subject_id" in missing_required:
        raise AssertionError("Qualification record 5 must omit only subject_id.")
    if invalid_timestamp.get("opened_at") != "2026-08-01T12:00:00":
        raise AssertionError("Qualification record 6 must use a timezone-naive opened_at.")
    inventory = next(
        event
        for event in canonical_mismatch["events"]
        if event["source_type"] == "asset_inventory"
    )
    if canonical_mismatch["asset_criticality"] == inventory["attributes"]["asset_criticality"]:
        raise AssertionError("Qualification record 7 must contain a canonical context mismatch.")

    parsed_cases = [json.loads(line) for line in case_lines[:3] + case_lines[4:]]
    case_ids = [record["case_id"] for record in parsed_cases]
    event_ids = [event["event_id"] for record in parsed_cases for event in record["events"]]
    if len(case_ids) != len(set(case_ids)) or len(event_ids) != len(set(event_ids)):
        raise AssertionError("Qualification-local defects must not introduce duplicate identifiers.")
    if any(record.get("schema_version") != VERSION for record in parsed_cases):
        raise AssertionError("Qualification-local defects must not introduce a version mismatch.")

    manifest = json.loads(artifacts[TARGET_DIR / "manifest.json"])
    files = {entry["role"]: entry for entry in manifest["files"]}
    for role, content in (("cases", cases_bytes), ("adjudications", adjudications_bytes)):
        if files[role]["sha256"] != _sha256_bytes(content):
            raise AssertionError(f"Manifest digest for {role} does not match generated bytes.")
        if files[role]["record_count"] != len(
            _nonblank_lines(content, label=f"generated {role}")
        ):
            raise AssertionError(f"Manifest count for {role} does not match nonblank rows.")

    expected = json.loads(artifacts[TARGET_DIR / "expected_qualification.json"])
    if expected["source_file_sha256"] != _sha256_bytes(cases_bytes):
        raise AssertionError("Expected qualification file is not bound to cases.jsonl.")
    for line, record, outcome in zip(
        case_lines, expected["records"], EXPECTED_OUTCOMES, strict=True
    ):
        if record["raw_line_sha256"] != _sha256_bytes(line.encode("utf-8")):
            raise AssertionError("Expected qualification line digest mismatch.")
        if (record["status"], record["error_category"], record["error_code"]) != outcome:
            raise AssertionError("Expected qualification outcome mismatch.")


def _assert_safe_target_set() -> None:
    targets = [
        *(TARGET_DIR / name for name in sorted(TARGET_DATA_FILES)),
        CONFIG_PATH,
    ]
    _assert_repository_path(TARGET_DIR, label="Qualification target directory")
    for target in targets:
        _assert_repository_path(target, label="Qualification fixture target")
        if target.exists() and target.is_file() and target.stat().st_nlink != 1:
            raise ValueError(f"Refusing hard-linked qualification target {target}.")
    if TARGET_DIR.exists():
        if not TARGET_DIR.is_dir() or TARGET_DIR.is_symlink():
            raise ValueError(f"Refusing unsafe qualification target {TARGET_DIR}.")
        unexpected = sorted(
            path.name
            for path in TARGET_DIR.iterdir()
            if path.name not in TARGET_DATA_FILES
        )
        if unexpected:
            raise ValueError(
                "Refusing to modify a qualification directory containing unreviewed entries: "
                + ", ".join(unexpected)
            )
        for path in TARGET_DIR.iterdir():
            if path.is_symlink() or not path.is_file():
                raise ValueError(f"Refusing unsafe qualification target entry {path}.")
    if CONFIG_PATH.exists() and (
        CONFIG_PATH.is_symlink() or not CONFIG_PATH.is_file()
    ):
        raise ValueError(f"Refusing unsafe qualification configuration target {CONFIG_PATH}.")


def _write(artifacts: dict[Path, bytes], *, overwrite: bool) -> None:
    _assert_safe_target_set()
    existing = sorted(str(path.relative_to(ROOT)) for path in artifacts if path.exists())
    if existing and not overwrite:
        raise ValueError(
            "Refusing to overwrite reviewed fixture targets without "
            "--overwrite-reviewed-fixture: " + ", ".join(existing)
        )
    for path, content in artifacts.items():
        try:
            _secure_write(path, content, overwrite=overwrite)
        except ValueError:
            raise
        except OSError as exc:
            raise ValueError(
                f"Secure fixture write refused target {path}: {exc}."
            ) from exc


def _check(artifacts: dict[Path, bytes]) -> None:
    _assert_safe_target_set()
    missing = [str(path.relative_to(ROOT)) for path in artifacts if not path.is_file()]
    if missing:
        raise ValueError("Missing generated qualification artifacts: " + ", ".join(missing))
    changed = [
        str(path.relative_to(ROOT))
        for path, content in artifacts.items()
        if _secure_read(path) != content
    ]
    if changed:
        raise ValueError("Qualification artifacts are not deterministic/current: " + ", ".join(changed))


def main() -> None:
    parser = argparse.ArgumentParser(
        description=(
            "Generate or verify the fixed Phase 2.1 synthetic qualification fixture. "
            "Writes are confined to the reviewed qualification targets."
        )
    )
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument(
        "--write-reviewed-fixture",
        action="store_true",
        help="Create the reviewed fixture only when none of its target files exist.",
    )
    mode.add_argument(
        "--overwrite-reviewed-fixture",
        action="store_true",
        help="Explicitly replace only the fixed, reviewed fixture target files.",
    )
    mode.add_argument(
        "--check",
        action="store_true",
        help="Verify the committed fixture exactly matches deterministic generation.",
    )
    args = parser.parse_args()

    artifacts = _build_artifacts()
    _validate_artifacts(artifacts)
    if args.check:
        _check(artifacts)
        action = "Verified"
    else:
        _write(artifacts, overwrite=args.overwrite_reviewed_fixture)
        action = "Generated"
    print(f"{action} Phase 2.1 qualification fixture at {TARGET_DIR}")


if __name__ == "__main__":
    main()
