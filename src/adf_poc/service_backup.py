"""Fail-closed cold backup and restore for the synthetic Stage A service.

The mechanism is deliberately limited to one quiesced, cooperative, local
service state.  It does not provide cross-host snapshots, continuous backup,
HA, RPO/RTO evidence, independent custody, or protection from a hostile writer
running as the same operating-system user.
"""

from __future__ import annotations

import hashlib
import os
import re
import stat
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from adf_poc.service import (
    EXECUTION_MODE,
    RUNTIME_PROFILE,
    STATE_FILES,
    ServiceConfigurationError,
    _assert_no_symlink_parent,
    _bounded_regular_file,
    _construct_firewall,
    _fsync_directory,
    _json_bytes,
    _load_configuration,
    _marker_value,
    _read_marker,
    _strict_json_object,
    _verify_marker,
    _write_marker,
)
from adf_poc.utils import utc_now_iso


BACKUP_SCHEMA_VERSION = "stage-a-cold-backup-v1"
BACKUP_MANIFEST = "backup-manifest.json"
BACKUP_STATE_FILES = (
    STATE_FILES["audit"],
    STATE_FILES["control"],
    STATE_FILES["adapter"],
)
MAX_BACKUP_MANIFEST_BYTES = 64 * 1024
MAX_BACKUP_FILE_BYTES = 8 * 1024 * 1024 * 1024
SHA256 = re.compile(r"^[0-9a-f]{64}$")
MANIFEST_FIELDS = {
    "schema_version",
    "runtime_profile",
    "execution_mode",
    "created_at",
    "trusted_time_claimed",
    "config_sha256",
    "policy_sha256",
    "secret_bindings_sha256",
    "control_ledger_id",
    "synthetic_adapter_store_id",
    "source_marker_sha256",
    "files",
}
FILE_FIELDS = {"sha256", "size"}


def _safe_private_directory(
    path: Path, *, label: str, require_empty: bool = False
) -> None:
    if not path.is_absolute():
        raise ServiceConfigurationError(f"{label} must be absolute")
    _assert_no_symlink_parent(path, label=label)
    try:
        metadata = path.lstat()
    except OSError as exc:
        raise ServiceConfigurationError(f"{label} is unavailable") from exc
    if (
        stat.S_ISLNK(metadata.st_mode)
        or not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != os.geteuid()
        or stat.S_IMODE(metadata.st_mode) & 0o077
        or not os.access(path, os.R_OK | os.W_OK | os.X_OK)
    ):
        raise ServiceConfigurationError(f"{label} must be owner-private")
    if require_empty:
        try:
            if any(path.iterdir()):
                raise ServiceConfigurationError(f"{label} must be empty")
        except OSError as exc:
            raise ServiceConfigurationError(f"{label} could not be inspected") from exc


def _require_new_destination(path: Path) -> Path:
    if not path.is_absolute():
        raise ServiceConfigurationError("Backup destination must be absolute")
    _assert_no_symlink_parent(path, label="backup destination")
    parent = path.parent
    _safe_private_directory(parent, label="backup destination parent")
    try:
        path.lstat()
    except FileNotFoundError:
        return parent
    except OSError as exc:
        raise ServiceConfigurationError("Backup destination is unavailable") from exc
    raise ServiceConfigurationError("Backup destination must not already exist")


def _is_within(path: Path, parent: Path) -> bool:
    try:
        path.absolute().relative_to(parent.absolute())
    except ValueError:
        return False
    return True


def _write_private_file(path: Path, body: bytes) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags, 0o600)
        with os.fdopen(descriptor, "wb", closefd=True) as handle:
            handle.write(body)
            handle.flush()
            os.fsync(handle.fileno())
    except OSError as exc:
        raise ServiceConfigurationError(
            "Backup artifact could not be committed"
        ) from exc


def _copy_bound_file(
    source: Path,
    destination: Path,
    *,
    expected_identity: tuple[int, int] | None,
    expected_sha256: str | None = None,
    expected_size: int | None = None,
) -> dict[str, str | int]:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    try:
        source_descriptor = os.open(source, flags)
    except OSError as exc:
        raise ServiceConfigurationError(
            "Backup source artifact is unavailable"
        ) from exc
    destination_descriptor: int | None = None
    try:
        opened = os.fstat(source_descriptor)
        current = source.lstat()
        identity = (opened.st_dev, opened.st_ino)
        if (
            not stat.S_ISREG(opened.st_mode)
            or opened.st_nlink != 1
            or opened.st_uid != os.geteuid()
            or stat.S_IMODE(opened.st_mode) & 0o077
            or stat.S_ISLNK(current.st_mode)
            or identity != (current.st_dev, current.st_ino)
            or (expected_identity is not None and identity != expected_identity)
            or opened.st_size > MAX_BACKUP_FILE_BYTES
        ):
            raise ServiceConfigurationError("Backup source artifact identity is unsafe")
        destination_flags = (
            os.O_WRONLY
            | os.O_CREAT
            | os.O_EXCL
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0)
        )
        destination_descriptor = os.open(destination, destination_flags, 0o600)
        digest = hashlib.sha256()
        size = 0
        while True:
            chunk = os.read(source_descriptor, 1024 * 1024)
            if not chunk:
                break
            size += len(chunk)
            if size > MAX_BACKUP_FILE_BYTES:
                raise ServiceConfigurationError(
                    "Backup source artifact exceeds its bound"
                )
            digest.update(chunk)
            view = memoryview(chunk)
            while view:
                written = os.write(destination_descriptor, view)
                if written <= 0:
                    raise OSError("short backup write")
                view = view[written:]
        os.fsync(destination_descriptor)
        after = os.fstat(source_descriptor)
        current_after = source.lstat()
        if (
            (after.st_dev, after.st_ino) != identity
            or (current_after.st_dev, current_after.st_ino) != identity
            or after.st_size != opened.st_size
            or size != opened.st_size
        ):
            raise ServiceConfigurationError(
                "Backup source artifact changed during copy"
            )
        observed_sha256 = digest.hexdigest()
        if expected_sha256 is not None and observed_sha256 != expected_sha256:
            raise ServiceConfigurationError("Backup artifact digest is invalid")
        if expected_size is not None and size != expected_size:
            raise ServiceConfigurationError("Backup artifact size is invalid")
        return {"sha256": observed_sha256, "size": size}
    except ServiceConfigurationError:
        raise
    except OSError as exc:
        raise ServiceConfigurationError("Backup artifact copy failed") from exc
    finally:
        os.close(source_descriptor)
        if destination_descriptor is not None:
            os.close(destination_descriptor)


def _assert_checkpointed(state: Path) -> None:
    for database_name in (STATE_FILES["control"], STATE_FILES["adapter"]):
        for suffix in ("-wal", "-shm", "-journal"):
            sidecar = state / f"{database_name}{suffix}"
            try:
                sidecar.lstat()
            except FileNotFoundError:
                continue
            except OSError as exc:
                raise ServiceConfigurationError(
                    "Durable store sidecar could not be inspected"
                ) from exc
            raise ServiceConfigurationError(
                "Cold backup requires checkpointed SQLite stores"
            )


def _cleanup_staging(
    path: Path,
    created: list[Path],
    *,
    expected_identity: tuple[int, int] | None,
) -> None:
    if expected_identity is None:
        return
    try:
        metadata = path.lstat()
    except FileNotFoundError:
        return
    except OSError:
        return
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or stat.S_ISLNK(metadata.st_mode)
        or (metadata.st_dev, metadata.st_ino) != expected_identity
    ):
        return
    for artifact in reversed(created):
        try:
            artifact.unlink()
        except FileNotFoundError:
            pass
    try:
        path.rmdir()
    except FileNotFoundError:
        pass


def create_cold_backup(
    config_path: str | Path,
    destination: str | Path,
    *,
    operator_asserted_quiesced: bool,
) -> dict[str, Any]:
    """Create one atomic, integrity-bound snapshot of a valid Stage A state."""

    if operator_asserted_quiesced is not True:
        raise ServiceConfigurationError(
            "Cold backup requires an explicit quiesced-service assertion"
        )
    loaded = _load_configuration(config_path, expect_empty=False)
    marker = _read_marker(loaded)
    firewall = _construct_firewall(loaded)
    _verify_marker(loaded, firewall, marker)
    target = Path(destination)
    if _is_within(target, loaded.state):
        raise ServiceConfigurationError(
            "Backup destination must be outside authoritative service state"
        )
    parent = _require_new_destination(target)
    staging = parent / f".adf-backup-{uuid.uuid4().hex}.tmp"
    created: list[Path] = []
    staging_identity: tuple[int, int] | None = None
    try:
        os.mkdir(staging, 0o700)
        staging_metadata = staging.lstat()
        staging_identity = (staging_metadata.st_dev, staging_metadata.st_ino)
        identities = {
            STATE_FILES["audit"]: firewall._audit_identity,
            STATE_FILES["control"]: firewall._control_ledger._bound_file_identity,
            STATE_FILES["adapter"]: firewall._adapter_store._bound_file_identity,
        }
        with firewall._exclusive_audit_execution():
            current_marker = _read_marker(loaded)
            _verify_marker(loaded, firewall, current_marker)
            if current_marker != marker:
                raise ServiceConfigurationError(
                    "Service state marker changed during backup"
                )
            _assert_checkpointed(loaded.state)
            files: dict[str, dict[str, str | int]] = {}
            for name in BACKUP_STATE_FILES:
                destination_path = staging / name
                created.append(destination_path)
                files[name] = _copy_bound_file(
                    loaded.state / name,
                    destination_path,
                    expected_identity=identities[name],
                )
            manifest = {
                "schema_version": BACKUP_SCHEMA_VERSION,
                "runtime_profile": RUNTIME_PROFILE,
                "execution_mode": EXECUTION_MODE,
                "created_at": utc_now_iso(),
                "trusted_time_claimed": False,
                "config_sha256": loaded.config_sha256,
                "policy_sha256": loaded.policy_sha256,
                "secret_bindings_sha256": loaded.secret_bindings_sha256,
                "control_ledger_id": firewall._control_ledger.issuer_instance_id,
                "synthetic_adapter_store_id": firewall._adapter_store.adapter_store_id,
                "source_marker_sha256": hashlib.sha256(
                    _json_bytes(current_marker)
                ).hexdigest(),
                "files": files,
            }
            manifest_path = staging / BACKUP_MANIFEST
            created.append(manifest_path)
            _write_private_file(manifest_path, _json_bytes(manifest))
            _fsync_directory(staging, label="backup staging")
        os.rename(staging, target)
        _fsync_directory(parent, label="backup destination parent")
    except ServiceConfigurationError:
        _cleanup_staging(staging, created, expected_identity=staging_identity)
        raise
    except OSError as exc:
        _cleanup_staging(staging, created, expected_identity=staging_identity)
        raise ServiceConfigurationError("Cold backup could not be committed") from exc
    return {
        "status": "BACKUP_CREATED",
        "runtime_profile": RUNTIME_PROFILE,
        "execution_mode": EXECUTION_MODE,
        "live_actions_enabled": False,
        "trusted_time_claimed": False,
        "destination": str(target),
        "files": list(BACKUP_STATE_FILES),
    }


def _validated_manifest(source: Path, loaded: Any) -> dict[str, Any]:
    _safe_private_directory(source, label="backup source")
    try:
        observed_names = {entry.name for entry in source.iterdir()}
    except OSError as exc:
        raise ServiceConfigurationError("Backup source could not be inspected") from exc
    expected_names = {BACKUP_MANIFEST, *BACKUP_STATE_FILES}
    if observed_names != expected_names:
        raise ServiceConfigurationError("Backup source file set is invalid")
    raw, _metadata = _bounded_regular_file(
        source / BACKUP_MANIFEST,
        label="backup manifest",
        maximum=MAX_BACKUP_MANIFEST_BYTES,
        owner_private=True,
    )
    manifest = _strict_json_object(raw, label="backup manifest")
    if set(manifest) != MANIFEST_FIELDS:
        raise ServiceConfigurationError("Backup manifest has an invalid closed shape")
    expected_static = {
        "schema_version": BACKUP_SCHEMA_VERSION,
        "runtime_profile": RUNTIME_PROFILE,
        "execution_mode": EXECUTION_MODE,
        "trusted_time_claimed": False,
        "config_sha256": loaded.config_sha256,
        "policy_sha256": loaded.policy_sha256,
        "secret_bindings_sha256": loaded.secret_bindings_sha256,
    }
    if any(manifest.get(key) != value for key, value in expected_static.items()):
        raise ServiceConfigurationError("Backup manifest binding is invalid")
    try:
        created_at = datetime.fromisoformat(manifest["created_at"])
    except (TypeError, ValueError) as exc:
        raise ServiceConfigurationError("Backup manifest timestamp is invalid") from exc
    if (
        created_at.tzinfo is None
        or created_at.utcoffset() is None
        or created_at.utcoffset().total_seconds() != 0
        or created_at.microsecond != 0
        or manifest["created_at"]
        != created_at.astimezone(timezone.utc).replace(microsecond=0).isoformat()
    ):
        raise ServiceConfigurationError("Backup manifest timestamp is invalid")
    for field in (
        "control_ledger_id",
        "synthetic_adapter_store_id",
    ):
        value = manifest.get(field)
        if type(value) is not str or not 1 <= len(value) <= 256:
            raise ServiceConfigurationError("Backup manifest store identity is invalid")
    marker_sha256 = manifest.get("source_marker_sha256")
    if type(marker_sha256) is not str or SHA256.fullmatch(marker_sha256) is None:
        raise ServiceConfigurationError("Backup manifest marker digest is invalid")
    files = manifest.get("files")
    if type(files) is not dict or set(files) != set(BACKUP_STATE_FILES):
        raise ServiceConfigurationError("Backup manifest file set is invalid")
    for name in BACKUP_STATE_FILES:
        row = files[name]
        if type(row) is not dict or set(row) != FILE_FIELDS:
            raise ServiceConfigurationError("Backup manifest file binding is invalid")
        digest = row.get("sha256")
        size = row.get("size")
        if (
            type(digest) is not str
            or SHA256.fullmatch(digest) is None
            or type(size) is not int
            or not 0 <= size <= MAX_BACKUP_FILE_BYTES
        ):
            raise ServiceConfigurationError("Backup manifest file binding is invalid")
    return manifest


def restore_cold_backup(
    config_path: str | Path,
    source: str | Path,
    *,
    expect_empty: bool,
) -> dict[str, Any]:
    """Restore a bound backup only into the exact empty configured state path."""

    if expect_empty is not True:
        raise ServiceConfigurationError("Restore requires explicit empty-state mode")
    loaded = _load_configuration(config_path, expect_empty=True)
    backup = Path(source)
    if not backup.is_absolute():
        raise ServiceConfigurationError("Backup source must be absolute")
    if _is_within(backup, loaded.state):
        raise ServiceConfigurationError(
            "Backup source must be outside authoritative service state"
        )
    manifest = _validated_manifest(backup, loaded)
    try:
        for name in BACKUP_STATE_FILES:
            row = manifest["files"][name]
            destination = loaded.state / name
            _copy_bound_file(
                backup / name,
                destination,
                expected_identity=None,
                expected_sha256=row["sha256"],
                expected_size=row["size"],
            )
        _fsync_directory(loaded.state, label="restored service state")
        firewall = _construct_firewall(loaded)
        if (
            firewall._control_ledger.issuer_instance_id != manifest["control_ledger_id"]
            or firewall._adapter_store.adapter_store_id
            != manifest["synthetic_adapter_store_id"]
        ):
            raise ServiceConfigurationError("Restored store identity is invalid")
        marker = _marker_value(loaded, firewall)
        _write_marker(loaded.state / STATE_FILES["marker"], marker)
    except ServiceConfigurationError:
        # A partial restore is retained fail-closed for operator inspection.  It
        # cannot be served or retried as an empty initialization.
        raise
    except OSError as exc:
        raise ServiceConfigurationError("Cold restore failed") from exc
    return {
        "status": "BACKUP_RESTORED",
        "runtime_profile": RUNTIME_PROFILE,
        "execution_mode": EXECUTION_MODE,
        "live_actions_enabled": False,
        "trusted_time_claimed": False,
        "source": str(backup),
        "files": list(BACKUP_STATE_FILES),
    }
