"""Single-host, synthetic-only Stage A authority-state controls.

This additive module does not add a live connector, operational credential,
distributed replay guarantee, deployment boundary, or production authority.
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import sqlite3
import stat
import tempfile
import uuid
from contextlib import contextmanager
from copy import deepcopy
from dataclasses import dataclass, replace
from datetime import datetime, timedelta, timezone
from pathlib import Path
from threading import RLock, local
from time import perf_counter, sleep
from typing import Any, Mapping

from adf_poc.utils import canonical_json, sha256_json, utc_now_iso

try:  # pragma: no cover - exercised on non-POSIX import targets
    import fcntl as _fcntl
except ImportError:  # pragma: no cover - exercised on Windows
    _fcntl = None


SCHEMA_VERSION = "2"
ADAPTER_SCHEMA_VERSION = "1"
REQUEST_LOOKUP_SCHEMA_VERSION = "stage-a-request-lookup-v1"
ADAPTER_RECEIPT_SCHEMA_VERSION = "stage-a-synthetic-receipt-v1"
SYNTHETIC_ADAPTER_ID = "adf-stage-a-offline-synthetic-adapter"
SYNTHETIC_ADAPTER_CONTRACT_VERSION = "1"
SYNTHETIC_EXECUTION_MODE = "synthetic_simulation"
SYNTHETIC_ADAPTER_CONTRACT_SHA256 = sha256_json(
    {
        "adapter_id": SYNTHETIC_ADAPTER_ID,
        "contract_version": SYNTHETIC_ADAPTER_CONTRACT_VERSION,
        "execution_mode": SYNTHETIC_EXECUTION_MODE,
        "supported_action": "NETWORK_ISOLATE",
        "receipt_semantics": "adapter_report_only_not_independent_verification",
    }
)
_AUTHORIZATION_STATES = frozenset({"ISSUED", "CONSUMED", "REVOKED"})
_ATTEMPT_STATES = frozenset(
    {
        "RESERVED",
        "RECEIPT_RECORDED",
        "VERIFIED_EFFECT",
        "FAILED_NO_EFFECT",
        "RECOVERY_REQUIRED",
        "UNKNOWN_EFFECT",
    }
)
_TERMINAL_ATTEMPT_STATES = _ATTEMPT_STATES - {"RESERVED", "RECEIPT_RECORDED"}
_REQUEST_STATES = frozenset(
    {"CLAIMED", "AUTHORIZED", "ATTEMPT_RESERVED", "TERMINAL"}
)
_REQUEST_DISPOSITIONS = frozenset(
    {
        "COMPLETED_VERIFIED",
        "DENIED_NO_EFFECT",
        "FAILED_NO_EFFECT",
        "ABORTED_NO_EFFECT",
        "RECOVERY_REQUIRED",
        "UNKNOWN_EFFECT",
    }
)
_ADAPTER_STATUSES = frozenset({"APPLIED", "NO_EFFECT", "PARTIAL", "AMBIGUOUS"})
_REQUIRED_TABLES = frozenset(
    {
        "metadata",
        "requests",
        "request_results",
        "authorizations",
        "attempts",
        "audit_outbox",
    }
)
_ADAPTER_REQUIRED_TABLES = frozenset(
    {"metadata", "target_states", "command_receipts"}
)
_AUTHORITY_BEARING_KEYS = frozenset(
    {
        "authorization_token",
        "nonce",
        "signature",
        "signatures",
        "audit_records",
        "credential",
        "credentials",
        "secret",
        "signing_key",
    }
)
_RESULT_AUTHORITY_BEARING_KEYS = _AUTHORITY_BEARING_KEYS | frozenset(
    {
        "token_id",
        "unsigned_token_sha256",
        "issuer_instance_id",
        "authorization_key_domain_id",
        "key_domain_id",
    }
)
_RECOVERY_SUMMARY_KEYS = frozenset(
    {
        "summary_version",
        "principal_id",
        "request_id",
        "request_sha256",
        "decision_id",
        "decision_outcome",
        "decision_sha256",
        "decision_context_sha256",
        "policy_sha256",
        "decided_at",
    }
)
_ADAPTER_BINDING_KEYS = frozenset(
    {
        "adapter_id",
        "adapter_contract_version",
        "adapter_contract_sha256",
        "execution_mode",
        "token_id",
        "unsigned_token_sha256",
        "issuer_instance_id",
        "authorization_key_domain_id",
        "principal_id",
        "request_id",
        "request_sha256",
        "decision_id",
        "decision_authorization_sha256",
        "decision_context_sha256",
        "agent_id",
        "command",
        "policy_id",
        "policy_version",
        "policy_sha256",
        "target_state_sha256",
    }
)
_DECISION_OUTCOMES = frozenset(
    {"ALLOW", "DENY", "ESCALATE", "ALLOW_CONSTRAINED", "NOT_DURABLY_RECORDED"}
)
_VERIFICATION_STATUSES = frozenset(
    {
        "VERIFIED",
        "FAILED",
        "PARTIAL",
        "UNEXPECTED_EFFECT",
        "ROLLBACK_REQUIRED",
        "NOT_APPLICABLE",
        "NOT_PERFORMED",
        "NOT_DURABLY_RECORDED",
    }
)
_CONTROL_METADATA_KEYS = frozenset({"schema_version", "ledger_id", "created_at"})
_ADAPTER_METADATA_KEYS = frozenset(
    {
        "schema_version",
        "adapter_store_id",
        "adapter_id",
        "adapter_contract_version",
        "adapter_contract_sha256",
        "execution_mode",
        "inventory_sha256",
        "fault_modes_sha256",
        "created_at",
    }
)

_STORE_STARTUP_LOCK_STATE = local()


@contextmanager
def _store_startup_lock_scope():
    depth = int(getattr(_STORE_STARTUP_LOCK_STATE, "depth", 0))
    _STORE_STARTUP_LOCK_STATE.depth = depth + 1
    try:
        yield
    finally:
        _STORE_STARTUP_LOCK_STATE.depth = depth


def _store_startup_lock_held() -> bool:
    return int(getattr(_STORE_STARTUP_LOCK_STATE, "depth", 0)) > 0


@contextmanager
def _exclusive_store_startup(
    path: Path,
    *,
    timeout_ms: int,
    error_type: type[ControlLedgerError] | type[SyntheticAdapterError],
    unavailable_reason: str,
    path_reason: str,
    label: str,
):
    """Bounded cooperative first-open fence without a lock-file artifact."""

    if _fcntl is None:
        raise error_type(
            unavailable_reason,
            f"{label} interprocess startup serialization is unavailable.",
        )
    absolute = path.absolute()
    parts = absolute.parts
    root = Path(absolute.anchor)
    stable_root = root / parts[1] if len(parts) > 1 else root
    try:
        metadata = stable_root.lstat()
        if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
            raise error_type(path_reason, f"{label} startup lock root is unsafe.")
        flags = os.O_RDONLY
        flags |= getattr(os, "O_CLOEXEC", 0)
        flags |= getattr(os, "O_DIRECTORY", 0)
        flags |= getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(stable_root, flags)
    except error_type:
        raise
    except OSError as exc:
        raise error_type(
            unavailable_reason, f"{label} startup lock root is unavailable."
        ) from exc
    deadline = perf_counter() + (timeout_ms / 1000.0)
    try:
        opened = os.fstat(descriptor)
        current = stable_root.lstat()
        if (
            not stat.S_ISDIR(opened.st_mode)
            or opened.st_dev != current.st_dev
            or opened.st_ino != current.st_ino
        ):
            raise error_type(path_reason, f"{label} startup lock root changed.")
        while True:
            try:
                _fcntl.flock(descriptor, _fcntl.LOCK_EX | _fcntl.LOCK_NB)
                break
            except BlockingIOError:
                remaining = deadline - perf_counter()
                if remaining <= 0:
                    raise error_type(
                        unavailable_reason,
                        f"{label} startup ownership timed out.",
                    ) from None
                sleep(min(0.01, remaining))
        with _store_startup_lock_scope():
            yield
    finally:
        try:
            _fcntl.flock(descriptor, _fcntl.LOCK_UN)
        finally:
            os.close(descriptor)

_CONTROL_SCHEMA_SQL = """
BEGIN IMMEDIATE;
CREATE TABLE IF NOT EXISTS metadata (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
) STRICT;
CREATE TABLE IF NOT EXISTS requests (
    principal_id TEXT NOT NULL,
    request_id TEXT NOT NULL,
    request_sha256 TEXT NOT NULL CHECK(
        length(request_sha256) = 64 AND request_sha256 NOT GLOB '*[^0-9a-f]*'
    ),
    state TEXT NOT NULL CHECK(state IN (
        'CLAIMED', 'AUTHORIZED', 'ATTEMPT_RESERVED', 'TERMINAL'
    )),
    claimed_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    PRIMARY KEY (principal_id, request_id),
    UNIQUE (principal_id, request_id, request_sha256)
) STRICT;
CREATE TABLE IF NOT EXISTS request_results (
    principal_id TEXT NOT NULL,
    request_id TEXT NOT NULL,
    result_json TEXT NOT NULL,
    result_sha256 TEXT NOT NULL CHECK(
        length(result_sha256) = 64 AND result_sha256 NOT GLOB '*[^0-9a-f]*'
    ),
    terminal_at TEXT NOT NULL,
    PRIMARY KEY (principal_id, request_id),
    FOREIGN KEY (principal_id, request_id)
        REFERENCES requests(principal_id, request_id)
) STRICT;
CREATE TABLE IF NOT EXISTS authorizations (
    token_id TEXT PRIMARY KEY,
    verification_id TEXT NOT NULL UNIQUE,
    decision_id TEXT NOT NULL UNIQUE,
    principal_id TEXT,
    request_id TEXT,
    request_sha256 TEXT CHECK(
        request_sha256 IS NULL OR (
            length(request_sha256) = 64
            AND request_sha256 NOT GLOB '*[^0-9a-f]*'
        )
    ),
    unsigned_token_sha256 TEXT CHECK(
        unsigned_token_sha256 IS NULL OR (
            length(unsigned_token_sha256) = 64
            AND unsigned_token_sha256 NOT GLOB '*[^0-9a-f]*'
        )
    ),
    issuer_instance_id TEXT,
    key_domain_id TEXT,
    decision_authorization_sha256 TEXT CHECK(
        decision_authorization_sha256 IS NULL
        OR (
            length(decision_authorization_sha256) = 64
            AND decision_authorization_sha256 NOT GLOB '*[^0-9a-f]*'
        )
    ),
    state TEXT NOT NULL CHECK(state IN ('ISSUED', 'CONSUMED', 'REVOKED')),
    issued_at TEXT NOT NULL,
    consumed_at TEXT,
    revoked_at TEXT,
    revocation_reason TEXT,
    CHECK(
        (principal_id IS NULL AND request_id IS NULL
         AND request_sha256 IS NULL
         AND unsigned_token_sha256 IS NULL
         AND issuer_instance_id IS NULL
         AND key_domain_id IS NULL
         AND decision_authorization_sha256 IS NULL)
        OR
        (principal_id IS NOT NULL AND request_id IS NOT NULL
         AND request_sha256 IS NOT NULL
         AND unsigned_token_sha256 IS NOT NULL
         AND issuer_instance_id IS NOT NULL
         AND key_domain_id IS NOT NULL
         AND decision_authorization_sha256 IS NOT NULL)
    ),
    CHECK(
        (state='ISSUED' AND consumed_at IS NULL
         AND revoked_at IS NULL AND revocation_reason IS NULL)
        OR
        (state='CONSUMED' AND consumed_at IS NOT NULL
         AND revoked_at IS NULL AND revocation_reason IS NULL)
        OR
        (state='REVOKED' AND consumed_at IS NULL
         AND revoked_at IS NOT NULL AND revocation_reason IS NOT NULL)
    ),
    UNIQUE (principal_id, request_id),
    UNIQUE (token_id, principal_id, request_id, request_sha256),
    FOREIGN KEY (principal_id, request_id)
        REFERENCES requests(principal_id, request_id),
    FOREIGN KEY (principal_id, request_id, request_sha256)
        REFERENCES requests(principal_id, request_id, request_sha256)
) STRICT;
CREATE TABLE IF NOT EXISTS attempts (
    attempt_id TEXT PRIMARY KEY,
    token_id TEXT NOT NULL UNIQUE REFERENCES authorizations(token_id),
    principal_id TEXT,
    request_id TEXT,
    request_sha256 TEXT CHECK(
        request_sha256 IS NULL OR (
            length(request_sha256) = 64
            AND request_sha256 NOT GLOB '*[^0-9a-f]*'
        )
    ),
    idempotency_key TEXT NOT NULL UNIQUE CHECK(
        length(idempotency_key) = 64 AND idempotency_key NOT GLOB '*[^0-9a-f]*'
    ),
    binding_sha256 TEXT NOT NULL UNIQUE CHECK(
        length(binding_sha256) = 64 AND binding_sha256 NOT GLOB '*[^0-9a-f]*'
    ),
    recovery_summary_json TEXT,
    recovery_summary_sha256 TEXT CHECK(
        recovery_summary_sha256 IS NULL
        OR (
            length(recovery_summary_sha256) = 64
            AND recovery_summary_sha256 NOT GLOB '*[^0-9a-f]*'
        )
    ),
    state TEXT NOT NULL CHECK(state IN (
        'RESERVED', 'RECEIPT_RECORDED', 'VERIFIED_EFFECT',
        'FAILED_NO_EFFECT', 'RECOVERY_REQUIRED', 'UNKNOWN_EFFECT'
    )),
    outcome_sha256 TEXT CHECK(
        outcome_sha256 IS NULL OR (
            length(outcome_sha256) = 64
            AND outcome_sha256 NOT GLOB '*[^0-9a-f]*'
        )
    ),
    adapter_receipt_sha256 TEXT CHECK(
        adapter_receipt_sha256 IS NULL
        OR (
            length(adapter_receipt_sha256) = 64
            AND adapter_receipt_sha256 NOT GLOB '*[^0-9a-f]*'
        )
    ),
    reserved_at TEXT NOT NULL,
    completed_at TEXT,
    CHECK(idempotency_key = binding_sha256),
    CHECK(
        (principal_id IS NULL AND request_id IS NULL
         AND request_sha256 IS NULL
         AND recovery_summary_json IS NULL
         AND recovery_summary_sha256 IS NULL)
        OR
        (principal_id IS NOT NULL AND request_id IS NOT NULL
         AND request_sha256 IS NOT NULL
         AND recovery_summary_json IS NOT NULL
         AND recovery_summary_sha256 IS NOT NULL)
    ),
    CHECK(
        (state='RESERVED' AND outcome_sha256 IS NULL
         AND adapter_receipt_sha256 IS NULL AND completed_at IS NULL)
        OR
        (state='RECEIPT_RECORDED' AND outcome_sha256 IS NOT NULL
         AND adapter_receipt_sha256 IS NOT NULL AND completed_at IS NULL)
        OR
        (state IN ('VERIFIED_EFFECT','FAILED_NO_EFFECT','RECOVERY_REQUIRED')
         AND outcome_sha256 IS NOT NULL
         AND adapter_receipt_sha256 IS NOT NULL
         AND completed_at IS NOT NULL)
        OR
        (state='UNKNOWN_EFFECT' AND outcome_sha256 IS NOT NULL
         AND completed_at IS NOT NULL)
    ),
    UNIQUE (principal_id, request_id),
    FOREIGN KEY (principal_id, request_id)
        REFERENCES requests(principal_id, request_id),
    FOREIGN KEY (token_id, principal_id, request_id, request_sha256)
        REFERENCES authorizations(
            token_id, principal_id, request_id, request_sha256
        )
) STRICT;
CREATE TABLE IF NOT EXISTS audit_outbox (
    event_id INTEGER PRIMARY KEY AUTOINCREMENT,
    event_type TEXT NOT NULL,
    subject_id TEXT NOT NULL,
    payload_sha256 TEXT NOT NULL CHECK(
        length(payload_sha256) = 64 AND payload_sha256 NOT GLOB '*[^0-9a-f]*'
    ),
    created_at TEXT NOT NULL,
    exported_at TEXT,
    UNIQUE(event_type, subject_id, payload_sha256)
) STRICT;
COMMIT;
"""

_ADAPTER_SCHEMA_SQL = """
BEGIN IMMEDIATE;
CREATE TABLE IF NOT EXISTS metadata (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
) STRICT;
CREATE TABLE IF NOT EXISTS target_states (
    target_id TEXT PRIMARY KEY,
    state_json TEXT NOT NULL,
    state_sha256 TEXT NOT NULL CHECK(
        length(state_sha256)=64 AND state_sha256 NOT GLOB '*[^0-9a-f]*'
    ),
    updated_at TEXT NOT NULL
) STRICT;
CREATE TABLE IF NOT EXISTS command_receipts (
    idempotency_key TEXT PRIMARY KEY CHECK(
        length(idempotency_key)=64 AND idempotency_key NOT GLOB '*[^0-9a-f]*'
    ),
    principal_id TEXT NOT NULL,
    request_id TEXT NOT NULL,
    binding_json TEXT NOT NULL,
    binding_sha256 TEXT NOT NULL UNIQUE CHECK(
        length(binding_sha256)=64 AND binding_sha256 NOT GLOB '*[^0-9a-f]*'
    ),
    receipt_json TEXT NOT NULL,
    receipt_sha256 TEXT NOT NULL CHECK(
        length(receipt_sha256)=64 AND receipt_sha256 NOT GLOB '*[^0-9a-f]*'
    ),
    target_id TEXT NOT NULL REFERENCES target_states(target_id),
    committed_at TEXT NOT NULL,
    CHECK(idempotency_key = binding_sha256),
    UNIQUE(principal_id, request_id)
) STRICT;
COMMIT;
"""


class ControlLedgerError(RuntimeError):
    def __init__(self, reason_code: str, message: str) -> None:
        super().__init__(message)
        self.reason_code = reason_code


class SyntheticAdapterError(RuntimeError):
    def __init__(self, reason_code: str, message: str) -> None:
        super().__init__(message)
        self.reason_code = reason_code


def _require_identifier(
    name: str,
    value: object,
    *,
    error_type: type[ControlLedgerError] | type[SyntheticAdapterError] = ControlLedgerError,
    reason_code: str = "CONTROL_LEDGER_BINDING_INVALID",
) -> str:
    if type(value) is not str or not value or len(value) > 512:
        raise error_type(
            reason_code,
            f"{name} must be a non-empty bounded exact string.",
        )
    return value


def _require_sha256(
    name: str,
    value: object,
    *,
    error_type: type[ControlLedgerError] | type[SyntheticAdapterError] = ControlLedgerError,
    reason_code: str = "CONTROL_LEDGER_BINDING_INVALID",
) -> str:
    candidate = _require_identifier(
        name, value, error_type=error_type, reason_code=reason_code
    )
    if len(candidate) != 64 or any(
        character not in "0123456789abcdef" for character in candidate
    ):
        raise error_type(
            reason_code,
            f"{name} must be a lowercase SHA-256 digest.",
        )
    return candidate


def _event_digest(event_type: str, subject_id: str, payload: dict[str, Any]) -> str:
    return hashlib.sha256(
        canonical_json(
            {
                "event_type": event_type,
                "subject_id": subject_id,
                "payload": payload,
            }
        ).encode("utf-8")
    ).hexdigest()


def _application_schema_sha256(connection: sqlite3.Connection) -> str:
    projection = [
        {
            "type": str(row[0]),
            "name": str(row[1]),
            "tbl_name": str(row[2]),
            "sql": row[3],
        }
        for row in connection.execute(
            """
            SELECT type, name, tbl_name, sql FROM sqlite_master
            WHERE name NOT LIKE 'sqlite_%'
            ORDER BY type, name
            """
        )
    ]
    return sha256_json(projection)


def _schema_contract_sha256(schema_sql: str) -> str:
    """Derive the supported DDL projection using this runtime's SQLite parser."""

    reference = sqlite3.connect(":memory:", isolation_level=None)
    try:
        reference.execute("PRAGMA foreign_keys=ON")
        reference.executescript(schema_sql)
        return _application_schema_sha256(reference)
    finally:
        reference.close()


_CONTROL_SCHEMA_SHA256 = _schema_contract_sha256(_CONTROL_SCHEMA_SQL)
_ADAPTER_SCHEMA_SHA256 = _schema_contract_sha256(_ADAPTER_SCHEMA_SQL)


def _file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while chunk := handle.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def _assert_sqlite_wal_header(
    path: Path,
    *,
    error_type: type[ControlLedgerError] | type[SyntheticAdapterError],
    reason_code: str,
    label: str,
) -> None:
    try:
        with path.open("rb") as handle:
            header = handle.read(100)
    except OSError as exc:
        raise error_type(reason_code, f"{label} header could not be read.") from exc
    if (
        len(header) < 100
        or header[:16] != b"SQLite format 3\x00"
        or header[18] != 2
        or header[19] != 2
    ):
        raise error_type(reason_code, f"{label} file header is not WAL-formatted.")


def _open_readonly_preflight(
    path: Path, *, busy_timeout_ms: int
) -> tuple[sqlite3.Connection, tempfile.TemporaryDirectory[str] | None, bool]:
    """Open a nonmutating validation view; copy an active WAL into scratch space."""

    wal_path = Path(str(path) + "-wal")
    shm_path = Path(str(path) + "-shm")
    if shm_path.exists() and not wal_path.exists():
        raise sqlite3.DatabaseError("SQLite SHM exists without its WAL.")
    scratch: tempfile.TemporaryDirectory[str] | None = None
    validation_path = path
    immutable = not wal_path.exists()
    if wal_path.exists():
        originals = (path, wal_path)
        before = {
            item: (item.stat().st_size, item.stat().st_mtime_ns, _file_sha256(item))
            for item in originals
        }
        scratch = tempfile.TemporaryDirectory(prefix="adf-stage-a-preflight-")
        validation_path = Path(scratch.name) / path.name
        shutil.copy2(path, validation_path)
        shutil.copy2(wal_path, Path(str(validation_path) + "-wal"))
        after = {
            item: (item.stat().st_size, item.stat().st_mtime_ns, _file_sha256(item))
            for item in originals
        }
        if before != after:
            scratch.cleanup()
            raise sqlite3.DatabaseError("SQLite files changed during preflight copy.")
    suffix = "?mode=ro&immutable=1" if immutable else "?mode=ro"
    try:
        connection = sqlite3.connect(
            validation_path.resolve().as_uri() + suffix,
            uri=True,
            timeout=busy_timeout_ms / 1000.0,
            isolation_level=None,
        )
    except Exception:
        if scratch is not None:
            scratch.cleanup()
        raise
    return connection, scratch, not immutable


def _assert_sqlite_runtime_integrity(
    connection: sqlite3.Connection,
    *,
    expected_schema_sha256: str,
    error_type: type[ControlLedgerError] | type[SyntheticAdapterError],
    schema_reason: str,
    corrupt_reason: str,
    durability_reason: str,
    label: str,
    verify_journal_mode: bool = True,
) -> None:
    if _application_schema_sha256(connection) != expected_schema_sha256:
        raise error_type(
            schema_reason,
            f"{label} application schema does not exactly match the supported contract.",
        )
    if verify_journal_mode and str(
        connection.execute("PRAGMA journal_mode").fetchone()[0]
    ).lower() != "wal":
        raise error_type(durability_reason, f"{label} journal mode is not WAL.")
    if int(connection.execute("PRAGMA synchronous").fetchone()[0]) != 2:
        raise error_type(durability_reason, f"{label} synchronous mode is not FULL.")
    if int(connection.execute("PRAGMA foreign_keys").fetchone()[0]) != 1:
        raise error_type(durability_reason, f"{label} foreign keys are not enforced.")
    if connection.execute("PRAGMA integrity_check").fetchone()[0] != "ok":
        raise error_type(corrupt_reason, f"{label} integrity check failed.")
    if connection.execute("PRAGMA foreign_key_check").fetchone() is not None:
        raise error_type(corrupt_reason, f"{label} contains a foreign-key violation.")


def _reject_authority_bearing_keys(
    value: object,
    *,
    error_type: type[ControlLedgerError] | type[SyntheticAdapterError],
    reason_code: str,
    denied_keys: frozenset[str] = _AUTHORITY_BEARING_KEYS,
) -> None:
    stack: list[tuple[object, int]] = [(value, 0)]
    nodes = 0
    while stack:
        current, depth = stack.pop()
        nodes += 1
        if depth > 32 or nodes > 4_096:
            raise error_type(
                reason_code, "Persisted JSON exceeds structural bounds."
            )
        if type(current) is dict:
            for key, child in current.items():
                if type(key) is not str:
                    raise error_type(
                        reason_code, "Persisted JSON keys must be exact strings."
                    )
                if key.lower() in denied_keys:
                    raise error_type(
                        reason_code,
                        "Persisted receipt/result contains authority-bearing material.",
                    )
                stack.append((child, depth + 1))
        elif type(current) is list:
            stack.extend((child, depth + 1) for child in current)


def _load_json_object(
    raw: object,
    *,
    error_type: type[ControlLedgerError] | type[SyntheticAdapterError],
    reason_code: str,
    max_bytes: int = 32_768,
) -> dict[str, Any]:
    if type(raw) is not str:
        raise error_type(reason_code, "Persisted JSON must be an exact string.")
    try:
        if len(raw.encode("utf-8")) > max_bytes:
            raise error_type(reason_code, "Persisted JSON exceeds its size bound.")
    except UnicodeEncodeError as exc:
        raise error_type(reason_code, "Persisted JSON text is invalid.") from exc

    def reject_constant(value: str) -> object:
        raise ValueError(f"nonfinite JSON constant {value}")

    try:
        value = json.loads(raw, parse_constant=reject_constant)
    except (TypeError, ValueError, json.JSONDecodeError, RecursionError) as exc:
        raise error_type(reason_code, "Persisted JSON is invalid.") from exc
    stack: list[tuple[object, int]] = [(value, 0)]
    nodes = 0
    while stack:
        child, depth = stack.pop()
        nodes += 1
        if depth > 32 or nodes > 4_096:
            raise error_type(reason_code, "Persisted JSON exceeds structural bounds.")
        if type(child) is dict:
            stack.extend((grandchild, depth + 1) for grandchild in child.values())
        elif type(child) is list:
            stack.extend((grandchild, depth + 1) for grandchild in child)
    try:
        canonical = canonical_json(value)
    except (TypeError, ValueError, RecursionError) as exc:
        raise error_type(reason_code, "Persisted JSON is not canonical.") from exc
    if type(value) is not dict or canonical != raw:
        raise error_type(reason_code, "Persisted JSON is not a canonical exact object.")
    return value


def _assert_quiesced(value: object) -> None:
    if value is not True:
        raise ControlLedgerError(
            "RECOVERY_QUIESCENCE_REQUIRED",
            "Recovery requires an exact operator assertion that execution is "
            "quiesced; the assertion is not a lease or fencing mechanism.",
        )


def _is_uuid(value: object) -> bool:
    if type(value) is not str:
        return False
    try:
        return str(uuid.UUID(value)) == value.lower()
    except (ValueError, AttributeError):
        return False


def _is_offset_timestamp(value: object) -> bool:
    if type(value) is not str or not value or len(value) > 64:
        return False
    try:
        parsed = datetime.fromisoformat(value)
        return parsed.tzinfo is not None and parsed.utcoffset() is not None
    except (TypeError, ValueError, OverflowError):
        return False


def _require_offset_timestamp(
    name: str,
    value: object,
    *,
    error_type: type[ControlLedgerError] | type[SyntheticAdapterError] = ControlLedgerError,
    reason_code: str = "CONTROL_LEDGER_BINDING_INVALID",
) -> str:
    if not _is_offset_timestamp(value):
        raise error_type(reason_code, f"{name} must be a bounded offset timestamp.")
    return str(value)


def _validate_control_metadata(metadata: Mapping[str, str]) -> None:
    if (
        set(metadata) != _CONTROL_METADATA_KEYS
        or metadata.get("schema_version") != SCHEMA_VERSION
        or not _is_uuid(metadata.get("ledger_id"))
        or not _is_offset_timestamp(metadata.get("created_at"))
    ):
        raise ControlLedgerError(
            "CONTROL_LEDGER_SCHEMA_UNSUPPORTED",
            "Control-ledger immutable metadata is not the exact supported contract.",
        )


def _validate_control_relations(connection: sqlite3.Connection) -> None:
    rows = connection.execute(
        """
        SELECT r.principal_id, r.request_id, r.request_sha256, r.state,
               r.claimed_at, r.updated_at,
               (SELECT count(*) FROM authorizations z
                WHERE z.principal_id=r.principal_id AND z.request_id=r.request_id)
                   AS authorization_count,
               (SELECT max(z.state) FROM authorizations z
                WHERE z.principal_id=r.principal_id AND z.request_id=r.request_id)
                   AS authorization_state,
               (SELECT count(*) FROM attempts a
                WHERE a.principal_id=r.principal_id AND a.request_id=r.request_id)
                   AS attempt_count,
               (SELECT max(a.state) FROM attempts a
                WHERE a.principal_id=r.principal_id AND a.request_id=r.request_id)
                   AS attempt_state,
               (SELECT count(*) FROM request_results x
                WHERE x.principal_id=r.principal_id AND x.request_id=r.request_id)
                   AS result_count
        FROM requests r
        """
    ).fetchall()
    for row in rows:
        try:
            principal_id = _require_identifier("principal_id", row["principal_id"])
            request_id = _require_identifier("request_id", row["request_id"])
            request_sha256 = _require_sha256(
                "request_sha256", row["request_sha256"]
            )
            claimed_at = _require_offset_timestamp("claimed_at", row["claimed_at"])
            updated_at = _require_offset_timestamp("updated_at", row["updated_at"])
            if datetime.fromisoformat(updated_at) < datetime.fromisoformat(claimed_at):
                raise ControlLedgerError(
                    "CONTROL_LEDGER_CORRUPT",
                    "Control-ledger request timestamps are not monotonic.",
                )

            authorizations = connection.execute(
                """
                SELECT token_id, verification_id, decision_id, principal_id,
                       request_id, request_sha256, unsigned_token_sha256,
                       issuer_instance_id, key_domain_id,
                       decision_authorization_sha256, state, issued_at,
                       consumed_at, revoked_at, revocation_reason
                FROM authorizations
                WHERE principal_id=? AND request_id=?
                """,
                (principal_id, request_id),
            ).fetchall()
            attempts = connection.execute(
                """
                SELECT attempt_id, token_id, principal_id, request_id,
                       request_sha256, idempotency_key, binding_sha256,
                       recovery_summary_json, recovery_summary_sha256,
                       state, outcome_sha256, adapter_receipt_sha256,
                       reserved_at, completed_at
                FROM attempts
                WHERE principal_id=? AND request_id=?
                """,
                (principal_id, request_id),
            ).fetchall()
            results = connection.execute(
                """
                SELECT principal_id, request_id, result_json,
                       result_sha256, terminal_at
                FROM request_results
                WHERE principal_id=? AND request_id=?
                """,
                (principal_id, request_id),
            ).fetchall()
            auth_count = len(authorizations)
            attempt_count = len(attempts)
            result_count = len(results)
            state = row["state"]
            coherent = False
            if state == "CLAIMED":
                coherent = auth_count == attempt_count == result_count == 0
            elif state == "AUTHORIZED":
                coherent = (
                    auth_count == 1
                    and authorizations[0]["state"] in {"ISSUED", "REVOKED"}
                    and attempt_count == 0
                    and result_count == 0
                )
            elif state == "ATTEMPT_RESERVED":
                coherent = (
                    auth_count == 1
                    and authorizations[0]["state"] == "CONSUMED"
                    and attempt_count == 1
                    and attempts[0]["state"] in {"RESERVED", "RECEIPT_RECORDED"}
                    and result_count == 0
                )
            elif state == "TERMINAL":
                coherent = result_count == 1 and (
                    (
                        attempt_count == 0
                        and (
                            auth_count == 0
                            or (
                                auth_count == 1
                                and authorizations[0]["state"] == "REVOKED"
                            )
                        )
                    )
                    or (
                        attempt_count == 1
                        and auth_count == 1
                        and authorizations[0]["state"] == "CONSUMED"
                        and attempts[0]["state"] in _TERMINAL_ATTEMPT_STATES
                    )
                )
            if not coherent:
                raise ControlLedgerError(
                    "CONTROL_LEDGER_CORRUPT",
                    "Control-ledger request lifecycle cardinality is inconsistent.",
                )

            authorization = authorizations[0] if authorizations else None
            if authorization is not None:
                for name in (
                    "token_id",
                    "verification_id",
                    "decision_id",
                    "issuer_instance_id",
                    "key_domain_id",
                ):
                    _require_identifier(name, authorization[name])
                for name in (
                    "request_sha256",
                    "unsigned_token_sha256",
                    "decision_authorization_sha256",
                ):
                    _require_sha256(name, authorization[name])
                if (
                    authorization["principal_id"] != principal_id
                    or authorization["request_id"] != request_id
                    or authorization["request_sha256"] != request_sha256
                ):
                    raise ControlLedgerError(
                        "CONTROL_LEDGER_CORRUPT",
                        "Control-ledger authorization request binding is invalid.",
                    )
                issued_at = _require_offset_timestamp(
                    "issued_at", authorization["issued_at"]
                )
                if datetime.fromisoformat(issued_at) < datetime.fromisoformat(
                    claimed_at
                ) or (state == "AUTHORIZED" and updated_at != issued_at):
                    raise ControlLedgerError(
                        "CONTROL_LEDGER_CORRUPT",
                        "Control-ledger authorization chronology is inconsistent.",
                    )
                terminal_auth_at = (
                    authorization["consumed_at"]
                    if authorization["state"] == "CONSUMED"
                    else authorization["revoked_at"]
                    if authorization["state"] == "REVOKED"
                    else None
                )
                if terminal_auth_at is not None and (
                    not _is_offset_timestamp(terminal_auth_at)
                    or datetime.fromisoformat(terminal_auth_at)
                    < datetime.fromisoformat(issued_at)
                ):
                    raise ControlLedgerError(
                        "CONTROL_LEDGER_CORRUPT",
                        "Control-ledger authorization timestamps are invalid.",
                    )
                if authorization["state"] == "REVOKED":
                    _require_identifier(
                        "revocation_reason", authorization["revocation_reason"]
                    )

            attempt = attempts[0] if attempts else None
            summary: dict[str, Any] | None = None
            if attempt is not None:
                for name in ("attempt_id", "token_id"):
                    _require_identifier(name, attempt[name])
                for name in (
                    "request_sha256",
                    "idempotency_key",
                    "binding_sha256",
                ):
                    _require_sha256(name, attempt[name])
                if (
                    authorization is None
                    or attempt["token_id"] != authorization["token_id"]
                    or attempt["principal_id"] != principal_id
                    or attempt["request_id"] != request_id
                    or attempt["request_sha256"] != request_sha256
                    or attempt["idempotency_key"] != attempt["binding_sha256"]
                ):
                    raise ControlLedgerError(
                        "CONTROL_LEDGER_CORRUPT",
                        "Control-ledger attempt authority binding is invalid.",
                    )
                reserved_at = _require_offset_timestamp(
                    "reserved_at", attempt["reserved_at"]
                )
                if (
                    authorization["consumed_at"] != reserved_at
                    or datetime.fromisoformat(reserved_at)
                    < datetime.fromisoformat(authorization["issued_at"])
                    or (state == "ATTEMPT_RESERVED" and updated_at != reserved_at)
                ):
                    raise ControlLedgerError(
                        "CONTROL_LEDGER_CORRUPT",
                        "Control-ledger attempt chronology is inconsistent.",
                    )
                raw_summary = attempt["recovery_summary_json"]
                raw_summary_sha256 = attempt["recovery_summary_sha256"]
                if (
                    type(raw_summary) is not str
                    or len(raw_summary.encode("utf-8")) > 16_384
                    or hashlib.sha256(raw_summary.encode("utf-8")).hexdigest()
                    != raw_summary_sha256
                ):
                    raise ControlLedgerError(
                        "CONTROL_LEDGER_CORRUPT",
                        "Control-ledger recovery-summary integrity failed.",
                    )
                summary = _validate_recovery_summary(
                    _load_json_object(
                        raw_summary,
                        error_type=ControlLedgerError,
                        reason_code="CONTROL_LEDGER_CORRUPT",
                        max_bytes=16_384,
                    )
                )
                if (
                    summary["principal_id"] != principal_id
                    or summary["request_id"] != request_id
                    or summary["request_sha256"] != request_sha256
                    or summary["decision_id"] != authorization["decision_id"]
                    or summary["decision_sha256"]
                    != authorization["decision_authorization_sha256"]
                    or summary["decision_outcome"]
                    not in {"ALLOW", "ALLOW_CONSTRAINED"}
                    or datetime.fromisoformat(summary["decided_at"])
                    < datetime.fromisoformat(claimed_at)
                    or datetime.fromisoformat(summary["decided_at"])
                    > datetime.fromisoformat(authorization["issued_at"])
                ):
                    raise ControlLedgerError(
                        "CONTROL_LEDGER_CORRUPT",
                        "Control-ledger recovery-summary provenance is invalid.",
                    )
                if attempt["outcome_sha256"] is not None:
                    _require_sha256("outcome_sha256", attempt["outcome_sha256"])
                if attempt["adapter_receipt_sha256"] is not None:
                    _require_sha256(
                        "adapter_receipt_sha256",
                        attempt["adapter_receipt_sha256"],
                    )
                if attempt["completed_at"] is not None:
                    completed_at = _require_offset_timestamp(
                        "completed_at", attempt["completed_at"]
                    )
                    if datetime.fromisoformat(completed_at) < datetime.fromisoformat(
                        reserved_at
                    ):
                        raise ControlLedgerError(
                            "CONTROL_LEDGER_CORRUPT",
                            "Control-ledger attempt timestamps are not monotonic.",
                        )

            if results:
                result_row = results[0]
                raw_result = result_row["result_json"]
                if (
                    type(raw_result) is not str
                    or len(raw_result.encode("utf-8")) > 32_768
                    or hashlib.sha256(raw_result.encode("utf-8")).hexdigest()
                    != result_row["result_sha256"]
                ):
                    raise ControlLedgerError(
                        "CONTROL_LEDGER_CORRUPT",
                        "Terminal request-result integrity failed.",
                    )
                result = RequestLookupResult.from_dict(
                    _load_json_object(
                        raw_result,
                        error_type=ControlLedgerError,
                        reason_code="CONTROL_LEDGER_CORRUPT",
                    )
                )
                if (
                    result.replayed
                    or result.principal_id != principal_id
                    or result.request_id != request_id
                    or result.request_sha256 != request_sha256
                    or result_row["terminal_at"] != result.terminal_at
                    or updated_at != result.terminal_at
                ):
                    raise ControlLedgerError(
                        "CONTROL_LEDGER_CORRUPT",
                        "Terminal request-result row binding is invalid.",
                    )
                if attempt is None:
                    if result.attempt_id is not None:
                        raise ControlLedgerError(
                            "CONTROL_LEDGER_CORRUPT",
                            "Nonexecuting result unexpectedly binds an attempt.",
                        )
                    if authorization is not None:
                        if (
                            authorization["state"] != "REVOKED"
                            or result.disposition != "ABORTED_NO_EFFECT"
                            or datetime.fromisoformat(result.terminal_at)
                            < datetime.fromisoformat(authorization["revoked_at"])
                        ):
                            raise ControlLedgerError(
                                "CONTROL_LEDGER_CORRUPT",
                                "Retained revoked authority does not bind an aborted result.",
                            )
                    elif result.disposition not in {
                        "DENIED_NO_EFFECT",
                        "ABORTED_NO_EFFECT",
                    }:
                        raise ControlLedgerError(
                            "CONTROL_LEDGER_CORRUPT",
                            "Nonexecuting result has an invalid authority history.",
                        )
                else:
                    disposition_states = {
                        "COMPLETED_VERIFIED": "VERIFIED_EFFECT",
                        "FAILED_NO_EFFECT": "FAILED_NO_EFFECT",
                        "RECOVERY_REQUIRED": "RECOVERY_REQUIRED",
                        "UNKNOWN_EFFECT": "UNKNOWN_EFFECT",
                    }
                    if (
                        summary is None
                        or result.attempt_id != attempt["attempt_id"]
                        or disposition_states.get(result.disposition)
                        != attempt["state"]
                        or result.adapter_receipt_sha256
                        != attempt["adapter_receipt_sha256"]
                        or result.terminal_at != attempt["completed_at"]
                        or attempt["outcome_sha256"]
                        != terminal_attempt_outcome_sha256(result, attempt["state"])
                        or result.decision_id != summary["decision_id"]
                        or result.decision_outcome != summary["decision_outcome"]
                        or result.decision_sha256 != summary["decision_sha256"]
                        or result.decision_context_sha256
                        != summary["decision_context_sha256"]
                        or result.policy_sha256 != summary["policy_sha256"]
                        or result.decided_at != summary["decided_at"]
                    ):
                        raise ControlLedgerError(
                            "CONTROL_LEDGER_CORRUPT",
                            "Terminal result, attempt, and authorization provenance differ.",
                        )
        except ControlLedgerError as exc:
            if exc.reason_code == "CONTROL_LEDGER_CORRUPT":
                raise
            raise ControlLedgerError(
                "CONTROL_LEDGER_CORRUPT",
                "Control-ledger row semantics are invalid.",
            ) from exc

    try:
        unlinked_authorizations = connection.execute(
            """
            SELECT token_id, verification_id, decision_id, state, issued_at,
                   consumed_at, revoked_at, revocation_reason
            FROM authorizations
            WHERE principal_id IS NULL
            """
        ).fetchall()
        unlinked_by_token = {}
        for authorization in unlinked_authorizations:
            for name in ("token_id", "verification_id", "decision_id"):
                _require_identifier(name, authorization[name])
            issued_at = _require_offset_timestamp(
                "issued_at", authorization["issued_at"]
            )
            terminal_at = (
                authorization["consumed_at"]
                if authorization["state"] == "CONSUMED"
                else authorization["revoked_at"]
                if authorization["state"] == "REVOKED"
                else None
            )
            if terminal_at is not None and (
                not _is_offset_timestamp(terminal_at)
                or datetime.fromisoformat(terminal_at)
                < datetime.fromisoformat(issued_at)
            ):
                raise ControlLedgerError(
                    "CONTROL_LEDGER_CORRUPT",
                    "Unlinked authorization timestamps are not monotonic.",
                )
            if authorization["state"] == "REVOKED":
                _require_identifier(
                    "revocation_reason", authorization["revocation_reason"]
                )
            unlinked_by_token[str(authorization["token_id"])] = authorization

        unlinked_attempts = connection.execute(
            """
            SELECT attempt_id, token_id, idempotency_key, binding_sha256,
                   state, outcome_sha256, adapter_receipt_sha256,
                   reserved_at, completed_at
            FROM attempts
            WHERE principal_id IS NULL
            """
        ).fetchall()
        for attempt in unlinked_attempts:
            _require_identifier("attempt_id", attempt["attempt_id"])
            _require_identifier("token_id", attempt["token_id"])
            _require_sha256("idempotency_key", attempt["idempotency_key"])
            _require_sha256("binding_sha256", attempt["binding_sha256"])
            authorization = unlinked_by_token.get(str(attempt["token_id"]))
            reserved_at = _require_offset_timestamp(
                "reserved_at", attempt["reserved_at"]
            )
            if (
                authorization is None
                or authorization["state"] != "CONSUMED"
                or authorization["consumed_at"] != reserved_at
                or datetime.fromisoformat(reserved_at)
                < datetime.fromisoformat(authorization["issued_at"])
            ):
                raise ControlLedgerError(
                    "CONTROL_LEDGER_CORRUPT",
                    "Unlinked attempt authority chronology is inconsistent.",
                )
            if attempt["outcome_sha256"] is not None:
                _require_sha256("outcome_sha256", attempt["outcome_sha256"])
            if attempt["adapter_receipt_sha256"] is not None:
                _require_sha256(
                    "adapter_receipt_sha256", attempt["adapter_receipt_sha256"]
                )
            if attempt["completed_at"] is not None and (
                not _is_offset_timestamp(attempt["completed_at"])
                or datetime.fromisoformat(attempt["completed_at"])
                < datetime.fromisoformat(reserved_at)
            ):
                raise ControlLedgerError(
                    "CONTROL_LEDGER_CORRUPT",
                    "Unlinked attempt timestamps are not monotonic.",
                )
    except ControlLedgerError as exc:
        if exc.reason_code == "CONTROL_LEDGER_CORRUPT":
            raise
        raise ControlLedgerError(
            "CONTROL_LEDGER_CORRUPT",
            "Unlinked control-ledger row semantics are invalid.",
        ) from exc


def _control_correlation_snapshot(
    connection: sqlite3.Connection,
) -> tuple[dict[str, str | None], ...]:
    """Return the closed cross-store projection after control validation."""

    rows = connection.execute(
        """
        SELECT a.principal_id, a.request_id, a.attempt_id, a.idempotency_key,
               a.request_sha256, a.binding_sha256, a.state,
               a.adapter_receipt_sha256, a.recovery_summary_json,
               z.token_id, z.unsigned_token_sha256, z.issuer_instance_id,
               z.key_domain_id, z.decision_id,
               z.decision_authorization_sha256,
               x.result_json
        FROM attempts a
        JOIN authorizations z ON z.token_id=a.token_id
        LEFT JOIN request_results x
          ON x.principal_id=a.principal_id AND x.request_id=a.request_id
        WHERE a.principal_id IS NOT NULL
        ORDER BY a.principal_id, a.request_id
        """
    ).fetchall()
    snapshot: list[dict[str, str | None]] = []
    for row in rows:
        summary = _validate_recovery_summary(
            _load_json_object(
                row["recovery_summary_json"],
                error_type=ControlLedgerError,
                reason_code="CONTROL_LEDGER_CORRUPT",
                max_bytes=16_384,
            )
        )
        target_state_sha256: str | None = None
        if row["result_json"] is not None:
            result = RequestLookupResult.from_dict(
                _load_json_object(
                    row["result_json"],
                    error_type=ControlLedgerError,
                    reason_code="CONTROL_LEDGER_CORRUPT",
                )
            )
            target_state_sha256 = result.target_state_sha256
        snapshot.append({
            "principal_id": str(row["principal_id"]),
            "request_id": str(row["request_id"]),
            "attempt_id": str(row["attempt_id"]),
            "request_sha256": str(row["request_sha256"]),
            "token_id": str(row["token_id"]),
            "unsigned_token_sha256": str(row["unsigned_token_sha256"]),
            "issuer_instance_id": str(row["issuer_instance_id"]),
            "authorization_key_domain_id": str(row["key_domain_id"]),
            "decision_id": str(row["decision_id"]),
            "decision_authorization_sha256": str(
                row["decision_authorization_sha256"]
            ),
            "decision_context_sha256": str(summary["decision_context_sha256"]),
            "policy_sha256": str(summary["policy_sha256"]),
            "idempotency_key": str(row["idempotency_key"]),
            "binding_sha256": str(row["binding_sha256"]),
            "state": str(row["state"]),
            "target_state_sha256": target_state_sha256,
            "adapter_receipt_sha256": (
                str(row["adapter_receipt_sha256"])
                if row["adapter_receipt_sha256"] is not None
                else None
            ),
        })
    return tuple(snapshot)


def _assert_safe_parent_chain(
    path: Path,
    *,
    allow_missing: bool,
    error_type: type[ControlLedgerError] | type[SyntheticAdapterError],
    reason_code: str,
    label: str,
) -> None:
    for ancestor in reversed(path.parents):
        try:
            metadata = ancestor.lstat()
        except FileNotFoundError:
            if allow_missing:
                continue
            raise error_type(
                reason_code, f"{label} parent directory is unavailable."
            ) from None
        if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
            raise error_type(
                reason_code,
                f"{label} parent chain cannot contain symbolic links or non-directories.",
            )


def _assert_safe_path(
    path: Path,
    *,
    allow_missing: bool,
    error_type: type[ControlLedgerError] | type[SyntheticAdapterError],
    unsafe_reason: str,
    unavailable_reason: str,
    label: str,
) -> None:
    _assert_safe_parent_chain(
        path,
        allow_missing=allow_missing,
        error_type=error_type,
        reason_code=unsafe_reason,
        label=label,
    )
    if path.exists() or path.is_symlink():
        metadata = path.lstat()
        if (
            path.is_symlink()
            or not stat.S_ISREG(metadata.st_mode)
            or metadata.st_nlink != 1
        ):
            raise error_type(
                unsafe_reason,
                f"{label} path must be a singly linked regular file.",
            )
    elif not allow_missing:
        raise error_type(unavailable_reason, f"{label} file is unavailable.")


def _assert_safe_sqlite_sidecars(
    path: Path,
    *,
    error_type: type[ControlLedgerError] | type[SyntheticAdapterError],
    reason_code: str,
    label: str,
) -> None:
    for suffix in ("-wal", "-shm", "-journal"):
        sidecar = Path(str(path) + suffix)
        if not sidecar.exists() and not sidecar.is_symlink():
            continue
        metadata = sidecar.lstat()
        if (
            suffix == "-journal"
            or stat.S_ISLNK(metadata.st_mode)
            or not stat.S_ISREG(metadata.st_mode)
            or metadata.st_nlink != 1
            or metadata.st_uid != os.geteuid()
            or stat.S_IMODE(metadata.st_mode) & 0o077
        ):
            raise error_type(
                reason_code,
                f"{label} SQLite sidecars must be owner-private singly linked regular WAL/SHM files.",
            )


@dataclass(frozen=True, slots=True)
class RequestLookupResult:
    """Closed sanitized terminal result; it never conveys executable authority."""

    schema_version: str
    principal_id: str
    request_id: str
    request_sha256: str
    disposition: str
    decision_id: str
    decision_outcome: str
    decision_sha256: str
    decision_context_sha256: str
    policy_sha256: str
    verification_status: str
    verification_sha256: str | None
    attempt_id: str | None
    adapter_receipt_sha256: str | None
    target_state_sha256: str | None
    decided_at: str
    terminal_at: str
    recovery_required: bool
    reason_codes: tuple[str, ...]
    replayed: bool
    execution_attempted_this_call: bool
    new_decision: bool
    new_authorization: bool
    new_effect: bool
    authorization: None = None

    def __post_init__(self) -> None:
        if self.schema_version != REQUEST_LOOKUP_SCHEMA_VERSION:
            raise ControlLedgerError(
                "REQUEST_RESULT_SCHEMA_UNSUPPORTED",
                "Request-result schema version is unsupported.",
            )
        for name in (
            "principal_id",
            "request_id",
            "disposition",
            "decision_id",
            "decision_outcome",
            "verification_status",
            "decided_at",
            "terminal_at",
        ):
            _require_identifier(name, getattr(self, name))
        for name in (
            "request_sha256",
            "decision_sha256",
            "decision_context_sha256",
            "policy_sha256",
        ):
            _require_sha256(name, getattr(self, name))
        for name in (
            "verification_sha256",
            "adapter_receipt_sha256",
            "target_state_sha256",
        ):
            value = getattr(self, name)
            if value is not None:
                _require_sha256(name, value)
        if self.attempt_id is not None:
            _require_identifier("attempt_id", self.attempt_id)
        if self.disposition not in _REQUEST_DISPOSITIONS:
            raise ControlLedgerError(
                "REQUEST_RESULT_INVALID", "Request disposition is not closed."
            )
        if self.decision_outcome not in _DECISION_OUTCOMES:
            raise ControlLedgerError(
                "REQUEST_RESULT_INVALID", "Decision outcome is not closed."
            )
        if (
            self.disposition == "DENIED_NO_EFFECT"
            and self.decision_outcome not in {"DENY", "ESCALATE"}
        ) or (
            self.disposition == "ABORTED_NO_EFFECT"
            and self.decision_outcome != "NOT_DURABLY_RECORDED"
        ) or (
            self.disposition
            in {
                "COMPLETED_VERIFIED",
                "FAILED_NO_EFFECT",
                "RECOVERY_REQUIRED",
                "UNKNOWN_EFFECT",
            }
            and self.decision_outcome not in {"ALLOW", "ALLOW_CONSTRAINED"}
        ):
            raise ControlLedgerError(
                "REQUEST_RESULT_INVALID",
                "Request disposition and decision outcome are inconsistent.",
            )
        if self.verification_status not in _VERIFICATION_STATUSES:
            raise ControlLedgerError(
                "REQUEST_RESULT_INVALID", "Verification status is not closed."
            )
        if type(self.recovery_required) is not bool or any(
            type(getattr(self, name)) is not bool
            for name in (
                "replayed",
                "execution_attempted_this_call",
                "new_decision",
                "new_authorization",
                "new_effect",
            )
        ):
            raise ControlLedgerError(
                "REQUEST_RESULT_INVALID", "Request-result flags must be exact booleans."
            )
        if (
            self.execution_attempted_this_call
            or self.new_decision
            or self.new_authorization
            or self.new_effect
        ):
            raise ControlLedgerError(
                "REQUEST_RESULT_AUTHORITY_PROHIBITED",
                "A terminal lookup envelope cannot claim new work or a new effect.",
            )
        if (
            type(self.reason_codes) is not tuple
            or len(self.reason_codes) > 32
            or any(
                type(reason) is not str
                or not reason
                or len(reason) > 128
                for reason in self.reason_codes
            )
        ):
            raise ControlLedgerError(
                "REQUEST_RESULT_INVALID", "Request-result reasons are invalid."
            )
        if self.authorization is not None:
            raise ControlLedgerError(
                "REQUEST_RESULT_AUTHORITY_PROHIBITED",
                "A request lookup result cannot contain authorization.",
            )
        if self.attempt_id is None:
            if (
                self.disposition not in {"DENIED_NO_EFFECT", "ABORTED_NO_EFFECT"}
                or self.adapter_receipt_sha256 is not None
                or self.target_state_sha256 is not None
                or self.verification_sha256 is not None
                or self.recovery_required
                or self.verification_status not in {"NOT_APPLICABLE", "NOT_PERFORMED"}
            ):
                raise ControlLedgerError(
                    "REQUEST_RESULT_INVALID",
                    "Nonexecuting terminal result has inconsistent effect fields.",
                )
        elif self.disposition == "COMPLETED_VERIFIED":
            if (
                self.adapter_receipt_sha256 is None
                or self.target_state_sha256 is None
                or self.verification_sha256 is None
                or self.verification_status != "VERIFIED"
                or self.recovery_required
            ):
                raise ControlLedgerError(
                    "REQUEST_RESULT_INVALID",
                    "Verified result lacks its closed receipt and verification binding.",
                )
        elif self.disposition == "FAILED_NO_EFFECT":
            if (
                self.adapter_receipt_sha256 is None
                or self.target_state_sha256 is None
                or self.recovery_required
                or self.verification_status == "VERIFIED"
            ):
                raise ControlLedgerError(
                    "REQUEST_RESULT_INVALID",
                    "No-effect result lacks its closed adapter binding.",
                )
        elif self.disposition in {"RECOVERY_REQUIRED", "UNKNOWN_EFFECT"}:
            if (
                not self.recovery_required
                or self.verification_status == "VERIFIED"
                or (self.adapter_receipt_sha256 is None)
                != (self.target_state_sha256 is None)
                or (
                    self.disposition == "RECOVERY_REQUIRED"
                    and self.adapter_receipt_sha256 is None
                )
            ):
                raise ControlLedgerError(
                    "REQUEST_RESULT_INVALID",
                    "Indeterminate result must remain explicitly recovery-required.",
                )
        else:
            raise ControlLedgerError(
                "REQUEST_RESULT_INVALID",
                "Attempted result disposition is inconsistent.",
            )
        parsed_timestamps: dict[str, datetime] = {}
        for name in ("decided_at", "terminal_at"):
            try:
                parsed = datetime.fromisoformat(getattr(self, name))
                if parsed.tzinfo is None or parsed.utcoffset() is None:
                    raise ValueError("timestamp has no offset")
                parsed_timestamps[name] = parsed
            except (TypeError, ValueError, OverflowError) as exc:
                raise ControlLedgerError(
                    "REQUEST_RESULT_INVALID",
                    f"Request-result {name} timestamp is invalid.",
                ) from exc
        if parsed_timestamps["terminal_at"] < parsed_timestamps["decided_at"]:
            raise ControlLedgerError(
                "REQUEST_RESULT_INVALID",
                "Request-result terminal time precedes its decision time.",
            )
        summary_only_statuses = {
            "NOT_APPLICABLE",
            "NOT_PERFORMED",
            "NOT_DURABLY_RECORDED",
        }
        if (self.verification_status in summary_only_statuses) != (
            self.verification_sha256 is None
        ):
            raise ControlLedgerError(
                "REQUEST_RESULT_INVALID",
                "Verification status and durable verification digest are inconsistent.",
            )

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "principal_id": self.principal_id,
            "request_id": self.request_id,
            "request_sha256": self.request_sha256,
            "disposition": self.disposition,
            "decision_id": self.decision_id,
            "decision_outcome": self.decision_outcome,
            "decision_sha256": self.decision_sha256,
            "decision_context_sha256": self.decision_context_sha256,
            "policy_sha256": self.policy_sha256,
            "verification_status": self.verification_status,
            "verification_sha256": self.verification_sha256,
            "attempt_id": self.attempt_id,
            "adapter_receipt_sha256": self.adapter_receipt_sha256,
            "target_state_sha256": self.target_state_sha256,
            "decided_at": self.decided_at,
            "terminal_at": self.terminal_at,
            "recovery_required": self.recovery_required,
            "reason_codes": list(self.reason_codes),
            "replayed": self.replayed,
            "execution_attempted_this_call": self.execution_attempted_this_call,
            "new_decision": self.new_decision,
            "new_authorization": self.new_authorization,
            "new_effect": self.new_effect,
            "authorization": None,
        }

    @classmethod
    def from_dict(cls, value: object) -> "RequestLookupResult":
        if type(value) is not dict or set(value) != set(cls.__dataclass_fields__):
            raise ControlLedgerError(
                "REQUEST_RESULT_INVALID",
                "Request-result object has an invalid closed shape.",
            )
        authority = value.get("authorization")
        if authority is not None:
            raise ControlLedgerError(
                "REQUEST_RESULT_AUTHORITY_PROHIBITED",
                "Request-result authorization must be absent.",
            )
        inspectable = {key: child for key, child in value.items() if key != "authorization"}
        _reject_authority_bearing_keys(
            inspectable,
            error_type=ControlLedgerError,
            reason_code="REQUEST_RESULT_AUTHORITY_PROHIBITED",
            denied_keys=_RESULT_AUTHORITY_BEARING_KEYS,
        )
        reasons = value["reason_codes"]
        if type(reasons) is not list:
            raise ControlLedgerError(
                "REQUEST_RESULT_INVALID",
                "Request-result reasons must be an exact array.",
            )
        return cls(**{**value, "reason_codes": tuple(reasons)})

    def as_replay(self) -> "RequestLookupResult":
        return replace(
            self,
            replayed=True,
            execution_attempted_this_call=False,
            new_decision=False,
            new_authorization=False,
            new_effect=False,
            authorization=None,
        )


def terminal_attempt_outcome_sha256(
    result: RequestLookupResult, attempt_state: str
) -> str:
    """Canonical digest binding a terminal attempt to its sanitized result."""

    if type(result) is not RequestLookupResult or attempt_state not in _TERMINAL_ATTEMPT_STATES:
        raise ControlLedgerError(
            "REQUEST_RESULT_BINDING_INVALID", "Terminal attempt digest input is invalid."
        )
    stored = replace(
        result,
        replayed=False,
        execution_attempted_this_call=False,
        new_decision=False,
        new_authorization=False,
        new_effect=False,
        authorization=None,
    )
    request_result_sha256 = hashlib.sha256(
        canonical_json(stored.to_dict()).encode("utf-8")
    ).hexdigest()
    return sha256_json(
        {
            "attempt_state": attempt_state,
            "request_result_sha256": request_result_sha256,
        }
    )


def _validate_recovery_summary(value: object) -> dict[str, Any]:
    if type(value) is not dict or set(value) != _RECOVERY_SUMMARY_KEYS:
        raise ControlLedgerError(
            "CONTROL_LEDGER_RECOVERY_SUMMARY_INVALID",
            "Recovery summary has an invalid closed shape.",
        )
    _reject_authority_bearing_keys(
        value,
        error_type=ControlLedgerError,
        reason_code="CONTROL_LEDGER_RECOVERY_SUMMARY_INVALID",
    )
    if value["summary_version"] != "1":
        raise ControlLedgerError(
            "CONTROL_LEDGER_RECOVERY_SUMMARY_INVALID",
            "Recovery summary version is unsupported.",
        )
    for name in (
        "principal_id",
        "request_id",
        "decision_id",
    ):
        _require_identifier(name, value[name])
    if value["decision_outcome"] not in _DECISION_OUTCOMES - {
        "NOT_DURABLY_RECORDED"
    }:
        raise ControlLedgerError(
            "CONTROL_LEDGER_RECOVERY_SUMMARY_INVALID",
            "Recovery summary decision outcome is not closed.",
        )
    _require_offset_timestamp(
        "decided_at",
        value["decided_at"],
        reason_code="CONTROL_LEDGER_RECOVERY_SUMMARY_INVALID",
    )
    for name in (
        "request_sha256",
        "decision_sha256",
        "decision_context_sha256",
        "policy_sha256",
    ):
        _require_sha256(name, value[name])
    return deepcopy(value)


@dataclass(frozen=True, slots=True)
class SyntheticAdapterReceipt:
    """Immutable adapter report.  Receipt status is not verification status."""

    schema_version: str
    receipt_id: str
    adapter_id: str
    adapter_contract_version: str
    adapter_contract_sha256: str
    execution_mode: str
    idempotency_key: str
    binding_sha256: str
    attempt_id: str
    request_id: str
    decision_id: str
    target_id: str
    action_type: str
    status: str
    attempted_at: str
    reported_success: bool
    message: str
    state_before_sha256: str
    state_after_sha256: str

    def __post_init__(self) -> None:
        if self.schema_version != ADAPTER_RECEIPT_SCHEMA_VERSION:
            raise SyntheticAdapterError(
                "SYNTHETIC_ADAPTER_RECEIPT_SCHEMA_UNSUPPORTED",
                "Synthetic receipt schema version is unsupported.",
            )
        if (
            self.adapter_id != SYNTHETIC_ADAPTER_ID
            or self.execution_mode != SYNTHETIC_EXECUTION_MODE
            or self.adapter_contract_version != SYNTHETIC_ADAPTER_CONTRACT_VERSION
            or self.adapter_contract_sha256 != SYNTHETIC_ADAPTER_CONTRACT_SHA256
        ):
            raise SyntheticAdapterError(
                "SYNTHETIC_ADAPTER_BINDING_INVALID",
                "Synthetic receipt contract binding is invalid.",
            )
        for name in (
            "adapter_contract_sha256",
            "idempotency_key",
            "binding_sha256",
            "state_before_sha256",
            "state_after_sha256",
        ):
            _require_sha256(
                name,
                getattr(self, name),
                error_type=SyntheticAdapterError,
                reason_code="SYNTHETIC_ADAPTER_BINDING_INVALID",
            )
        if self.idempotency_key != self.binding_sha256:
            raise SyntheticAdapterError(
                "SYNTHETIC_ADAPTER_BINDING_INVALID",
                "Synthetic receipt idempotency key must equal its binding digest.",
            )
        for name in (
            "receipt_id",
            "attempt_id",
            "request_id",
            "decision_id",
            "target_id",
            "action_type",
            "status",
            "attempted_at",
            "message",
        ):
            _require_identifier(
                name,
                getattr(self, name),
                error_type=SyntheticAdapterError,
                reason_code="SYNTHETIC_ADAPTER_BINDING_INVALID",
            )
        if self.status not in _ADAPTER_STATUSES or type(self.reported_success) is not bool:
            raise SyntheticAdapterError(
                "SYNTHETIC_ADAPTER_BINDING_INVALID",
                "Synthetic receipt disposition is invalid.",
            )
        if len(self.message) > 2_048:
            raise SyntheticAdapterError(
                "SYNTHETIC_ADAPTER_BINDING_INVALID",
                "Synthetic receipt message exceeds its bound.",
            )
        no_effect = self.state_before_sha256 == self.state_after_sha256
        if self.status == "NO_EFFECT":
            if self.reported_success or not no_effect:
                raise SyntheticAdapterError(
                    "SYNTHETIC_ADAPTER_RECEIPT_INVALID",
                    "NO_EFFECT receipt semantics are inconsistent.",
                )
        elif not self.reported_success or no_effect:
            raise SyntheticAdapterError(
                "SYNTHETIC_ADAPTER_RECEIPT_INVALID",
                "Effect receipt semantics are inconsistent.",
            )
        try:
            attempted = datetime.fromisoformat(self.attempted_at)
            if attempted.tzinfo is None or attempted.utcoffset() is None:
                raise ValueError("timestamp has no offset")
        except (TypeError, ValueError, OverflowError) as exc:
            raise SyntheticAdapterError(
                "SYNTHETIC_ADAPTER_RECEIPT_INVALID",
                "Synthetic receipt timestamp is invalid.",
            ) from exc

    def to_dict(self) -> dict[str, Any]:
        value = {
            name: getattr(self, name) for name in self.__dataclass_fields__
        }
        _reject_authority_bearing_keys(
            value,
            error_type=SyntheticAdapterError,
            reason_code="SYNTHETIC_ADAPTER_RECEIPT_AUTHORITY_PROHIBITED",
        )
        return value

    @classmethod
    def from_dict(cls, value: object) -> "SyntheticAdapterReceipt":
        if type(value) is not dict or set(value) != set(cls.__dataclass_fields__):
            raise SyntheticAdapterError(
                "SYNTHETIC_ADAPTER_RECEIPT_INVALID",
                "Synthetic receipt has an invalid closed shape.",
            )
        _reject_authority_bearing_keys(
            value,
            error_type=SyntheticAdapterError,
            reason_code="SYNTHETIC_ADAPTER_RECEIPT_AUTHORITY_PROHIBITED",
        )
        return cls(**value)

    @property
    def receipt_sha256(self) -> str:
        return sha256_json(self.to_dict())


class InMemoryControlLedger:
    """Compatibility ledger for the immutable Phase 3 simulation baseline."""

    def __init__(self) -> None:
        self._requests: dict[tuple[str, str], str] = {}
        self._authorization_states: dict[str, str] = {}
        self._verification_ids: set[str] = set()
        self._decision_ids: set[str] = set()
        self._attempts: dict[str, dict[str, str | None]] = {}
        self._token_attempts: dict[str, str] = {}
        self._outbox: list[dict[str, Any]] = []
        self._lock = RLock()
        self.issuer_instance_id = f"issuer-{uuid.uuid4()}"

    def _append_event(
        self, event_type: str, subject_id: str, payload: dict[str, Any]
    ) -> None:
        event_id = len(self._outbox) + 1
        self._outbox.append(
            {
                "event_id": event_id,
                "event_type": event_type,
                "subject_id": subject_id,
                "payload_sha256": _event_digest(event_type, subject_id, payload),
                "created_at": utc_now_iso(),
                "exported_at": None,
            }
        )

    def claim_request(
        self,
        principal_id: str,
        request_id: str,
        request_sha256: str,
        *,
        claimed_at: str | None = None,
    ) -> str:
        principal_id = _require_identifier("principal_id", principal_id)
        request_id = _require_identifier("request_id", request_id)
        request_sha256 = _require_sha256("request_sha256", request_sha256)
        if claimed_at is not None:
            _require_offset_timestamp("claimed_at", claimed_at)
        key = (principal_id, request_id)
        with self._lock:
            existing = self._requests.get(key)
            if existing is None:
                self._requests[key] = request_sha256
                self._append_event(
                    "REQUEST_CLAIMED",
                    f"{principal_id}:{request_id}",
                    {"request_sha256": request_sha256},
                )
                return "NEW"
            return "DUPLICATE" if existing == request_sha256 else "CONFLICT"

    def register(
        self,
        token_id: str,
        *,
        verification_id: str | None = None,
        decision_id: str | None = None,
        principal_id: str | None = None,
        request_id: str | None = None,
        request_sha256: str | None = None,
        unsigned_token_sha256: str | None = None,
        issuer_instance_id: str | None = None,
        key_domain_id: str | None = None,
        decision_authorization_sha256: str | None = None,
        issued_at: str | None = None,
    ) -> None:
        token_id = _require_identifier("token_id", token_id)
        verification_id = _require_identifier(
            "verification_id", verification_id or f"legacy:{token_id}"
        )
        decision_id = _require_identifier(
            "decision_id", decision_id or f"legacy:{token_id}"
        )
        if issued_at is not None:
            _require_offset_timestamp("issued_at", issued_at)
        with self._lock:
            if token_id in self._authorization_states:
                raise ControlLedgerError(
                    "AUTHORIZATION_ID_COLLISION",
                    "Authorization token identifier already exists.",
                )
            if verification_id in self._verification_ids or decision_id in self._decision_ids:
                raise ControlLedgerError(
                    "AUTHORIZATION_DECISION_REPLAY",
                    "This verified decision already issued an authorization.",
                )
            self._authorization_states[token_id] = "ISSUED"
            self._verification_ids.add(verification_id)
            self._decision_ids.add(decision_id)
            self._append_event(
                "AUTHORIZATION_ISSUED",
                token_id,
                {
                    "verification_id_sha256": hashlib.sha256(
                        verification_id.encode("utf-8")
                    ).hexdigest(),
                    "decision_id_sha256": hashlib.sha256(
                        decision_id.encode("utf-8")
                    ).hexdigest(),
                },
            )

    def consume_once(
        self,
        token_id: str,
        *,
        attempt_id: str | None = None,
        attempt_binding_sha256: str | None = None,
        consumed_at: str | None = None,
        idempotency_key: str | None = None,
        recovery_summary: dict[str, Any] | None = None,
    ) -> None:
        token_id = _require_identifier("token_id", token_id)
        if (attempt_id is None) != (attempt_binding_sha256 is None):
            raise ControlLedgerError(
                "CONTROL_LEDGER_BINDING_INVALID",
                "Attempt identifier and binding digest must be supplied together.",
            )
        summary_json: str | None = None
        summary_sha256: str | None = None
        if attempt_id is not None:
            attempt_id = _require_identifier("attempt_id", attempt_id)
            attempt_binding_sha256 = _require_sha256(
                "attempt_binding_sha256", attempt_binding_sha256
            )
            idempotency_key = _require_sha256(
                "idempotency_key", idempotency_key or attempt_binding_sha256
            )
            if idempotency_key != attempt_binding_sha256:
                raise ControlLedgerError(
                    "ATTEMPT_IDEMPOTENCY_CONFLICT",
                    "Idempotency key must equal the exact attempt-binding digest.",
                )
            consumed_at = _require_offset_timestamp("consumed_at", consumed_at)
            if recovery_summary is not None:
                recovery_summary = _validate_recovery_summary(recovery_summary)
                summary_json = canonical_json(recovery_summary)
                summary_sha256 = hashlib.sha256(
                    summary_json.encode("utf-8")
                ).hexdigest()
        with self._lock:
            state = self._authorization_states.get(token_id)
            if state is None:
                raise ControlLedgerError(
                    "AUTHORIZATION_UNKNOWN",
                    "Authorization was not issued by this control ledger.",
                )
            if state != "ISSUED":
                raise ControlLedgerError(
                    "AUTHORIZATION_REPLAY", "Authorization was already consumed."
                )
            if attempt_id is not None:
                if attempt_id in self._attempts or token_id in self._token_attempts:
                    raise ControlLedgerError(
                        "ATTEMPT_IDEMPOTENCY_CONFLICT",
                        "Attempt or token already has a reservation.",
                    )
                self._attempts[attempt_id] = {
                    "attempt_id": attempt_id,
                    "token_id": token_id,
                    "binding_sha256": attempt_binding_sha256,
                    "state": "RESERVED",
                    "outcome_sha256": None,
                    "reserved_at": consumed_at,
                    "completed_at": None,
                }
                self._token_attempts[token_id] = attempt_id
                self._append_event(
                    "ATTEMPT_RESERVED",
                    attempt_id,
                    {
                        "token_id_sha256": hashlib.sha256(
                            token_id.encode("utf-8")
                        ).hexdigest(),
                        "binding_sha256": attempt_binding_sha256,
                    },
                )
            self._authorization_states[token_id] = "CONSUMED"
            self._append_event(
                "AUTHORIZATION_CONSUMED", token_id, {"attempt_id": attempt_id}
            )

    def state(self, token_id: str) -> str | None:
        token_id = _require_identifier("token_id", token_id)
        with self._lock:
            return self._authorization_states.get(token_id)

    def record_adapter_receipt(
        self,
        attempt_id: str,
        *,
        adapter_receipt_sha256: str,
        receipt_outcome_sha256: str,
        recorded_at: str,
    ) -> None:
        attempt_id = _require_identifier("attempt_id", attempt_id)
        adapter_receipt_sha256 = _require_sha256(
            "adapter_receipt_sha256", adapter_receipt_sha256
        )
        receipt_outcome_sha256 = _require_sha256(
            "receipt_outcome_sha256", receipt_outcome_sha256
        )
        _require_identifier("recorded_at", recorded_at)
        with self._lock:
            row = self._attempts.get(attempt_id)
            if row is None or row["state"] != "RESERVED":
                raise ControlLedgerError(
                    "ATTEMPT_OUTCOME_CONFLICT",
                    "Attempt is not available for adapter receipt recording.",
                )
            row.update(
                {
                    "state": "RECEIPT_RECORDED",
                    "outcome_sha256": receipt_outcome_sha256,
                    "adapter_receipt_sha256": adapter_receipt_sha256,
                }
            )
            self._append_event(
                "ADAPTER_RECEIPT_RECORDED",
                attempt_id,
                {"adapter_receipt_sha256": adapter_receipt_sha256},
            )

    def record_attempt_outcome(
        self,
        attempt_id: str,
        *,
        outcome_state: str,
        outcome_sha256: str,
        completed_at: str,
    ) -> None:
        attempt_id = _require_identifier("attempt_id", attempt_id)
        outcome_sha256 = _require_sha256("outcome_sha256", outcome_sha256)
        completed_at = _require_identifier("completed_at", completed_at)
        if outcome_state not in _TERMINAL_ATTEMPT_STATES:
            raise ControlLedgerError(
                "ATTEMPT_STATE_INVALID", "Attempt outcome state is not terminal."
            )
        with self._lock:
            row = self._attempts.get(attempt_id)
            if row is None:
                raise ControlLedgerError(
                    "ATTEMPT_UNKNOWN", "Attempt reservation does not exist."
                )
            if row["state"] not in {"RESERVED", "RECEIPT_RECORDED"}:
                if (
                    row["state"] == outcome_state
                    and row["outcome_sha256"] == outcome_sha256
                ):
                    return
                raise ControlLedgerError(
                    "ATTEMPT_OUTCOME_CONFLICT",
                    "Attempt already has a different terminal outcome.",
                )
            row.update(
                {
                    "state": outcome_state,
                    "outcome_sha256": outcome_sha256,
                    "completed_at": completed_at,
                }
            )
            self._append_event(
                "ATTEMPT_TERMINAL",
                attempt_id,
                {"state": outcome_state, "outcome_sha256": outcome_sha256},
            )

    def attempt_snapshot(self, attempt_id: str) -> dict[str, str | None] | None:
        attempt_id = _require_identifier("attempt_id", attempt_id)
        with self._lock:
            row = self._attempts.get(attempt_id)
            return dict(row) if row is not None else None

    def recover_incomplete_attempts(
        self, *, operator_asserted_quiesced: bool
    ) -> int:
        _assert_quiesced(operator_asserted_quiesced)
        recovered = 0
        with self._lock:
            for attempt_id, row in self._attempts.items():
                if row["state"] != "RESERVED":
                    continue
                row["state"] = "UNKNOWN_EFFECT"
                row["completed_at"] = utc_now_iso()
                row["outcome_sha256"] = hashlib.sha256(
                    canonical_json(
                        {"attempt_id": attempt_id, "state": "UNKNOWN_EFFECT"}
                    ).encode("utf-8")
                ).hexdigest()
                self._append_event(
                    "ATTEMPT_RECOVERED_UNKNOWN",
                    attempt_id,
                    {"state": "UNKNOWN_EFFECT"},
                )
                recovered += 1
            for token_id, state in tuple(self._authorization_states.items()):
                if state == "ISSUED":
                    self._authorization_states[token_id] = "REVOKED"
                    self._append_event(
                        "AUTHORIZATION_REVOKED",
                        token_id,
                        {"reason_code": "QUIESCED_RECOVERY"},
                    )
        return recovered

    def pending_outbox(self) -> tuple[dict[str, Any], ...]:
        with self._lock:
            return tuple(dict(row) for row in self._outbox if row["exported_at"] is None)


class _SQLiteControlLedgerBase:
    """Single-host Stage A transaction ledger.

    SQLite provides development-grade durability and interprocess exclusion for
    this offline increment.  It is not a distributed consensus, HA, WORM, or
    external-custody mechanism.
    """

    def __init__(
        self,
        path: str | Path,
        *,
        busy_timeout_ms: int = 1000,
        created_at: str | None = None,
    ) -> None:
        if type(busy_timeout_ms) is not int or not 25 <= busy_timeout_ms <= 30_000:
            raise ValueError("Control-ledger busy timeout must be within 25..30000 ms.")
        self.path = Path(path).absolute()
        self.busy_timeout_ms = busy_timeout_ms
        self._created_at = _require_offset_timestamp(
            "created_at", created_at if created_at is not None else utc_now_iso()
        )
        def initialize_and_identify() -> str:
            self._initialize()
            return self._metadata("ledger_id")

        if _store_startup_lock_held():
            ledger_id = initialize_and_identify()
        else:
            with _exclusive_store_startup(
                self.path,
                timeout_ms=busy_timeout_ms,
                error_type=ControlLedgerError,
                unavailable_reason="CONTROL_LEDGER_UNAVAILABLE",
                path_reason="CONTROL_LEDGER_PATH_UNSAFE",
                label="Control-ledger",
            ):
                ledger_id = initialize_and_identify()
        self.issuer_instance_id = f"stage-a-ledger-{ledger_id}"

    @classmethod
    def preflight_existing(
        cls, path: str | Path, *, busy_timeout_ms: int = 1000
    ) -> tuple[dict[str, str | None], ...]:
        """Validate an existing control store through a query-only connection."""

        if type(busy_timeout_ms) is not int or not 25 <= busy_timeout_ms <= 30_000:
            raise ValueError("Control-ledger busy timeout must be within 25..30000 ms.")
        instance = object.__new__(cls)
        instance.path = Path(path).absolute()
        instance.busy_timeout_ms = busy_timeout_ms
        instance._assert_safe_path(allow_missing=False)
        connection: sqlite3.Connection | None = None
        scratch: tempfile.TemporaryDirectory[str] | None = None
        try:
            connection, scratch, copied_wal = _open_readonly_preflight(
                instance.path, busy_timeout_ms=busy_timeout_ms
            )
            connection.row_factory = sqlite3.Row
            connection.execute(f"PRAGMA busy_timeout={busy_timeout_ms}")
            connection.execute("PRAGMA query_only=ON")
            connection.execute("PRAGMA foreign_keys=ON")
            _assert_sqlite_runtime_integrity(
                connection,
                expected_schema_sha256=_CONTROL_SCHEMA_SHA256,
                error_type=ControlLedgerError,
                schema_reason="CONTROL_LEDGER_SCHEMA_UNSUPPORTED",
                corrupt_reason="CONTROL_LEDGER_CORRUPT",
                durability_reason="CONTROL_LEDGER_DURABILITY_UNAVAILABLE",
                label="Control-ledger",
                verify_journal_mode=copied_wal,
            )
            _assert_sqlite_wal_header(
                instance.path,
                error_type=ControlLedgerError,
                reason_code="CONTROL_LEDGER_DURABILITY_UNAVAILABLE",
                label="Control-ledger",
            )
            _validate_control_metadata(
                dict(connection.execute("SELECT key, value FROM metadata"))
            )
            _validate_control_relations(connection)
            return _control_correlation_snapshot(connection)
        except ControlLedgerError:
            raise
        except (OSError, sqlite3.Error) as exc:
            raise ControlLedgerError(
                "CONTROL_LEDGER_UNAVAILABLE",
                "Control-ledger read-only preflight failed closed.",
            ) from exc
        finally:
            if connection is not None:
                connection.close()
            if scratch is not None:
                scratch.cleanup()

    def _assert_safe_parent_chain(self, *, allow_missing: bool) -> None:
        _assert_safe_parent_chain(
            self.path,
            allow_missing=allow_missing,
            error_type=ControlLedgerError,
            reason_code="CONTROL_LEDGER_PATH_UNSAFE",
            label="Control-ledger",
        )

    def _assert_safe_path(self, *, allow_missing: bool) -> None:
        _assert_safe_path(
            self.path,
            allow_missing=allow_missing,
            error_type=ControlLedgerError,
            unsafe_reason="CONTROL_LEDGER_PATH_UNSAFE",
            unavailable_reason="CONTROL_LEDGER_UNAVAILABLE",
            label="Control-ledger",
        )
        _assert_safe_sqlite_sidecars(
            self.path,
            error_type=ControlLedgerError,
            reason_code="CONTROL_LEDGER_PATH_UNSAFE",
            label="Control-ledger",
        )

    def _raw_connect(self) -> sqlite3.Connection:
        self._assert_safe_path(allow_missing=False)
        connection = sqlite3.connect(
            self.path,
            timeout=self.busy_timeout_ms / 1000.0,
            isolation_level=None,
        )
        connection.row_factory = sqlite3.Row
        connection.execute(f"PRAGMA busy_timeout={self.busy_timeout_ms}")
        connection.execute("PRAGMA foreign_keys=ON")
        connection.execute("PRAGMA synchronous=FULL")
        return connection

    def _connect(self) -> sqlite3.Connection:
        connection: sqlite3.Connection | None = None
        try:
            connection = self._raw_connect()
            _assert_sqlite_runtime_integrity(
                connection,
                expected_schema_sha256=_CONTROL_SCHEMA_SHA256,
                error_type=ControlLedgerError,
                schema_reason="CONTROL_LEDGER_SCHEMA_UNSUPPORTED",
                corrupt_reason="CONTROL_LEDGER_CORRUPT",
                durability_reason="CONTROL_LEDGER_DURABILITY_UNAVAILABLE",
                label="Control-ledger",
            )
            _validate_control_metadata(
                dict(connection.execute("SELECT key, value FROM metadata"))
            )
            _validate_control_relations(connection)
            return connection
        except ControlLedgerError:
            if connection is not None:
                connection.close()
            raise
        except (OSError, sqlite3.Error) as exc:
            if connection is not None:
                connection.close()
            raise ControlLedgerError(
                "CONTROL_LEDGER_UNAVAILABLE", "Control-ledger access failed closed."
            ) from exc

    def _initialize(self) -> None:
        connection: sqlite3.Connection | None = None
        try:
            self._assert_safe_parent_chain(allow_missing=True)
            self.path.parent.mkdir(parents=True, exist_ok=True)
            self._assert_safe_parent_chain(allow_missing=False)
            self._assert_safe_path(allow_missing=True)
            existing_file = self.path.exists()
            connection = sqlite3.connect(
                self.path,
                timeout=self.busy_timeout_ms / 1000.0,
                isolation_level=None,
            )
            connection.row_factory = sqlite3.Row
            connection.execute(f"PRAGMA busy_timeout={self.busy_timeout_ms}")
            if existing_file:
                tables = {
                    str(row[0])
                    for row in connection.execute(
                        "SELECT name FROM sqlite_master WHERE type='table'"
                    )
                }
                if not _REQUIRED_TABLES <= tables:
                    raise ControlLedgerError(
                        "CONTROL_LEDGER_SCHEMA_UNSUPPORTED",
                        "Existing database is not a recognized control ledger.",
                    )
                _validate_control_metadata(
                    dict(connection.execute("SELECT key, value FROM metadata"))
                )
                if _application_schema_sha256(connection) != _CONTROL_SCHEMA_SHA256:
                    raise ControlLedgerError(
                        "CONTROL_LEDGER_SCHEMA_UNSUPPORTED",
                        "Control-ledger application schema is not the exact supported v2 schema.",
                    )
                journal_mode = connection.execute("PRAGMA journal_mode").fetchone()[0]
            else:
                journal_mode = connection.execute("PRAGMA journal_mode=WAL").fetchone()[0]
            if str(journal_mode).lower() != "wal":
                raise ControlLedgerError(
                    "CONTROL_LEDGER_DURABILITY_UNAVAILABLE",
                    "Control ledger requires SQLite WAL mode.",
                )
            connection.execute("PRAGMA synchronous=FULL")
            connection.execute("PRAGMA foreign_keys=ON")
            connection.executescript(_CONTROL_SCHEMA_SQL)
            if _application_schema_sha256(connection) != _CONTROL_SCHEMA_SHA256:
                raise ControlLedgerError(
                    "CONTROL_LEDGER_SCHEMA_UNSUPPORTED",
                    "Control-ledger application schema is not the exact supported v2 schema.",
                )
            metadata = dict(connection.execute("SELECT key, value FROM metadata"))
            if not metadata:
                connection.execute("BEGIN IMMEDIATE")
                connection.execute(
                    "INSERT INTO metadata(key, value) VALUES('schema_version', ?)",
                    (SCHEMA_VERSION,),
                )
                connection.execute(
                    "INSERT INTO metadata(key, value) VALUES('ledger_id', ?)",
                    (str(uuid.uuid4()),),
                )
                connection.execute(
                    "INSERT INTO metadata(key, value) VALUES('created_at', ?)",
                    (self._created_at,),
                )
                connection.commit()
                metadata = dict(connection.execute("SELECT key, value FROM metadata"))
            _validate_control_metadata(metadata)
            _validate_control_relations(connection)
            connection.close()
            connection = None
            os.chmod(self.path, 0o600)
            self._assert_safe_path(allow_missing=False)
        except ControlLedgerError:
            raise
        except (OSError, sqlite3.Error) as exc:
            raise ControlLedgerError(
                "CONTROL_LEDGER_UNAVAILABLE",
                "Control-ledger initialization failed closed.",
            ) from exc
        finally:
            if connection is not None:
                connection.close()

    def _metadata(self, key: str) -> str:
        connection = self._connect()
        try:
            row = connection.execute(
                "SELECT value FROM metadata WHERE key=?", (key,)
            ).fetchone()
            if row is None:
                raise ControlLedgerError(
                    "CONTROL_LEDGER_SCHEMA_UNSUPPORTED",
                    "Required control-ledger metadata is absent.",
                )
            return str(row[0])
        finally:
            connection.close()

    def correlation_snapshot(self) -> tuple[dict[str, str | None], ...]:
        """Return a validated, authority-free projection for store correlation."""

        connection = self._connect()
        try:
            return _control_correlation_snapshot(connection)
        finally:
            connection.close()


class SQLiteSyntheticAdapterStore:
    """Separate SQLite owner for offline synthetic state and immutable receipts."""

    def __init__(
        self,
        path: str | Path,
        *,
        target_inventory: Mapping[str, Any],
        fault_modes: Mapping[str, str] | None = None,
        busy_timeout_ms: int = 1000,
        created_at: str | None = None,
    ) -> None:
        if type(busy_timeout_ms) is not int or not 25 <= busy_timeout_ms <= 30_000:
            raise ValueError(
                "Synthetic-adapter busy timeout must be within 25..30000 ms."
            )
        if not isinstance(target_inventory, Mapping) or not target_inventory:
            raise ValueError(
                "Synthetic adapter requires a non-empty inert target inventory."
            )
        self.path = Path(path).absolute()
        self.busy_timeout_ms = busy_timeout_ms
        self._created_at = _require_offset_timestamp(
            "created_at",
            created_at if created_at is not None else utc_now_iso(),
            error_type=SyntheticAdapterError,
            reason_code="SYNTHETIC_ADAPTER_BINDING_INVALID",
        )
        self._fault_modes = dict(fault_modes or {})
        if (
            set(self._fault_modes.values())
            - {"NONE", "FAILED", "PARTIAL", "UNEXPECTED_EFFECT"}
            or set(self._fault_modes) - set(target_inventory)
        ):
            raise ValueError(
                "Synthetic adapter fault configuration is not closed and valid."
            )
        self._initial_states: dict[str, dict[str, Any]] = {}
        for target_id, record in target_inventory.items():
            if (
                type(target_id) is not str
                or not target_id
                or getattr(record, "id", None) != target_id
                or type(getattr(record, "type", None)) is not str
            ):
                raise TypeError("Synthetic adapter inventory records are invalid.")
            self._initial_states[target_id] = {
                "target_id": target_id,
                "target_type": record.type,
                "network_state": "connected",
                "management_channel": True,
                "isolation_expires_at": None,
                "service_health": "healthy",
                "last_action_id": None,
            }
        self._inventory_sha256 = sha256_json(self._initial_states)
        self._fault_modes_sha256 = sha256_json(self._fault_modes)
        def initialize_and_identify() -> str:
            self._initialize()
            connection = self._connect()
            try:
                row = connection.execute(
                    "SELECT value FROM metadata WHERE key='adapter_store_id'"
                ).fetchone()
                if row is None or type(row[0]) is not str or not row[0]:
                    raise SyntheticAdapterError(
                        "SYNTHETIC_ADAPTER_SCHEMA_UNSUPPORTED",
                        "Synthetic-adapter store identity is absent.",
                    )
                return str(row[0])
            finally:
                connection.close()

        if _store_startup_lock_held():
            self.adapter_store_id = initialize_and_identify()
        else:
            with _exclusive_store_startup(
                self.path,
                timeout_ms=busy_timeout_ms,
                error_type=SyntheticAdapterError,
                unavailable_reason="SYNTHETIC_ADAPTER_UNAVAILABLE",
                path_reason="SYNTHETIC_ADAPTER_PATH_UNSAFE",
                label="Synthetic-adapter store",
            ):
                self.adapter_store_id = initialize_and_identify()

    @classmethod
    def preflight_existing(
        cls,
        path: str | Path,
        *,
        target_inventory: Mapping[str, Any],
        fault_modes: Mapping[str, str] | None = None,
        busy_timeout_ms: int = 1000,
    ) -> tuple[dict[str, str], ...]:
        """Validate an existing adapter store without opening it for writes."""

        if type(busy_timeout_ms) is not int or not 25 <= busy_timeout_ms <= 30_000:
            raise ValueError(
                "Synthetic-adapter busy timeout must be within 25..30000 ms."
            )
        if not isinstance(target_inventory, Mapping) or not target_inventory:
            raise ValueError(
                "Synthetic adapter requires a non-empty inert target inventory."
            )
        instance = object.__new__(cls)
        instance.path = Path(path).absolute()
        instance.busy_timeout_ms = busy_timeout_ms
        instance._fault_modes = dict(fault_modes or {})
        if (
            set(instance._fault_modes.values())
            - {"NONE", "FAILED", "PARTIAL", "UNEXPECTED_EFFECT"}
            or set(instance._fault_modes) - set(target_inventory)
        ):
            raise ValueError(
                "Synthetic adapter fault configuration is not closed and valid."
            )
        instance._initial_states = {}
        for target_id, record in target_inventory.items():
            if (
                type(target_id) is not str
                or not target_id
                or getattr(record, "id", None) != target_id
                or type(getattr(record, "type", None)) is not str
            ):
                raise TypeError("Synthetic adapter inventory records are invalid.")
            instance._initial_states[target_id] = {
                "target_id": target_id,
                "target_type": record.type,
                "network_state": "connected",
                "management_channel": True,
                "isolation_expires_at": None,
                "service_health": "healthy",
                "last_action_id": None,
            }
        instance._inventory_sha256 = sha256_json(instance._initial_states)
        instance._fault_modes_sha256 = sha256_json(instance._fault_modes)
        instance._safe(allow_missing=False)
        connection: sqlite3.Connection | None = None
        scratch: tempfile.TemporaryDirectory[str] | None = None
        try:
            connection, scratch, copied_wal = _open_readonly_preflight(
                instance.path, busy_timeout_ms=busy_timeout_ms
            )
            connection.row_factory = sqlite3.Row
            connection.execute(f"PRAGMA busy_timeout={busy_timeout_ms}")
            connection.execute("PRAGMA query_only=ON")
            connection.execute("PRAGMA foreign_keys=ON")
            _assert_sqlite_runtime_integrity(
                connection,
                expected_schema_sha256=_ADAPTER_SCHEMA_SHA256,
                error_type=SyntheticAdapterError,
                schema_reason="SYNTHETIC_ADAPTER_SCHEMA_UNSUPPORTED",
                corrupt_reason="SYNTHETIC_ADAPTER_CORRUPT",
                durability_reason="SYNTHETIC_ADAPTER_DURABILITY_UNAVAILABLE",
                label="Synthetic-adapter store",
                verify_journal_mode=copied_wal,
            )
            _assert_sqlite_wal_header(
                instance.path,
                error_type=SyntheticAdapterError,
                reason_code="SYNTHETIC_ADAPTER_DURABILITY_UNAVAILABLE",
                label="Synthetic-adapter store",
            )
            instance._validate_metadata_and_inventory(connection)
            return instance._correlation_snapshot_from_connection(connection)
        except SyntheticAdapterError:
            raise
        except (OSError, sqlite3.Error) as exc:
            raise SyntheticAdapterError(
                "SYNTHETIC_ADAPTER_UNAVAILABLE",
                "Synthetic-adapter read-only preflight failed closed.",
            ) from exc
        finally:
            if connection is not None:
                connection.close()
            if scratch is not None:
                scratch.cleanup()

    def _safe(self, *, allow_missing: bool) -> None:
        _assert_safe_path(
            self.path,
            allow_missing=allow_missing,
            error_type=SyntheticAdapterError,
            unsafe_reason="SYNTHETIC_ADAPTER_PATH_UNSAFE",
            unavailable_reason="SYNTHETIC_ADAPTER_UNAVAILABLE",
            label="Synthetic-adapter store",
        )
        _assert_safe_sqlite_sidecars(
            self.path,
            error_type=SyntheticAdapterError,
            reason_code="SYNTHETIC_ADAPTER_PATH_UNSAFE",
            label="Synthetic-adapter store",
        )

    def _validate_metadata_and_inventory(
        self, connection: sqlite3.Connection
    ) -> dict[str, str]:
        metadata = dict(connection.execute("SELECT key, value FROM metadata"))
        if (
            set(metadata) != _ADAPTER_METADATA_KEYS
            or metadata.get("schema_version") != ADAPTER_SCHEMA_VERSION
            or not _is_uuid(metadata.get("adapter_store_id"))
            or metadata.get("adapter_id") != SYNTHETIC_ADAPTER_ID
            or metadata.get("adapter_contract_version")
            != SYNTHETIC_ADAPTER_CONTRACT_VERSION
            or metadata.get("adapter_contract_sha256")
            != SYNTHETIC_ADAPTER_CONTRACT_SHA256
            or metadata.get("execution_mode") != SYNTHETIC_EXECUTION_MODE
            or metadata.get("inventory_sha256") != self._inventory_sha256
            or metadata.get("fault_modes_sha256") != self._fault_modes_sha256
            or not _is_offset_timestamp(metadata.get("created_at"))
        ):
            raise SyntheticAdapterError(
                "SYNTHETIC_ADAPTER_SCHEMA_UNSUPPORTED",
                "Synthetic-adapter immutable metadata is not the exact supported contract.",
            )
        rows = connection.execute(
            "SELECT target_id, state_json, state_sha256, updated_at FROM target_states"
        ).fetchall()
        if {str(row["target_id"]) for row in rows} != set(self._initial_states):
            raise SyntheticAdapterError(
                "SYNTHETIC_ADAPTER_SCHEMA_UNSUPPORTED",
                "Synthetic-adapter target inventory identity has drifted.",
            )
        current_state_sha256: dict[str, str] = {}
        current_updated_at: dict[str, str] = {}
        for row in rows:
            raw = row["state_json"]
            if (
                type(raw) is not str
                or not _is_offset_timestamp(row["updated_at"])
                or hashlib.sha256(raw.encode("utf-8")).hexdigest()
                != row["state_sha256"]
            ):
                raise SyntheticAdapterError(
                    "SYNTHETIC_ADAPTER_CORRUPT",
                    "Synthetic target-state integrity failed.",
                )
            state = self._validate_target_state(
                _load_json_object(
                    raw,
                    error_type=SyntheticAdapterError,
                    reason_code="SYNTHETIC_ADAPTER_CORRUPT",
                ),
                target_id=str(row["target_id"]),
            )
            current_state_sha256[str(row["target_id"])] = str(row["state_sha256"])
            current_updated_at[str(row["target_id"])] = str(row["updated_at"])
            if state["target_type"] != self._initial_states[str(row["target_id"])][
                "target_type"
            ]:
                raise SyntheticAdapterError(
                    "SYNTHETIC_ADAPTER_SCHEMA_UNSUPPORTED",
                    "Synthetic-adapter target type binding has drifted.",
                )
        receipt_rows = connection.execute(
            """
            SELECT rowid AS receipt_order, idempotency_key,
                   principal_id, request_id, target_id,
                   binding_json, binding_sha256, receipt_json, receipt_sha256,
                   committed_at
            FROM command_receipts
            ORDER BY rowid
            """
        ).fetchall()
        chained_state_sha256 = {
            target_id: sha256_json(state)
            for target_id, state in self._initial_states.items()
        }
        chained_updated_at = {
            target_id: str(metadata["created_at"])
            for target_id in self._initial_states
        }
        for receipt_row in receipt_rows:
            receipt = self._validated_receipt_row(
                receipt_row, idempotency_key=str(receipt_row["idempotency_key"])
            )
            if (
                receipt.state_before_sha256
                != chained_state_sha256[receipt.target_id]
                or datetime.fromisoformat(receipt.attempted_at)
                < datetime.fromisoformat(chained_updated_at[receipt.target_id])
            ):
                raise SyntheticAdapterError(
                    "SYNTHETIC_ADAPTER_CORRUPT",
                    "Synthetic receipt history does not form a continuous state/time chain.",
                )
            chained_state_sha256[receipt.target_id] = receipt.state_after_sha256
            chained_updated_at[receipt.target_id] = receipt.attempted_at
        if (
            current_state_sha256 != chained_state_sha256
            or current_updated_at != chained_updated_at
        ):
            raise SyntheticAdapterError(
                "SYNTHETIC_ADAPTER_CORRUPT",
                "Synthetic target state does not match its durable receipt history.",
            )
        return metadata

    def _connect(self) -> sqlite3.Connection:
        connection: sqlite3.Connection | None = None
        try:
            self._safe(allow_missing=False)
            connection = sqlite3.connect(
                self.path,
                timeout=self.busy_timeout_ms / 1000.0,
                isolation_level=None,
            )
            connection.row_factory = sqlite3.Row
            connection.execute(f"PRAGMA busy_timeout={self.busy_timeout_ms}")
            connection.execute("PRAGMA foreign_keys=ON")
            connection.execute("PRAGMA synchronous=FULL")
            _assert_sqlite_runtime_integrity(
                connection,
                expected_schema_sha256=_ADAPTER_SCHEMA_SHA256,
                error_type=SyntheticAdapterError,
                schema_reason="SYNTHETIC_ADAPTER_SCHEMA_UNSUPPORTED",
                corrupt_reason="SYNTHETIC_ADAPTER_CORRUPT",
                durability_reason="SYNTHETIC_ADAPTER_DURABILITY_UNAVAILABLE",
                label="Synthetic-adapter store",
            )
            self._validate_metadata_and_inventory(connection)
            return connection
        except SyntheticAdapterError:
            if connection is not None:
                connection.close()
            raise
        except (OSError, sqlite3.Error) as exc:
            if connection is not None:
                connection.close()
            raise SyntheticAdapterError(
                "SYNTHETIC_ADAPTER_UNAVAILABLE",
                "Synthetic-adapter access failed closed.",
            ) from exc

    def _initialize(self) -> None:
        connection: sqlite3.Connection | None = None
        try:
            _assert_safe_parent_chain(
                self.path,
                allow_missing=True,
                error_type=SyntheticAdapterError,
                reason_code="SYNTHETIC_ADAPTER_PATH_UNSAFE",
                label="Synthetic-adapter store",
            )
            self.path.parent.mkdir(parents=True, exist_ok=True)
            _assert_safe_parent_chain(
                self.path,
                allow_missing=False,
                error_type=SyntheticAdapterError,
                reason_code="SYNTHETIC_ADAPTER_PATH_UNSAFE",
                label="Synthetic-adapter store",
            )
            self._safe(allow_missing=True)
            existing_file = self.path.exists()
            connection = sqlite3.connect(
                self.path,
                timeout=self.busy_timeout_ms / 1000.0,
                isolation_level=None,
            )
            connection.row_factory = sqlite3.Row
            connection.execute(f"PRAGMA busy_timeout={self.busy_timeout_ms}")
            if existing_file:
                tables = {
                    str(row[0])
                    for row in connection.execute(
                        "SELECT name FROM sqlite_master WHERE type='table'"
                    )
                }
                if "metadata" not in tables:
                    raise SyntheticAdapterError(
                        "SYNTHETIC_ADAPTER_SCHEMA_UNSUPPORTED",
                        "Existing database is not a recognized synthetic-adapter store.",
                    )
                if not _ADAPTER_REQUIRED_TABLES <= tables:
                    raise SyntheticAdapterError(
                        "SYNTHETIC_ADAPTER_SCHEMA_UNSUPPORTED",
                        "Synthetic-adapter store schema is unsupported.",
                    )
                if _application_schema_sha256(connection) != _ADAPTER_SCHEMA_SHA256:
                    raise SyntheticAdapterError(
                        "SYNTHETIC_ADAPTER_SCHEMA_UNSUPPORTED",
                        "Synthetic-adapter application schema is not the exact supported v1 schema.",
                    )
                journal_mode = connection.execute("PRAGMA journal_mode").fetchone()[0]
            else:
                journal_mode = connection.execute("PRAGMA journal_mode=WAL").fetchone()[0]
            if str(journal_mode).lower() != "wal":
                raise SyntheticAdapterError(
                    "SYNTHETIC_ADAPTER_DURABILITY_UNAVAILABLE",
                    "Synthetic-adapter store requires SQLite WAL mode.",
                )
            connection.execute("PRAGMA synchronous=FULL")
            connection.execute("PRAGMA foreign_keys=ON")
            connection.executescript(_ADAPTER_SCHEMA_SQL)
            if _application_schema_sha256(connection) != _ADAPTER_SCHEMA_SHA256:
                raise SyntheticAdapterError(
                    "SYNTHETIC_ADAPTER_SCHEMA_UNSUPPORTED",
                    "Synthetic-adapter application schema is not the exact supported v1 schema.",
                )
            metadata = dict(connection.execute("SELECT key, value FROM metadata"))
            if not metadata:
                now = self._created_at
                connection.execute("BEGIN IMMEDIATE")
                connection.executemany(
                    "INSERT INTO metadata(key, value) VALUES(?, ?)",
                    (
                        ("schema_version", ADAPTER_SCHEMA_VERSION),
                        ("adapter_store_id", str(uuid.uuid4())),
                        ("adapter_id", SYNTHETIC_ADAPTER_ID),
                        (
                            "adapter_contract_version",
                            SYNTHETIC_ADAPTER_CONTRACT_VERSION,
                        ),
                        (
                            "adapter_contract_sha256",
                            SYNTHETIC_ADAPTER_CONTRACT_SHA256,
                        ),
                        ("execution_mode", SYNTHETIC_EXECUTION_MODE),
                        ("inventory_sha256", self._inventory_sha256),
                        ("fault_modes_sha256", self._fault_modes_sha256),
                        ("created_at", now),
                    ),
                )
                for target_id, state in self._initial_states.items():
                    state_json = canonical_json(state)
                    connection.execute(
                        """
                        INSERT INTO target_states(
                            target_id, state_json, state_sha256, updated_at
                        ) VALUES(?, ?, ?, ?)
                        """,
                        (
                            target_id,
                            state_json,
                            hashlib.sha256(state_json.encode("utf-8")).hexdigest(),
                            now,
                        ),
                    )
                connection.commit()
            self._validate_metadata_and_inventory(connection)
            connection.close()
            connection = None
            os.chmod(self.path, 0o600)
            self._safe(allow_missing=False)
        except SyntheticAdapterError:
            raise
        except (OSError, sqlite3.Error) as exc:
            raise SyntheticAdapterError(
                "SYNTHETIC_ADAPTER_UNAVAILABLE",
                "Synthetic-adapter initialization failed closed.",
            ) from exc
        finally:
            if connection is not None:
                connection.close()

    @staticmethod
    def _validate_binding(value: object) -> dict[str, Any]:
        if type(value) is not dict or set(value) != _ADAPTER_BINDING_KEYS:
            raise SyntheticAdapterError(
                "SYNTHETIC_ADAPTER_BINDING_INVALID",
                "Adapter command binding has an invalid closed shape.",
            )
        _reject_authority_bearing_keys(
            value,
            error_type=SyntheticAdapterError,
            reason_code="SYNTHETIC_ADAPTER_BINDING_INVALID",
        )
        if (
            value["adapter_id"] != SYNTHETIC_ADAPTER_ID
            or value["adapter_contract_version"]
            != SYNTHETIC_ADAPTER_CONTRACT_VERSION
            or value["adapter_contract_sha256"]
            != SYNTHETIC_ADAPTER_CONTRACT_SHA256
            or value["execution_mode"] != SYNTHETIC_EXECUTION_MODE
        ):
            raise SyntheticAdapterError(
                "SYNTHETIC_ADAPTER_BINDING_INVALID",
                "Adapter contract binding is invalid.",
            )
        for name in (
            "unsigned_token_sha256",
            "request_sha256",
            "decision_authorization_sha256",
            "decision_context_sha256",
            "policy_sha256",
            "target_state_sha256",
        ):
            _require_sha256(
                name,
                value[name],
                error_type=SyntheticAdapterError,
                reason_code="SYNTHETIC_ADAPTER_BINDING_INVALID",
            )
        for name in (
            "token_id",
            "issuer_instance_id",
            "authorization_key_domain_id",
            "principal_id",
            "request_id",
            "decision_id",
            "agent_id",
            "policy_id",
            "policy_version",
        ):
            _require_identifier(
                name,
                value[name],
                error_type=SyntheticAdapterError,
                reason_code="SYNTHETIC_ADAPTER_BINDING_INVALID",
            )
        command = value["command"]
        if (
            type(command) is not dict
            or set(command) != {"type", "target", "parameters"}
            or type(command["type"]) is not str
            or not command["type"]
            or type(command["target"]) is not str
            or not command["target"]
            or type(command["parameters"]) is not dict
        ):
            raise SyntheticAdapterError(
                "SYNTHETIC_ADAPTER_BINDING_INVALID",
                "Adapter command shape is invalid.",
            )
        try:
            encoded = canonical_json(value).encode("utf-8")
            copied = deepcopy(value)
        except (TypeError, ValueError, OverflowError, RecursionError) as exc:
            raise SyntheticAdapterError(
                "SYNTHETIC_ADAPTER_BINDING_INVALID",
                "Adapter command binding is not canonical JSON.",
            ) from exc
        if len(encoded) > 32_768:
            raise SyntheticAdapterError(
                "SYNTHETIC_ADAPTER_BINDING_INVALID",
                "Adapter command binding exceeds the durable size bound.",
            )
        return copied

    @staticmethod
    def _validate_target_state(value: object, *, target_id: str) -> dict[str, Any]:
        expected = {
            "target_id",
            "target_type",
            "network_state",
            "management_channel",
            "isolation_expires_at",
            "service_health",
            "last_action_id",
        }
        if (
            type(value) is not dict
            or set(value) != expected
            or value["target_id"] != target_id
            or type(value["target_type"]) is not str
            or not value["target_type"]
            or len(value["target_type"]) > 512
            or value["network_state"] not in {"connected", "isolated"}
            or type(value["management_channel"]) is not bool
            or (
                value["isolation_expires_at"] is not None
                and not _is_offset_timestamp(value["isolation_expires_at"])
            )
            or value["service_health"] not in {"healthy", "degraded"}
            or (
                value["last_action_id"] is not None
                and (
                    type(value["last_action_id"]) is not str
                    or not value["last_action_id"]
                    or len(value["last_action_id"]) > 512
                )
            )
        ):
            raise SyntheticAdapterError(
                "SYNTHETIC_ADAPTER_CORRUPT",
                "Synthetic target state has an invalid closed binding.",
            )
        return deepcopy(value)

    def observe(self, target_id: str) -> dict[str, Any]:
        target_id = _require_identifier(
            "target_id",
            target_id,
            error_type=SyntheticAdapterError,
            reason_code="SYNTHETIC_ADAPTER_BINDING_INVALID",
        )
        connection = self._connect()
        try:
            row = connection.execute(
                "SELECT state_json, state_sha256 FROM target_states WHERE target_id=?",
                (target_id,),
            ).fetchone()
            if row is None:
                raise SyntheticAdapterError(
                    "TARGET_UNKNOWN",
                    "Target is not present in the synthetic adapter inventory.",
                )
            if (
                hashlib.sha256(row["state_json"].encode("utf-8")).hexdigest()
                != row["state_sha256"]
            ):
                raise SyntheticAdapterError(
                    "SYNTHETIC_ADAPTER_CORRUPT",
                    "Synthetic target-state integrity failed.",
                )
            return self._validate_target_state(
                _load_json_object(
                    row["state_json"],
                    error_type=SyntheticAdapterError,
                    reason_code="SYNTHETIC_ADAPTER_CORRUPT",
                ),
                target_id=target_id,
            )
        except SyntheticAdapterError:
            raise
        except sqlite3.Error as exc:
            raise SyntheticAdapterError(
                "SYNTHETIC_ADAPTER_UNAVAILABLE",
                "Synthetic target observation failed closed.",
            ) from exc
        finally:
            connection.close()

    def _validated_receipt_row(
        self, row: sqlite3.Row, *, idempotency_key: str
    ) -> SyntheticAdapterReceipt:
        binding_raw = row["binding_json"]
        receipt_raw = row["receipt_json"]
        if (
            type(binding_raw) is not str
            or len(binding_raw.encode("utf-8")) > 32_768
            or hashlib.sha256(binding_raw.encode("utf-8")).hexdigest()
            != row["binding_sha256"]
            or row["binding_sha256"] != idempotency_key
        ):
            raise SyntheticAdapterError(
                "SYNTHETIC_ADAPTER_CORRUPT",
                "Synthetic command-binding integrity failed.",
            )
        if (
            type(receipt_raw) is not str
            or len(receipt_raw.encode("utf-8")) > 16_384
            or hashlib.sha256(receipt_raw.encode("utf-8")).hexdigest()
            != row["receipt_sha256"]
        ):
            raise SyntheticAdapterError(
                "SYNTHETIC_ADAPTER_CORRUPT",
                "Synthetic receipt integrity failed.",
            )
        binding = self._validate_binding(
            _load_json_object(
                binding_raw,
                error_type=SyntheticAdapterError,
                reason_code="SYNTHETIC_ADAPTER_CORRUPT",
            )
        )
        receipt = SyntheticAdapterReceipt.from_dict(
            _load_json_object(
                receipt_raw,
                error_type=SyntheticAdapterError,
                reason_code="SYNTHETIC_ADAPTER_CORRUPT",
            )
        )
        if (
            receipt.idempotency_key != idempotency_key
            or receipt.binding_sha256 != row["binding_sha256"]
            or receipt.request_id != row["request_id"]
            or receipt.request_id != binding["request_id"]
            or row["principal_id"] != binding["principal_id"]
            or receipt.target_id != row["target_id"]
            or receipt.target_id != binding["command"]["target"]
            or receipt.decision_id != binding["decision_id"]
            or receipt.action_type != binding["command"]["type"]
            or not _is_offset_timestamp(row["committed_at"])
            or row["committed_at"] != receipt.attempted_at
            or (
                receipt.status != "NO_EFFECT"
                and receipt.state_before_sha256 != binding["target_state_sha256"]
            )
        ):
            raise SyntheticAdapterError(
                "SYNTHETIC_ADAPTER_CORRUPT",
                "Synthetic receipt row binding is inconsistent.",
            )
        return receipt

    def _correlation_snapshot_from_connection(
        self, connection: sqlite3.Connection
    ) -> tuple[dict[str, str], ...]:
        rows = connection.execute(
            """
            SELECT idempotency_key, principal_id, request_id, target_id,
                   binding_json, binding_sha256, receipt_json, receipt_sha256,
                   committed_at
            FROM command_receipts
            ORDER BY idempotency_key
            """
        ).fetchall()
        snapshot: list[dict[str, str]] = []
        for row in rows:
            idempotency_key = str(row["idempotency_key"])
            receipt = self._validated_receipt_row(
                row, idempotency_key=idempotency_key
            )
            binding = self._validate_binding(
                _load_json_object(
                    row["binding_json"],
                    error_type=SyntheticAdapterError,
                    reason_code="SYNTHETIC_ADAPTER_CORRUPT",
                )
            )
            snapshot.append(
                {
                    "principal_id": str(row["principal_id"]),
                    "request_id": str(row["request_id"]),
                    "attempt_id": receipt.attempt_id,
                    "idempotency_key": idempotency_key,
                    "binding_sha256": str(row["binding_sha256"]),
                    "receipt_sha256": str(row["receipt_sha256"]),
                    "status": receipt.status,
                    "request_sha256": str(binding["request_sha256"]),
                    "token_id": str(binding["token_id"]),
                    "unsigned_token_sha256": str(
                        binding["unsigned_token_sha256"]
                    ),
                    "issuer_instance_id": str(binding["issuer_instance_id"]),
                    "authorization_key_domain_id": str(
                        binding["authorization_key_domain_id"]
                    ),
                    "decision_id": str(binding["decision_id"]),
                    "decision_authorization_sha256": str(
                        binding["decision_authorization_sha256"]
                    ),
                    "decision_context_sha256": str(
                        binding["decision_context_sha256"]
                    ),
                    "policy_sha256": str(binding["policy_sha256"]),
                    "state_after_sha256": receipt.state_after_sha256,
                }
            )
        return tuple(snapshot)

    def receipt(self, idempotency_key: str) -> SyntheticAdapterReceipt | None:
        idempotency_key = _require_sha256(
            "idempotency_key",
            idempotency_key,
            error_type=SyntheticAdapterError,
            reason_code="SYNTHETIC_ADAPTER_BINDING_INVALID",
        )
        connection = self._connect()
        try:
            row = connection.execute(
                """
                SELECT principal_id, request_id, target_id,
                       binding_json, binding_sha256,
                       receipt_json, receipt_sha256, committed_at
                FROM command_receipts
                WHERE idempotency_key=?
                """,
                (idempotency_key,),
            ).fetchone()
            if row is None:
                return None
            return self._validated_receipt_row(row, idempotency_key=idempotency_key)
        except SyntheticAdapterError:
            raise
        except sqlite3.Error as exc:
            raise SyntheticAdapterError(
                "SYNTHETIC_ADAPTER_UNAVAILABLE",
                "Synthetic receipt read failed closed.",
            ) from exc
        finally:
            connection.close()


    def execute_once(
        self,
        *,
        idempotency_key: str,
        binding: dict[str, Any],
        attempt_id: str,
        attempted_at: str,
    ) -> SyntheticAdapterReceipt:
        """Atomically apply one synthetic mutation and insert its immutable receipt."""

        binding = self._validate_binding(binding)
        binding_json = canonical_json(binding)
        binding_sha256 = hashlib.sha256(binding_json.encode("utf-8")).hexdigest()
        idempotency_key = _require_sha256(
            "idempotency_key",
            idempotency_key,
            error_type=SyntheticAdapterError,
            reason_code="SYNTHETIC_ADAPTER_BINDING_INVALID",
        )
        if idempotency_key != binding_sha256:
            raise SyntheticAdapterError(
                "SYNTHETIC_ADAPTER_IDEMPOTENCY_CONFLICT",
                "Idempotency key does not equal the exact command-binding digest.",
            )
        attempt_id = _require_identifier(
            "attempt_id",
            attempt_id,
            error_type=SyntheticAdapterError,
            reason_code="SYNTHETIC_ADAPTER_BINDING_INVALID",
        )
        attempted_at = _require_identifier(
            "attempted_at",
            attempted_at,
            error_type=SyntheticAdapterError,
            reason_code="SYNTHETIC_ADAPTER_BINDING_INVALID",
        )
        try:
            executed_at = datetime.fromisoformat(attempted_at)
            if executed_at.tzinfo is None or executed_at.utcoffset() is None:
                raise ValueError("timestamp has no UTC offset")
            executed_at = executed_at.astimezone(timezone.utc).replace(microsecond=0)
        except (TypeError, ValueError, OverflowError) as exc:
            raise SyntheticAdapterError(
                "SYNTHETIC_ADAPTER_BINDING_INVALID",
                "Adapter attempted_at timestamp is invalid.",
            ) from exc
        attempted_at = executed_at.isoformat()
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            self._validate_metadata_and_inventory(connection)
            existing = connection.execute(
                """
                SELECT principal_id, request_id, target_id,
                       binding_json, binding_sha256, receipt_json, receipt_sha256,
                       committed_at
                FROM command_receipts WHERE idempotency_key=?
                """,
                (idempotency_key,),
            ).fetchone()
            if existing is not None:
                if (
                    existing["binding_sha256"] != binding_sha256
                    or existing["binding_json"] != binding_json
                ):
                    raise SyntheticAdapterError(
                        "SYNTHETIC_ADAPTER_IDEMPOTENCY_CONFLICT",
                        "Idempotency key is bound to a different command.",
                    )
                receipt = self._validated_receipt_row(
                    existing, idempotency_key=idempotency_key
                )
                connection.commit()
                return receipt
            command = binding["command"]
            target_id = command["target"]
            state_row = connection.execute(
                """
                SELECT state_json, state_sha256, updated_at
                FROM target_states WHERE target_id=?
                """,
                (target_id,),
            ).fetchone()
            if state_row is None:
                raise SyntheticAdapterError(
                    "TARGET_UNKNOWN",
                    "Target is not present in the synthetic adapter inventory.",
                )
            if (
                hashlib.sha256(state_row["state_json"].encode("utf-8")).hexdigest()
                != state_row["state_sha256"]
            ):
                raise SyntheticAdapterError(
                    "SYNTHETIC_ADAPTER_CORRUPT",
                    "Synthetic target-state integrity failed.",
                )
            before = self._validate_target_state(
                _load_json_object(
                    state_row["state_json"],
                    error_type=SyntheticAdapterError,
                    reason_code="SYNTHETIC_ADAPTER_CORRUPT",
                ),
                target_id=target_id,
            )
            if datetime.fromisoformat(attempted_at) < datetime.fromisoformat(
                state_row["updated_at"]
            ):
                raise SyntheticAdapterError(
                    "SYNTHETIC_ADAPTER_TIME_INVALID",
                    "Synthetic execution time cannot precede target history.",
                )
            before_sha256 = sha256_json(before)
            after = deepcopy(before)
            status = "NO_EFFECT"
            reported_success = False
            message = "Synthetic adapter reported no effect."
            if before_sha256 != binding["target_state_sha256"]:
                message = "Synthetic target precondition changed before mutation."
            elif command["type"] != "NETWORK_ISOLATE":
                message = "Synthetic adapter does not implement the requested action."
            else:
                parameters = command["parameters"]
                if (
                    set(parameters)
                    != {"duration_seconds", "preserve_management"}
                    or type(parameters["duration_seconds"]) is not int
                    or parameters["duration_seconds"] <= 0
                    or type(parameters["preserve_management"]) is not bool
                ):
                    raise SyntheticAdapterError(
                        "SYNTHETIC_ADAPTER_BINDING_INVALID",
                        "Synthetic NETWORK_ISOLATE parameters are invalid.",
                    )
                fault_mode = self._fault_modes.get(target_id, "NONE")
                if fault_mode == "FAILED":
                    message = "Injected synthetic downstream failure; no state changed."
                else:
                    after["last_action_id"] = attempt_id
                    after["network_state"] = "isolated"
                    reported_success = True
                    if fault_mode == "PARTIAL":
                        status = "PARTIAL"
                        after["isolation_expires_at"] = None
                        message = "Injected partial transition in the synthetic target."
                    else:
                        after["management_channel"] = parameters[
                            "preserve_management"
                        ]
                        after["isolation_expires_at"] = (
                            executed_at
                            + timedelta(seconds=parameters["duration_seconds"])
                        ).replace(microsecond=0).isoformat()
                        if fault_mode == "UNEXPECTED_EFFECT":
                            status = "AMBIGUOUS"
                            after["service_health"] = "degraded"
                            message = (
                                "Synthetic action completed with an injected "
                                "unexpected effect."
                            )
                        else:
                            status = "APPLIED"
                            message = (
                                "Synthetic network isolation applied by the "
                                "durable offline adapter."
                            )
            after_json = canonical_json(after)
            after_sha256 = hashlib.sha256(after_json.encode("utf-8")).hexdigest()
            receipt = SyntheticAdapterReceipt(
                schema_version=ADAPTER_RECEIPT_SCHEMA_VERSION,
                receipt_id=f"receipt-{uuid.uuid4()}",
                adapter_id=SYNTHETIC_ADAPTER_ID,
                adapter_contract_version=SYNTHETIC_ADAPTER_CONTRACT_VERSION,
                adapter_contract_sha256=SYNTHETIC_ADAPTER_CONTRACT_SHA256,
                execution_mode=SYNTHETIC_EXECUTION_MODE,
                idempotency_key=idempotency_key,
                binding_sha256=binding_sha256,
                attempt_id=attempt_id,
                request_id=binding["request_id"],
                decision_id=binding["decision_id"],
                target_id=target_id,
                action_type=command["type"],
                status=status,
                attempted_at=attempted_at,
                reported_success=reported_success,
                message=message,
                state_before_sha256=before_sha256,
                state_after_sha256=after_sha256,
            )
            receipt_json = canonical_json(receipt.to_dict())
            if len(receipt_json.encode("utf-8")) > 16_384:
                raise SyntheticAdapterError(
                    "SYNTHETIC_ADAPTER_RECEIPT_INVALID",
                    "Synthetic receipt exceeds the durable size bound.",
                )
            receipt_sha256 = hashlib.sha256(
                receipt_json.encode("utf-8")
            ).hexdigest()
            updated = connection.execute(
                """
                UPDATE target_states
                SET state_json=?, state_sha256=?, updated_at=?
                WHERE target_id=? AND state_sha256=? AND updated_at=?
                """,
                (
                    after_json,
                    after_sha256,
                    attempted_at,
                    target_id,
                    state_row["state_sha256"],
                    state_row["updated_at"],
                ),
            )
            if updated.rowcount != 1:
                raise SyntheticAdapterError(
                    "SYNTHETIC_ADAPTER_CONCURRENCY_CONFLICT",
                    "Synthetic state transition lost its compare-and-set race.",
                )
            connection.execute(
                """
                INSERT INTO command_receipts(
                    idempotency_key, principal_id, request_id,
                    binding_json, binding_sha256,
                    receipt_json, receipt_sha256, target_id, committed_at
                ) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    idempotency_key,
                    binding["principal_id"],
                    binding["request_id"],
                    binding_json,
                    binding_sha256,
                    receipt_json,
                    receipt_sha256,
                    target_id,
                    attempted_at,
                ),
            )
            connection.commit()
            return receipt
        except SyntheticAdapterError:
            connection.rollback()
            raise
        except sqlite3.IntegrityError as exc:
            connection.rollback()
            raise SyntheticAdapterError(
                "SYNTHETIC_ADAPTER_IDEMPOTENCY_CONFLICT",
                "Synthetic adapter command identity is already differently bound.",
            ) from exc
        except (OSError, sqlite3.Error, TypeError, ValueError, KeyError) as exc:
            connection.rollback()
            raise SyntheticAdapterError(
                "SYNTHETIC_ADAPTER_FAILURE",
                "Synthetic adapter transaction failed closed.",
            ) from exc
        finally:
            connection.close()

    def receipt_count(self) -> int:
        connection = self._connect()
        try:
            return int(
                connection.execute(
                    "SELECT COUNT(*) FROM command_receipts"
                ).fetchone()[0]
            )
        finally:
            connection.close()

    def correlation_snapshot(self) -> tuple[dict[str, str], ...]:
        """Return a validated, authority-free projection for store correlation."""

        connection = self._connect()
        try:
            return self._correlation_snapshot_from_connection(connection)
        finally:
            connection.close()


class SQLiteControlLedger(_SQLiteControlLedgerBase):
    """Public v2 control-ledger API layered on the fail-closed SQLite base."""

    @staticmethod
    def _insert_outbox(
        connection: sqlite3.Connection,
        event_type: str,
        subject_id: str,
        payload: dict[str, Any],
    ) -> None:
        connection.execute(
            """
            INSERT INTO audit_outbox(
                event_type, subject_id, payload_sha256, created_at
            ) VALUES(?, ?, ?, ?)
            """,
            (
                event_type,
                subject_id,
                _event_digest(event_type, subject_id, payload),
                utc_now_iso(),
            ),
        )

    def claim_request(
        self,
        principal_id: str,
        request_id: str,
        request_sha256: str,
        *,
        claimed_at: str | None = None,
    ) -> str:
        principal_id = _require_identifier("principal_id", principal_id)
        request_id = _require_identifier("request_id", request_id)
        request_sha256 = _require_sha256("request_sha256", request_sha256)
        claimed_at = _require_offset_timestamp(
            "claimed_at", claimed_at or utc_now_iso()
        )
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            _validate_control_relations(connection)
            row = connection.execute(
                """
                SELECT request_sha256 FROM requests
                WHERE principal_id=? AND request_id=?
                """,
                (principal_id, request_id),
            ).fetchone()
            if row is not None:
                connection.commit()
                return "DUPLICATE" if row[0] == request_sha256 else "CONFLICT"
            connection.execute(
                """
                INSERT INTO requests(
                    principal_id, request_id, request_sha256, state,
                    claimed_at, updated_at
                ) VALUES(?, ?, ?, 'CLAIMED', ?, ?)
                """,
                (
                    principal_id,
                    request_id,
                    request_sha256,
                    claimed_at,
                    claimed_at,
                ),
            )
            self._insert_outbox(
                connection,
                "REQUEST_CLAIMED",
                f"{principal_id}:{request_id}",
                {"request_sha256": request_sha256},
            )
            connection.commit()
            return "NEW"
        except ControlLedgerError:
            connection.rollback()
            raise
        except (OSError, sqlite3.Error) as exc:
            connection.rollback()
            raise ControlLedgerError(
                "CONTROL_LEDGER_UNAVAILABLE",
                "Request claim could not be committed.",
            ) from exc
        finally:
            connection.close()

    def request_snapshot(
        self, principal_id: str, request_id: str, request_sha256: str
    ) -> dict[str, Any] | None:
        """Read one request/attempt snapshot without retaining a transaction."""

        principal_id = _require_identifier("principal_id", principal_id)
        request_id = _require_identifier("request_id", request_id)
        request_sha256 = _require_sha256("request_sha256", request_sha256)
        connection = self._connect()
        try:
            connection.execute("BEGIN")
            _validate_control_relations(connection)
            row = connection.execute(
                """
                SELECT r.principal_id, r.request_id, r.request_sha256,
                       r.state, r.claimed_at, r.updated_at,
                       a.attempt_id, a.token_id, a.idempotency_key,
                       a.binding_sha256, a.recovery_summary_json,
                       a.recovery_summary_sha256,
                       a.state AS attempt_state, a.outcome_sha256,
                       a.adapter_receipt_sha256,
                       z.decision_id AS authorization_decision_id
                FROM requests r
                LEFT JOIN attempts a
                  ON a.principal_id=r.principal_id AND a.request_id=r.request_id
                LEFT JOIN authorizations z ON z.token_id=a.token_id
                WHERE r.principal_id=? AND r.request_id=?
                """,
                (principal_id, request_id),
            ).fetchone()
            if row is None:
                return None
            if row["request_sha256"] != request_sha256:
                raise ControlLedgerError(
                    "REQUEST_ID_CONFLICT",
                    "Request identifier is bound to different content.",
                )
            value = dict(row)
            raw_summary = value.pop("recovery_summary_json")
            summary_sha256 = value.pop("recovery_summary_sha256")
            value["recovery_summary"] = None
            if raw_summary is not None:
                if (
                    summary_sha256 is None
                    or hashlib.sha256(raw_summary.encode("utf-8")).hexdigest()
                    != summary_sha256
                ):
                    raise ControlLedgerError(
                        "CONTROL_LEDGER_CORRUPT",
                        "Recovery-summary integrity failed.",
                    )
                summary = _validate_recovery_summary(
                    _load_json_object(
                        raw_summary,
                        error_type=ControlLedgerError,
                        reason_code="CONTROL_LEDGER_CORRUPT",
                    )
                )
                if (
                    summary["principal_id"] != principal_id
                    or summary["request_id"] != request_id
                    or summary["request_sha256"] != request_sha256
                    or summary["decision_id"]
                    != value["authorization_decision_id"]
                ):
                    raise ControlLedgerError(
                        "CONTROL_LEDGER_CORRUPT",
                        "Recovery-summary row binding is invalid.",
                    )
                value["recovery_summary"] = summary
            return value
        except ControlLedgerError:
            raise
        except sqlite3.Error as exc:
            raise ControlLedgerError(
                "CONTROL_LEDGER_UNAVAILABLE", "Request state read failed."
            ) from exc
        finally:
            connection.close()

    def register(
        self,
        token_id: str,
        *,
        verification_id: str | None = None,
        decision_id: str | None = None,
        principal_id: str | None = None,
        request_id: str | None = None,
        request_sha256: str | None = None,
        unsigned_token_sha256: str | None = None,
        issuer_instance_id: str | None = None,
        key_domain_id: str | None = None,
        decision_authorization_sha256: str | None = None,
        issued_at: str | None = None,
    ) -> None:
        token_id = _require_identifier("token_id", token_id)
        verification_id = _require_identifier(
            "verification_id", verification_id or f"legacy:{token_id}"
        )
        decision_id = _require_identifier(
            "decision_id", decision_id or f"legacy:{token_id}"
        )
        linked_values = (
            principal_id,
            request_id,
            request_sha256,
            unsigned_token_sha256,
            issuer_instance_id,
            key_domain_id,
            decision_authorization_sha256,
        )
        issued_at = _require_offset_timestamp("issued_at", issued_at or utc_now_iso())
        linked = any(value is not None for value in linked_values)
        if linked:
            principal_id = _require_identifier("principal_id", principal_id)
            request_id = _require_identifier("request_id", request_id)
            request_sha256 = _require_sha256("request_sha256", request_sha256)
            unsigned_token_sha256 = _require_sha256(
                "unsigned_token_sha256", unsigned_token_sha256
            )
            issuer_instance_id = _require_identifier(
                "issuer_instance_id", issuer_instance_id
            )
            key_domain_id = _require_identifier("key_domain_id", key_domain_id)
            decision_authorization_sha256 = _require_sha256(
                "decision_authorization_sha256", decision_authorization_sha256
            )
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            _validate_control_relations(connection)
            if linked:
                request = connection.execute(
                    """
                    SELECT request_sha256, state, claimed_at, updated_at FROM requests
                    WHERE principal_id=? AND request_id=?
                    """,
                    (principal_id, request_id),
                ).fetchone()
                if (
                    request is None
                    or request["request_sha256"] != request_sha256
                    or request["state"] != "CLAIMED"
                    or datetime.fromisoformat(issued_at)
                    < datetime.fromisoformat(request["updated_at"])
                ):
                    raise ControlLedgerError(
                        "AUTHORIZATION_REQUEST_LINK_INVALID",
                        "Authorization request linkage is absent or invalid.",
                    )
            connection.execute(
                """
                INSERT INTO authorizations(
                    token_id, verification_id, decision_id,
                    principal_id, request_id, request_sha256,
                    unsigned_token_sha256, issuer_instance_id, key_domain_id,
                    decision_authorization_sha256, state, issued_at
                ) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'ISSUED', ?)
                """,
                (
                    token_id,
                    verification_id,
                    decision_id,
                    principal_id,
                    request_id,
                    request_sha256,
                    unsigned_token_sha256,
                    issuer_instance_id,
                    key_domain_id,
                    decision_authorization_sha256,
                    issued_at,
                ),
            )
            if linked:
                connection.execute(
                    """
                    UPDATE requests SET state='AUTHORIZED', updated_at=?
                    WHERE principal_id=? AND request_id=?
                    """,
                    (issued_at, principal_id, request_id),
                )
            self._insert_outbox(
                connection,
                "AUTHORIZATION_ISSUED",
                token_id,
                {
                    "verification_id_sha256": hashlib.sha256(
                        verification_id.encode("utf-8")
                    ).hexdigest(),
                    "decision_id_sha256": hashlib.sha256(
                        decision_id.encode("utf-8")
                    ).hexdigest(),
                    "request_sha256": request_sha256,
                },
            )
            connection.commit()
        except ControlLedgerError:
            connection.rollback()
            raise
        except sqlite3.IntegrityError as exc:
            connection.rollback()
            reason = (
                "AUTHORIZATION_ID_COLLISION"
                if connection.execute(
                    "SELECT 1 FROM authorizations WHERE token_id=?", (token_id,)
                ).fetchone()
                else "AUTHORIZATION_DECISION_REPLAY"
            )
            raise ControlLedgerError(reason, "Authorization issuance conflicted.") from exc
        except (OSError, sqlite3.Error) as exc:
            connection.rollback()
            raise ControlLedgerError(
                "CONTROL_LEDGER_UNAVAILABLE",
                "Authorization issuance could not be committed.",
            ) from exc
        finally:
            connection.close()

    def consume_once(
        self,
        token_id: str,
        *,
        attempt_id: str | None = None,
        attempt_binding_sha256: str | None = None,
        consumed_at: str | None = None,
        idempotency_key: str | None = None,
        recovery_summary: dict[str, Any] | None = None,
    ) -> None:
        token_id = _require_identifier("token_id", token_id)
        if (attempt_id is None) != (attempt_binding_sha256 is None):
            raise ControlLedgerError(
                "CONTROL_LEDGER_BINDING_INVALID",
                "Attempt identifier and binding digest must be supplied together.",
            )
        summary_json: str | None = None
        summary_sha256: str | None = None
        if attempt_id is not None:
            attempt_id = _require_identifier("attempt_id", attempt_id)
            attempt_binding_sha256 = _require_sha256(
                "attempt_binding_sha256", attempt_binding_sha256
            )
            idempotency_key = _require_sha256(
                "idempotency_key", idempotency_key or attempt_binding_sha256
            )
            consumed_at = _require_identifier("consumed_at", consumed_at)
            if idempotency_key != attempt_binding_sha256:
                raise ControlLedgerError(
                    "ATTEMPT_IDEMPOTENCY_CONFLICT",
                    "Idempotency key must equal the exact attempt-binding digest.",
                )
            if recovery_summary is not None:
                recovery_summary = _validate_recovery_summary(recovery_summary)
                summary_json = canonical_json(recovery_summary)
                summary_sha256 = hashlib.sha256(
                    summary_json.encode("utf-8")
                ).hexdigest()
        consumed_at = _require_offset_timestamp(
            "consumed_at", consumed_at or utc_now_iso()
        )
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            _validate_control_relations(connection)
            row = connection.execute(
                """
                SELECT state, principal_id, request_id, request_sha256, decision_id,
                       decision_authorization_sha256, issued_at,
                       (SELECT updated_at FROM requests r
                        WHERE r.principal_id=authorizations.principal_id
                          AND r.request_id=authorizations.request_id)
                           AS request_updated_at,
                       (SELECT claimed_at FROM requests r
                        WHERE r.principal_id=authorizations.principal_id
                          AND r.request_id=authorizations.request_id)
                           AS request_claimed_at
                FROM authorizations WHERE token_id=?
                """,
                (token_id,),
            ).fetchone()
            if row is None:
                raise ControlLedgerError(
                    "AUTHORIZATION_UNKNOWN",
                    "Authorization was not issued by this control ledger.",
                )
            if row["state"] != "ISSUED":
                raise ControlLedgerError(
                    "AUTHORIZATION_REPLAY", "Authorization is not in ISSUED state."
                )
            if (
                datetime.fromisoformat(consumed_at)
                < datetime.fromisoformat(row["issued_at"])
                or (
                    row["principal_id"] is not None
                    and
                    row["request_updated_at"] is not None
                    and datetime.fromisoformat(consumed_at)
                    < datetime.fromisoformat(row["request_updated_at"])
                )
            ):
                raise ControlLedgerError(
                    "AUTHORIZATION_TIME_INVALID",
                    "Authorization consumption cannot precede its durable issuance.",
                )
            if row["principal_id"] is not None:
                if attempt_id is None or recovery_summary is None:
                    raise ControlLedgerError(
                        "AUTHORIZATION_REQUEST_LINK_INVALID",
                        "Linked authorization requires an exact attempt and recovery summary.",
                    )
                if (
                    recovery_summary["principal_id"] != row["principal_id"]
                    or recovery_summary["request_id"] != row["request_id"]
                    or recovery_summary["request_sha256"] != row["request_sha256"]
                    or recovery_summary["decision_id"] != row["decision_id"]
                    or recovery_summary["decision_sha256"]
                    != row["decision_authorization_sha256"]
                    or recovery_summary["decision_outcome"]
                    not in {"ALLOW", "ALLOW_CONSTRAINED"}
                    or datetime.fromisoformat(recovery_summary["decided_at"])
                    < datetime.fromisoformat(row["request_claimed_at"])
                    or datetime.fromisoformat(recovery_summary["decided_at"])
                    > datetime.fromisoformat(row["issued_at"])
                    or datetime.fromisoformat(recovery_summary["decided_at"])
                    > datetime.fromisoformat(consumed_at)
                ):
                    raise ControlLedgerError(
                        "CONTROL_LEDGER_RECOVERY_SUMMARY_INVALID",
                        "Recovery summary does not bind to the issued authorization.",
                    )
            elif recovery_summary is not None:
                raise ControlLedgerError(
                    "CONTROL_LEDGER_RECOVERY_SUMMARY_INVALID",
                    "Unlinked legacy authorization cannot carry a recovery summary.",
                )
            if attempt_id is not None:
                connection.execute(
                    """
                    INSERT INTO attempts(
                        attempt_id, token_id, principal_id, request_id,
                        request_sha256, idempotency_key, binding_sha256,
                        recovery_summary_json, recovery_summary_sha256,
                        state, reserved_at
                    ) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, 'RESERVED', ?)
                    """,
                    (
                        attempt_id,
                        token_id,
                        row["principal_id"],
                        row["request_id"],
                        row["request_sha256"],
                        idempotency_key,
                        attempt_binding_sha256,
                        summary_json,
                        summary_sha256,
                        consumed_at,
                    ),
                )
                if row["principal_id"] is not None:
                    updated_request = connection.execute(
                        """
                        UPDATE requests SET state='ATTEMPT_RESERVED', updated_at=?
                        WHERE principal_id=? AND request_id=? AND request_sha256=?
                          AND state='AUTHORIZED'
                        """,
                        (
                            consumed_at,
                            row["principal_id"],
                            row["request_id"],
                            row["request_sha256"],
                        ),
                    )
                    if updated_request.rowcount != 1:
                        raise ControlLedgerError(
                            "AUTHORIZATION_REQUEST_LINK_INVALID",
                            "Request was not ready for attempt reservation.",
                        )
                self._insert_outbox(
                    connection,
                    "ATTEMPT_RESERVED",
                    attempt_id,
                    {
                        "token_id_sha256": hashlib.sha256(
                            token_id.encode("utf-8")
                        ).hexdigest(),
                        "binding_sha256": attempt_binding_sha256,
                        "idempotency_key": idempotency_key,
                    },
                )
            updated = connection.execute(
                """
                UPDATE authorizations
                SET state='CONSUMED', consumed_at=?
                WHERE token_id=? AND state='ISSUED'
                """,
                (consumed_at, token_id),
            )
            if updated.rowcount != 1:
                raise ControlLedgerError(
                    "AUTHORIZATION_REPLAY", "Authorization consumption lost its race."
                )
            self._insert_outbox(
                connection,
                "AUTHORIZATION_CONSUMED",
                token_id,
                {"attempt_id": attempt_id},
            )
            connection.commit()
        except ControlLedgerError:
            connection.rollback()
            raise
        except sqlite3.IntegrityError as exc:
            connection.rollback()
            raise ControlLedgerError(
                "ATTEMPT_IDEMPOTENCY_CONFLICT",
                "Attempt, token, binding, or idempotency key already has a reservation.",
            ) from exc
        except (OSError, sqlite3.Error) as exc:
            connection.rollback()
            raise ControlLedgerError(
                "CONTROL_LEDGER_UNAVAILABLE",
                "Authorization reservation could not be committed.",
            ) from exc
        finally:
            connection.close()

    def state(self, token_id: str) -> str | None:
        token_id = _require_identifier("token_id", token_id)
        connection = self._connect()
        try:
            row = connection.execute(
                "SELECT state FROM authorizations WHERE token_id=?", (token_id,)
            ).fetchone()
            return str(row[0]) if row is not None else None
        except sqlite3.Error as exc:
            raise ControlLedgerError(
                "CONTROL_LEDGER_UNAVAILABLE", "Authorization state read failed."
            ) from exc
        finally:
            connection.close()

    def authorization_snapshot(self, token_id: str) -> dict[str, Any] | None:
        token_id = _require_identifier("token_id", token_id)
        connection = self._connect()
        try:
            row = connection.execute(
                """
                SELECT token_id, principal_id, request_id, request_sha256,
                       unsigned_token_sha256, issuer_instance_id, key_domain_id,
                       decision_authorization_sha256, state, issued_at,
                       consumed_at, revoked_at, revocation_reason
                FROM authorizations WHERE token_id=?
                """,
                (token_id,),
            ).fetchone()
            return dict(row) if row is not None else None
        except sqlite3.Error as exc:
            raise ControlLedgerError(
                "CONTROL_LEDGER_UNAVAILABLE", "Authorization state read failed."
            ) from exc
        finally:
            connection.close()

    def record_adapter_receipt(
        self,
        attempt_id: str,
        *,
        adapter_receipt_sha256: str,
        receipt_outcome_sha256: str,
        recorded_at: str,
    ) -> None:
        """Record only adapter-reported outcome; this is not verification."""

        attempt_id = _require_identifier("attempt_id", attempt_id)
        adapter_receipt_sha256 = _require_sha256(
            "adapter_receipt_sha256", adapter_receipt_sha256
        )
        receipt_outcome_sha256 = _require_sha256(
            "receipt_outcome_sha256", receipt_outcome_sha256
        )
        recorded_at = _require_offset_timestamp("recorded_at", recorded_at)
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            _validate_control_relations(connection)
            row = connection.execute(
                """
                SELECT principal_id, state, outcome_sha256,
                       adapter_receipt_sha256, reserved_at
                FROM attempts WHERE attempt_id=?
                """,
                (attempt_id,),
            ).fetchone()
            if row is None:
                raise ControlLedgerError(
                    "ATTEMPT_UNKNOWN", "Attempt reservation does not exist."
                )
            if datetime.fromisoformat(recorded_at) < datetime.fromisoformat(
                row["reserved_at"]
            ):
                raise ControlLedgerError(
                    "CONTROL_LEDGER_BINDING_INVALID",
                    "Adapter receipt time cannot precede attempt reservation.",
                )
            if row["state"] == "RECEIPT_RECORDED":
                if (
                    row["outcome_sha256"] == receipt_outcome_sha256
                    and row["adapter_receipt_sha256"] == adapter_receipt_sha256
                ):
                    connection.commit()
                    return
                raise ControlLedgerError(
                    "ATTEMPT_OUTCOME_CONFLICT",
                    "Attempt already has a different adapter receipt.",
                )
            if row["state"] != "RESERVED":
                raise ControlLedgerError(
                    "ATTEMPT_OUTCOME_CONFLICT", "Attempt is already terminal."
                )
            connection.execute(
                """
                UPDATE attempts
                SET state='RECEIPT_RECORDED', outcome_sha256=?,
                    adapter_receipt_sha256=?
                WHERE attempt_id=? AND state='RESERVED'
                """,
                (receipt_outcome_sha256, adapter_receipt_sha256, attempt_id),
            )
            self._insert_outbox(
                connection,
                "ADAPTER_RECEIPT_RECORDED",
                attempt_id,
                {
                    "adapter_receipt_sha256": adapter_receipt_sha256,
                    "receipt_outcome_sha256": receipt_outcome_sha256,
                },
            )
            connection.commit()
        except ControlLedgerError:
            connection.rollback()
            raise
        except (OSError, sqlite3.Error) as exc:
            connection.rollback()
            raise ControlLedgerError(
                "CONTROL_LEDGER_UNAVAILABLE",
                "Adapter receipt could not be committed.",
            ) from exc
        finally:
            connection.close()

    def record_attempt_outcome(
        self,
        attempt_id: str,
        *,
        outcome_state: str,
        outcome_sha256: str,
        completed_at: str,
        adapter_receipt_sha256: str | None = None,
    ) -> None:
        attempt_id = _require_identifier("attempt_id", attempt_id)
        outcome_sha256 = _require_sha256("outcome_sha256", outcome_sha256)
        completed_at = _require_offset_timestamp("completed_at", completed_at)
        if adapter_receipt_sha256 is not None:
            adapter_receipt_sha256 = _require_sha256(
                "adapter_receipt_sha256", adapter_receipt_sha256
            )
        if outcome_state not in _TERMINAL_ATTEMPT_STATES:
            raise ControlLedgerError(
                "ATTEMPT_STATE_INVALID", "Attempt outcome state is not terminal."
            )
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            _validate_control_relations(connection)
            row = connection.execute(
                """
                SELECT principal_id, recovery_summary_json, state,
                       outcome_sha256, adapter_receipt_sha256,
                       reserved_at, completed_at
                FROM attempts WHERE attempt_id=?
                """,
                (attempt_id,),
            ).fetchone()
            if row is None:
                raise ControlLedgerError(
                    "ATTEMPT_UNKNOWN", "Attempt reservation does not exist."
                )
            if row["principal_id"] is not None:
                raise ControlLedgerError(
                    "REQUEST_RESULT_ATOMIC_COMMIT_REQUIRED",
                    "Receipt-backed linked attempts must terminalize with the request result atomically.",
                )
            if datetime.fromisoformat(completed_at) < datetime.fromisoformat(
                row["reserved_at"]
            ):
                raise ControlLedgerError(
                    "ATTEMPT_TIME_INVALID",
                    "Attempt completion cannot precede its reservation.",
                )
            if row["state"] not in {"RESERVED", "RECEIPT_RECORDED"}:
                if (
                    row["state"] == outcome_state
                    and row["outcome_sha256"] == outcome_sha256
                    and row["completed_at"] == completed_at
                    and (
                        adapter_receipt_sha256 is None
                        or row["adapter_receipt_sha256"]
                        == adapter_receipt_sha256
                    )
                ):
                    connection.commit()
                    return
                raise ControlLedgerError(
                    "ATTEMPT_OUTCOME_CONFLICT",
                    "Attempt already has a different terminal outcome.",
                )
            connection.execute(
                """
                UPDATE attempts
                SET state=?, outcome_sha256=?,
                    adapter_receipt_sha256=COALESCE(?, adapter_receipt_sha256),
                    completed_at=?
                WHERE attempt_id=? AND state IN ('RESERVED', 'RECEIPT_RECORDED')
                """,
                (
                    outcome_state,
                    outcome_sha256,
                    adapter_receipt_sha256,
                    completed_at,
                    attempt_id,
                ),
            )
            self._insert_outbox(
                connection,
                "ATTEMPT_TERMINAL",
                attempt_id,
                {
                    "state": outcome_state,
                    "outcome_sha256": outcome_sha256,
                    "adapter_receipt_sha256": adapter_receipt_sha256,
                },
            )
            connection.commit()
        except ControlLedgerError:
            connection.rollback()
            raise
        except (OSError, sqlite3.Error) as exc:
            connection.rollback()
            raise ControlLedgerError(
                "CONTROL_LEDGER_UNAVAILABLE",
                "Attempt outcome could not be committed.",
            ) from exc
        finally:
            connection.close()

    def attempt_snapshot(self, attempt_id: str) -> dict[str, Any] | None:
        attempt_id = _require_identifier("attempt_id", attempt_id)
        connection = self._connect()
        try:
            row = connection.execute(
                """
                SELECT a.attempt_id, a.token_id, a.principal_id, a.request_id,
                       a.request_sha256, a.idempotency_key, a.binding_sha256,
                       a.recovery_summary_json, a.recovery_summary_sha256,
                       a.state, a.outcome_sha256, a.adapter_receipt_sha256,
                       a.reserved_at, a.completed_at,
                       z.decision_id AS authorization_decision_id
                FROM attempts a
                JOIN authorizations z ON z.token_id=a.token_id
                WHERE a.attempt_id=?
                """,
                (attempt_id,),
            ).fetchone()
            if row is None:
                return None
            value = dict(row)
            raw_summary = value.pop("recovery_summary_json")
            summary_sha256 = value.pop("recovery_summary_sha256")
            value["recovery_summary"] = None
            if raw_summary is not None:
                if (
                    summary_sha256 is None
                    or hashlib.sha256(raw_summary.encode("utf-8")).hexdigest()
                    != summary_sha256
                ):
                    raise ControlLedgerError(
                        "CONTROL_LEDGER_CORRUPT",
                        "Recovery-summary integrity failed.",
                    )
                summary = _validate_recovery_summary(
                    _load_json_object(
                        raw_summary,
                        error_type=ControlLedgerError,
                        reason_code="CONTROL_LEDGER_CORRUPT",
                    )
                )
                if (
                    summary["principal_id"] != value["principal_id"]
                    or summary["request_id"] != value["request_id"]
                    or summary["request_sha256"] != value["request_sha256"]
                    or summary["decision_id"]
                    != value["authorization_decision_id"]
                ):
                    raise ControlLedgerError(
                        "CONTROL_LEDGER_CORRUPT",
                        "Recovery-summary row binding is invalid.",
                    )
                value["recovery_summary"] = summary
            return value
        except sqlite3.Error as exc:
            raise ControlLedgerError(
                "CONTROL_LEDGER_UNAVAILABLE", "Attempt state read failed."
            ) from exc
        finally:
            connection.close()

    def complete_request(
        self,
        result: RequestLookupResult,
        *,
        attempt_state: str | None = None,
        attempt_outcome_sha256: str | None = None,
        adapter_receipt_sha256: str | None = None,
    ) -> None:
        """Atomically terminalize an attempt, insert result, transition request, and outbox."""

        if type(result) is not RequestLookupResult:
            raise ControlLedgerError(
                "REQUEST_RESULT_INVALID",
                "Terminal result must be an exact RequestLookupResult.",
            )
        stored = replace(
            result,
            replayed=False,
            execution_attempted_this_call=False,
            new_decision=False,
            new_authorization=False,
            new_effect=False,
            authorization=None,
        )
        result_json = canonical_json(stored.to_dict())
        if len(result_json.encode("utf-8")) > 32_768:
            raise ControlLedgerError(
                "REQUEST_RESULT_INVALID",
                "Terminal request result exceeds the durable size bound.",
            )
        result_sha256 = hashlib.sha256(result_json.encode("utf-8")).hexdigest()
        paired_attempt = stored.attempt_id is not None
        if paired_attempt != (attempt_state is not None) or paired_attempt != (
            attempt_outcome_sha256 is not None
        ):
            raise ControlLedgerError(
                "REQUEST_RESULT_BINDING_INVALID",
                "Attempt identifier, terminal state, and outcome digest must be paired.",
            )
        if attempt_state is not None and attempt_state not in _TERMINAL_ATTEMPT_STATES:
            raise ControlLedgerError(
                "ATTEMPT_STATE_INVALID", "Request completion attempt state is invalid."
            )
        if paired_attempt:
            attempt_outcome_sha256 = _require_sha256(
                "attempt_outcome_sha256", attempt_outcome_sha256
            )
            if adapter_receipt_sha256 is not None:
                adapter_receipt_sha256 = _require_sha256(
                    "adapter_receipt_sha256", adapter_receipt_sha256
                )
            if attempt_outcome_sha256 != terminal_attempt_outcome_sha256(
                stored, str(attempt_state)
            ):
                raise ControlLedgerError(
                    "REQUEST_RESULT_BINDING_INVALID",
                    "Attempt outcome digest does not match the terminal result projection.",
                )
        disposition_states = {
            "COMPLETED_VERIFIED": "VERIFIED_EFFECT",
            "FAILED_NO_EFFECT": "FAILED_NO_EFFECT",
            "RECOVERY_REQUIRED": "RECOVERY_REQUIRED",
            "UNKNOWN_EFFECT": "UNKNOWN_EFFECT",
        }
        expected_attempt_state = disposition_states.get(stored.disposition)
        if paired_attempt and expected_attempt_state != attempt_state:
            raise ControlLedgerError(
                "REQUEST_RESULT_BINDING_INVALID",
                "Request disposition does not match its attempt terminal state.",
            )
        if paired_attempt and stored.adapter_receipt_sha256 != adapter_receipt_sha256:
            raise ControlLedgerError(
                "REQUEST_RESULT_BINDING_INVALID",
                "Terminal result receipt digest does not match its attempt input.",
            )
        if (
            paired_attempt
            and attempt_state != "UNKNOWN_EFFECT"
            and adapter_receipt_sha256 is None
        ):
            raise ControlLedgerError(
                "REQUEST_RESULT_BINDING_INVALID",
                "Verified/no-effect/recovery terminal states require a receipt digest.",
            )
        if not paired_attempt and stored.disposition not in {
            "DENIED_NO_EFFECT",
            "ABORTED_NO_EFFECT",
        }:
            raise ControlLedgerError(
                "REQUEST_RESULT_BINDING_INVALID",
                "Executing disposition requires a bound attempt.",
            )
        if stored.disposition == "COMPLETED_VERIFIED" and (
            stored.verification_status != "VERIFIED" or stored.recovery_required
        ):
            raise ControlLedgerError(
                "REQUEST_RESULT_BINDING_INVALID",
                "Verified completion requires a durable VERIFIED summary.",
            )
        if stored.disposition in {"RECOVERY_REQUIRED", "UNKNOWN_EFFECT"} and (
            not stored.recovery_required or stored.verification_status == "VERIFIED"
        ):
            raise ControlLedgerError(
                "REQUEST_RESULT_BINDING_INVALID",
                "Indeterminate completion cannot be VERIFIED and requires recovery.",
            )
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            _validate_control_relations(connection)
            request = connection.execute(
                """
                SELECT request_sha256, state, updated_at FROM requests
                WHERE principal_id=? AND request_id=?
                """,
                (stored.principal_id, stored.request_id),
            ).fetchone()
            if request is None or request["request_sha256"] != stored.request_sha256:
                raise ControlLedgerError(
                    "REQUEST_RESULT_BINDING_INVALID",
                    "Terminal result does not bind to the claimed request.",
                )
            if datetime.fromisoformat(stored.terminal_at) < datetime.fromisoformat(
                request["updated_at"]
            ):
                raise ControlLedgerError(
                    "REQUEST_RESULT_BINDING_INVALID",
                    "Terminal result time cannot precede the request transition.",
                )
            attempt = None
            if paired_attempt:
                attempt = connection.execute(
                    """
                    SELECT a.state, a.outcome_sha256, a.adapter_receipt_sha256,
                           a.recovery_summary_json, a.recovery_summary_sha256,
                           a.reserved_at,
                           z.decision_id AS authorization_decision_id
                    FROM attempts a
                    JOIN authorizations z ON z.token_id=a.token_id
                    WHERE a.attempt_id=? AND a.principal_id=? AND a.request_id=?
                      AND a.request_sha256=?
                    """,
                    (
                        stored.attempt_id,
                        stored.principal_id,
                        stored.request_id,
                        stored.request_sha256,
                    ),
                ).fetchone()
                if attempt is None:
                    raise ControlLedgerError(
                        "ATTEMPT_UNKNOWN", "Request attempt reservation does not exist."
                    )
                if datetime.fromisoformat(stored.terminal_at) < datetime.fromisoformat(
                    attempt["reserved_at"]
                ):
                    raise ControlLedgerError(
                        "REQUEST_RESULT_BINDING_INVALID",
                        "Terminal result time cannot precede attempt reservation.",
                    )
                raw_summary = attempt["recovery_summary_json"]
                if (
                    type(raw_summary) is not str
                    or len(raw_summary.encode("utf-8")) > 16_384
                    or hashlib.sha256(raw_summary.encode("utf-8")).hexdigest()
                    != attempt["recovery_summary_sha256"]
                ):
                    raise ControlLedgerError(
                        "CONTROL_LEDGER_CORRUPT",
                        "Attempt recovery-summary integrity failed.",
                    )
                summary = _validate_recovery_summary(
                    _load_json_object(
                        raw_summary,
                        error_type=ControlLedgerError,
                        reason_code="CONTROL_LEDGER_CORRUPT",
                    )
                )
                if (
                    summary["principal_id"] != stored.principal_id
                    or summary["request_id"] != stored.request_id
                    or summary["request_sha256"] != stored.request_sha256
                    or summary["decision_id"] != attempt["authorization_decision_id"]
                    or summary["decision_id"] != stored.decision_id
                    or summary["decision_outcome"] != stored.decision_outcome
                    or summary["decision_sha256"] != stored.decision_sha256
                    or summary["decision_context_sha256"]
                    != stored.decision_context_sha256
                    or summary["policy_sha256"] != stored.policy_sha256
                    or summary["decided_at"] != stored.decided_at
                ):
                    raise ControlLedgerError(
                        "REQUEST_RESULT_BINDING_INVALID",
                        "Terminal result does not match the immutable recovery summary.",
                    )
            if request["state"] == "TERMINAL":
                existing_terminal = connection.execute(
                    """
                    SELECT result_sha256, result_json FROM request_results
                    WHERE principal_id=? AND request_id=?
                    """,
                    (stored.principal_id, stored.request_id),
                ).fetchone()
                if (
                    existing_terminal is not None
                    and existing_terminal["result_sha256"] == result_sha256
                    and existing_terminal["result_json"] == result_json
                ):
                    if paired_attempt and (
                        attempt["state"] != attempt_state
                        or attempt["outcome_sha256"] != attempt_outcome_sha256
                        or attempt["adapter_receipt_sha256"]
                        != adapter_receipt_sha256
                    ):
                        raise ControlLedgerError(
                            "ATTEMPT_OUTCOME_CONFLICT",
                            "Repeated terminal write changed its attempt binding.",
                        )
                    connection.commit()
                    return
                raise ControlLedgerError(
                    "REQUEST_RESULT_CONFLICT",
                    "Terminal request already has a different result.",
                )
            if paired_attempt and request["state"] != "ATTEMPT_RESERVED":
                raise ControlLedgerError(
                    "REQUEST_RESULT_BINDING_INVALID",
                    "Attempted request is not in ATTEMPT_RESERVED state.",
                )
            if not paired_attempt and request["state"] not in {
                "CLAIMED",
                "AUTHORIZED",
            }:
                raise ControlLedgerError(
                    "REQUEST_RESULT_BINDING_INVALID",
                    "Nonexecuting request is not in a closable state.",
                )
            if not paired_attempt:
                authorization_row = connection.execute(
                    """
                    SELECT state, revoked_at FROM authorizations
                    WHERE principal_id=? AND request_id=?
                    LIMIT 1
                    """,
                    (stored.principal_id, stored.request_id),
                ).fetchone()
                if stored.disposition == "DENIED_NO_EFFECT" and authorization_row is not None:
                    raise ControlLedgerError(
                        "REQUEST_RESULT_BINDING_INVALID",
                        "A denied request cannot retain an authorization row.",
                    )
                if stored.disposition == "ABORTED_NO_EFFECT" and (
                    authorization_row is not None
                    and (
                        authorization_row["state"] != "REVOKED"
                        or datetime.fromisoformat(stored.terminal_at)
                        < datetime.fromisoformat(authorization_row["revoked_at"])
                    )
                ):
                    raise ControlLedgerError(
                        "REQUEST_RESULT_BINDING_INVALID",
                        "No-effect recovery must follow durable authorization revocation.",
                    )
            existing = connection.execute(
                """
                SELECT result_sha256, result_json FROM request_results
                WHERE principal_id=? AND request_id=?
                """,
                (stored.principal_id, stored.request_id),
            ).fetchone()
            if existing is not None:
                raise ControlLedgerError(
                    "CONTROL_LEDGER_CORRUPT",
                    "Nonterminal request already has a terminal result row.",
                )
            if stored.attempt_id is not None and attempt_state is not None:
                assert attempt is not None
                allowed_origins = (
                    {"RESERVED", "RECEIPT_RECORDED"}
                    if attempt_state == "UNKNOWN_EFFECT"
                    else {"RECEIPT_RECORDED"}
                )
                if attempt["state"] in allowed_origins:
                    if (
                        attempt["state"] == "RESERVED"
                        and adapter_receipt_sha256 is not None
                    ):
                        raise ControlLedgerError(
                            "REQUEST_RESULT_BINDING_INVALID",
                            "A RESERVED attempt cannot claim an unrecorded receipt.",
                        )
                    if (
                        attempt["state"] == "RECEIPT_RECORDED"
                        and (
                            adapter_receipt_sha256 is None
                            or attempt["adapter_receipt_sha256"]
                            != adapter_receipt_sha256
                        )
                    ):
                        raise ControlLedgerError(
                            "REQUEST_RESULT_BINDING_INVALID",
                            "Terminal result receipt does not match the recorded receipt.",
                        )
                    connection.execute(
                        """
                        UPDATE attempts
                        SET state=?, outcome_sha256=?,
                            adapter_receipt_sha256=COALESCE(?, adapter_receipt_sha256),
                            completed_at=?
                        WHERE attempt_id=?
                          AND state IN ('RESERVED', 'RECEIPT_RECORDED')
                        """,
                        (
                            attempt_state,
                            attempt_outcome_sha256,
                            adapter_receipt_sha256,
                            stored.terminal_at,
                            stored.attempt_id,
                        ),
                    )
                    self._insert_outbox(
                        connection,
                        "ATTEMPT_TERMINAL",
                        stored.attempt_id,
                        {
                            "state": attempt_state,
                            "outcome_sha256": attempt_outcome_sha256,
                            "adapter_receipt_sha256": adapter_receipt_sha256,
                        },
                    )
                elif attempt["state"] in {"RESERVED", "RECEIPT_RECORDED"}:
                    raise ControlLedgerError(
                        "REQUEST_RESULT_BINDING_INVALID",
                        "Attempt cannot make the requested terminal transition.",
                    )
                elif (
                    attempt["state"] != attempt_state
                    or attempt["outcome_sha256"] != attempt_outcome_sha256
                    or (
                        adapter_receipt_sha256 is not None
                        and attempt["adapter_receipt_sha256"]
                        != adapter_receipt_sha256
                    )
                ):
                    raise ControlLedgerError(
                        "ATTEMPT_OUTCOME_CONFLICT",
                        "Request completion conflicts with the attempt outcome.",
                    )
            connection.execute(
                """
                INSERT INTO request_results(
                    principal_id, request_id, result_json,
                    result_sha256, terminal_at
                ) VALUES(?, ?, ?, ?, ?)
                """,
                (
                    stored.principal_id,
                    stored.request_id,
                    result_json,
                    result_sha256,
                    stored.terminal_at,
                ),
            )
            updated = connection.execute(
                """
                UPDATE requests SET state='TERMINAL', updated_at=?
                WHERE principal_id=? AND request_id=? AND state!='TERMINAL'
                """,
                (stored.terminal_at, stored.principal_id, stored.request_id),
            )
            if updated.rowcount != 1:
                raise ControlLedgerError(
                    "REQUEST_RESULT_CONFLICT",
                    "Request terminal transition lost its race.",
                )
            self._insert_outbox(
                connection,
                "REQUEST_TERMINAL",
                f"{stored.principal_id}:{stored.request_id}",
                {
                    "result_sha256": result_sha256,
                    "disposition": stored.disposition,
                },
            )
            connection.commit()
        except ControlLedgerError:
            connection.rollback()
            raise
        except sqlite3.IntegrityError as exc:
            connection.rollback()
            raise ControlLedgerError(
                "REQUEST_RESULT_CONFLICT", "Request terminal result conflicted."
            ) from exc
        except (OSError, sqlite3.Error) as exc:
            connection.rollback()
            raise ControlLedgerError(
                "CONTROL_LEDGER_UNAVAILABLE",
                "Request terminal result could not be committed.",
            ) from exc
        finally:
            connection.close()

    def lookup_request_result(
        self, principal_id: str, request_id: str, request_sha256: str
    ) -> RequestLookupResult | None:
        principal_id = _require_identifier("principal_id", principal_id)
        request_id = _require_identifier("request_id", request_id)
        request_sha256 = _require_sha256("request_sha256", request_sha256)
        connection = self._connect()
        try:
            request = connection.execute(
                """
                SELECT request_sha256, state FROM requests
                WHERE principal_id=? AND request_id=?
                """,
                (principal_id, request_id),
            ).fetchone()
            if request is None:
                return None
            if request["request_sha256"] != request_sha256:
                raise ControlLedgerError(
                    "REQUEST_ID_CONFLICT",
                    "Request identifier is bound to different content.",
                )
            if request["state"] != "TERMINAL":
                return None
            row = connection.execute(
                """
                SELECT result_json, result_sha256, terminal_at FROM request_results
                WHERE principal_id=? AND request_id=?
                """,
                (principal_id, request_id),
            ).fetchone()
            if (
                row is None
                or len(row["result_json"].encode("utf-8")) > 32_768
                or hashlib.sha256(row["result_json"].encode("utf-8")).hexdigest()
                != row["result_sha256"]
            ):
                raise ControlLedgerError(
                    "CONTROL_LEDGER_CORRUPT",
                    "Terminal request result is absent or has invalid integrity.",
                )
            result = RequestLookupResult.from_dict(
                _load_json_object(
                    row["result_json"],
                    error_type=ControlLedgerError,
                    reason_code="CONTROL_LEDGER_CORRUPT",
                )
            )
            if (
                result.principal_id,
                result.request_id,
                result.request_sha256,
            ) != (principal_id, request_id, request_sha256):
                raise ControlLedgerError(
                    "CONTROL_LEDGER_CORRUPT",
                    "Terminal request-result binding is invalid.",
                )
            if row["terminal_at"] != result.terminal_at:
                raise ControlLedgerError(
                    "CONTROL_LEDGER_CORRUPT",
                    "Terminal request-result timestamp binding is invalid.",
                )
            attempt = connection.execute(
                """
                SELECT a.attempt_id, a.state, a.outcome_sha256,
                       a.adapter_receipt_sha256, a.completed_at,
                       a.recovery_summary_json, a.recovery_summary_sha256,
                       z.decision_id AS authorization_decision_id
                FROM attempts a
                JOIN authorizations z ON z.token_id=a.token_id
                WHERE a.principal_id=? AND a.request_id=?
                """,
                (principal_id, request_id),
            ).fetchone()
            disposition_states = {
                "COMPLETED_VERIFIED": "VERIFIED_EFFECT",
                "FAILED_NO_EFFECT": "FAILED_NO_EFFECT",
                "RECOVERY_REQUIRED": "RECOVERY_REQUIRED",
                "UNKNOWN_EFFECT": "UNKNOWN_EFFECT",
            }
            expected_state = disposition_states.get(result.disposition)
            if result.attempt_id is None:
                if attempt is not None or result.disposition not in {
                    "DENIED_NO_EFFECT",
                    "ABORTED_NO_EFFECT",
                }:
                    raise ControlLedgerError(
                        "CONTROL_LEDGER_CORRUPT",
                        "Terminal no-effect result has inconsistent attempt state.",
                    )
            elif (
                attempt is None
                or attempt["attempt_id"] != result.attempt_id
                or attempt["state"] != expected_state
                or attempt["adapter_receipt_sha256"]
                != result.adapter_receipt_sha256
            ):
                raise ControlLedgerError(
                    "CONTROL_LEDGER_CORRUPT",
                    "Terminal result and attempt state are inconsistent.",
                )
            if attempt is not None:
                if (
                    attempt["completed_at"] != result.terminal_at
                    or attempt["outcome_sha256"]
                    != terminal_attempt_outcome_sha256(result, str(expected_state))
                ):
                    raise ControlLedgerError(
                        "CONTROL_LEDGER_CORRUPT",
                        "Terminal result and attempt outcome binding are inconsistent.",
                    )
                raw_summary = attempt["recovery_summary_json"]
                if (
                    type(raw_summary) is not str
                    or len(raw_summary.encode("utf-8")) > 16_384
                    or hashlib.sha256(raw_summary.encode("utf-8")).hexdigest()
                    != attempt["recovery_summary_sha256"]
                ):
                    raise ControlLedgerError(
                        "CONTROL_LEDGER_CORRUPT",
                        "Terminal attempt recovery-summary integrity failed.",
                    )
                summary = _validate_recovery_summary(
                    _load_json_object(
                        raw_summary,
                        error_type=ControlLedgerError,
                        reason_code="CONTROL_LEDGER_CORRUPT",
                    )
                )
                if (
                    summary["principal_id"] != principal_id
                    or summary["request_id"] != request_id
                    or summary["request_sha256"] != request_sha256
                    or summary["decision_id"] != attempt["authorization_decision_id"]
                    or summary["decision_id"] != result.decision_id
                    or summary["decision_outcome"] != result.decision_outcome
                    or summary["decision_sha256"] != result.decision_sha256
                    or summary["decision_context_sha256"]
                    != result.decision_context_sha256
                    or summary["policy_sha256"] != result.policy_sha256
                    or summary["decided_at"] != result.decided_at
                ):
                    raise ControlLedgerError(
                        "CONTROL_LEDGER_CORRUPT",
                        "Terminal result provenance does not match its recovery summary.",
                    )
            if result.disposition == "COMPLETED_VERIFIED" and (
                result.verification_status != "VERIFIED"
                or result.recovery_required
            ):
                raise ControlLedgerError(
                    "CONTROL_LEDGER_CORRUPT",
                    "Verified terminal-result semantics are inconsistent.",
                )
            if result.disposition in {"RECOVERY_REQUIRED", "UNKNOWN_EFFECT"} and (
                not result.recovery_required
                or result.verification_status == "VERIFIED"
            ):
                raise ControlLedgerError(
                    "CONTROL_LEDGER_CORRUPT",
                    "Recovery terminal-result semantics are inconsistent.",
                )
            return result.as_replay()
        except ControlLedgerError:
            raise
        except sqlite3.Error as exc:
            raise ControlLedgerError(
                "CONTROL_LEDGER_UNAVAILABLE", "Terminal result lookup failed."
            ) from exc
        finally:
            connection.close()

    def revoke_issued_for_request(
        self,
        principal_id: str,
        request_id: str,
        request_sha256: str,
        *,
        operator_asserted_quiesced: bool,
        revoked_at: str | None = None,
    ) -> int:
        _assert_quiesced(operator_asserted_quiesced)
        principal_id = _require_identifier("principal_id", principal_id)
        request_id = _require_identifier("request_id", request_id)
        request_sha256 = _require_sha256("request_sha256", request_sha256)
        revoked_at = _require_offset_timestamp(
            "revoked_at", revoked_at or utc_now_iso()
        )
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            _validate_control_relations(connection)
            rows = connection.execute(
                """
                SELECT token_id, issued_at FROM authorizations
                WHERE principal_id=? AND request_id=? AND request_sha256=?
                  AND state='ISSUED'
                """,
                (principal_id, request_id, request_sha256),
            ).fetchall()
            for row in rows:
                if datetime.fromisoformat(revoked_at) < datetime.fromisoformat(
                    row["issued_at"]
                ):
                    raise ControlLedgerError(
                        "AUTHORIZATION_TIME_INVALID",
                        "Authorization revocation cannot precede its durable issuance.",
                    )
                connection.execute(
                    """
                    UPDATE authorizations
                    SET state='REVOKED', revoked_at=?,
                        revocation_reason='QUIESCED_RECOVERY'
                    WHERE token_id=? AND state='ISSUED'
                    """,
                    (revoked_at, row["token_id"]),
                )
                self._insert_outbox(
                    connection,
                    "AUTHORIZATION_REVOKED",
                    row["token_id"],
                    {"reason_code": "QUIESCED_RECOVERY"},
                )
            connection.commit()
            return len(rows)
        except (OSError, sqlite3.Error) as exc:
            connection.rollback()
            raise ControlLedgerError(
                "CONTROL_LEDGER_UNAVAILABLE",
                "Authorization revocation could not be committed.",
            ) from exc
        finally:
            connection.close()

    def recover_incomplete_attempts(
        self, *, operator_asserted_quiesced: bool
    ) -> int:
        _assert_quiesced(operator_asserted_quiesced)
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            _validate_control_relations(connection)
            recovery_at = utc_now_iso()
            linked = connection.execute(
                """
                SELECT 1 FROM attempts
                WHERE principal_id IS NOT NULL
                  AND state IN ('RESERVED', 'RECEIPT_RECORDED')
                LIMIT 1
                """
            ).fetchone()
            if linked is not None:
                raise ControlLedgerError(
                    "RECOVERY_EXACT_REQUEST_REQUIRED",
                    "Linked attempts require receipt-informed exact-request recovery.",
                )
            rows = connection.execute(
                """
                SELECT attempt_id, reserved_at FROM attempts
                WHERE principal_id IS NULL
                  AND state IN ('RESERVED', 'RECEIPT_RECORDED')
                ORDER BY attempt_id
                """
            ).fetchall()
            for row in rows:
                attempt_id = str(row[0])
                if datetime.fromisoformat(recovery_at) < datetime.fromisoformat(
                    row["reserved_at"]
                ):
                    raise ControlLedgerError(
                        "RECOVERY_TIME_INVALID",
                        "Recovery completion cannot precede attempt reservation.",
                    )
                outcome_sha256 = hashlib.sha256(
                    canonical_json(
                        {"attempt_id": attempt_id, "state": "UNKNOWN_EFFECT"}
                    ).encode("utf-8")
                ).hexdigest()
                connection.execute(
                    """
                    UPDATE attempts
                    SET state='UNKNOWN_EFFECT', outcome_sha256=?, completed_at=?
                    WHERE attempt_id=?
                      AND state IN ('RESERVED', 'RECEIPT_RECORDED')
                    """,
                    (outcome_sha256, recovery_at, attempt_id),
                )
                self._insert_outbox(
                    connection,
                    "ATTEMPT_RECOVERED_UNKNOWN",
                    attempt_id,
                    {"state": "UNKNOWN_EFFECT"},
                )
            issued = connection.execute(
                """
                SELECT token_id, issued_at FROM authorizations
                WHERE principal_id IS NULL AND state='ISSUED'
                """
            ).fetchall()
            revoked_at = recovery_at
            for row in issued:
                if datetime.fromisoformat(revoked_at) < datetime.fromisoformat(
                    row["issued_at"]
                ):
                    raise ControlLedgerError(
                        "RECOVERY_TIME_INVALID",
                        "Recovery revocation cannot precede authorization issuance.",
                    )
                connection.execute(
                    """
                    UPDATE authorizations
                    SET state='REVOKED', revoked_at=?,
                        revocation_reason='QUIESCED_RECOVERY'
                    WHERE token_id=? AND state='ISSUED'
                    """,
                    (revoked_at, row["token_id"]),
                )
                self._insert_outbox(
                    connection,
                    "AUTHORIZATION_REVOKED",
                    row["token_id"],
                    {"reason_code": "QUIESCED_RECOVERY"},
                )
            connection.commit()
            return len(rows)
        except ControlLedgerError:
            connection.rollback()
            raise
        except (OSError, sqlite3.Error) as exc:
            connection.rollback()
            raise ControlLedgerError(
                "CONTROL_LEDGER_UNAVAILABLE",
                "Incomplete-attempt recovery could not be committed.",
            ) from exc
        finally:
            connection.close()

    def pending_outbox(self) -> tuple[dict[str, Any], ...]:
        connection = self._connect()
        try:
            rows = connection.execute(
                """
                SELECT event_id, event_type, subject_id, payload_sha256,
                       created_at, exported_at
                FROM audit_outbox
                WHERE exported_at IS NULL
                ORDER BY event_id
                """
            ).fetchall()
            return tuple(dict(row) for row in rows)
        except sqlite3.Error as exc:
            raise ControlLedgerError(
                "CONTROL_LEDGER_UNAVAILABLE", "Audit outbox read failed."
            ) from exc
        finally:
            connection.close()
