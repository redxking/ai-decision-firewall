"""Single-host, synthetic-only Stage A authority-state controls.

This additive module does not add a live connector, operational credential,
distributed replay guarantee, deployment boundary, or production authority.
"""

from __future__ import annotations

import hashlib
import os
import sqlite3
import stat
import uuid
from pathlib import Path
from threading import RLock
from typing import Any

from adf_poc.utils import canonical_json, utc_now_iso


SCHEMA_VERSION = "1"
_AUTHORIZATION_STATES = frozenset({"ISSUED", "CONSUMED"})
_ATTEMPT_STATES = frozenset(
    {"RESERVED", "COMPLETED", "FAILED_NO_EFFECT", "UNKNOWN_EFFECT"}
)
_TERMINAL_ATTEMPT_STATES = _ATTEMPT_STATES - {"RESERVED"}
_REQUIRED_TABLES = frozenset(
    {"metadata", "requests", "authorizations", "attempts", "audit_outbox"}
)


class ControlLedgerError(RuntimeError):
    def __init__(self, reason_code: str, message: str) -> None:
        super().__init__(message)
        self.reason_code = reason_code


def _require_identifier(name: str, value: object) -> str:
    if type(value) is not str or not value or len(value) > 512:
        raise ControlLedgerError(
            "CONTROL_LEDGER_BINDING_INVALID",
            f"{name} must be a non-empty bounded exact string.",
        )
    return value


def _require_sha256(name: str, value: object) -> str:
    candidate = _require_identifier(name, value)
    if len(candidate) != 64 or any(character not in "0123456789abcdef" for character in candidate):
        raise ControlLedgerError(
            "CONTROL_LEDGER_BINDING_INVALID",
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
        self, principal_id: str, request_id: str, request_sha256: str
    ) -> str:
        principal_id = _require_identifier("principal_id", principal_id)
        request_id = _require_identifier("request_id", request_id)
        request_sha256 = _require_sha256("request_sha256", request_sha256)
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
    ) -> None:
        token_id = _require_identifier("token_id", token_id)
        verification_id = _require_identifier(
            "verification_id", verification_id or f"legacy:{token_id}"
        )
        decision_id = _require_identifier(
            "decision_id", decision_id or f"legacy:{token_id}"
        )
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
    ) -> None:
        token_id = _require_identifier("token_id", token_id)
        if (attempt_id is None) != (attempt_binding_sha256 is None):
            raise ControlLedgerError(
                "CONTROL_LEDGER_BINDING_INVALID",
                "Attempt identifier and binding digest must be supplied together.",
            )
        if attempt_id is not None:
            attempt_id = _require_identifier("attempt_id", attempt_id)
            attempt_binding_sha256 = _require_sha256(
                "attempt_binding_sha256", attempt_binding_sha256
            )
            consumed_at = _require_identifier("consumed_at", consumed_at)
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
            if row["state"] != "RESERVED":
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

    def recover_incomplete_attempts(self) -> int:
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
        return recovered

    def pending_outbox(self) -> tuple[dict[str, Any], ...]:
        with self._lock:
            return tuple(dict(row) for row in self._outbox if row["exported_at"] is None)


class SQLiteControlLedger:
    """Single-host Stage A transaction ledger.

    SQLite provides development-grade durability and interprocess exclusion for
    this offline increment.  It is not a distributed consensus, HA, WORM, or
    external-custody mechanism.
    """

    def __init__(self, path: str | Path, *, busy_timeout_ms: int = 1000) -> None:
        if type(busy_timeout_ms) is not int or not 25 <= busy_timeout_ms <= 30_000:
            raise ValueError("Control-ledger busy timeout must be within 25..30000 ms.")
        self.path = Path(path).absolute()
        self.busy_timeout_ms = busy_timeout_ms
        self._initialize()
        ledger_id = self._metadata("ledger_id")
        self.issuer_instance_id = f"stage-a-ledger-{ledger_id}"

    def _assert_safe_parent_chain(self, *, allow_missing: bool) -> None:
        for ancestor in reversed(self.path.parents):
            try:
                metadata = ancestor.lstat()
            except FileNotFoundError:
                if allow_missing:
                    continue
                raise ControlLedgerError(
                    "CONTROL_LEDGER_PATH_UNSAFE",
                    "Control-ledger parent directory is unavailable.",
                ) from None
            if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
                raise ControlLedgerError(
                    "CONTROL_LEDGER_PATH_UNSAFE",
                    "Control-ledger parent chain cannot contain symbolic links or non-directories.",
                )

    def _assert_safe_path(self, *, allow_missing: bool) -> None:
        self._assert_safe_parent_chain(allow_missing=allow_missing)
        if self.path.exists() or self.path.is_symlink():
            metadata = self.path.lstat()
            if (
                self.path.is_symlink()
                or not stat.S_ISREG(metadata.st_mode)
                or metadata.st_nlink != 1
            ):
                raise ControlLedgerError(
                    "CONTROL_LEDGER_PATH_UNSAFE",
                    "Control-ledger path must be a singly linked regular file.",
                )
        elif not allow_missing:
            raise ControlLedgerError(
                "CONTROL_LEDGER_UNAVAILABLE", "Control-ledger file is unavailable."
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
            if connection.execute("PRAGMA integrity_check").fetchone()[0] != "ok":
                raise ControlLedgerError(
                    "CONTROL_LEDGER_CORRUPT", "Control-ledger integrity check failed."
                )
            version = connection.execute(
                "SELECT value FROM metadata WHERE key='schema_version'"
            ).fetchone()
            if version is None or version[0] != SCHEMA_VERSION:
                raise ControlLedgerError(
                    "CONTROL_LEDGER_SCHEMA_UNSUPPORTED",
                    "Control-ledger schema version is unsupported.",
                )
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
            existing_nonempty = self.path.exists() and self.path.stat().st_size > 0
            connection = sqlite3.connect(
                self.path,
                timeout=self.busy_timeout_ms / 1000.0,
                isolation_level=None,
            )
            connection.execute(f"PRAGMA busy_timeout={self.busy_timeout_ms}")
            if existing_nonempty:
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
                existing_version = connection.execute(
                    "SELECT value FROM metadata WHERE key='schema_version'"
                ).fetchone()
                if existing_version is None or existing_version[0] != SCHEMA_VERSION:
                    raise ControlLedgerError(
                        "CONTROL_LEDGER_SCHEMA_UNSUPPORTED",
                        "Control-ledger schema version is unsupported.",
                    )
            journal_mode = connection.execute("PRAGMA journal_mode=WAL").fetchone()[0]
            if str(journal_mode).lower() != "wal":
                raise ControlLedgerError(
                    "CONTROL_LEDGER_DURABILITY_UNAVAILABLE",
                    "Control ledger requires SQLite WAL mode.",
                )
            connection.execute("PRAGMA synchronous=FULL")
            connection.execute("PRAGMA foreign_keys=ON")
            connection.executescript(
                """
                BEGIN IMMEDIATE;
                CREATE TABLE IF NOT EXISTS metadata (
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL
                ) STRICT;
                CREATE TABLE IF NOT EXISTS requests (
                    principal_id TEXT NOT NULL,
                    request_id TEXT NOT NULL,
                    request_sha256 TEXT NOT NULL CHECK(length(request_sha256) = 64),
                    claimed_at TEXT NOT NULL,
                    PRIMARY KEY (principal_id, request_id)
                ) STRICT;
                CREATE TABLE IF NOT EXISTS authorizations (
                    token_id TEXT PRIMARY KEY,
                    verification_id TEXT NOT NULL UNIQUE,
                    decision_id TEXT NOT NULL UNIQUE,
                    state TEXT NOT NULL CHECK(state IN ('ISSUED', 'CONSUMED')),
                    issued_at TEXT NOT NULL,
                    consumed_at TEXT
                ) STRICT;
                CREATE TABLE IF NOT EXISTS attempts (
                    attempt_id TEXT PRIMARY KEY,
                    token_id TEXT NOT NULL UNIQUE REFERENCES authorizations(token_id),
                    binding_sha256 TEXT NOT NULL UNIQUE CHECK(length(binding_sha256) = 64),
                    state TEXT NOT NULL CHECK(state IN (
                        'RESERVED', 'COMPLETED', 'FAILED_NO_EFFECT', 'UNKNOWN_EFFECT'
                    )),
                    outcome_sha256 TEXT CHECK(
                        outcome_sha256 IS NULL OR length(outcome_sha256) = 64
                    ),
                    reserved_at TEXT NOT NULL,
                    completed_at TEXT
                ) STRICT;
                CREATE TABLE IF NOT EXISTS audit_outbox (
                    event_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    event_type TEXT NOT NULL,
                    subject_id TEXT NOT NULL,
                    payload_sha256 TEXT NOT NULL CHECK(length(payload_sha256) = 64),
                    created_at TEXT NOT NULL,
                    exported_at TEXT,
                    UNIQUE(event_type, subject_id, payload_sha256)
                ) STRICT;
                COMMIT;
                """
            )
            existing_version = connection.execute(
                "SELECT value FROM metadata WHERE key='schema_version'"
            ).fetchone()
            if existing_version is None:
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
                    (utc_now_iso(),),
                )
                connection.commit()
            elif existing_version[0] != SCHEMA_VERSION:
                raise ControlLedgerError(
                    "CONTROL_LEDGER_SCHEMA_UNSUPPORTED",
                    "Control-ledger schema version is unsupported.",
                )
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
        self, principal_id: str, request_id: str, request_sha256: str
    ) -> str:
        principal_id = _require_identifier("principal_id", principal_id)
        request_id = _require_identifier("request_id", request_id)
        request_sha256 = _require_sha256("request_sha256", request_sha256)
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
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
                    principal_id, request_id, request_sha256, claimed_at
                ) VALUES(?, ?, ?, ?)
                """,
                (principal_id, request_id, request_sha256, utc_now_iso()),
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

    def register(
        self,
        token_id: str,
        *,
        verification_id: str | None = None,
        decision_id: str | None = None,
    ) -> None:
        token_id = _require_identifier("token_id", token_id)
        verification_id = _require_identifier(
            "verification_id", verification_id or f"legacy:{token_id}"
        )
        decision_id = _require_identifier(
            "decision_id", decision_id or f"legacy:{token_id}"
        )
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            connection.execute(
                """
                INSERT INTO authorizations(
                    token_id, verification_id, decision_id, state, issued_at
                ) VALUES(?, ?, ?, 'ISSUED', ?)
                """,
                (token_id, verification_id, decision_id, utc_now_iso()),
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
                },
            )
            connection.commit()
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
    ) -> None:
        token_id = _require_identifier("token_id", token_id)
        if (attempt_id is None) != (attempt_binding_sha256 is None):
            raise ControlLedgerError(
                "CONTROL_LEDGER_BINDING_INVALID",
                "Attempt identifier and binding digest must be supplied together.",
            )
        if attempt_id is not None:
            attempt_id = _require_identifier("attempt_id", attempt_id)
            attempt_binding_sha256 = _require_sha256(
                "attempt_binding_sha256", attempt_binding_sha256
            )
            consumed_at = _require_identifier("consumed_at", consumed_at)
        consumed_at = consumed_at or utc_now_iso()
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                "SELECT state FROM authorizations WHERE token_id=?", (token_id,)
            ).fetchone()
            if row is None:
                raise ControlLedgerError(
                    "AUTHORIZATION_UNKNOWN",
                    "Authorization was not issued by this control ledger.",
                )
            if row[0] != "ISSUED":
                raise ControlLedgerError(
                    "AUTHORIZATION_REPLAY", "Authorization was already consumed."
                )
            if attempt_id is not None:
                connection.execute(
                    """
                    INSERT INTO attempts(
                        attempt_id, token_id, binding_sha256, state, reserved_at
                    ) VALUES(?, ?, ?, 'RESERVED', ?)
                    """,
                    (attempt_id, token_id, attempt_binding_sha256, consumed_at),
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
                "Attempt or token already has a reservation.",
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
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                """
                SELECT state, outcome_sha256 FROM attempts WHERE attempt_id=?
                """,
                (attempt_id,),
            ).fetchone()
            if row is None:
                raise ControlLedgerError(
                    "ATTEMPT_UNKNOWN", "Attempt reservation does not exist."
                )
            if row[0] != "RESERVED":
                if row[0] == outcome_state and row[1] == outcome_sha256:
                    connection.commit()
                    return
                raise ControlLedgerError(
                    "ATTEMPT_OUTCOME_CONFLICT",
                    "Attempt already has a different terminal outcome.",
                )
            connection.execute(
                """
                UPDATE attempts
                SET state=?, outcome_sha256=?, completed_at=?
                WHERE attempt_id=? AND state='RESERVED'
                """,
                (outcome_state, outcome_sha256, completed_at, attempt_id),
            )
            self._insert_outbox(
                connection,
                "ATTEMPT_TERMINAL",
                attempt_id,
                {"state": outcome_state, "outcome_sha256": outcome_sha256},
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

    def attempt_snapshot(self, attempt_id: str) -> dict[str, str | None] | None:
        attempt_id = _require_identifier("attempt_id", attempt_id)
        connection = self._connect()
        try:
            row = connection.execute(
                """
                SELECT attempt_id, token_id, binding_sha256, state,
                       outcome_sha256, reserved_at, completed_at
                FROM attempts WHERE attempt_id=?
                """,
                (attempt_id,),
            ).fetchone()
            return dict(row) if row is not None else None
        except sqlite3.Error as exc:
            raise ControlLedgerError(
                "CONTROL_LEDGER_UNAVAILABLE", "Attempt state read failed."
            ) from exc
        finally:
            connection.close()

    def recover_incomplete_attempts(self) -> int:
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            rows = connection.execute(
                "SELECT attempt_id FROM attempts WHERE state='RESERVED' ORDER BY attempt_id"
            ).fetchall()
            for row in rows:
                attempt_id = str(row[0])
                outcome_sha256 = hashlib.sha256(
                    canonical_json(
                        {"attempt_id": attempt_id, "state": "UNKNOWN_EFFECT"}
                    ).encode("utf-8")
                ).hexdigest()
                connection.execute(
                    """
                    UPDATE attempts
                    SET state='UNKNOWN_EFFECT', outcome_sha256=?, completed_at=?
                    WHERE attempt_id=? AND state='RESERVED'
                    """,
                    (outcome_sha256, utc_now_iso(), attempt_id),
                )
                self._insert_outbox(
                    connection,
                    "ATTEMPT_RECOVERED_UNKNOWN",
                    attempt_id,
                    {"state": "UNKNOWN_EFFECT"},
                )
            connection.commit()
            return len(rows)
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
