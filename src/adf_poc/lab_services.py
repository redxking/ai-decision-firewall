from __future__ import annotations

import hashlib
import json
import os
import re
import stat
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable

from adf_poc.lab_contracts import (
    COMMAND,
    OBSERVATION,
    OBSERVATION_REQUEST,
    RECEIPT,
    LabContractError,
    lab_message_sha256,
    load_authenticated_lab_message,
    observation_facts_sha256,
    sign_lab_message,
    validate_lab_message_dict,
)
from adf_poc.utils import StrictJSONError, canonical_json, strict_json_loads

try:
    import fcntl
except ImportError:  # pragma: no cover - Unix-only lab service
    fcntl = None  # type: ignore[assignment]


MAX_JOURNAL_BYTES = 4 * 1024 * 1024
MAX_LOCK_SECONDS = 5.0
ZERO_DIGEST = "0" * 64
JOURNAL_DOMAIN = b"ADF-LAB-EXECUTOR-JOURNAL\x00v1\x00"
IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
JOURNAL_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,95}\.jsonl$")
EXECUTOR_AFTER_RESERVATION = "AFTER_RESERVATION"
EXECUTOR_AFTER_COMPLETION = "AFTER_COMPLETION"


class LabServiceError(RuntimeError):
    """Fail-closed executor/observer service error with a stable reason code."""

    def __init__(self, reason_code: str, message: str) -> None:
        self.reason_code = reason_code
        self.code = reason_code
        self.message = message
        super().__init__(f"{reason_code}: {message}")


@dataclass(frozen=True)
class LabObservedState:
    """Closed target facts returned by a code-owned read-only observer."""

    target_boot_id: str
    beacon_reachable: bool
    management_reachable: bool
    ruleset_sha256: str


def _utc_seconds(clock: Callable[[], datetime]) -> tuple[datetime, str]:
    value = clock()
    if (
        not isinstance(value, datetime)
        or value.tzinfo is None
        or value.utcoffset() is None
    ):
        raise LabServiceError(
            "LAB_SERVICE_CLOCK_INVALID", "Service clock must return an aware datetime."
        )
    normalized = value.astimezone(timezone.utc).replace(microsecond=0)
    return normalized, normalized.isoformat()


def _validate_key(value: bytes, *, label: str) -> bytes:
    if type(value) is not bytes or len(value) < 32:
        raise LabServiceError(
            "LAB_SERVICE_CONFIGURATION_INVALID",
            f"{label} must be an exact bytes value of at least 32 bytes.",
        )
    return value


def _validate_identifier(value: str, *, label: str) -> str:
    if type(value) is not str or IDENTIFIER.fullmatch(value) is None:
        raise LabServiceError(
            "LAB_SERVICE_CONFIGURATION_INVALID", f"{label} is invalid."
        )
    return value


def _validate_observed_state(value: LabObservedState) -> LabObservedState:
    if type(value) is not LabObservedState:
        raise LabServiceError(
            "LAB_OBSERVATION_STATE_INVALID",
            "Observer returned an unexpected state representation.",
        )
    if (
        type(value.target_boot_id) is not str
        or not value.target_boot_id
        or len(value.target_boot_id) > 128
        or type(value.beacon_reachable) is not bool
        or type(value.management_reachable) is not bool
        or type(value.ruleset_sha256) is not str
        or len(value.ruleset_sha256) != 64
        or any(
            character not in "0123456789abcdef" for character in value.ruleset_sha256
        )
    ):
        raise LabServiceError(
            "LAB_OBSERVATION_STATE_INVALID", "Observer returned malformed target facts."
        )
    return value


def _safe_parent(path: Path) -> os.stat_result:
    if not path.is_absolute() or JOURNAL_NAME.fullmatch(path.name) is None:
        raise LabServiceError(
            "LAB_JOURNAL_PATH_UNSAFE", "Journal path must be absolute."
        )
    try:
        metadata = path.parent.lstat()
    except OSError as exc:
        raise LabServiceError(
            "LAB_JOURNAL_PATH_UNSAFE", "Journal parent is unavailable."
        ) from exc
    if (
        path.parent.is_symlink()
        or not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != os.geteuid()
        or stat.S_IMODE(metadata.st_mode) != 0o700
    ):
        raise LabServiceError(
            "LAB_JOURNAL_PATH_UNSAFE",
            "Journal parent must be an owner-private non-symlink directory.",
        )
    return metadata


def _safe_file_stat(path: Path) -> os.stat_result:
    try:
        metadata = path.lstat()
    except OSError as exc:
        raise LabServiceError(
            "LAB_JOURNAL_PATH_UNSAFE", "Executor journal is unavailable."
        ) from exc
    if (
        path.is_symlink()
        or not stat.S_ISREG(metadata.st_mode)
        or metadata.st_nlink != 1
        or metadata.st_uid != os.geteuid()
        or stat.S_IMODE(metadata.st_mode) != 0o600
    ):
        raise LabServiceError(
            "LAB_JOURNAL_PATH_UNSAFE",
            "Executor journal must be an owner-private singly linked regular file.",
        )
    return metadata


def initialize_executor_journal(path: str | Path, *, expect_empty: bool) -> None:
    """Create the replay journal once; serving code never creates it."""

    if expect_empty is not True:
        raise LabServiceError(
            "LAB_JOURNAL_INITIALIZATION_NOT_AUTHORIZED",
            "Journal initialization requires an explicit expect-empty assertion.",
        )
    target = Path(path)
    _safe_parent(target)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    flags |= getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
    try:
        descriptor = os.open(target, flags, 0o600)
    except FileExistsError as exc:
        raise LabServiceError(
            "LAB_JOURNAL_ALREADY_EXISTS", "Executor journal already exists."
        ) from exc
    except OSError as exc:
        raise LabServiceError(
            "LAB_JOURNAL_PATH_UNSAFE", "Executor journal could not be created safely."
        ) from exc
    try:
        os.fchmod(descriptor, 0o600)
        os.fsync(descriptor)
        directory_fd = os.open(
            target.parent,
            os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_CLOEXEC", 0),
        )
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    finally:
        os.close(descriptor)
    _safe_file_stat(target)


class ExecutorReplayJournal:
    """Append-only reservation/completion fence for the lab executor."""

    def __init__(self, path: str | Path, *, require_existing: bool) -> None:
        if require_existing is not True or fcntl is None:
            raise LabServiceError(
                "LAB_JOURNAL_CONFIGURATION_INVALID",
                "Serving requires an existing journal on a Unix platform.",
            )
        self.path = Path(path)
        self._parent_identity = _safe_parent(self.path)
        self._file_identity = _safe_file_stat(self.path)

    @staticmethod
    def _same_identity(left: os.stat_result, right: os.stat_result) -> bool:
        return (left.st_dev, left.st_ino) == (right.st_dev, right.st_ino)

    def _require_bound_path(self) -> None:
        parent = _safe_parent(self.path)
        current = _safe_file_stat(self.path)
        if not self._same_identity(
            parent, self._parent_identity
        ) or not self._same_identity(current, self._file_identity):
            raise LabServiceError(
                "LAB_JOURNAL_IDENTITY_CHANGED", "Executor journal identity changed."
            )

    def _open_locked(self) -> int:
        parent = _safe_parent(self.path)
        before = _safe_file_stat(self.path)
        if not self._same_identity(
            parent, self._parent_identity
        ) or not self._same_identity(before, self._file_identity):
            raise LabServiceError(
                "LAB_JOURNAL_IDENTITY_CHANGED", "Executor journal identity changed."
            )
        flags = os.O_RDWR | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
        try:
            descriptor = os.open(self.path, flags)
        except OSError as exc:
            raise LabServiceError(
                "LAB_JOURNAL_PATH_UNSAFE",
                "Executor journal could not be opened safely.",
            ) from exc
        opened = os.fstat(descriptor)
        if (
            not self._same_identity(opened, before)
            or not stat.S_ISREG(opened.st_mode)
            or opened.st_nlink != 1
            or opened.st_uid != os.geteuid()
            or stat.S_IMODE(opened.st_mode) != 0o600
        ):
            os.close(descriptor)
            raise LabServiceError(
                "LAB_JOURNAL_IDENTITY_CHANGED",
                "Executor journal changed while opening.",
            )
        deadline = time.monotonic() + MAX_LOCK_SECONDS
        while True:
            try:
                fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
                return descriptor
            except BlockingIOError:
                if time.monotonic() >= deadline:
                    os.close(descriptor)
                    raise LabServiceError(
                        "LAB_JOURNAL_BUSY", "Executor journal lock deadline expired."
                    )
                time.sleep(0.01)
            except OSError as exc:
                os.close(descriptor)
                raise LabServiceError(
                    "LAB_JOURNAL_LOCK_FAILED", "Executor journal could not be locked."
                ) from exc

    @staticmethod
    def _record_digest(record: dict[str, object]) -> str:
        unsigned = dict(record)
        unsigned.pop("record_sha256", None)
        return hashlib.sha256(
            JOURNAL_DOMAIN + canonical_json(unsigned).encode("utf-8")
        ).hexdigest()

    def _read_records(self, descriptor: int) -> list[dict[str, object]]:
        size = os.fstat(descriptor).st_size
        if size < 0 or size > MAX_JOURNAL_BYTES:
            raise LabServiceError(
                "LAB_JOURNAL_CORRUPT", "Executor journal exceeds its bounded size."
            )
        raw = os.pread(descriptor, size, 0)
        if len(raw) != size:
            raise LabServiceError(
                "LAB_JOURNAL_CORRUPT", "Executor journal read was short."
            )
        if not raw:
            return []
        if not raw.endswith(b"\n"):
            raise LabServiceError(
                "LAB_JOURNAL_CORRUPT", "Executor journal tail is incomplete."
            )
        records: list[dict[str, object]] = []
        previous = ZERO_DIGEST
        try:
            for sequence, line in enumerate(raw.splitlines(), start=1):
                record = strict_json_loads(line)
                if type(record) is not dict or set(record) != {
                    "sequence",
                    "record_type",
                    "idempotency_key",
                    "command_sha256",
                    "receipt_json",
                    "recorded_at",
                    "previous_sha256",
                    "record_sha256",
                }:
                    raise ValueError("record shape")
                if (
                    type(record["sequence"]) is not int
                    or record["sequence"] != sequence
                    or record["record_type"] not in ("RESERVATION", "COMPLETION")
                    or type(record["idempotency_key"]) is not str
                    or not record["idempotency_key"]
                    or type(record["command_sha256"]) is not str
                    or len(record["command_sha256"]) != 64
                    or any(
                        character not in "0123456789abcdef"
                        for character in record["command_sha256"]
                    )
                    or type(record["receipt_json"]) is not str
                    or (record["record_type"] == "RESERVATION")
                    != (record["receipt_json"] == "")
                    or record["previous_sha256"] != previous
                    or record["record_sha256"] != self._record_digest(record)
                ):
                    raise ValueError("record invariant")
                if line != canonical_json(record).encode("utf-8"):
                    raise ValueError("record is not canonical")
                previous = str(record["record_sha256"])
                records.append(record)
        except (
            UnicodeError,
            json.JSONDecodeError,
            StrictJSONError,
            TypeError,
            ValueError,
        ) as exc:
            raise LabServiceError(
                "LAB_JOURNAL_CORRUPT", "Executor journal validation failed."
            ) from exc
        states: dict[str, tuple[str, str]] = {}
        for record in records:
            key = str(record["idempotency_key"])
            digest = str(record["command_sha256"])
            kind = str(record["record_type"])
            if kind == "RESERVATION":
                if key in states:
                    raise LabServiceError(
                        "LAB_JOURNAL_CORRUPT", "Duplicate reservation found."
                    )
                states[key] = (digest, kind)
            elif states.get(key) != (digest, "RESERVATION"):
                raise LabServiceError(
                    "LAB_JOURNAL_CORRUPT", "Completion lacks its reservation."
                )
            else:
                states[key] = (digest, kind)
        return records

    def _append(self, descriptor: int, record: dict[str, object]) -> None:
        record["record_sha256"] = self._record_digest(record)
        payload = canonical_json(record).encode("utf-8") + b"\n"
        if os.fstat(descriptor).st_size + len(payload) > MAX_JOURNAL_BYTES:
            raise LabServiceError(
                "LAB_JOURNAL_FULL", "Executor journal size bound reached."
            )
        os.lseek(descriptor, 0, os.SEEK_END)
        offset = 0
        while offset < len(payload):
            written = os.write(descriptor, payload[offset:])
            if written <= 0:
                raise LabServiceError(
                    "LAB_JOURNAL_WRITE_FAILED", "Journal write was incomplete."
                )
            offset += written
        os.fsync(descriptor)
        after = _safe_file_stat(self.path)
        if not self._same_identity(after, self._file_identity):
            raise LabServiceError(
                "LAB_JOURNAL_IDENTITY_CHANGED",
                "Executor journal changed during update.",
            )

    def reserve_or_replay(
        self, *, idempotency_key: str, command_sha256: str, recorded_at: str
    ) -> str | None:
        _validate_identifier(idempotency_key, label="Idempotency key")
        if (
            type(command_sha256) is not str
            or len(command_sha256) != 64
            or any(character not in "0123456789abcdef" for character in command_sha256)
        ):
            raise LabServiceError(
                "LAB_SERVICE_CONFIGURATION_INVALID", "Command digest is invalid."
            )
        descriptor = self._open_locked()
        try:
            records = self._read_records(descriptor)
            matches = [
                row for row in records if row["idempotency_key"] == idempotency_key
            ]
            if matches:
                if any(row["command_sha256"] != command_sha256 for row in matches):
                    raise LabServiceError(
                        "LAB_IDEMPOTENCY_CONFLICT",
                        "Idempotency key is already bound to different command bytes.",
                    )
                if matches[-1]["record_type"] == "COMPLETION":
                    self._require_bound_path()
                    return str(matches[-1]["receipt_json"])
                raise LabServiceError(
                    "LAB_EXECUTOR_RECOVERY_REQUIRED",
                    "A prior reservation has no durable completion; automatic retry is fenced.",
                )
            previous = str(records[-1]["record_sha256"]) if records else ZERO_DIGEST
            self._append(
                descriptor,
                {
                    "sequence": len(records) + 1,
                    "record_type": "RESERVATION",
                    "idempotency_key": idempotency_key,
                    "command_sha256": command_sha256,
                    "receipt_json": "",
                    "recorded_at": recorded_at,
                    "previous_sha256": previous,
                },
            )
            return None
        finally:
            fcntl.flock(descriptor, fcntl.LOCK_UN)
            os.close(descriptor)

    def replay_if_known(
        self, *, idempotency_key: str, command_sha256: str
    ) -> str | None:
        """Return an exact completion without creating state for an unknown command."""

        _validate_identifier(idempotency_key, label="Idempotency key")
        if (
            type(command_sha256) is not str
            or len(command_sha256) != 64
            or any(character not in "0123456789abcdef" for character in command_sha256)
        ):
            raise LabServiceError(
                "LAB_SERVICE_CONFIGURATION_INVALID", "Command digest is invalid."
            )
        descriptor = self._open_locked()
        try:
            records = self._read_records(descriptor)
            self._require_bound_path()
            matches = [
                row for row in records if row["idempotency_key"] == idempotency_key
            ]
            if not matches:
                return None
            if any(row["command_sha256"] != command_sha256 for row in matches):
                raise LabServiceError(
                    "LAB_IDEMPOTENCY_CONFLICT",
                    "Idempotency key is already bound to different command bytes.",
                )
            if matches[-1]["record_type"] != "COMPLETION":
                raise LabServiceError(
                    "LAB_EXECUTOR_RECOVERY_REQUIRED",
                    "A prior reservation has no durable completion; automatic retry is fenced.",
                )
            return str(matches[-1]["receipt_json"])
        finally:
            fcntl.flock(descriptor, fcntl.LOCK_UN)
            os.close(descriptor)

    def complete(
        self,
        *,
        idempotency_key: str,
        command_sha256: str,
        receipt_json: str,
        recorded_at: str,
    ) -> None:
        descriptor = self._open_locked()
        try:
            records = self._read_records(descriptor)
            matches = [
                row for row in records if row["idempotency_key"] == idempotency_key
            ]
            if len(matches) != 1 or matches[0]["record_type"] != "RESERVATION":
                raise LabServiceError(
                    "LAB_JOURNAL_STATE_INVALID",
                    "Exactly one open reservation is required.",
                )
            if matches[0]["command_sha256"] != command_sha256:
                raise LabServiceError(
                    "LAB_IDEMPOTENCY_CONFLICT", "Reservation command digest changed."
                )
            self._append(
                descriptor,
                {
                    "sequence": len(records) + 1,
                    "record_type": "COMPLETION",
                    "idempotency_key": idempotency_key,
                    "command_sha256": command_sha256,
                    "receipt_json": receipt_json,
                    "recorded_at": recorded_at,
                    "previous_sha256": str(records[-1]["record_sha256"]),
                },
            )
        finally:
            fcntl.flock(descriptor, fcntl.LOCK_UN)
            os.close(descriptor)


class LabExecutorService:
    """Authenticated pre-effect executor handler with durable replay fencing."""

    def __init__(
        self,
        *,
        journal: ExecutorReplayJournal,
        key_id: str,
        key: bytes,
        read_state: Callable[[], LabObservedState],
        clock: Callable[[], datetime] = lambda: datetime.now(timezone.utc),
        failure_hook: Callable[[str], None] | None = None,
        enabled: bool,
    ) -> None:
        if (
            enabled is not True
            or type(journal) is not ExecutorReplayJournal
            or not callable(read_state)
            or not callable(clock)
            or (failure_hook is not None and not callable(failure_hook))
        ):
            raise LabServiceError(
                "LAB_SERVICE_NOT_ENABLED",
                "Executor requires explicit opt-in and callables.",
            )
        self.journal = journal
        self.key_id = _validate_identifier(key_id, label="Executor key identifier")
        self.key = _validate_key(key, label="Executor key")
        self.read_state = read_state
        self.clock = clock
        self.failure_hook = failure_hook

    def handle(self, raw: bytes) -> bytes:
        now, timestamp = _utc_seconds(self.clock)
        command = load_authenticated_lab_message(
            raw,
            message_type=COMMAND,
            expected_key_id=self.key_id,
            key=self.key,
            now=now,
            allow_expired=True,
        )
        command_digest = lab_message_sha256(command)
        known = self.journal.replay_if_known(
            idempotency_key=command["idempotency_key"],
            command_sha256=command_digest,
        )
        if known is not None:
            receipt = load_authenticated_lab_message(
                known,
                message_type=RECEIPT,
                expected_key_id=self.key_id,
                key=self.key,
                now=now,
            )
            if receipt["command_sha256"] != command_digest:
                raise LabServiceError(
                    "LAB_JOURNAL_CORRUPT", "Stored receipt does not bind the command."
                )
            return known.encode("utf-8")

        # Unknown commands must still be currently valid before any reservation.
        command = validate_lab_message_dict(command, message_type=COMMAND, now=now)
        replay = self.journal.reserve_or_replay(
            idempotency_key=command["idempotency_key"],
            command_sha256=command_digest,
            recorded_at=timestamp,
        )
        if replay is not None:
            receipt = load_authenticated_lab_message(
                replay,
                message_type=RECEIPT,
                expected_key_id=self.key_id,
                key=self.key,
                now=now,
            )
            if receipt["command_sha256"] != command_digest:
                raise LabServiceError(
                    "LAB_JOURNAL_CORRUPT", "Stored receipt does not bind the command."
                )
            return replay.encode("utf-8")

        if self.failure_hook is not None:
            self.failure_hook(EXECUTOR_AFTER_RESERVATION)

        try:
            _validate_observed_state(self.read_state())
        except LabServiceError:
            raise
        except Exception as exc:
            raise LabServiceError(
                "LAB_TARGET_READ_FAILED",
                "Executor could not establish the target prestate after reservation.",
            ) from exc
        receipt = sign_lab_message(
            {
                "schema_version": "0.4.0",
                "message_type": RECEIPT,
                "lab_session_id": command["lab_session_id"],
                "request_id": command["request_id"],
                "decision_id": command["decision_id"],
                "authorization_id": command["authorization_id"],
                "command_sha256": command_digest,
                "idempotency_key": command["idempotency_key"],
                "target_id": command["target_id"],
                "target_boot_id": command["target_boot_id"],
                "sequence": command["sequence"],
                "status": "NO_EFFECT",
                "effect_possible": False,
                "reason_code": "REJECTED_PRE_EFFECT",
                "prestate_sha256": command["prestate_sha256"],
                "poststate_sha256": command["prestate_sha256"],
                "executed_at": timestamp,
                "recorded_at": timestamp,
            },
            message_type=RECEIPT,
            key_id=self.key_id,
            key=self.key,
            now=now,
        )
        receipt_json = canonical_json(receipt)
        self.journal.complete(
            idempotency_key=command["idempotency_key"],
            command_sha256=command_digest,
            receipt_json=receipt_json,
            recorded_at=timestamp,
        )
        if self.failure_hook is not None:
            self.failure_hook(EXECUTOR_AFTER_COMPLETION)
        return receipt_json.encode("utf-8")


class LabObserverService:
    """Authenticated independent read-only observation handler."""

    def __init__(
        self,
        *,
        key_id: str,
        key: bytes,
        read_state: Callable[[], LabObservedState],
        clock: Callable[[], datetime] = lambda: datetime.now(timezone.utc),
        enabled: bool,
    ) -> None:
        if enabled is not True or not callable(read_state) or not callable(clock):
            raise LabServiceError(
                "LAB_SERVICE_NOT_ENABLED",
                "Observer requires explicit opt-in and callables.",
            )
        self.key_id = _validate_identifier(key_id, label="Observer key identifier")
        self.key = _validate_key(key, label="Observer key")
        self.read_state = read_state
        self.clock = clock

    def handle(self, raw: bytes) -> bytes:
        now, timestamp = _utc_seconds(self.clock)
        request = load_authenticated_lab_message(
            raw,
            message_type=OBSERVATION_REQUEST,
            expected_key_id=self.key_id,
            key=self.key,
            now=now,
        )
        try:
            state = _validate_observed_state(self.read_state())
        except LabServiceError:
            raise
        except Exception as exc:
            raise LabServiceError(
                "LAB_TARGET_READ_FAILED",
                "Observer could not read the target state.",
            ) from exc
        if state.target_boot_id != request["target_boot_id"]:
            raise LabServiceError(
                "LAB_TARGET_BOOT_ID_MISMATCH",
                "Observed target boot identity does not match the request.",
            )
        observation = {
            "schema_version": "0.4.0",
            "message_type": OBSERVATION,
            "lab_session_id": request["lab_session_id"],
            "request_id": request["request_id"],
            "decision_id": request["decision_id"],
            "command_sha256": request["command_sha256"],
            "idempotency_key": request["idempotency_key"],
            "target_id": request["target_id"],
            "target_boot_id": request["target_boot_id"],
            "sequence": request["sequence"],
            "beacon_reachable": state.beacon_reachable,
            "management_reachable": state.management_reachable,
            "ruleset_sha256": state.ruleset_sha256,
            "observed_at": timestamp,
            "recorded_at": timestamp,
        }
        observation["observation_facts_sha256"] = observation_facts_sha256(observation)
        signed = sign_lab_message(
            observation,
            message_type=OBSERVATION,
            key_id=self.key_id,
            key=self.key,
            now=now,
        )
        return canonical_json(signed).encode("utf-8")
