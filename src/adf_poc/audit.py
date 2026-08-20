from __future__ import annotations

import json
import os
import stat
from contextlib import contextmanager
from copy import deepcopy
from pathlib import Path
from threading import RLock
from typing import Any, Iterable

from .utils import canonical_json, sha256_json, utc_now_iso


class _DuplicateJSONMember(ValueError):
    """Internal marker for an ambiguous serialized audit row."""


def _reject_duplicate_json_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, child in pairs:
        if key in value:
            raise _DuplicateJSONMember
        value[key] = child
    return value


def _decode_audit_row(line: str) -> dict[str, Any]:
    try:
        value = json.loads(line, object_pairs_hook=_reject_duplicate_json_pairs)
    except _DuplicateJSONMember:
        raise ValueError("Audit row contains duplicate JSON members.") from None
    if not isinstance(value, dict):
        raise ValueError("Audit row must be a JSON object.")
    return value


class AuditLogger:
    """Append-only, hash-chained audit log for POC decisions and actions."""

    def __init__(self, path: str | Path | None = None) -> None:
        self._lock = RLock()
        self.path = Path(path) if path is not None else None
        self._rows: list[dict[str, Any]] = []
        self.previous_hash = "0" * 64
        self.sequence = 0
        self._bound_fd: int | None = None
        self._bound_identity: tuple[int, int] | None = None
        if self.path is None:
            return
        self.path.parent.mkdir(parents=True, exist_ok=True)
        if self.path.exists():
            metadata = self.path.lstat()
            if (
                self.path.is_symlink()
                or not stat.S_ISREG(metadata.st_mode)
                or metadata.st_nlink != 1
            ):
                raise ValueError("Audit path must be a singly linked regular file.")
        if self.path.exists() and self.path.stat().st_size:
            rows = self.read_all()
            valid, errors = self.verify_rows(rows)
            if not valid:
                raise ValueError(
                    "Existing audit chain is invalid: " + "; ".join(errors)
                )
            last = rows[-1]
            self.previous_hash = str(last["record_hash"])
            self.sequence = int(last["sequence"]) + 1

    def _assert_bound_identity(self) -> None:
        if self._bound_fd is None or self._bound_identity is None or self.path is None:
            raise RuntimeError("Audit descriptor binding is unavailable.")
        try:
            opened = os.fstat(self._bound_fd)
            current = self.path.lstat()
        except OSError as exc:
            raise RuntimeError("Audit path identity changed while locked.") from exc
        expected = self._bound_identity
        if (
            (opened.st_dev, opened.st_ino) != expected
            or (current.st_dev, current.st_ino) != expected
            or not stat.S_ISREG(current.st_mode)
            or current.st_nlink != 1
        ):
            raise RuntimeError("Audit path identity changed while locked.")

    @contextmanager
    def bind_descriptor(self, descriptor: int, *, expected_identity: tuple[int, int]):
        """Route all path-backed reads and appends through one locked descriptor."""

        with self._lock:
            if self.path is None or self._bound_fd is not None:
                raise RuntimeError("Audit descriptor binding is invalid.")
            duplicate = os.dup(descriptor)
            os.set_inheritable(duplicate, False)
            self._bound_fd = duplicate
            self._bound_identity = expected_identity
            try:
                self._assert_bound_identity()
                yield
                self._assert_bound_identity()
            finally:
                self._bound_fd = None
                self._bound_identity = None
                os.close(duplicate)

    def append(self, record_type: str, payload: dict[str, Any]) -> dict[str, Any]:
        with self._lock:
            body: dict[str, Any] = {
                "sequence": self.sequence,
                "recorded_at": utc_now_iso(),
                "record_type": record_type,
                "previous_hash": self.previous_hash,
                "payload": payload,
            }
            body["record_hash"] = sha256_json(body)
            if self.path is None:
                self._rows.append(deepcopy(body))
            elif self._bound_fd is not None:
                self._assert_bound_identity()
                encoded = (canonical_json(body) + "\n").encode("utf-8")
                view = memoryview(encoded)
                while view:
                    written = os.write(self._bound_fd, view)
                    if written <= 0:
                        raise OSError("Audit append made no forward progress.")
                    view = view[written:]
                os.fsync(self._bound_fd)
                self._assert_bound_identity()
            else:
                with self.path.open("a", encoding="utf-8") as handle:
                    handle.write(canonical_json(body) + "\n")
                    handle.flush()
                    os.fsync(handle.fileno())
            self.previous_hash = body["record_hash"]
            self.sequence += 1
            return _decode_audit_row(canonical_json(body))

    def read_all(self) -> list[dict[str, Any]]:
        with self._lock:
            if self.path is None:
                return deepcopy(self._rows)
            if self._bound_fd is not None:
                self._assert_bound_identity()
                os.lseek(self._bound_fd, 0, os.SEEK_SET)
                raw = bytearray()
                while chunk := os.read(self._bound_fd, 1024 * 1024):
                    raw.extend(chunk)
                self._assert_bound_identity()
                try:
                    lines = bytes(raw).decode("utf-8").splitlines()
                except UnicodeDecodeError as exc:
                    raise ValueError("Audit log is not valid UTF-8.") from exc
                return [_decode_audit_row(line) for line in lines if line.strip()]
            if not self.path.exists():
                return []
            return [
                _decode_audit_row(line)
                for line in self.path.read_text(encoding="utf-8").splitlines()
                if line.strip()
            ]

    @staticmethod
    def verify_rows(rows: Iterable[dict[str, Any]]) -> tuple[bool, list[str]]:
        """Verify an in-memory audit chain without mutating caller-owned rows."""

        return _verify_indexed_rows(
            (index, deepcopy(row)) for index, row in enumerate(rows)
        )

    @staticmethod
    def verify(path: str | Path) -> tuple[bool, list[str]]:
        target = Path(path)
        if not target.exists():
            return False, ["Audit log does not exist."]
        indexed_rows: list[tuple[int, dict[str, Any]]] = []
        for index, line in enumerate(target.read_text(encoding="utf-8").splitlines()):
            if not line.strip():
                continue
            indexed_rows.append((index, _decode_audit_row(line)))
        return _verify_indexed_rows(indexed_rows)


def _verify_indexed_rows(
    indexed_rows: Iterable[tuple[int, dict[str, Any]]],
) -> tuple[bool, list[str]]:
    previous = "0" * 64
    errors: list[str] = []
    for index, row in indexed_rows:
        claimed = row.pop("record_hash", None)
        if row.get("previous_hash") != previous:
            errors.append(f"Record {index} previous_hash does not match the chain.")
        calculated = sha256_json(row)
        if claimed != calculated:
            errors.append(f"Record {index} hash is invalid.")
        previous = str(claimed)
    return not errors, errors
