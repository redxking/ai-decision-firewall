from __future__ import annotations

import json
from copy import deepcopy
from pathlib import Path
from typing import Any, Iterable

from .utils import canonical_json, sha256_json, utc_now_iso


class AuditLogger:
    """Append-only, hash-chained audit log for POC decisions and actions."""

    def __init__(self, path: str | Path | None = None) -> None:
        self.path = Path(path) if path is not None else None
        self._rows: list[dict[str, Any]] = []
        self.previous_hash = "0" * 64
        self.sequence = 0
        if self.path is None:
            return
        self.path.parent.mkdir(parents=True, exist_ok=True)
        if self.path.exists() and self.path.stat().st_size:
            rows = self.read_all()
            last = rows[-1]
            self.previous_hash = str(last["record_hash"])
            self.sequence = int(last["sequence"]) + 1

    def append(self, record_type: str, payload: dict[str, Any]) -> dict[str, Any]:
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
        else:
            with self.path.open("a", encoding="utf-8") as handle:
                handle.write(canonical_json(body) + "\n")
        self.previous_hash = body["record_hash"]
        self.sequence += 1
        return deepcopy(body) if self.path is None else body

    def read_all(self) -> list[dict[str, Any]]:
        if self.path is None:
            return deepcopy(self._rows)
        if not self.path.exists():
            return []
        return [
            json.loads(line)
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
            indexed_rows.append((index, json.loads(line)))
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
