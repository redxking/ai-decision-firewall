from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .utils import canonical_json, sha256_json, utc_now_iso


class AuditLogger:
    """Append-only, hash-chained audit log for POC decisions and actions."""

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.previous_hash = "0" * 64
        self.sequence = 0
        if self.path.exists() and self.path.stat().st_size:
            rows = self.read_all()
            last = rows[-1]
            self.previous_hash = str(last["record_hash"])
            self.sequence = int(last["sequence"]) + 1

    def append(self, record_type: str, payload: dict[str, Any]) -> dict[str, Any]:
        body = {
            "sequence": self.sequence,
            "recorded_at": utc_now_iso(),
            "record_type": record_type,
            "previous_hash": self.previous_hash,
            "payload": payload,
        }
        body["record_hash"] = sha256_json(body)
        with self.path.open("a", encoding="utf-8") as handle:
            handle.write(canonical_json(body) + "\n")
        self.previous_hash = body["record_hash"]
        self.sequence += 1
        return body

    def read_all(self) -> list[dict[str, Any]]:
        if not self.path.exists():
            return []
        return [json.loads(line) for line in self.path.read_text(encoding="utf-8").splitlines() if line.strip()]

    @staticmethod
    def verify(path: str | Path) -> tuple[bool, list[str]]:
        target = Path(path)
        if not target.exists():
            return False, ["Audit log does not exist."]
        previous = "0" * 64
        errors: list[str] = []
        for index, line in enumerate(target.read_text(encoding="utf-8").splitlines()):
            if not line.strip():
                continue
            row = json.loads(line)
            claimed = row.pop("record_hash", None)
            if row.get("previous_hash") != previous:
                errors.append(f"Record {index} previous_hash does not match the chain.")
            calculated = sha256_json(row)
            if claimed != calculated:
                errors.append(f"Record {index} hash is invalid.")
            previous = str(claimed)
        return not errors, errors
