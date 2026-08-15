from __future__ import annotations

import hashlib
import json
import math
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable


class StrictJSONError(ValueError):
    """Raised when JSON contains duplicate members or non-finite numbers."""


def _reject_duplicate_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, child in pairs:
        if key in value:
            raise StrictJSONError("JSON contains duplicate object members.")
        value[key] = child
    return value


def _reject_nonstandard_number(_: str) -> None:
    raise StrictJSONError("JSON contains a non-standard numeric constant.")


def strict_json_loads(value: str | bytes) -> Any:
    """Decode strict JSON and reject ambiguous or non-finite numeric values."""

    parsed = json.loads(
        value,
        object_pairs_hook=_reject_duplicate_pairs,
        parse_constant=_reject_nonstandard_number,
    )
    pending = [parsed]
    while pending:
        child = pending.pop()
        if isinstance(child, float) and not math.isfinite(child):
            raise StrictJSONError("JSON contains a non-finite number.")
        if isinstance(child, dict):
            pending.extend(child.values())
        elif isinstance(child, list):
            pending.extend(child)
    return parsed


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def canonical_json(value: Any) -> str:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    )


def sha256_json(value: Any) -> str:
    return hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()


def sha256_file(path: str | Path, chunk_size: int = 1024 * 1024) -> str:
    digest = hashlib.sha256()
    with Path(path).open("rb") as handle:
        while chunk := handle.read(chunk_size):
            digest.update(chunk)
    return digest.hexdigest()


def write_json(path: str | Path, value: Any) -> None:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(
        json.dumps(value, indent=2, sort_keys=True, allow_nan=False),
        encoding="utf-8",
    )


def read_json(path: str | Path) -> Any:
    return strict_json_loads(Path(path).read_text(encoding="utf-8"))


def write_jsonl(path: str | Path, rows: Iterable[dict[str, Any]]) -> int:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    count = 0
    with target.open("w", encoding="utf-8") as handle:
        for row in rows:
            handle.write(canonical_json(row) + "\n")
            count += 1
    return count


def read_jsonl(path: str | Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    with Path(path).open("r", encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if line:
                value = strict_json_loads(line)
                if not isinstance(value, dict):
                    raise StrictJSONError("JSONL records must be objects.")
                rows.append(value)
    return rows


def clamp(value: float, lower: float = 0.0, upper: float = 1.0) -> float:
    return max(lower, min(upper, value))
