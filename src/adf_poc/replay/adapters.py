from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol

from .contracts import (
    ContractValidationError,
    ManifestFile,
    load_jsonl_objects,
    validate_adjudication_records,
    validate_case_records,
)


@dataclass(frozen=True, slots=True)
class AdapterCaseBatch:
    records: tuple[dict, ...]
    mapping_warnings: tuple[dict[str, str], ...] = ()


class ReplayAdapter(Protocol):
    name: str

    def load_cases(self, entry: ManifestFile) -> AdapterCaseBatch: ...

    def load_adjudications(
        self, entry: ManifestFile, *, known_case_ids: set[str]
    ) -> list[dict]: ...


class CanonicalJSONLAdapter:
    """Adapter for the versioned canonical JSONL contract.

    Vendor-specific mapping is intentionally outside this starter adapter. A future
    adapter must emit the same validated records before the decision engine sees them.
    """

    name = "canonical_jsonl_v0.2"

    def load_cases(self, entry: ManifestFile) -> AdapterCaseBatch:
        if entry.role != "cases":
            raise ContractValidationError(
                f"Cannot load manifest role {entry.role!r} as runtime cases."
            )
        rows = load_jsonl_objects(entry.resolved_path, label="replay cases")
        return AdapterCaseBatch(records=tuple(validate_case_records(rows)))

    def load_adjudications(
        self, entry: ManifestFile, *, known_case_ids: set[str]
    ) -> list[dict]:
        if entry.role != "adjudications":
            raise ContractValidationError(
                f"Cannot load manifest role {entry.role!r} as adjudications."
            )
        rows = load_jsonl_objects(entry.resolved_path, label="replay adjudications")
        return validate_adjudication_records(rows, known_case_ids=known_case_ids)


_ADAPTERS: dict[str, ReplayAdapter] = {
    CanonicalJSONLAdapter.name: CanonicalJSONLAdapter(),
}


def get_adapter(name: str) -> ReplayAdapter:
    try:
        return _ADAPTERS[name]
    except KeyError as exc:
        raise ContractValidationError(f"Replay adapter {name!r} is not registered.") from exc


def registered_adapters() -> tuple[str, ...]:
    return tuple(sorted(_ADAPTERS))
