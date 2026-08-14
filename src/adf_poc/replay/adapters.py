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
from .qualification import qualify_case_file


@dataclass(frozen=True, slots=True)
class AdapterCaseBatch:
    records: tuple[dict, ...]
    mapping_warnings: tuple[dict[str, str], ...] = ()
    qualification_records: tuple[dict, ...] = ()
    rejection_records: tuple[dict, ...] = ()


class ReplayAdapter(Protocol):
    name: str

    def load_cases(
        self,
        entry: ManifestFile,
        *,
        record_failure_policy: str = "FAIL_DATASET",
        dataset_id: str | None = None,
    ) -> AdapterCaseBatch: ...

    def load_adjudications(
        self, entry: ManifestFile, *, known_case_ids: set[str]
    ) -> list[dict]: ...


class CanonicalJSONLAdapter:
    """Adapter for the versioned canonical JSONL contract.

    Vendor-specific mapping is intentionally outside this starter adapter. A future
    adapter must emit the same validated records before the decision engine sees them.
    """

    name = "canonical_jsonl_v0.2"

    def load_cases(
        self,
        entry: ManifestFile,
        *,
        record_failure_policy: str = "FAIL_DATASET",
        dataset_id: str | None = None,
    ) -> AdapterCaseBatch:
        if entry.role != "cases":
            raise ContractValidationError(
                f"Cannot load manifest role {entry.role!r} as runtime cases."
            )
        if record_failure_policy == "FAIL_DATASET":
            rows = load_jsonl_objects(entry.resolved_path, label="replay cases")
            return AdapterCaseBatch(records=tuple(validate_case_records(rows)))
        if record_failure_policy != "QUARANTINE_RECORD":
            raise ContractValidationError(
                f"Unsupported record failure policy {record_failure_policy!r}."
            )
        if not dataset_id:
            raise ContractValidationError(
                "dataset_id is required for record qualification."
            )
        result = qualify_case_file(
            entry.resolved_path,
            entry.sha256,
            dataset_id=dataset_id,
        )
        return AdapterCaseBatch(
            records=result.accepted_records,
            qualification_records=result.accounting_records,
            rejection_records=result.rejection_records,
        )

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
