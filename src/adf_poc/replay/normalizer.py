from __future__ import annotations

from datetime import timezone
from pathlib import Path
from typing import Any, Iterable

from adf_poc.utils import write_jsonl

from .contracts import parse_timestamp, validate_case_records


def normalize_timestamp(value: str) -> str:
    parsed = parse_timestamp(value, "timestamp").astimezone(timezone.utc)
    return parsed.isoformat()


def _event_sort_key(event: dict[str, Any]) -> tuple[str, str, str, str, str]:
    return (
        normalize_timestamp(str(event["observed_at"])),
        normalize_timestamp(str(event["collected_at"])),
        str(event["source_type"]),
        str(event["source_instance"]),
        str(event["event_id"]),
    )


def normalize_case(record: dict[str, Any]) -> dict[str, Any]:
    """Return an engine-compatible case with deterministic evidence ordering."""

    events: list[dict[str, Any]] = []
    for source in sorted(record["events"], key=_event_sort_key):
        events.append(
            {
                "event_id": source["event_id"],
                "case_id": source["case_id"],
                "source_type": source["source_type"],
                "source_instance": source["source_instance"],
                "observed_at": normalize_timestamp(source["observed_at"]),
                "collected_at": normalize_timestamp(source["collected_at"]),
                "integrity": source["integrity"],
                "provenance_id": source["provenance_id"],
                "trust_score": float(source["trust_score"]),
                "entity_refs": list(source["entity_refs"]),
                "attributes": dict(source["attributes"]),
                "untrusted_text": source["untrusted_text"],
                "contains_instructional_content": source[
                    "contains_instructional_content"
                ],
            }
        )
    return {
        "case_id": record["case_id"],
        "opened_at": normalize_timestamp(record["opened_at"]),
        "subject_id": record["subject_id"],
        "privilege_level": record["privilege_level"],
        "break_glass": record["break_glass"],
        "asset_id": record["asset_id"],
        "asset_criticality": float(record["asset_criticality"]),
        "events": events,
    }


def normalize_cases(records: Iterable[dict[str, Any]]) -> list[dict[str, Any]]:
    normalized, _ = normalize_cases_with_diagnostics(records)
    return normalized


def normalize_cases_with_diagnostics(
    records: Iterable[dict[str, Any]],
    *,
    mapping_warnings: Iterable[dict[str, str]] = (),
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    validated = validate_case_records(records)
    warnings: list[dict[str, Any]] = [
        {
            "warning_type": "SOURCE_MAPPING",
            "code": str(warning.get("code", "MAPPING_WARNING")),
            "case_id": str(warning.get("case_id", "")),
            "message": str(warning.get("message", "Adapter reported a mapping warning.")),
        }
        for warning in mapping_warnings
    ]
    normalized: list[dict[str, Any]] = []
    reordered_cases = 0
    event_count = 0
    for record in sorted(validated, key=lambda row: row["case_id"]):
        original_order = [event["event_id"] for event in record["events"]]
        normalized_record = normalize_case(record)
        normalized_order = [event["event_id"] for event in normalized_record["events"]]
        event_count += len(original_order)
        if original_order != normalized_order:
            reordered_cases += 1
            warnings.append(
                {
                    "warning_type": "TEMPORAL_ORDERING",
                    "code": "EVENT_ORDER_NORMALIZED",
                    "case_id": record["case_id"],
                    "message": (
                        "Evidence events arrived out of canonical order and were sorted by "
                        "observed_at, collected_at, source, and event_id."
                    ),
                }
            )
        normalized.append(normalized_record)
    warnings.sort(key=lambda row: (row["case_id"], row["warning_type"], row["code"]))
    diagnostics = {
        "schema_version": "0.2.0",
        "case_count": len(normalized),
        "event_count": event_count,
        "mapping_warning_count": sum(
            1 for warning in warnings if warning["warning_type"] == "SOURCE_MAPPING"
        ),
        "temporal_reordering_warning_count": reordered_cases,
        "warning_count": len(warnings),
        "warnings": warnings,
    }
    return normalized, diagnostics


def write_normalized_cases(path: str | Path, records: Iterable[dict[str, Any]]) -> int:
    return write_jsonl(path, normalize_cases(records))
