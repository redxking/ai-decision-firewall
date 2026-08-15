"""Bounded, fail-closed qualification of Phase 2 replay case records.

The qualifier is deliberately narrower than the canonical replay adapter.  It
turns every nonblank physical line into a sanitized accounting record, retains
contract-valid cases for replay, and quarantines ordinary record defects.  A
small set of ambiguity, contamination, version, and resource failures aborts
the entire file through :class:`QualificationFatalError`.

No rejected payload, parser message, contract error text, identifier, or
``untrusted_text`` value is copied into accounting records or exception text.
"""

from __future__ import annotations

import hashlib
import io
import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Final

from .contracts import (
    CONTRACT_VERSION,
    MAX_JSONL_LINE_BYTES,
    MAX_RECORDS_PER_FILE,
    ContractValidationError,
    detect_runtime_label_leakage,
    validate_case_record,
)


QUALIFICATION_TAXONOMY_VERSION: Final = "1.0.0"
_SOURCE_ROLE: Final = "cases"
_IDENTIFIER_PATTERN: Final = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_SHA256_PATTERN: Final = re.compile(r"^[a-f0-9]{64}$")
_READ_CHUNK_BYTES: Final = 64 * 1024
MAX_JSON_NESTING_DEPTH: Final = 128

LedgerRecord = dict[str, str | int]


class QualificationFatalError(RuntimeError):
    """A sanitized, typed failure that invalidates the whole qualification run."""

    def __init__(
        self,
        *,
        error_category: str,
        error_code: str,
        qualification_run_id: str,
        source_file_sha256: str,
        physical_line_number: int | None = None,
        nonblank_record_number: int | None = None,
        raw_line_sha256: str | None = None,
    ) -> None:
        self.error_category = error_category
        self.error_code = error_code
        self.qualification_run_id = qualification_run_id
        self.source_file_sha256 = source_file_sha256
        self.physical_line_number = physical_line_number
        self.nonblank_record_number = nonblank_record_number
        self.raw_line_sha256 = raw_line_sha256
        location = (
            f" at physical line {physical_line_number}, nonblank record "
            f"{nonblank_record_number}"
            if physical_line_number is not None and nonblank_record_number is not None
            else ""
        )
        super().__init__(
            f"Case qualification aborted [{error_category}/{error_code}]{location}."
        )


@dataclass(frozen=True, slots=True, repr=False)
class QualificationResult:
    """Deterministically ordered outputs of a successful qualification pass."""

    qualification_run_id: str
    source_file_sha256: str
    accepted_records: tuple[dict[str, Any], ...]
    accounting_records: tuple[LedgerRecord, ...]
    rejection_records: tuple[LedgerRecord, ...]

    def __post_init__(self) -> None:
        if len(self.accounting_records) != (
            len(self.accepted_records) + len(self.rejection_records)
        ):
            raise ValueError(
                "Qualification accounting invariant failed: "
                "input must equal accepted plus rejected."
            )

    @property
    def input_record_count(self) -> int:
        return len(self.accounting_records)

    @property
    def accepted_record_count(self) -> int:
        return len(self.accepted_records)

    @property
    def rejected_record_count(self) -> int:
        return len(self.rejection_records)

    def __repr__(self) -> str:
        # Payload-bearing accepted records are intentionally excluded from repr.
        return (
            "QualificationResult("
            f"qualification_run_id={self.qualification_run_id!r}, "
            f"source_file_sha256={self.source_file_sha256!r}, "
            f"input_record_count={self.input_record_count}, "
            f"accepted_record_count={self.accepted_record_count}, "
            f"rejected_record_count={self.rejected_record_count})"
        )


class _DuplicateJSONMember(ValueError):
    def __init__(self, duplicate_keys: frozenset[str]) -> None:
        self.duplicate_keys = duplicate_keys
        super().__init__("JSON object contains duplicate member names.")


class _JSONNestingDepthExceeded(RuntimeError):
    """Internal marker for a code-owned parser resource bound."""


def _qualification_run_id(*, dataset_id: str, source_file_sha256: str) -> str:
    material = (
        f"{QUALIFICATION_TAXONOMY_VERSION}\n{dataset_id}\n{source_file_sha256}"
    ).encode("utf-8")
    return "qualification-" + hashlib.sha256(material).hexdigest()


def _strip_terminal_line_delimiter(raw: bytes) -> bytes:
    if raw.endswith(b"\r\n"):
        return raw[:-2]
    if raw.endswith(b"\n"):
        return raw[:-1]
    return raw


def _digest_oversized_line(
    handle: Any,
    *,
    initial: bytes,
    source_hasher: Any,
    qualification_run_id: str,
    source_file_sha256: str,
) -> str:
    """Consume and hash an oversized line without retaining it in memory."""

    digest = hashlib.sha256()
    pending = b""
    chunk = initial
    while True:
        combined = pending + chunk
        if len(combined) > 2:
            digest.update(combined[:-2])
            pending = combined[-2:]
        else:
            pending = combined
        if chunk.endswith(b"\n"):
            break
        chunk = _readline_or_fatal(
            handle,
            _READ_CHUNK_BYTES,
            qualification_run_id=qualification_run_id,
            source_file_sha256=source_file_sha256,
        )
        if not chunk:
            break
        source_hasher.update(chunk)
    digest.update(_strip_terminal_line_delimiter(pending))
    return digest.hexdigest()


def _readline_or_fatal(
    handle: Any,
    size: int,
    *,
    qualification_run_id: str,
    source_file_sha256: str,
) -> bytes:
    """Read one source segment without exposing operating-system error text."""

    try:
        return handle.readline(size)
    except OSError:
        raise _fatal(
            error_category="INTERNAL",
            error_code="SOURCE_READ_FAILURE",
            qualification_run_id=qualification_run_id,
            source_file_sha256=source_file_sha256,
        ) from None


def _ledger_record(
    *,
    qualification_run_id: str,
    dataset_id: str,
    source_file_sha256: str,
    physical_line_number: int,
    nonblank_record_number: int,
    raw_line_sha256: str,
    status: str,
    error_category: str = "",
    error_code: str = "",
) -> LedgerRecord:
    return {
        "schema_version": CONTRACT_VERSION,
        "qualification_run_id": qualification_run_id,
        "dataset_id": dataset_id,
        "source_role": _SOURCE_ROLE,
        "source_file_sha256": source_file_sha256,
        "physical_line_number": physical_line_number,
        "nonblank_record_number": nonblank_record_number,
        "raw_line_sha256": raw_line_sha256,
        "status": status,
        "error_category": error_category,
        "error_code": error_code,
    }


def _fatal(
    *,
    error_category: str,
    error_code: str,
    qualification_run_id: str,
    source_file_sha256: str,
    physical_line_number: int | None = None,
    nonblank_record_number: int | None = None,
    raw_line_sha256: str | None = None,
) -> QualificationFatalError:
    return QualificationFatalError(
        error_category=error_category,
        error_code=error_code,
        qualification_run_id=qualification_run_id,
        source_file_sha256=source_file_sha256,
        physical_line_number=physical_line_number,
        nonblank_record_number=nonblank_record_number,
        raw_line_sha256=raw_line_sha256,
    )


def _parse_json_object_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    duplicates: set[str] = set()
    for key, child in pairs:
        if key in value:
            duplicates.add(key)
        value[key] = child
    if duplicates:
        raise _DuplicateJSONMember(frozenset(duplicates))
    return value


def _reject_nonstandard_number(_: str) -> None:
    raise ValueError("Non-standard JSON numeric constant is prohibited.")


def _json_nesting_depth_exceeded(text: str) -> bool:
    """Return true when structural JSON nesting exceeds the reviewed bound.

    Brackets and braces inside JSON strings are ignored. Syntax remains the JSON
    decoder's responsibility; this pass exists only to make parser resource use
    deterministic and independent of the interpreter recursion limit.
    """

    depth = 0
    in_string = False
    escaped = False
    for character in text:
        if in_string:
            if escaped:
                escaped = False
            elif character == "\\":
                escaped = True
            elif character == '"':
                in_string = False
            continue
        if character == '"':
            in_string = True
        elif character in "[{":
            depth += 1
            if depth > MAX_JSON_NESTING_DEPTH:
                return True
        elif character in "]}" and depth:
            depth -= 1
    return False


def _parse_json(payload: bytes) -> Any:
    text = payload.decode("utf-8")
    if _json_nesting_depth_exceeded(text):
        raise _JSONNestingDepthExceeded
    try:
        return json.loads(
            text,
            object_pairs_hook=_parse_json_object_pairs,
            parse_constant=_reject_nonstandard_number,
        )
    except RecursionError:
        # Defensive fallback if a supported interpreter reaches its own recursion
        # ceiling below the explicit code-owned bound.
        raise _JSONNestingDepthExceeded from None


def _classify_contract_failure(
    exc: ContractValidationError,
    *,
    record: dict[str, Any],
) -> tuple[str, str] | None:
    """Map current canonical-contract failures to code-owned public taxonomy."""

    message = str(exc)
    if "missing required fields" in message:
        return "STRUCTURE", "MISSING_REQUIRED_FIELD"
    if "contains unsupported fields" in message:
        return "STRUCTURE", "UNEXPECTED_FIELD"
    if "events exceeds the" in message and "event limit" in message:
        return "RESOURCE_LIMIT", "EVENT_COUNT_EXCEEDED"
    if ".untrusted_text exceeds the" in message:
        return "RESOURCE_LIMIT", "UNTRUSTED_TEXT_TOO_LONG"
    if ".attributes exceeds the" in message:
        return "RESOURCE_LIMIT", "ATTRIBUTES_TOO_LARGE"
    if "must be an ISO-8601 timestamp" in message or "explicit UTC offset" in message:
        return "SEMANTICS", "INVALID_TIMESTAMP"
    if "must be a boolean" in message:
        return "SEMANTICS", "INVALID_BOOLEAN"
    if "must be an integer" in message:
        return "SEMANTICS", "INVALID_TYPE"
    if "must be numeric" in message:
        return "SEMANTICS", "INVALID_TYPE"
    if "must be finite and within [" in message:
        return "SEMANTICS", "NUMERIC_OUT_OF_RANGE"
    if "contains a non-finite JSON number" in message:
        return "SEMANTICS", "NUMERIC_OUT_OF_RANGE"
    if ".source_conflict is not authorized for this source_type" in message:
        return "SEMANTICS", "UNAUTHORIZED_DECISION_SIGNAL"
    if "is not authorized for this source_type" in message:
        return "SEMANTICS", "UNAUTHORIZED_MODELED_SIGNAL"
    if ".case_id" in message and "does not match parent case" in message:
        return "SEMANTICS", "CASE_EVENT_ID_MISMATCH"
    if ".collected_at cannot precede observed_at" in message:
        return "SEMANTICS", "EVENT_TIME_ORDER_INVALID"
    if "requires at least one asset_inventory event" in message:
        return "SEMANTICS", "CANONICAL_CONTEXT_MISSING"
    if "asset_inventory attributes must include" in message:
        return "SEMANTICS", "CANONICAL_CONTEXT_MISSING"
    if "Canonical " in message and " must equal " in message:
        return "SEMANTICS", "CANONICAL_CONTEXT_MISMATCH"
    if ".entity_refs contains duplicate" in message:
        return "SEMANTICS", "DUPLICATE_ENTITY_REFERENCE"
    if (
        "must be a non-empty string" in message
        or "must match ^" in message
        or "must be an identifier" in message
    ):
        return "SEMANTICS", "INVALID_IDENTIFIER"
    if ".events must be a non-empty array" in message:
        if not isinstance(record.get("events"), list):
            return "SEMANTICS", "INVALID_TYPE"
        return "SEMANTICS", "EMPTY_REQUIRED_COLLECTION"
    if ".integrity must be verified, unverified, or failed" in message:
        return "SEMANTICS", "INVALID_ENUM_VALUE"
    if any(
        fragment in message
        for fragment in (
            ".provenance_id must be a string",
            "must be a JSON object",
            ".entity_refs must be an array",
            ".untrusted_text must be a string",
            ".attributes must contain canonical JSON values",
        )
    ):
        return "SEMANTICS", "INVALID_TYPE"
    return None


def _identifier_definitions(
    value: dict[str, Any],
) -> tuple[str | None, tuple[str, ...]]:
    case_value = value.get("case_id")
    case_id = case_value if isinstance(case_value, str) and case_value else None
    event_ids: list[str] = []
    events = value.get("events")
    if isinstance(events, list):
        for event in events:
            if not isinstance(event, dict):
                continue
            event_value = event.get("event_id")
            if isinstance(event_value, str) and event_value:
                event_ids.append(event_value)
    return case_id, tuple(event_ids)


def _qualify_case_source(
    source: str | Path | bytes,
    source_file_sha256: str,
    *,
    dataset_id: str,
    source_role: str = _SOURCE_ROLE,
) -> QualificationResult:
    """Qualify canonical case JSONL from a path or already-custodied bytes.

    The supplied source digest is verified against the exact file bytes.  Raw
    line digests cover all source bytes except a terminal LF or CRLF delimiter;
    other whitespace remains significant.  Blank lines are skipped only when
    the delimiter-stripped bytes are empty after :meth:`bytes.strip`.
    """

    if source_role != _SOURCE_ROLE:
        raise ValueError("Phase 2.1 qualification supports source_role='cases' only.")
    if not _IDENTIFIER_PATTERN.fullmatch(dataset_id):
        raise ValueError("dataset_id must be a valid canonical identifier.")
    if not _SHA256_PATTERN.fullmatch(source_file_sha256):
        raise ValueError("source_file_sha256 must be a lowercase SHA-256 digest.")

    qualification_run_id = _qualification_run_id(
        dataset_id=dataset_id,
        source_file_sha256=source_file_sha256,
    )
    accepted: list[dict[str, Any]] = []
    accounting: list[LedgerRecord] = []
    rejected: list[LedgerRecord] = []
    seen_case_ids: set[str] = set()
    seen_event_ids: set[str] = set()
    physical_line_number = 0
    nonblank_record_number = 0
    source_hasher = hashlib.sha256()

    try:
        handle = (
            io.BytesIO(source) if isinstance(source, bytes) else Path(source).open("rb")
        )
    except OSError:
        raise _fatal(
            error_category="INTERNAL",
            error_code="SOURCE_READ_FAILURE",
            qualification_run_id=qualification_run_id,
            source_file_sha256=source_file_sha256,
        ) from None

    with handle:
        preverified_hasher = hashlib.sha256()
        try:
            while chunk := handle.read(_READ_CHUNK_BYTES):
                preverified_hasher.update(chunk)
            handle.seek(0)
        except OSError:
            raise _fatal(
                error_category="INTERNAL",
                error_code="SOURCE_READ_FAILURE",
                qualification_run_id=qualification_run_id,
                source_file_sha256=source_file_sha256,
            ) from None
        if preverified_hasher.hexdigest() != source_file_sha256:
            raise _fatal(
                error_category="INTERNAL",
                error_code="SOURCE_DIGEST_MISMATCH",
                qualification_run_id=qualification_run_id,
                source_file_sha256=source_file_sha256,
            )

        while True:
            raw = _readline_or_fatal(
                handle,
                MAX_JSONL_LINE_BYTES + 1,
                qualification_run_id=qualification_run_id,
                source_file_sha256=source_file_sha256,
            )
            if not raw:
                break
            physical_line_number += 1
            source_hasher.update(raw)
            if len(raw) > MAX_JSONL_LINE_BYTES:
                raw_line_sha256 = _digest_oversized_line(
                    handle,
                    initial=raw,
                    source_hasher=source_hasher,
                    qualification_run_id=qualification_run_id,
                    source_file_sha256=source_file_sha256,
                )
                raise _fatal(
                    error_category="RESOURCE_LIMIT",
                    error_code="LINE_TOO_LARGE",
                    qualification_run_id=qualification_run_id,
                    source_file_sha256=source_file_sha256,
                    physical_line_number=physical_line_number,
                    nonblank_record_number=nonblank_record_number + 1,
                    raw_line_sha256=raw_line_sha256,
                )
            payload = _strip_terminal_line_delimiter(raw)
            if not payload.strip():
                continue

            nonblank_record_number += 1
            raw_line_sha256 = hashlib.sha256(payload).hexdigest()
            if nonblank_record_number > MAX_RECORDS_PER_FILE:
                raise _fatal(
                    error_category="RESOURCE_LIMIT",
                    error_code="RECORD_COUNT_EXCEEDED",
                    qualification_run_id=qualification_run_id,
                    source_file_sha256=source_file_sha256,
                    physical_line_number=physical_line_number,
                    nonblank_record_number=nonblank_record_number,
                    raw_line_sha256=raw_line_sha256,
                )

            try:
                value = _parse_json(payload)
            except UnicodeDecodeError:
                raise _fatal(
                    error_category="ENCODING",
                    error_code="INVALID_UTF8",
                    qualification_run_id=qualification_run_id,
                    source_file_sha256=source_file_sha256,
                    physical_line_number=physical_line_number,
                    nonblank_record_number=nonblank_record_number,
                    raw_line_sha256=raw_line_sha256,
                ) from None
            except _JSONNestingDepthExceeded:
                raise _fatal(
                    error_category="RESOURCE_LIMIT",
                    error_code="JSON_NESTING_DEPTH_EXCEEDED",
                    qualification_run_id=qualification_run_id,
                    source_file_sha256=source_file_sha256,
                    physical_line_number=physical_line_number,
                    nonblank_record_number=nonblank_record_number,
                    raw_line_sha256=raw_line_sha256,
                ) from None
            except _DuplicateJSONMember as exc:
                if "case_id" in exc.duplicate_keys:
                    code = "DUPLICATE_CASE_ID"
                elif "event_id" in exc.duplicate_keys:
                    code = "DUPLICATE_EVENT_ID"
                else:
                    row = _ledger_record(
                        qualification_run_id=qualification_run_id,
                        dataset_id=dataset_id,
                        source_file_sha256=source_file_sha256,
                        physical_line_number=physical_line_number,
                        nonblank_record_number=nonblank_record_number,
                        raw_line_sha256=raw_line_sha256,
                        status="QUARANTINED",
                        error_category="SYNTAX",
                        error_code="INVALID_JSON",
                    )
                    accounting.append(row)
                    rejected.append(row)
                    continue
                raise _fatal(
                    error_category="DUPLICATE",
                    error_code=code,
                    qualification_run_id=qualification_run_id,
                    source_file_sha256=source_file_sha256,
                    physical_line_number=physical_line_number,
                    nonblank_record_number=nonblank_record_number,
                    raw_line_sha256=raw_line_sha256,
                ) from None
            except (json.JSONDecodeError, ValueError):
                row = _ledger_record(
                    qualification_run_id=qualification_run_id,
                    dataset_id=dataset_id,
                    source_file_sha256=source_file_sha256,
                    physical_line_number=physical_line_number,
                    nonblank_record_number=nonblank_record_number,
                    raw_line_sha256=raw_line_sha256,
                    status="QUARANTINED",
                    error_category="SYNTAX",
                    error_code="INVALID_JSON",
                )
                accounting.append(row)
                rejected.append(row)
                continue

            if detect_runtime_label_leakage(value):
                raise _fatal(
                    error_category="POLICY",
                    error_code="RUNTIME_LABEL_LEAKAGE",
                    qualification_run_id=qualification_run_id,
                    source_file_sha256=source_file_sha256,
                    physical_line_number=physical_line_number,
                    nonblank_record_number=nonblank_record_number,
                    raw_line_sha256=raw_line_sha256,
                )
            if not isinstance(value, dict):
                row = _ledger_record(
                    qualification_run_id=qualification_run_id,
                    dataset_id=dataset_id,
                    source_file_sha256=source_file_sha256,
                    physical_line_number=physical_line_number,
                    nonblank_record_number=nonblank_record_number,
                    raw_line_sha256=raw_line_sha256,
                    status="QUARANTINED",
                    error_category="STRUCTURE",
                    error_code="RECORD_NOT_OBJECT",
                )
                accounting.append(row)
                rejected.append(row)
                continue
            if (
                "schema_version" in value
                and value["schema_version"] != CONTRACT_VERSION
            ):
                raise _fatal(
                    error_category="STRUCTURE",
                    error_code="UNSUPPORTED_SCHEMA_VERSION",
                    qualification_run_id=qualification_run_id,
                    source_file_sha256=source_file_sha256,
                    physical_line_number=physical_line_number,
                    nonblank_record_number=nonblank_record_number,
                    raw_line_sha256=raw_line_sha256,
                )

            case_id, event_ids = _identifier_definitions(value)
            if case_id is not None:
                if case_id in seen_case_ids:
                    raise _fatal(
                        error_category="DUPLICATE",
                        error_code="DUPLICATE_CASE_ID",
                        qualification_run_id=qualification_run_id,
                        source_file_sha256=source_file_sha256,
                        physical_line_number=physical_line_number,
                        nonblank_record_number=nonblank_record_number,
                        raw_line_sha256=raw_line_sha256,
                    )
                seen_case_ids.add(case_id)
            local_event_ids: set[str] = set()
            for event_id in event_ids:
                if event_id in local_event_ids or event_id in seen_event_ids:
                    raise _fatal(
                        error_category="DUPLICATE",
                        error_code="DUPLICATE_EVENT_ID",
                        qualification_run_id=qualification_run_id,
                        source_file_sha256=source_file_sha256,
                        physical_line_number=physical_line_number,
                        nonblank_record_number=nonblank_record_number,
                        raw_line_sha256=raw_line_sha256,
                    )
                local_event_ids.add(event_id)
                seen_event_ids.add(event_id)

            try:
                validate_case_record(value)
            except ContractValidationError as exc:
                classification = _classify_contract_failure(exc, record=value)
                if classification is None:
                    raise _fatal(
                        error_category="INTERNAL",
                        error_code="UNKNOWN_VALIDATION_FAILURE",
                        qualification_run_id=qualification_run_id,
                        source_file_sha256=source_file_sha256,
                        physical_line_number=physical_line_number,
                        nonblank_record_number=nonblank_record_number,
                        raw_line_sha256=raw_line_sha256,
                    ) from None
                error_category, error_code = classification
                row = _ledger_record(
                    qualification_run_id=qualification_run_id,
                    dataset_id=dataset_id,
                    source_file_sha256=source_file_sha256,
                    physical_line_number=physical_line_number,
                    nonblank_record_number=nonblank_record_number,
                    raw_line_sha256=raw_line_sha256,
                    status="QUARANTINED",
                    error_category=error_category,
                    error_code=error_code,
                )
                accounting.append(row)
                rejected.append(row)
                continue

            accepted.append(value)
            accounting.append(
                _ledger_record(
                    qualification_run_id=qualification_run_id,
                    dataset_id=dataset_id,
                    source_file_sha256=source_file_sha256,
                    physical_line_number=physical_line_number,
                    nonblank_record_number=nonblank_record_number,
                    raw_line_sha256=raw_line_sha256,
                    status="ACCEPTED",
                )
            )

    if source_hasher.hexdigest() != source_file_sha256:
        raise _fatal(
            error_category="INTERNAL",
            error_code="SOURCE_DIGEST_MISMATCH",
            qualification_run_id=qualification_run_id,
            source_file_sha256=source_file_sha256,
        )

    return QualificationResult(
        qualification_run_id=qualification_run_id,
        source_file_sha256=source_file_sha256,
        accepted_records=tuple(accepted),
        accounting_records=tuple(accounting),
        rejection_records=tuple(rejected),
    )


def qualify_case_file(
    path: str | Path,
    source_file_sha256: str,
    *,
    dataset_id: str,
    source_role: str = _SOURCE_ROLE,
) -> QualificationResult:
    """Qualify a local canonical case JSONL file for replay."""

    return _qualify_case_source(
        path,
        source_file_sha256,
        dataset_id=dataset_id,
        source_role=source_role,
    )


def qualify_case_bytes(
    content: bytes,
    source_file_sha256: str,
    *,
    dataset_id: str,
    source_role: str = _SOURCE_ROLE,
) -> QualificationResult:
    """Qualify already-custodied canonical case JSONL without opening a path."""

    if not isinstance(content, bytes):
        raise TypeError("content must be bytes.")
    return _qualify_case_source(
        content,
        source_file_sha256,
        dataset_id=dataset_id,
        source_role=source_role,
    )


__all__ = [
    "MAX_JSON_NESTING_DEPTH",
    "QUALIFICATION_TAXONOMY_VERSION",
    "QualificationFatalError",
    "QualificationResult",
    "qualify_case_bytes",
    "qualify_case_file",
]
