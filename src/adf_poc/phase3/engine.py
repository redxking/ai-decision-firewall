from __future__ import annotations

import hashlib
import hmac
import os
import stat
import uuid
from collections import Counter
from contextlib import contextmanager
from dataclasses import replace
from datetime import datetime, timezone
from pathlib import Path
from threading import Lock
from time import perf_counter, sleep
from typing import Any, Callable

from adf_poc.audit import AuditLogger
from adf_poc.stage_a import (
    REQUEST_LOOKUP_SCHEMA_VERSION,
    ControlLedgerError,
    InMemoryControlLedger,
    RequestLookupResult,
    SQLiteControlLedger,
    SQLiteSyntheticAdapterStore,
    SyntheticAdapterError,
    _store_startup_lock_scope,
    terminal_attempt_outcome_sha256,
)
from adf_poc.utils import canonical_json, sha256_json

from .approval import HumanApprovalGate
from .attestation import EvidenceAttestationVerifier
from .audit import validate_phase3_audit_chain, validate_phase3_lifecycle
from .authorization import AuthorizationError, AuthorizationGate
from .config import Phase3PolicyConfig
from .consequence import assess_consequence
from .contracts import (
    AgentSecurityStatus,
    AuthenticatedPrincipal,
    DecisionRequest,
    RequestValidationError,
    load_decision_request_json,
)
from .decision import assess_authority, build_decision
from .evidence import assess_evidence
from .identity import (
    PrincipalAuthenticationError,
    ResolvedPrincipal,
    TrustedPrincipalResolver,
)
from .metrics import Phase3Metrics
from .models import (
    AuthorityAssessment,
    ApprovalReceipt,
    ApprovalRequirement,
    DecisionOutcome,
    DecisionRecord,
    Phase3Result,
    PostActionVerification,
    VerificationStatus,
)
from .simulation import (
    build_simulated_execution_boundary,
)
from .verifier import IndependentDecisionVerifier

try:  # pragma: no cover - exercised on non-POSIX import targets
    import fcntl as _fcntl
except ImportError:  # pragma: no cover - exercised on Windows
    _fcntl = None


MAX_REQUEST_AGE_SECONDS = 300


def _deterministic_failure_id(prefix: str, *bindings: str) -> str:
    material = canonical_json([prefix, *bindings]).encode("utf-8")
    return f"{prefix}-{hashlib.sha256(material).hexdigest()[:24]}"


def _fallback_utc_now() -> datetime:
    return datetime.now(timezone.utc).replace(microsecond=0)


def _fsync_directory(path: Path) -> None:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags)
    try:
        opened = os.fstat(descriptor)
        current = path.lstat()
        if (
            not stat.S_ISDIR(opened.st_mode)
            or opened.st_dev != current.st_dev
            or opened.st_ino != current.st_ino
        ):
            raise OSError("directory identity changed during sync")
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


@contextmanager
def _exclusive_durable_startup(paths: tuple[Path, ...], *, timeout_ms: int):
    """Serialize cooperative Stage A startup without creating lock artifacts."""

    if not paths:
        yield
        return
    if _fcntl is None:
        raise ValueError(
            "Durable startup interprocess serialization is unavailable on this platform."
        )
    lock_roots: dict[str, Path] = {}
    for path in paths:
        absolute = path.absolute()
        parts = absolute.parts
        root = Path(absolute.anchor)
        stable_root = root / parts[1] if len(parts) > 1 else root
        try:
            metadata = stable_root.lstat()
        except OSError as exc:
            raise ValueError("Durable startup lock root is unavailable.") from exc
        if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
            raise ValueError("Durable startup lock root is unsafe.")
        lock_roots[str(stable_root)] = stable_root
    handles: list[int] = []
    deadline = perf_counter() + (timeout_ms / 1000.0)
    flags = os.O_RDONLY
    flags |= getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_DIRECTORY", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    try:
        for stable_root in (lock_roots[key] for key in sorted(lock_roots)):
            handle = os.open(stable_root, flags)
            handles.append(handle)
            opened = os.fstat(handle)
            current = stable_root.lstat()
            if (
                not stat.S_ISDIR(opened.st_mode)
                or opened.st_dev != current.st_dev
                or opened.st_ino != current.st_ino
            ):
                raise ValueError("Durable startup lock root changed during open.")
            while True:
                try:
                    _fcntl.flock(handle, _fcntl.LOCK_EX | _fcntl.LOCK_NB)
                    break
                except BlockingIOError:
                    remaining = deadline - perf_counter()
                    if remaining <= 0:
                        raise ControlLedgerError(
                            "DURABLE_STARTUP_BUSY",
                            "Durable startup ownership could not be acquired within the configured bound.",
                        ) from None
                    sleep(min(0.01, remaining))
        yield
    finally:
        for handle in reversed(handles):
            try:
                _fcntl.flock(handle, _fcntl.LOCK_UN)
            finally:
                os.close(handle)


def _validate_durable_store_correlation(
    control_rows: tuple[dict[str, str | None], ...],
    adapter_rows: tuple[dict[str, str], ...],
) -> None:
    """Fail closed when the independently owned stores tell different histories."""

    controls = {str(row["idempotency_key"]): row for row in control_rows}
    adapters = {str(row["idempotency_key"]): row for row in adapter_rows}
    if len(controls) != len(control_rows) or len(adapters) != len(adapter_rows):
        raise ControlLedgerError(
            "DURABLE_STORE_CORRELATION_INVALID",
            "Durable store correlation identities are not unique.",
        )
    if set(adapters) - set(controls):
        raise ControlLedgerError(
            "DURABLE_STORE_CORRELATION_INVALID",
            "Synthetic adapter contains an orphan command receipt.",
        )
    terminal_statuses = {
        "VERIFIED_EFFECT": {"APPLIED"},
        "FAILED_NO_EFFECT": {"NO_EFFECT"},
        "RECOVERY_REQUIRED": {"APPLIED", "PARTIAL", "AMBIGUOUS"},
        "UNKNOWN_EFFECT": {"APPLIED", "PARTIAL", "AMBIGUOUS"},
    }
    for key, control in controls.items():
        adapter = adapters.get(key)
        state = str(control["state"])
        receipt_sha256 = control["adapter_receipt_sha256"]
        receipt_optional = state == "RESERVED"
        receipt_absent_allowed = state == "UNKNOWN_EFFECT" and receipt_sha256 is None
        if adapter is None:
            if receipt_optional or receipt_absent_allowed:
                continue
            raise ControlLedgerError(
                "DURABLE_STORE_CORRELATION_INVALID",
                "Control history references a missing synthetic adapter receipt.",
            )
        if (
            adapter["principal_id"] != control["principal_id"]
            or adapter["request_id"] != control["request_id"]
            or adapter["request_sha256"] != control["request_sha256"]
            or adapter["attempt_id"] != control["attempt_id"]
            or any(
                adapter[name] != control[name]
                for name in (
                    "token_id",
                    "unsigned_token_sha256",
                    "issuer_instance_id",
                    "authorization_key_domain_id",
                    "decision_id",
                    "decision_authorization_sha256",
                    "decision_context_sha256",
                    "policy_sha256",
                )
            )
            or adapter["binding_sha256"] != control["binding_sha256"]
            or adapter["idempotency_key"] != control["idempotency_key"]
            or (state != "RESERVED" and adapter["receipt_sha256"] != receipt_sha256)
            or (
                state in terminal_statuses
                and adapter["status"] not in terminal_statuses[state]
            )
            or (
                state in terminal_statuses
                and adapter["state_after_sha256"] != control["target_state_sha256"]
            )
        ):
            raise ControlLedgerError(
                "DURABLE_STORE_CORRELATION_INVALID",
                "Control and synthetic-adapter receipt bindings differ.",
            )


def _audit_continuity_error(message: str) -> ControlLedgerError:
    return ControlLedgerError("AUDIT_CONTINUITY_REQUIRED", message)


def _validate_durable_audit_continuity(
    rows: list[dict[str, Any]],
    control_rows: tuple[dict[str, str | None], ...],
    adapter_rows: tuple[dict[str, str], ...],
    control_activity: dict[str, int] | None = None,
) -> bool:
    """Bind durable request state to complete decision or recovery lifecycles.

    Returns True when an unresolved, nonterminal ordinary lifecycle is present;
    callers may permit only the explicit recovery path in that state.
    """

    activity = control_activity or {}
    if activity.get("unbound_authorizations", 0) or activity.get("unbound_attempts", 0):
        raise _audit_continuity_error(
            "Unbound durable authority activity has no request lifecycle audit binding."
        )
    if (control_rows or adapter_rows or any(activity.values())) and not rows:
        raise _audit_continuity_error(
            "Durable authority or adapter activity exists without lifecycle audit evidence."
        )

    complete: list[dict[str, str]] = []
    incomplete: list[dict[str, str]] = []
    recovered: list[dict[str, str]] = []
    base_by_intake: dict[str, list[dict[str, Any]]] = {}
    index = 0
    while index < len(rows):
        record_type = str(rows[index].get("record_type", ""))
        if record_type == "REQUEST_RECEIVED":
            start = index
            index += 1
            while index < len(rows) and str(rows[index].get("record_type", "")) not in {
                "REQUEST_RECEIVED",
                "RECOVERY_STARTED",
                "APPROVAL_RECORDED",
            }:
                index += 1
                if (
                    str(rows[index - 1].get("record_type", ""))
                    == "FINAL_STATE_RECORDED"
                ):
                    break
            lifecycle = rows[start:index]
            intake_id = str(lifecycle[0].get("payload", {}).get("intake_id", ""))
            validated = next(
                (
                    row.get("payload", {})
                    for row in lifecycle
                    if row.get("record_type") == "REQUEST_VALIDATED"
                ),
                {},
            )
            decision = next(
                (
                    row.get("payload", {})
                    for row in lifecycle
                    if row.get("record_type") == "DECISION_PRODUCED"
                ),
                {},
            )
            binding = {
                "request_id": str(validated.get("request_id", "")),
                "request_sha256": str(validated.get("request_sha256", "")),
                "decision_id": str(decision.get("decision_id", "")),
            }
            if lifecycle[-1].get("record_type") == "FINAL_STATE_RECORDED":
                valid, errors = validate_phase3_lifecycle(lifecycle)
                if not valid:
                    raise _audit_continuity_error(
                        "Closed lifecycle validation failed: " + "; ".join(errors)
                    )
                lifecycle_types = {str(row.get("record_type", "")) for row in lifecycle}
                if (
                    "REQUEST_REJECTED" not in lifecycle_types
                    and "POLICY_EVALUATION_FAILED" not in lifecycle_types
                    and lifecycle_types
                    & {
                        "EVIDENCE_EVALUATED",
                        "POLICY_EVALUATED",
                        "CONTROL_PLANE_FAILURE",
                    }
                ):
                    complete.append(binding)
                base_by_intake[intake_id] = lifecycle
            else:
                if not binding["request_id"] or not binding["request_sha256"]:
                    raise _audit_continuity_error(
                        "Incomplete lifecycle lacks a durable request binding."
                    )
                incomplete.append(binding)
            continue

        if record_type == "APPROVAL_RECORDED":
            payload = rows[index].get("payload", {})
            intake_id = str(payload.get("intake_id", ""))
            base = base_by_intake.get(intake_id)
            if base is None:
                raise _audit_continuity_error(
                    "Approval audit suffix lacks its complete base lifecycle."
                )
            valid, errors = validate_phase3_lifecycle([*base, rows[index]])
            if not valid:
                raise _audit_continuity_error(
                    "Approval lifecycle validation failed: " + "; ".join(errors)
                )
            index += 1
            continue

        if record_type == "RECOVERY_STARTED":
            recovery: list[dict[str, Any]] = []
            while index < len(rows) and str(
                rows[index].get("record_type", "")
            ).startswith("RECOVERY_"):
                recovery.append(rows[index])
                index += 1
            expected = (
                "RECOVERY_STARTED",
                "RECOVERY_EVIDENCE_ASSESSED",
                "RECOVERY_FINALIZED",
            )
            types = tuple(str(row.get("record_type", "")) for row in recovery)
            if types != expected[: len(types)] or len(recovery) > len(expected):
                raise _audit_continuity_error(
                    "Recovery lifecycle is not an exact prefix."
                )
            payloads = [row.get("payload", {}) for row in recovery]
            binding_values = {
                (
                    str(payload.get("request_id", "")),
                    str(payload.get("request_sha256", "")),
                    str(payload.get("decision_id", "")),
                    str(payload.get("recovery_id", "")),
                )
                for payload in payloads
            }
            if len(binding_values) != 1 or any(
                not item for item in next(iter(binding_values))
            ):
                raise _audit_continuity_error(
                    "Recovery lifecycle binding is inconsistent."
                )
            if len(recovery) == len(expected):
                request_id, request_sha256, decision_id, _recovery_id = next(
                    iter(binding_values)
                )
                recovered.append(
                    {
                        "request_id": request_id,
                        "request_sha256": request_sha256,
                        "decision_id": decision_id,
                    }
                )
            elif index != len(rows):
                raise _audit_continuity_error(
                    "Incomplete recovery lifecycle is not the audit tail."
                )
            continue

        raise _audit_continuity_error(
            f"Unexpected top-level audit record {record_type or '<empty>'}."
        )

    complete_counts = Counter(
        (row["request_id"], row["request_sha256"], row["decision_id"])
        for row in complete
        if all(row.values())
    )
    recovered_counts = Counter(
        (row["request_id"], row["request_sha256"], row["decision_id"])
        for row in recovered
        if all(row.values())
    )
    ordinary_by_pair = Counter(
        (row["request_id"], row["request_sha256"])
        for row in [*complete, *incomplete]
        if row["request_id"] and row["request_sha256"]
    )
    control_by_pair = {
        (str(row["request_id"]), str(row["request_sha256"])): row
        for row in control_rows
    }
    for binding, count in [*complete_counts.items(), *recovered_counts.items()]:
        if count != 1:
            raise _audit_continuity_error(
                "A durable request binding has duplicate lifecycle audit mappings."
            )
    if sum(complete_counts.values()) != len(complete) or sum(
        recovered_counts.values()
    ) != len(recovered):
        raise _audit_continuity_error(
            "A durable lifecycle lacks a complete request and decision binding."
        )
    for lifecycle_kind, mappings in (
        ("ordinary", complete_counts),
        ("recovery", recovered_counts),
    ):
        for binding in mappings:
            pair = binding[:2]
            control = control_by_pair.get(pair)
            if control is None or (
                control.get("decision_id") is not None
                and str(control["decision_id"]) != binding[2]
            ):
                raise _audit_continuity_error(
                    f"A complete {lifecycle_kind} audit lifecycle lacks its exact durable control binding."
                )
    for row in incomplete:
        pair = (row["request_id"], row["request_sha256"])
        if pair not in control_by_pair:
            raise _audit_continuity_error(
                "An incomplete ordinary lifecycle lacks its exact durable request."
            )

    recovery_only = False
    for row in control_rows:
        pair = (str(row["request_id"]), str(row["request_sha256"]))
        if ordinary_by_pair[pair] != 1:
            raise _audit_continuity_error(
                "Durable control state lacks exactly one bound ordinary lifecycle."
            )
        if row["state"] != "TERMINAL":
            recovery_only = True
            continue
        binding = (
            pair[0],
            pair[1],
            str(row["decision_id"] or ""),
        )
        complete_count = complete_counts[binding]
        recovery_count = recovered_counts[binding]
        if complete_count + recovery_count != 1:
            raise _audit_continuity_error(
                "Terminal control state requires exactly one complete bound decision or recovery audit."
            )
    return recovery_only


class Phase3DecisionFirewall:
    """Simulation-only Phase 3 request-to-decision-to-verification path."""

    execution_mode = "synthetic_simulation"

    def _assert_durable_store_correlation(self) -> None:
        if self._adapter_store is None:
            return
        if type(self._control_ledger) is not SQLiteControlLedger:
            raise ControlLedgerError(
                "DURABLE_STORE_CORRELATION_INVALID",
                "Synthetic adapter is not paired with a SQLite control ledger.",
            )
        _validate_durable_store_correlation(
            self._control_ledger.correlation_snapshot(),
            self._adapter_store.correlation_snapshot(),
        )

    def _pending_recovery_tail(
        self, rows: list[dict[str, Any]]
    ) -> dict[str, Any] | None:
        """Return an uncommitted exact recovery tail, or fail on malformed recovery rows."""

        if not rows or not str(rows[-1].get("record_type", "")).startswith("RECOVERY_"):
            return None
        end = len(rows)
        start = end - 1
        while start > 0 and str(rows[start - 1].get("record_type", "")).startswith(
            "RECOVERY_"
        ):
            start -= 1
        recovery_rows = rows[start:end]
        expected_types = (
            "RECOVERY_STARTED",
            "RECOVERY_EVIDENCE_ASSESSED",
            "RECOVERY_FINALIZED",
        )
        types = tuple(str(row.get("record_type", "")) for row in recovery_rows)
        payloads = [row.get("payload") for row in recovery_rows]
        if (
            not 1 <= len(recovery_rows) <= len(expected_types)
            or types != expected_types[: len(recovery_rows)]
            or any(type(payload) is not dict for payload in payloads)
        ):
            raise ControlLedgerError(
                "RECOVERY_AUDIT_CONFLICT",
                "Audit tail contains a malformed recovery lifecycle.",
            )
        recovery_ids = {payload.get("recovery_id") for payload in payloads}
        if len(recovery_ids) != 1 or not next(iter(recovery_ids), None):
            raise ControlLedgerError(
                "RECOVERY_AUDIT_CONFLICT",
                "Audit recovery tail has inconsistent identity.",
            )
        first = payloads[0]
        descriptor = {
            "recovery_id": first.get("recovery_id"),
            "principal_id": first.get("principal_id"),
            "request_id": first.get("request_id"),
            "request_sha256": first.get("request_sha256"),
            "row_count": len(recovery_rows),
        }
        if len(recovery_rows) == len(expected_types):
            final = payloads[-1]
            if final.get("control_commit_pending") is not True:
                raise ControlLedgerError(
                    "RECOVERY_AUDIT_CONFLICT",
                    "Recovery finalization does not preserve the pending control commit.",
                )
            if (
                type(descriptor["principal_id"]) is str
                and type(descriptor["request_id"]) is str
                and type(descriptor["request_sha256"]) is str
                and type(final.get("result_sha256")) is str
                and type(self._control_ledger) is SQLiteControlLedger
            ):
                existing = self._control_ledger.lookup_request_result(
                    descriptor["principal_id"],
                    descriptor["request_id"],
                    descriptor["request_sha256"],
                )
                if existing is not None:
                    stored = replace(
                        existing,
                        replayed=False,
                        execution_attempted_this_call=False,
                        new_decision=False,
                        new_authorization=False,
                        new_effect=False,
                        authorization=None,
                    )
                    if sha256_json(stored.to_dict()) != final["result_sha256"]:
                        raise ControlLedgerError(
                            "RECOVERY_AUDIT_CONFLICT",
                            "Recovery audit and committed terminal result differ.",
                        )
                    return None
        return descriptor

    @contextmanager
    def _exclusive_audit_file_execution(
        self,
        *,
        allow_pending_recovery: bool = False,
        validate_store_correlation: bool = True,
        allow_incomplete_lifecycle: bool = False,
    ):
        """Serialize a complete audit lifecycle across local processes."""

        if self._audit.path is None:
            yield
            return
        if _fcntl is None:
            raise RuntimeError(
                "Durable audit interprocess serialization is unavailable."
            )
        audit_path = self._audit.path.absolute()
        for ancestor in reversed(audit_path.parents):
            metadata = ancestor.lstat()
            if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
                raise RuntimeError("Audit ownership parent path is unsafe.")
        flags = os.O_RDWR | os.O_APPEND | getattr(os, "O_CLOEXEC", 0)
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        try:
            descriptor = os.open(audit_path, flags, 0o600)
        except OSError as exc:
            raise RuntimeError(
                "Audit ownership path could not be opened safely."
            ) from exc
        with os.fdopen(descriptor, "a+b") as ownership:
            descriptor_metadata = os.fstat(ownership.fileno())
            path_metadata = audit_path.lstat()
            if (
                stat.S_ISLNK(path_metadata.st_mode)
                or not stat.S_ISREG(path_metadata.st_mode)
                or path_metadata.st_nlink != 1
                or path_metadata.st_uid != os.geteuid()
                or stat.S_IMODE(path_metadata.st_mode) & 0o077
                or descriptor_metadata.st_uid != os.geteuid()
                or stat.S_IMODE(descriptor_metadata.st_mode) & 0o077
                or descriptor_metadata.st_dev != path_metadata.st_dev
                or descriptor_metadata.st_ino != path_metadata.st_ino
                or (descriptor_metadata.st_dev, descriptor_metadata.st_ino)
                != self._audit_identity
            ):
                raise RuntimeError("Audit ownership path identity is unsafe.")
            deadline = perf_counter() + (self._startup_timeout_ms / 1000.0)
            while True:
                try:
                    _fcntl.flock(ownership.fileno(), _fcntl.LOCK_EX | _fcntl.LOCK_NB)
                    break
                except BlockingIOError:
                    remaining = deadline - perf_counter()
                    if remaining <= 0:
                        raise ControlLedgerError(
                            "DURABLE_AUDIT_BUSY",
                            "Durable audit ownership timed out.",
                        ) from None
                    sleep(min(0.01, remaining))
            try:
                with self._audit.bind_descriptor(
                    ownership.fileno(), expected_identity=self._audit_identity
                ):
                    rows = self._audit.read_all()
                    valid, errors = validate_phase3_audit_chain(rows)
                    if not valid:
                        raise RuntimeError(
                            "Existing Phase 3 audit chain is invalid: "
                            + "; ".join(errors)
                        )
                    pending = self._pending_recovery_tail(rows)
                    if pending is not None and not allow_pending_recovery:
                        raise ControlLedgerError(
                            "RECOVERY_AUDIT_PENDING",
                            "An exact recovery lifecycle must reach its control commit "
                            "before another audit writer may proceed.",
                        )
                    unresolved = False
                    if type(self._control_ledger) is SQLiteControlLedger:
                        unresolved = _validate_durable_audit_continuity(
                            rows,
                            self._control_ledger.audit_continuity_snapshot(),
                            (
                                self._adapter_store.correlation_snapshot()
                                if self._adapter_store is not None
                                and validate_store_correlation
                                else ()
                            ),
                            self._control_ledger.audit_activity_snapshot(),
                        )
                    if unresolved and not allow_incomplete_lifecycle:
                        raise _audit_continuity_error(
                            "An incomplete durable lifecycle permits only exact reconciliation."
                        )
                    if validate_store_correlation:
                        self._assert_durable_store_correlation()
                    if rows:
                        self._audit.previous_hash = str(rows[-1]["record_hash"])
                        self._audit.sequence = int(rows[-1]["sequence"]) + 1
                    else:
                        self._audit.previous_hash = "0" * 64
                        self._audit.sequence = 0
                    yield
            finally:
                _fcntl.flock(ownership.fileno(), _fcntl.LOCK_UN)

    @contextmanager
    def _exclusive_audit_execution(
        self,
        *,
        allow_pending_recovery: bool = False,
        validate_store_correlation: bool = True,
        allow_incomplete_lifecycle: bool = False,
    ):
        """Serialize startup/preflight and every durable audit/store operation."""

        with _exclusive_durable_startup(
            self._durable_paths, timeout_ms=self._startup_timeout_ms
        ):
            with self._exclusive_audit_file_execution(
                allow_pending_recovery=allow_pending_recovery,
                validate_store_correlation=validate_store_correlation,
                allow_incomplete_lifecycle=allow_incomplete_lifecycle,
            ):
                yield

    def _open_durable_state(
        self,
        *,
        audit_path: str | Path | None,
        control_ledger_path: str | Path | None,
        control_ledger_busy_timeout_ms: int,
        synthetic_adapter_path: str | Path | None,
        synthetic_adapter_busy_timeout_ms: int,
        fault_modes: dict[str, str] | None,
        startup_at: str,
    ) -> tuple[
        AuditLogger,
        SQLiteControlLedger | InMemoryControlLedger,
        SQLiteSyntheticAdapterStore | None,
    ]:
        """Preflight all existing artifacts, then open them as one startup unit."""

        control_preflight: tuple[dict[str, str | None], ...] = ()
        adapter_preflight: tuple[dict[str, str], ...] = ()
        if control_ledger_path is not None and Path(control_ledger_path).exists():
            control_preflight = SQLiteControlLedger.preflight_existing(
                control_ledger_path,
                busy_timeout_ms=control_ledger_busy_timeout_ms,
            )
        if synthetic_adapter_path is not None and Path(synthetic_adapter_path).exists():
            adapter_preflight = SQLiteSyntheticAdapterStore.preflight_existing(
                synthetic_adapter_path,
                target_inventory=self._policy.target_inventory,
                fault_modes=fault_modes,
                busy_timeout_ms=synthetic_adapter_busy_timeout_ms,
            )
        if synthetic_adapter_path is not None:
            _validate_durable_store_correlation(control_preflight, adapter_preflight)

        configured_artifacts = tuple(
            Path(path).absolute()
            for path in (audit_path, control_ledger_path, synthetic_adapter_path)
            if path is not None
        )
        if configured_artifacts:
            artifact_presence = tuple(path.exists() for path in configured_artifacts)
            if any(artifact_presence) and not all(artifact_presence):
                raise _audit_continuity_error(
                    "A durable state set cannot be initialized from a partial authoritative artifact set."
                )

        control_ledger: SQLiteControlLedger | InMemoryControlLedger = (
            SQLiteControlLedger(
                control_ledger_path,
                busy_timeout_ms=control_ledger_busy_timeout_ms,
                created_at=startup_at,
            )
            if control_ledger_path is not None
            else InMemoryControlLedger()
        )
        adapter_store = (
            SQLiteSyntheticAdapterStore(
                synthetic_adapter_path,
                target_inventory=self._policy.target_inventory,
                fault_modes=fault_modes,
                busy_timeout_ms=synthetic_adapter_busy_timeout_ms,
                created_at=startup_at,
            )
            if synthetic_adapter_path is not None
            else None
        )
        if adapter_store is not None:
            if type(control_ledger) is not SQLiteControlLedger:
                raise ControlLedgerError(
                    "DURABLE_STORE_CORRELATION_INVALID",
                    "Synthetic adapter requires a SQLite control ledger.",
                )
            _validate_durable_store_correlation(
                control_ledger.correlation_snapshot(),
                adapter_store.correlation_snapshot(),
            )
        if audit_path is not None:
            audit_target = Path(audit_path).absolute()
            control_continuity = (
                control_ledger.audit_continuity_snapshot()
                if type(control_ledger) is SQLiteControlLedger
                else ()
            )
            adapter_continuity = (
                adapter_store.correlation_snapshot()
                if adapter_store is not None
                else ()
            )
            if not audit_target.exists():
                if control_continuity or adapter_continuity:
                    raise _audit_continuity_error(
                        "Established durable state is missing its lifecycle audit file."
                    )
                audit_target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
                flags = os.O_RDWR | os.O_CREAT | os.O_EXCL
                if hasattr(os, "O_CLOEXEC"):
                    flags |= os.O_CLOEXEC
                if hasattr(os, "O_NOFOLLOW"):
                    flags |= os.O_NOFOLLOW
                try:
                    descriptor = os.open(audit_target, flags, 0o600)
                    try:
                        os.fchmod(descriptor, 0o600)
                        os.fsync(descriptor)
                        opened = os.fstat(descriptor)
                        current = audit_target.lstat()
                        if (
                            not stat.S_ISREG(opened.st_mode)
                            or opened.st_nlink != 1
                            or opened.st_uid != os.geteuid()
                            or stat.S_IMODE(opened.st_mode) != 0o600
                            or opened.st_dev != current.st_dev
                            or opened.st_ino != current.st_ino
                        ):
                            raise OSError("Audit identity changed during creation.")
                        _fsync_directory(audit_target.parent)
                    finally:
                        os.close(descriptor)
                except OSError as exc:
                    raise _audit_continuity_error(
                        "Initial lifecycle audit file could not be created safely."
                    ) from exc
            audit = AuditLogger(audit_target)
            existing_rows = audit.read_all()
            existing_audit_valid, existing_audit_errors = validate_phase3_audit_chain(
                existing_rows
            )
            if not existing_audit_valid:
                raise ValueError(
                    "Existing Phase 3 audit chain is invalid: "
                    + "; ".join(existing_audit_errors)
                )
            if type(control_ledger) is SQLiteControlLedger:
                _validate_durable_audit_continuity(
                    existing_rows,
                    control_continuity,
                    adapter_continuity,
                    control_ledger.audit_activity_snapshot(),
                )
        else:
            audit = AuditLogger(None)
        return audit, control_ledger, adapter_store

    def __init__(
        self,
        *,
        policy: Phase3PolicyConfig,
        signing_key: bytes,
        evidence_attestation_keys: dict[str, bytes],
        principal_resolver: TrustedPrincipalResolver,
        audit_path: str | Path | None = None,
        control_ledger_path: str | Path | None = None,
        control_ledger_busy_timeout_ms: int = 1000,
        synthetic_adapter_path: str | Path | None = None,
        synthetic_adapter_busy_timeout_ms: int = 1000,
        clock: Callable[[], datetime] | None = None,
        id_factory: Callable[[str], str] | None = None,
        fault_modes: dict[str, str] | None = None,
    ) -> None:
        if type(policy) is not Phase3PolicyConfig:
            raise TypeError("Phase 3 requires an exact validated policy object.")
        if type(principal_resolver) is not TrustedPrincipalResolver:
            raise TypeError("Phase 3 requires the closed trusted-principal resolver.")
        if type(signing_key) is not bytes or len(signing_key) < 32:
            raise TypeError(
                "Phase 3 signing key must be an exact bytes value of at least 32 bytes."
            )
        if type(evidence_attestation_keys) is not dict:
            raise TypeError("Phase 3 evidence attestation keys require an exact dict.")
        trust_material_digests = [hashlib.sha256(signing_key).digest()]
        trust_material_digests.extend(
            hashlib.sha256(value).digest()
            for value in evidence_attestation_keys.values()
            if type(value) is bytes
        )
        trust_material_digests.extend(principal_resolver.credential_digests())
        if len(trust_material_digests) != len(set(trust_material_digests)):
            raise ValueError(
                "Phase 3 signing, evidence-source, and invocation trust domains "
                "must use distinct key material."
            )
        self._policy = Phase3PolicyConfig.from_dict(Phase3PolicyConfig.to_dict(policy))
        self._policy_sha256 = sha256_json(Phase3PolicyConfig.to_dict(self._policy))
        self.__principal_resolver = principal_resolver.immutable_snapshot()
        self.clock = clock or (
            lambda: datetime.now(timezone.utc).replace(microsecond=0)
        )
        self.id_factory = id_factory or (lambda prefix: f"{prefix}-{uuid.uuid4()}")
        if audit_path is not None and _fcntl is None:
            raise ValueError(
                "Durable audit interprocess serialization is unavailable on this platform."
            )
        if synthetic_adapter_path is not None and (
            control_ledger_path is None or audit_path is None
        ):
            raise ValueError(
                "Durable synthetic adapter requires separate durable audit and control stores."
            )
        configured_paths = {
            "audit": audit_path,
            "control-ledger": control_ledger_path,
            "synthetic-adapter": synthetic_adapter_path,
        }
        resolved_paths: dict[str, tuple[Path, Path]] = {}
        for label, configured in configured_paths.items():
            if configured is None:
                continue
            try:
                candidate = Path(configured)
                resolved_paths[label] = (
                    candidate,
                    candidate.resolve(strict=False),
                )
            except (OSError, RuntimeError) as exc:
                raise ValueError(
                    "Durable state paths could not be resolved safely."
                ) from exc
            absolute_candidate = candidate.absolute()
            for ancestor in reversed(absolute_candidate.parents):
                try:
                    metadata = ancestor.lstat()
                except FileNotFoundError:
                    continue
                if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
                    raise ValueError(
                        "Durable state parent chains cannot contain symbolic "
                        "links or non-directories."
                    )
            if absolute_candidate.exists() or absolute_candidate.is_symlink():
                metadata = absolute_candidate.lstat()
                if (
                    stat.S_ISLNK(metadata.st_mode)
                    or not stat.S_ISREG(metadata.st_mode)
                    or metadata.st_nlink != 1
                    or metadata.st_uid != os.geteuid()
                    or stat.S_IMODE(metadata.st_mode) & 0o077
                ):
                    raise ValueError(
                        "Durable state paths must be owner-private singly linked regular files."
                    )
        labels = tuple(resolved_paths)
        for index, left_label in enumerate(labels):
            left, left_resolved = resolved_paths[left_label]
            for right_label in labels[index + 1 :]:
                right, right_resolved = resolved_paths[right_label]
                try:
                    paths_collide = left_resolved == right_resolved
                    if not paths_collide and left.exists() and right.exists():
                        paths_collide = left.samefile(right)
                    if not paths_collide:
                        paths_collide = (
                            left_resolved in right_resolved.parents
                            or right_resolved in left_resolved.parents
                        )
                    if not paths_collide:
                        left_names = {
                            Path(str(left_resolved) + suffix)
                            for suffix in ("-wal", "-shm", "-journal")
                        }
                        right_names = {
                            Path(str(right_resolved) + suffix)
                            for suffix in ("-wal", "-shm", "-journal")
                        }
                        paths_collide = (
                            right_resolved in left_names or left_resolved in right_names
                        )
                except (OSError, RuntimeError) as exc:
                    raise ValueError(
                        "Durable state paths could not be resolved safely."
                    ) from exc
                if paths_collide:
                    raise ValueError(
                        "Audit, control-ledger, and synthetic-adapter paths must "
                        "identify distinct files with disjoint SQLite sidecar namespaces."
                    )
        durable_paths = tuple(
            Path(path)
            for path in (audit_path, control_ledger_path, synthetic_adapter_path)
            if path is not None
        )
        self._durable_paths = durable_paths
        self._startup_timeout_ms = max(
            control_ledger_busy_timeout_ms,
            synthetic_adapter_busy_timeout_ms,
        )
        startup_at = (
            self.clock().astimezone(timezone.utc).replace(microsecond=0).isoformat()
            if durable_paths
            else _fallback_utc_now().isoformat()
        )
        with _exclusive_durable_startup(
            durable_paths,
            timeout_ms=self._startup_timeout_ms,
        ):
            with _store_startup_lock_scope():
                (
                    self._audit,
                    self._control_ledger,
                    self._adapter_store,
                ) = self._open_durable_state(
                    audit_path=audit_path,
                    control_ledger_path=control_ledger_path,
                    control_ledger_busy_timeout_ms=control_ledger_busy_timeout_ms,
                    synthetic_adapter_path=synthetic_adapter_path,
                    synthetic_adapter_busy_timeout_ms=synthetic_adapter_busy_timeout_ms,
                    fault_modes=fault_modes,
                    startup_at=startup_at,
                )
                if self._audit.path is not None:
                    audit_metadata = self._audit.path.lstat()
                    self._audit_identity = (
                        audit_metadata.st_dev,
                        audit_metadata.st_ino,
                    )
                else:
                    self._audit_identity = None
        self._metrics = Phase3Metrics()
        self._process_lock = Lock()
        self.__evidence_attestation_verifier = EvidenceAttestationVerifier(
            evidence_attestation_keys,
            required_source_instances=set(self._policy.evidence.trusted_sources),
        )
        verifier_key = hmac.new(
            bytes(signing_key), b"phase3-decision-verifier", hashlib.sha256
        ).digest()
        approval_key = hmac.new(
            bytes(signing_key), b"phase3-human-approval", hashlib.sha256
        ).digest()
        self.__approval_gate = HumanApprovalGate(
            signing_key=approval_key,
            ttl_seconds=self._policy.approval_ttl_seconds,
            principal_resolver=self.__principal_resolver,
            clock=self.clock,
            id_factory=self.id_factory,
        )
        self.__decision_verifier = IndependentDecisionVerifier(
            signing_key=verifier_key,
            attestation_verifier=self.__evidence_attestation_verifier,
            approval_gate=self.__approval_gate,
            principal_resolver=self.__principal_resolver,
            clock=self.clock,
            id_factory=self.id_factory,
        )
        self.__authorization_gate = AuthorizationGate(
            signing_key=signing_key,
            decision_verification_key=verifier_key,
            verifier_instance_id=self.__decision_verifier.verifier_instance_id,
            ttl_seconds=self._policy.authorization_ttl_seconds,
            metrics=self._metrics,
            clock=self.clock,
            ledger=self._control_ledger,
            issuer_instance_id=self._control_ledger.issuer_instance_id,
            id_factory=self.id_factory,
        )
        self.observer, self.__broker, self.__target_verifier = (
            build_simulated_execution_boundary(
                target_inventory=self._policy.target_inventory,
                gate=self.__authorization_gate,
                metrics=self._metrics,
                fault_modes=fault_modes,
                clock=self.clock,
                id_factory=self.id_factory,
                adapter_store=self._adapter_store,
            )
        )

    @property
    def policy(self) -> Phase3PolicyConfig:
        return self._policy

    def _audit_start(self) -> int:
        return len(self._audit.read_all())

    def _audit_rows(self, start: int) -> tuple[dict[str, Any], ...]:
        return tuple(self._audit.read_all()[start:])

    def _validated_result(self, result: Phase3Result) -> Phase3Result:
        chain_valid, chain_errors = validate_phase3_audit_chain(self._audit.read_all())
        lifecycle_valid, lifecycle_errors = validate_phase3_lifecycle(
            result.audit_records
        )
        if not chain_valid or not lifecycle_valid:
            raise RuntimeError(
                "Phase 3 audit lifecycle did not close: "
                + "; ".join(chain_errors + lifecycle_errors)
            )
        return result

    def _terminal_lookup_from_result(
        self,
        result: Phase3Result,
        *,
        principal_id: str,
        adapter_receipt_sha256: str | None,
        disposition: str,
        recovery_required: bool,
        terminal_at: str,
    ) -> RequestLookupResult:
        verification = result.verification
        broker_result = result.broker_result
        attempt_id = (
            broker_result.attempt_id
            if broker_result is not None
            else (verification.attempt_id if verification is not None else None)
        )
        return RequestLookupResult(
            schema_version=REQUEST_LOOKUP_SCHEMA_VERSION,
            principal_id=principal_id,
            request_id=result.decision.request_id,
            request_sha256=result.decision.request_sha256,
            disposition=disposition,
            decision_id=result.decision.decision_id,
            decision_outcome=result.decision.outcome,
            decision_sha256=result.decision.authorization_sha256(),
            decision_context_sha256=result.decision.decision_context_sha256,
            policy_sha256=result.decision.policy_sha256,
            verification_status=(
                verification.status if verification is not None else "NOT_APPLICABLE"
            ),
            verification_sha256=(
                sha256_json(verification.to_dict())
                if verification is not None
                else None
            ),
            attempt_id=attempt_id,
            adapter_receipt_sha256=adapter_receipt_sha256,
            target_state_sha256=(
                sha256_json(result.final_state)
                if attempt_id is not None and result.final_state is not None
                else None
            ),
            decided_at=result.decision.decided_at,
            terminal_at=terminal_at,
            recovery_required=recovery_required,
            reason_codes=tuple(
                dict.fromkeys(
                    [
                        *result.decision.reason_codes,
                        *(
                            verification.reason_codes
                            if verification is not None
                            else ()
                        ),
                    ]
                )
            ),
            replayed=False,
            execution_attempted_this_call=False,
            new_decision=False,
            new_authorization=False,
            new_effect=False,
            authorization=None,
        )

    def _persist_durable_terminal_result(
        self, result: Phase3Result, *, principal_id: str
    ) -> None:
        if type(self._control_ledger) is not SQLiteControlLedger:
            return
        if any(
            reason in result.decision.reason_codes
            for reason in (
                "DUPLICATE_REQUEST",
                "REQUEST_ID_CONFLICT",
                "CONTROL_LEDGER_UNAVAILABLE",
            )
        ):
            return
        snapshot = self._control_ledger.request_snapshot(
            principal_id,
            result.decision.request_id,
            result.decision.request_sha256,
        )
        if snapshot is None or snapshot["state"] == "TERMINAL":
            return
        terminal_at = (
            self.clock().astimezone(timezone.utc).replace(microsecond=0).isoformat()
        )
        attempt_id = snapshot.get("attempt_id")
        if attempt_id is None:
            if snapshot["state"] == "CLAIMED":
                lookup = self._terminal_lookup_from_result(
                    result,
                    principal_id=principal_id,
                    adapter_receipt_sha256=None,
                    disposition="DENIED_NO_EFFECT",
                    recovery_required=False,
                    terminal_at=terminal_at,
                )
                self._control_ledger.complete_request(lookup)
            return
        if snapshot.get("attempt_state") != "RECEIPT_RECORDED":
            # Normal execution never repairs a missing T2 control write. A
            # RESERVED attempt with an adapter receipt requires explicit,
            # quiesced receipt-informed reconciliation.
            return
        receipt = None
        receipt_sha256 = snapshot.get("adapter_receipt_sha256")
        if self._adapter_store is not None:
            idempotency_key = snapshot.get("idempotency_key")
            receipt = (
                self._adapter_store.receipt(idempotency_key)
                if type(idempotency_key) is str
                else None
            )
            if receipt is None:
                # A missing receipt remains open for explicit quiesced recovery.
                return
            if (
                receipt.attempt_id != attempt_id
                or receipt.binding_sha256 != snapshot["binding_sha256"]
            ):
                raise ControlLedgerError(
                    "REQUEST_RESULT_BINDING_INVALID",
                    "Adapter receipt does not bind to the reserved control attempt.",
                )
            receipt_sha256 = receipt.receipt_sha256
        if type(receipt_sha256) is not str:
            return
        final_state_sha256 = (
            sha256_json(result.final_state) if result.final_state is not None else None
        )
        durably_verified = (
            result.verification is not None
            and result.verification.status == "VERIFIED"
            and (
                receipt is None
                or (
                    receipt.status == "APPLIED"
                    and final_state_sha256 == receipt.state_after_sha256
                )
            )
        )
        if durably_verified:
            disposition = "COMPLETED_VERIFIED"
            attempt_state = "VERIFIED_EFFECT"
            recovery_required = False
        elif (receipt is not None and receipt.status == "NO_EFFECT") or (
            receipt is None
            and result.broker_result is not None
            and not result.broker_result.reported_success
        ):
            disposition = "FAILED_NO_EFFECT"
            attempt_state = "FAILED_NO_EFFECT"
            recovery_required = False
        else:
            disposition = "RECOVERY_REQUIRED"
            attempt_state = "RECOVERY_REQUIRED"
            recovery_required = True
        lookup = self._terminal_lookup_from_result(
            result,
            principal_id=principal_id,
            adapter_receipt_sha256=receipt_sha256,
            disposition=disposition,
            recovery_required=recovery_required,
            terminal_at=terminal_at,
        )
        outcome_sha256 = terminal_attempt_outcome_sha256(lookup, attempt_state)
        self._control_ledger.complete_request(
            lookup,
            attempt_state=attempt_state,
            attempt_outcome_sha256=outcome_sha256,
            adapter_receipt_sha256=receipt_sha256,
        )

    def _append(
        self,
        record_type: str,
        *,
        intake_id: str,
        request_id: str,
        decision_id: str,
        payload: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        before = self._audit.read_all()
        audit_payload = {
            "intake_id": intake_id,
            "request_id": request_id,
            "decision_id": decision_id,
            **(payload or {}),
        }
        try:
            record = self._audit.append(record_type, audit_payload)
        except Exception:
            # An append can become durable before a caller observes an fsync or
            # readback failure. Reconcile the exact next row before propagating;
            # retrying an ambiguous write could duplicate a security event.
            try:
                reconciled = self._audit.read_all()
                chain_valid, _chain_errors = validate_phase3_audit_chain(reconciled)
            except Exception:
                raise
            if (
                len(reconciled) == len(before) + 1
                and reconciled[-1].get("record_type") == record_type
                and canonical_json(reconciled[-1].get("payload"))
                == canonical_json(audit_payload)
                and chain_valid
            ):
                return reconciled[-1]
            raise
        after = self._audit.read_all()
        chain_valid, chain_errors = validate_phase3_audit_chain(after)
        if (
            len(after) != len(before) + 1
            or not after
            or canonical_json(after[-1]) != canonical_json(record)
            or not chain_valid
        ):
            raise RuntimeError(
                "Phase 3 audit append/readback failed: "
                + "; ".join(chain_errors or ["record not durably observable"])
            )
        return record

    @staticmethod
    def _decision_audit_payload(decision: DecisionRecord) -> dict[str, Any]:
        """Return the closed, non-secret projection used for lifecycle binding."""

        projection = decision.to_dict()
        permitted = projection.get("permitted_action")
        requested = projection["requested_action"]
        return {
            "outcome": decision.outcome,
            "reason_codes": list(decision.reason_codes),
            "decision_context_sha256": decision.decision_context_sha256,
            "decision_sha256": DecisionRecord.authorization_sha256(decision),
            "request_sha256": decision.request_sha256,
            "principal_id": decision.authority.principal_id,
            "policy_id": decision.policy_id,
            "policy_version": decision.policy_version,
            "policy_sha256": decision.policy_sha256,
            "requested_action_sha256": sha256_json(projection["requested_action"]),
            "requested_action_type": requested["type"],
            "requested_target_id": requested["target"],
            "requested_parameters_sha256": sha256_json(requested["parameters"]),
            "action_type": permitted.get("type") if permitted else None,
            "target_id": permitted.get("target") if permitted else None,
            "parameters_sha256": (
                sha256_json(permitted["parameters"]) if permitted else None
            ),
        }

    def _fail_closed_decision(
        self,
        *,
        decision_id: str,
        request_id: str,
        request_sha256: str,
        principal: AuthenticatedPrincipal,
        reason_code: str,
        additional_reason_codes: tuple[str, ...] = (),
        requested_action: dict[str, Any] | None = None,
        decided_at: datetime | None = None,
    ) -> DecisionRecord:
        now = (
            (decided_at or _fallback_utc_now())
            .astimezone(timezone.utc)
            .replace(microsecond=0)
        )
        reasons = tuple(
            dict.fromkeys(("INVALID_REQUEST", reason_code, *additional_reason_codes))
        )
        authority = AuthorityAssessment(
            authenticated=bool(principal.authenticated),
            principal_id=principal.id,
            claimed_agent_id="",
            attributes_match=False,
            trusted_roles=tuple(sorted(principal.roles)),
            trusted_authority=tuple(sorted(principal.authority)),
            required_authority="unresolved",
            authorized=False,
            reason_codes=(reason_code,),
        )
        context_hash = sha256_json(
            {
                "request_sha256": request_sha256,
                "policy_id": self.policy.policy_id,
                "policy_version": self.policy.version,
                "policy_sha256": self._policy_sha256,
                "outcome": DecisionOutcome.DENY.value,
                "reason_codes": list(reasons),
            }
        )
        return DecisionRecord(
            decision_id=decision_id,
            request_id=request_id,
            decided_at=now.isoformat(),
            policy_id=self.policy.policy_id,
            policy_version=self.policy.version,
            policy_sha256=self._policy_sha256,
            outcome=DecisionOutcome.DENY.value,
            reason_codes=reasons,
            applicable_rules=("P3-FAIL-CLOSED",),
            requested_action=requested_action or {},
            permitted_action=None,
            authority=authority,
            evidence=None,
            consequence=None,
            constraints=(),
            explanation={
                "decision": DecisionOutcome.DENY.value,
                "reason_codes": list(reasons),
                "evidence_assessment": None,
                "applicable_policies": ["P3-FAIL-CLOSED"],
                "agent_authority": authority.to_dict(),
                "target_criticality": "UNRESOLVED",
                "risk_and_consequence": None,
                "conflicting_evidence": None,
                "missing_evidence": [],
                "constraints": [],
                "human_approval_requirement": None,
                "agent_recommendation_is_authoritative": False,
                "agent_confidence_is_authoritative": False,
            },
            request_sha256=request_sha256,
            decision_context_sha256=context_hash,
        )

    def _finish_nonexecuting_result(
        self,
        *,
        audit_start: int,
        intake_id: str,
        decision: DecisionRecord,
        conflict_count: int,
        started: float,
    ) -> Phase3Result:
        latency_ms = round((perf_counter() - started) * 1000.0, 6)
        decision = replace(decision, latency_ms=latency_ms)
        self._append(
            "AUTHORIZATION_NOT_ISSUED",
            intake_id=intake_id,
            request_id=decision.request_id,
            decision_id=decision.decision_id,
            payload={"outcome": decision.outcome},
        )
        self._append(
            "BROKER_SKIPPED",
            intake_id=intake_id,
            request_id=decision.request_id,
            decision_id=decision.decision_id,
            payload={"reason": "Decision did not authorize execution."},
        )
        self._append(
            "ACTION_SKIPPED",
            intake_id=intake_id,
            request_id=decision.request_id,
            decision_id=decision.decision_id,
            payload={"operational_effects": 0},
        )
        self._append(
            "VERIFICATION_SKIPPED",
            intake_id=intake_id,
            request_id=decision.request_id,
            decision_id=decision.decision_id,
            payload={"status": "NOT_APPLICABLE"},
        )
        target_id = decision.requested_action.get("target")
        final_state = None
        if isinstance(target_id, str):
            try:
                final_state = self.observer.observe(target_id)
            except Exception:
                final_state = None
        self._append(
            "FINAL_STATE_RECORDED",
            intake_id=intake_id,
            request_id=decision.request_id,
            decision_id=decision.decision_id,
            payload={
                "outcome": decision.outcome,
                "operational_effects": 0,
                "target_state_sha256": (
                    sha256_json(final_state) if final_state is not None else ""
                ),
            },
        )
        self._metrics.record_decision(
            decision.outcome,
            policy_rules=decision.applicable_rules,
            evidence_conflicts=conflict_count,
            latency_ms=latency_ms,
        )
        return self._validated_result(
            Phase3Result(
                decision=decision,
                authorization=None,
                broker_result=None,
                verification=None,
                final_state=final_state,
                audit_records=self._audit_rows(audit_start),
            )
        )

    def _close_post_effect_accounting_failure(
        self,
        *,
        failed_record_type: str,
        failure: Exception,
        audit_start: int,
        intake_id: str,
        request_id: str,
        decision_id: str,
        decision: DecisionRecord,
        evidence_conflict_count: int,
        started: float,
        token: Any,
        command: dict[str, Any],
        broker_result: Any,
        state_before: dict[str, Any],
        verification: PostActionVerification | None = None,
    ) -> Phase3Result:
        """Close a post-effect path when its ordinary audit record cannot commit.

        The alternate record carries the complete attempt and verification
        projections. It is intentionally conservative: any observed change after
        an accounting-control failure requires rollback review even if the target
        otherwise reached the requested synthetic state.
        """

        if verification is None:
            try:
                verification = self.__target_verifier.verify(
                    request_id=request_id,
                    decision_id=decision_id,
                    broker_result=broker_result,
                    state_before=state_before,
                    token=token,
                    permitted_command=command,
                )
            except Exception:
                try:
                    observed = self.observer.observe(token.target_id)
                    observation_failed = False
                except Exception:
                    observed = {
                        "target_id": token.target_id,
                        "state_unavailable": True,
                    }
                    observation_failed = True
                changed = observation_failed or observed != state_before
                verification = PostActionVerification(
                    verification_id=_deterministic_failure_id(
                        "verify", token.token_id, broker_result.attempt_id
                    ),
                    request_id=token.request_id,
                    decision_id=token.decision_id,
                    attempt_id=broker_result.attempt_id,
                    token_id=token.token_id,
                    action_type=token.action_type,
                    target_id=token.target_id,
                    parameters_sha256=sha256_json(token.permitted_parameters),
                    status=(
                        VerificationStatus.ROLLBACK_REQUIRED.value
                        if changed
                        else VerificationStatus.FAILED.value
                    ),
                    expected_state={
                        "action_type": token.action_type,
                        "target_id": token.target_id,
                        "last_action_id": broker_result.attempt_id,
                    },
                    observed_state=observed,
                    changed_fields=tuple(
                        sorted(
                            key
                            for key in set(state_before) | set(observed)
                            if state_before.get(key) != observed.get(key)
                        )
                    ),
                    unexpected_fields=(),
                    rollback_required=changed,
                    reason_codes=(
                        "POST_EFFECT_VERIFIER_FAILURE",
                        *(
                            ("POST_ACTION_OBSERVATION_FAILED",)
                            if observation_failed
                            else ()
                        ),
                    ),
                )

        final_state = dict(verification.observed_state)
        operational_effects = int(final_state != state_before)
        conservative_status = (
            VerificationStatus.ROLLBACK_REQUIRED.value
            if operational_effects
            else VerificationStatus.FAILED.value
        )
        conservative_reasons = tuple(
            dict.fromkeys(
                (
                    *verification.reason_codes,
                    "POST_EFFECT_ACCOUNTING_FAILURE",
                    failed_record_type,
                    type(failure).__name__,
                    *(("ROLLBACK_REQUIRED",) if operational_effects else ()),
                )
            )
        )
        verification = replace(
            verification,
            status=conservative_status,
            rollback_required=bool(operational_effects),
            reason_codes=conservative_reasons,
        )
        self._metrics.record_verification_failure()
        self._append(
            "POST_EFFECT_ACCOUNTING_FAILURE",
            intake_id=intake_id,
            request_id=request_id,
            decision_id=decision_id,
            payload={
                "failed_record_type": failed_record_type,
                "failure_type": type(failure).__name__,
                "token_id": token.token_id,
                "attempt_id": broker_result.attempt_id,
                "action": broker_result.to_dict(),
                "verification": verification.to_dict(),
                "operational_effects": operational_effects,
            },
        )
        latency_ms = round((perf_counter() - started) * 1000.0, 6)
        decision = replace(decision, latency_ms=latency_ms)
        self._append(
            "FINAL_STATE_RECORDED",
            intake_id=intake_id,
            request_id=request_id,
            decision_id=decision_id,
            payload={
                "outcome": decision.outcome,
                "verification_status": verification.status,
                "operational_effects": operational_effects,
                "target_state_sha256": sha256_json(final_state),
            },
        )
        self._metrics.record_decision(
            decision.outcome,
            policy_rules=decision.applicable_rules,
            evidence_conflicts=evidence_conflict_count,
            latency_ms=latency_ms,
        )
        return self._validated_result(
            Phase3Result(
                decision=decision,
                authorization=token,
                broker_result=broker_result,
                verification=verification,
                final_state=final_state,
                audit_records=self._audit_rows(audit_start),
            )
        )

    def process_json(
        self,
        raw_request: str | bytes,
        *,
        credential: bytes,
    ) -> Phase3Result:
        """Process an untrusted request through a firewall-owned identity boundary."""

        try:
            principal_resolution = self.__principal_resolver.resolve(credential)
            principal = self.__principal_resolver.verify_resolution(
                principal_resolution
            )
        except PrincipalAuthenticationError as exc:
            principal_resolution = None
            principal = AuthenticatedPrincipal.from_dict(
                {
                    "id": "UNRESOLVED_INVOCATION",
                    "type": "UNAUTHENTICATED",
                    "authenticated": False,
                    "roles": [],
                    "authority": [],
                    "security_status": "UNKNOWN",
                    "identity_source": "firewall_trusted_credential_resolver",
                    "authentication_reason_code": exc.reason_code,
                }
            )

        with self._exclusive_audit_execution(), self._process_lock:
            if (
                sha256_json(Phase3PolicyConfig.to_dict(self._policy))
                != self._policy_sha256
            ):
                raise RuntimeError("Phase 3 policy snapshot integrity changed.")
            metrics_before = self._metrics.snapshot()
            result = self._process_authenticated_json(
                raw_request,
                principal=principal,
                principal_resolution=principal_resolution,
            )
            metrics_after = self._metrics.snapshot()
            if (
                metrics_after["decisions_total"]
                != metrics_before["decisions_total"] + 1
                or metrics_after["decision_counts"].get(result.decision.outcome, 0)
                != metrics_before["decision_counts"].get(result.decision.outcome, 0) + 1
            ):
                raise RuntimeError("Phase 3 decision metrics did not reconcile.")
            if (
                type(self._control_ledger) is InMemoryControlLedger
                and result.broker_result is not None
            ):
                if (
                    result.verification is not None
                    and result.verification.status == "VERIFIED"
                ):
                    process_state = "VERIFIED_EFFECT"
                elif not result.broker_result.reported_success:
                    process_state = "FAILED_NO_EFFECT"
                else:
                    process_state = "RECOVERY_REQUIRED"
                self.__authorization_gate.record_attempt_outcome(
                    attempt_id=result.broker_result.attempt_id,
                    outcome_state=process_state,
                    outcome_sha256=sha256_json(
                        {
                            "broker_result": result.broker_result.to_dict(),
                            "verification": (
                                result.verification.to_dict()
                                if result.verification is not None
                                else None
                            ),
                        }
                    ),
                    completed_at=self.clock()
                    .astimezone(timezone.utc)
                    .replace(microsecond=0)
                    .isoformat(),
                )
            self._persist_durable_terminal_result(result, principal_id=principal.id)
            return result

    def authenticate_transport_credential(
        self, credential: bytes
    ) -> AuthenticatedPrincipal:
        """Authenticate one opaque transport credential without durable mutation."""

        try:
            resolution = self.__principal_resolver.resolve(credential)
            return self.__principal_resolver.verify_resolution(resolution)
        except PrincipalAuthenticationError as exc:
            raise ControlLedgerError(
                "TRANSPORT_AUTHENTICATION_FAILED",
                "Transport access requires a trusted invocation identity.",
            ) from exc

    def _authenticated_request_binding(
        self, raw_request: str | bytes, *, credential: bytes
    ) -> tuple[str, DecisionRequest, str]:
        try:
            resolution = self.__principal_resolver.resolve(credential)
            principal = self.__principal_resolver.verify_resolution(resolution)
        except PrincipalAuthenticationError as exc:
            raise ControlLedgerError(
                "REQUEST_LOOKUP_AUTHENTICATION_FAILED",
                "Request-result access requires a trusted invocation identity.",
            ) from exc
        try:
            request = load_decision_request_json(raw_request, now=self.clock())
        except RequestValidationError as exc:
            raise ControlLedgerError(
                "REQUEST_LOOKUP_BINDING_INVALID",
                "Request-result access requires the exact valid request.",
            ) from exc
        if request.agent.id != principal.id:
            raise ControlLedgerError(
                "REQUEST_LOOKUP_AUTHENTICATION_FAILED",
                "Request-result identity does not match the authenticated principal.",
            )
        return principal.id, request, request.request_sha256()

    def lookup_request_result(
        self, raw_request: str | bytes, *, credential: bytes
    ) -> RequestLookupResult | None:
        """Authenticated read-only lookup; it makes no decision or execution attempt."""

        if (
            self._adapter_store is None
            or type(self._control_ledger) is not SQLiteControlLedger
        ):
            raise ControlLedgerError(
                "REQUEST_LOOKUP_DURABILITY_NOT_CONFIGURED",
                "Stable request-result lookup requires both durable Stage A stores.",
            )
        principal_id, request, request_sha256 = self._authenticated_request_binding(
            raw_request, credential=credential
        )
        with self._exclusive_audit_execution(
            allow_pending_recovery=True,
            allow_incomplete_lifecycle=True,
        ):
            result = self._control_ledger.lookup_request_result(
                principal_id, request.request_id, request_sha256
            )
            if result is not None:
                self._assert_durable_store_correlation()
            return result

    def _recovery_terminal_at(self, recovery_id: str) -> str:
        rows = self._audit.read_all()
        matches = [
            (index, row)
            for index, row in enumerate(rows)
            if row.get("payload", {}).get("recovery_id") == recovery_id
        ]
        if not matches:
            return (
                self.clock().astimezone(timezone.utc).replace(microsecond=0).isoformat()
            )
        expected_types = (
            "RECOVERY_STARTED",
            "RECOVERY_EVIDENCE_ASSESSED",
            "RECOVERY_FINALIZED",
        )
        if (
            [index for index, _row in matches] != list(range(matches[0][0], len(rows)))
            or len(matches) > len(expected_types)
            or tuple(row.get("record_type") for _index, row in matches)
            != expected_types[: len(matches)]
        ):
            raise ControlLedgerError(
                "RECOVERY_AUDIT_CONFLICT",
                "Existing recovery audit rows are not an exact tail prefix.",
            )
        terminal_at = matches[0][1].get("payload", {}).get("recovery_terminal_at")
        try:
            parsed = datetime.fromisoformat(terminal_at)
            if parsed.tzinfo is None or parsed.utcoffset() is None:
                raise ValueError("timestamp has no offset")
        except (TypeError, ValueError, OverflowError) as exc:
            raise ControlLedgerError(
                "RECOVERY_AUDIT_CONFLICT",
                "Recovery audit terminal timestamp is invalid.",
            ) from exc
        return str(terminal_at)

    @staticmethod
    def _correlated_original_audit_status(
        rows: list[dict[str, Any]],
        *,
        request_id: str,
        decision_id: str | None,
        attempt_id: str | None,
    ) -> str:
        """Classify the one correlated normal lifecycle without conflating others."""

        groups: list[list[dict[str, Any]]] = []
        current: list[dict[str, Any]] | None = None
        for row in rows:
            record_type = str(row.get("record_type", ""))
            if record_type == "REQUEST_RECEIVED":
                if current:
                    groups.append(current)
                current = [row]
            elif record_type.startswith("RECOVERY_"):
                if current:
                    groups.append(current)
                    current = None
            elif current is not None:
                current.append(row)
        if current:
            groups.append(current)

        def payloads(group: list[dict[str, Any]]) -> list[dict[str, Any]]:
            return [row["payload"] for row in group if type(row.get("payload")) is dict]

        candidates = [
            group
            for group in groups
            if any(
                payload.get("request_id") == request_id for payload in payloads(group)
            )
            and (
                decision_id is None
                or any(
                    payload.get("decision_id") == decision_id
                    for payload in payloads(group)
                )
            )
        ]
        if attempt_id is not None:
            exact_attempt = [
                group
                for group in candidates
                if any(
                    payload.get("attempt_id") == attempt_id
                    for payload in payloads(group)
                )
            ]
            if exact_attempt:
                candidates = exact_attempt
            else:
                invoked = [
                    group
                    for group in candidates
                    if any(row.get("record_type") == "BROKER_INVOKED" for row in group)
                ]
                if invoked:
                    candidates = invoked
        if len(candidates) != 1:
            return "UNRESOLVED"
        valid, _errors = validate_phase3_lifecycle(candidates[0])
        return "COMPLETE" if valid else "INCOMPLETE"

    def _original_audit_status(
        self,
        *,
        recovery_id: str,
        request_id: str,
        decision_id: str | None,
        attempt_id: str | None,
    ) -> str:
        rows = self._audit.read_all()
        matches = [
            (index, row)
            for index, row in enumerate(rows)
            if row.get("payload", {}).get("recovery_id") == recovery_id
        ]
        if matches and [index for index, _row in matches] != list(
            range(matches[0][0], len(rows))
        ):
            raise ControlLedgerError(
                "RECOVERY_AUDIT_CONFLICT",
                "Existing recovery audit rows are not an exact tail.",
            )
        original = rows[: matches[0][0]] if matches else rows
        return self._correlated_original_audit_status(
            original,
            request_id=request_id,
            decision_id=decision_id,
            attempt_id=attempt_id,
        )

    def _close_recovery_audit(
        self,
        *,
        recovery_id: str,
        result: RequestLookupResult,
        receipt_status: str | None,
        original_audit_status: str,
        original_decision_id: str | None,
    ) -> None:
        rows = self._audit.read_all()
        matches = [
            (index, row)
            for index, row in enumerate(rows)
            if row.get("payload", {}).get("recovery_id") == recovery_id
        ]
        if matches and [index for index, _row in matches] != list(
            range(matches[0][0], len(rows))
        ):
            raise ControlLedgerError(
                "RECOVERY_AUDIT_CONFLICT",
                "Recovery audit rows are not a contiguous tail.",
            )
        original = rows[: matches[0][0]] if matches else rows
        observed_audit_status = self._correlated_original_audit_status(
            original,
            request_id=result.request_id,
            decision_id=original_decision_id,
            attempt_id=result.attempt_id,
        )
        if (
            original_audit_status not in {"COMPLETE", "INCOMPLETE", "UNRESOLVED"}
            or observed_audit_status != original_audit_status
        ):
            raise ControlLedgerError(
                "RECOVERY_AUDIT_CONFLICT",
                "Original execution audit status changed during recovery.",
            )
        prior_tip = str(original[-1]["record_hash"]) if original else "0" * 64
        result_sha256 = sha256_json(result.to_dict())
        common = {
            "recovery_id": recovery_id,
            "recovery_terminal_at": result.terminal_at,
            "prior_audit_tip": prior_tip,
            "principal_id": result.principal_id,
            "request_sha256": result.request_sha256,
            "original_execution_audit_status": original_audit_status,
            "original_execution_lifecycle_valid": original_audit_status == "COMPLETE",
            "operator_asserted_quiesced": True,
            "command_invoked": False,
            "new_effect": False,
        }
        expected = (
            (
                "RECOVERY_STARTED",
                {
                    **common,
                    "attempt_id": result.attempt_id,
                    "adapter_receipt_sha256": result.adapter_receipt_sha256,
                },
            ),
            (
                "RECOVERY_EVIDENCE_ASSESSED",
                {
                    **common,
                    "receipt_status": receipt_status,
                    "disposition": result.disposition,
                    "recovery_required": result.recovery_required,
                },
            ),
            (
                "RECOVERY_FINALIZED",
                {
                    **common,
                    "result_sha256": result_sha256,
                    "disposition": result.disposition,
                    "control_commit_pending": True,
                },
            ),
        )
        if len(matches) > len(expected):
            raise ControlLedgerError(
                "RECOVERY_AUDIT_CONFLICT", "Recovery audit has excess rows."
            )
        for offset, (_index, row) in enumerate(matches):
            record_type, extra = expected[offset]
            expected_payload = {
                "intake_id": recovery_id,
                "request_id": result.request_id,
                "decision_id": result.decision_id,
                **extra,
            }
            if row.get("record_type") != record_type or canonical_json(
                row.get("payload")
            ) != canonical_json(expected_payload):
                raise ControlLedgerError(
                    "RECOVERY_AUDIT_CONFLICT",
                    "Recovery audit prefix differs from the exact recovery result.",
                )
        for record_type, extra in expected[len(matches) :]:
            self._append(
                record_type,
                intake_id=recovery_id,
                request_id=result.request_id,
                decision_id=result.decision_id,
                payload=extra,
            )
        closed = self._audit.read_all()
        chain_valid, chain_errors = validate_phase3_audit_chain(closed)
        if not chain_valid or tuple(
            row.get("record_type") for row in closed[-3:]
        ) != tuple(record_type for record_type, _extra in expected):
            raise ControlLedgerError(
                "RECOVERY_AUDIT_INCOMPLETE",
                "Recovery audit lifecycle did not close: " + "; ".join(chain_errors),
            )

    def reconcile_request(
        self,
        raw_request: str | bytes,
        *,
        credential: bytes,
        operator_asserted_quiesced: bool,
    ) -> RequestLookupResult | None:
        with (
            self._exclusive_audit_execution(
                allow_pending_recovery=True,
                allow_incomplete_lifecycle=True,
            ),
            self._process_lock,
        ):
            return self._reconcile_request_owned(
                raw_request,
                credential=credential,
                operator_asserted_quiesced=operator_asserted_quiesced,
            )

    def _reconcile_request_owned(
        self,
        raw_request: str | bytes,
        *,
        credential: bytes,
        operator_asserted_quiesced: bool,
    ) -> RequestLookupResult | None:
        """Receipt-informed exact-request recovery under an operator quiescence assertion.

        The assertion is deliberately not represented as a lease or fencing epoch.
        Callers must externally quiesce execution before invoking this method.
        """

        if operator_asserted_quiesced is not True:
            raise ControlLedgerError(
                "RECOVERY_QUIESCENCE_REQUIRED",
                "Exact-request recovery requires an operator quiescence assertion.",
            )
        if (
            self._adapter_store is None
            or type(self._control_ledger) is not SQLiteControlLedger
        ):
            raise ControlLedgerError(
                "REQUEST_LOOKUP_DURABILITY_NOT_CONFIGURED",
                "Recovery requires both durable Stage A stores.",
            )
        principal_id, request, request_sha256 = self._authenticated_request_binding(
            raw_request, credential=credential
        )
        existing = self._control_ledger.lookup_request_result(
            principal_id, request.request_id, request_sha256
        )
        if existing is not None:
            return existing
        # request_snapshot closes its connection before the adapter is queried;
        # no control-ledger transaction spans this ownership boundary.
        snapshot = self._control_ledger.request_snapshot(
            principal_id, request.request_id, request_sha256
        )
        if snapshot is None:
            return None
        recovery_id = _deterministic_failure_id(
            "stage-a-recovery",
            principal_id,
            request.request_id,
            request_sha256,
            str(snapshot.get("attempt_id") or "NO_ATTEMPT"),
        )
        pending_recovery = self._pending_recovery_tail(self._audit.read_all())
        if pending_recovery is not None and (
            pending_recovery.get("recovery_id") != recovery_id
            or pending_recovery.get("principal_id") != principal_id
            or pending_recovery.get("request_id") != request.request_id
            or pending_recovery.get("request_sha256") != request_sha256
        ):
            raise ControlLedgerError(
                "RECOVERY_AUDIT_PENDING",
                "A different exact recovery lifecycle owns the durable audit tail.",
            )
        terminal_at = self._recovery_terminal_at(recovery_id)
        if snapshot["attempt_id"] is None:
            original_audit_status = self._original_audit_status(
                recovery_id=recovery_id,
                request_id=request.request_id,
                decision_id=None,
                attempt_id=None,
            )
            original_audit_reason = f"ORIGINAL_EXECUTION_AUDIT_{original_audit_status}"
            self._control_ledger.revoke_issued_for_request(
                principal_id,
                request.request_id,
                request_sha256,
                operator_asserted_quiesced=True,
                revoked_at=terminal_at,
            )
            sentinel = {
                "request_sha256": request_sha256,
                "state": snapshot["state"],
                "recovery": "aborted_before_attempt",
            }
            result = RequestLookupResult(
                schema_version=REQUEST_LOOKUP_SCHEMA_VERSION,
                principal_id=principal_id,
                request_id=request.request_id,
                request_sha256=request_sha256,
                disposition="ABORTED_NO_EFFECT",
                decision_id=_deterministic_failure_id(
                    "recovery", principal_id, request.request_id, request_sha256
                ),
                decision_outcome="NOT_DURABLY_RECORDED",
                decision_sha256=sha256_json(sentinel),
                decision_context_sha256=sha256_json(
                    {**sentinel, "projection": "decision_context_absent"}
                ),
                policy_sha256=self._policy_sha256,
                verification_status="NOT_PERFORMED",
                verification_sha256=None,
                attempt_id=None,
                adapter_receipt_sha256=None,
                target_state_sha256=None,
                decided_at=snapshot["updated_at"],
                terminal_at=terminal_at,
                recovery_required=False,
                reason_codes=(
                    "QUIESCED_RECOVERY_ABORTED_BEFORE_ATTEMPT",
                    original_audit_reason,
                ),
                replayed=False,
                execution_attempted_this_call=False,
                new_decision=False,
                new_authorization=False,
                new_effect=False,
                authorization=None,
            )
            self._close_recovery_audit(
                recovery_id=recovery_id,
                result=result,
                receipt_status=None,
                original_audit_status=original_audit_status,
                original_decision_id=None,
            )
            self._control_ledger.complete_request(result)
            return self._control_ledger.lookup_request_result(
                principal_id, request.request_id, request_sha256
            )
        summary = snapshot["recovery_summary"]
        if type(summary) is not dict or type(snapshot["idempotency_key"]) is not str:
            raise ControlLedgerError(
                "CONTROL_LEDGER_CORRUPT",
                "Incomplete request lacks its sanitized recovery binding.",
            )
        original_audit_status = self._original_audit_status(
            recovery_id=recovery_id,
            request_id=request.request_id,
            decision_id=summary["decision_id"],
            attempt_id=snapshot["attempt_id"],
        )
        original_audit_reason = f"ORIGINAL_EXECUTION_AUDIT_{original_audit_status}"
        receipt = self._adapter_store.receipt(snapshot["idempotency_key"])
        if receipt is not None and (
            receipt.attempt_id != snapshot["attempt_id"]
            or receipt.binding_sha256 != snapshot["binding_sha256"]
            or receipt.request_id != request.request_id
            or receipt.decision_id != summary["decision_id"]
        ):
            raise ControlLedgerError(
                "REQUEST_RESULT_BINDING_INVALID",
                "Adapter receipt does not bind to the incomplete control attempt.",
            )
        if receipt is not None and snapshot["attempt_state"] == "RESERVED":
            # The adapter read above completed before this independent control
            # transaction. Recording the exact receipt is idempotent and does
            # not invoke the command again.
            self._control_ledger.record_adapter_receipt(
                snapshot["attempt_id"],
                adapter_receipt_sha256=receipt.receipt_sha256,
                receipt_outcome_sha256=sha256_json(
                    {
                        "adapter_receipt_sha256": receipt.receipt_sha256,
                        "adapter_status": receipt.status,
                    }
                ),
                recorded_at=terminal_at,
            )
        elif receipt is not None and (
            snapshot["attempt_state"] != "RECEIPT_RECORDED"
            or snapshot["adapter_receipt_sha256"] != receipt.receipt_sha256
        ):
            raise ControlLedgerError(
                "REQUEST_RESULT_BINDING_INVALID",
                "Recorded control receipt does not match the durable adapter receipt.",
            )
        elif receipt is None and snapshot["attempt_state"] == "RECEIPT_RECORDED":
            raise ControlLedgerError(
                "REQUEST_RESULT_BINDING_INVALID",
                "Control receipt accounting exists but the adapter receipt is unavailable.",
            )
        if receipt is not None and receipt.status == "NO_EFFECT":
            disposition = "FAILED_NO_EFFECT"
            attempt_state = "FAILED_NO_EFFECT"
            recovery_required = False
            reason_codes = (
                "ADAPTER_EXACT_NO_EFFECT_RECEIPT",
                original_audit_reason,
            )
        else:
            disposition = "UNKNOWN_EFFECT"
            attempt_state = "UNKNOWN_EFFECT"
            recovery_required = True
            reason_codes = (
                (
                    "ADAPTER_RECEIPT_WITHOUT_DURABLE_VERIFICATION"
                    if receipt is not None
                    else "ADAPTER_RECEIPT_MISSING"
                ),
                original_audit_reason,
            )
        receipt_sha256 = receipt.receipt_sha256 if receipt is not None else None
        result = RequestLookupResult(
            schema_version=REQUEST_LOOKUP_SCHEMA_VERSION,
            principal_id=principal_id,
            request_id=request.request_id,
            request_sha256=request_sha256,
            disposition=disposition,
            decision_id=summary["decision_id"],
            decision_outcome=summary["decision_outcome"],
            decision_sha256=summary["decision_sha256"],
            decision_context_sha256=summary["decision_context_sha256"],
            policy_sha256=summary["policy_sha256"],
            verification_status="NOT_DURABLY_RECORDED",
            verification_sha256=None,
            attempt_id=snapshot["attempt_id"],
            adapter_receipt_sha256=receipt_sha256,
            target_state_sha256=(
                receipt.state_after_sha256 if receipt is not None else None
            ),
            decided_at=summary["decided_at"],
            terminal_at=terminal_at,
            recovery_required=recovery_required,
            reason_codes=reason_codes,
            replayed=False,
            execution_attempted_this_call=False,
            new_decision=False,
            new_authorization=False,
            new_effect=False,
            authorization=None,
        )
        self._close_recovery_audit(
            recovery_id=recovery_id,
            result=result,
            receipt_status=receipt.status if receipt is not None else None,
            original_audit_status=original_audit_status,
            original_decision_id=summary["decision_id"],
        )
        outcome_sha256 = terminal_attempt_outcome_sha256(result, attempt_state)
        self._control_ledger.complete_request(
            result,
            attempt_state=attempt_state,
            attempt_outcome_sha256=outcome_sha256,
            adapter_receipt_sha256=receipt_sha256,
        )
        return self._control_ledger.lookup_request_result(
            principal_id, request.request_id, request_sha256
        )

    def _process_authenticated_json(
        self,
        raw_request: str | bytes,
        *,
        principal: AuthenticatedPrincipal,
        principal_resolution: ResolvedPrincipal | None,
    ) -> Phase3Result:
        started = perf_counter()
        audit_start = self._audit_start()
        raw_bytes = (
            raw_request.encode("utf-8")
            if isinstance(raw_request, str)
            else (
                bytes(raw_request)
                if isinstance(raw_request, bytes)
                else repr(raw_request).encode("utf-8")
            )
        )
        raw_sha256 = hashlib.sha256(raw_bytes).hexdigest()
        intake_id = f"intake-{raw_sha256[:16]}"
        provisional_request_id = f"invalid-{raw_sha256[:16]}"
        try:
            decision_id = self.id_factory("decision")
            decision_id_failed = type(decision_id) is not str or not decision_id
        except Exception:
            decision_id = _deterministic_failure_id(
                "decision", intake_id, provisional_request_id
            )
            decision_id_failed = True
        self._append(
            "REQUEST_RECEIVED",
            intake_id=intake_id,
            request_id=provisional_request_id,
            decision_id=decision_id,
            payload={"raw_sha256": raw_sha256, "raw_size_bytes": len(raw_bytes)},
        )

        if decision_id_failed:
            self._append(
                "REQUEST_REJECTED",
                intake_id=intake_id,
                request_id=provisional_request_id,
                decision_id=decision_id,
                payload={"reason_code": "DECISION_IDENTIFIER_FAILURE"},
            )
            decision = self._fail_closed_decision(
                decision_id=decision_id,
                request_id=provisional_request_id,
                request_sha256=raw_sha256,
                principal=principal,
                reason_code="DECISION_IDENTIFIER_FAILURE",
                decided_at=_fallback_utc_now(),
            )
            self._append(
                "DECISION_PRODUCED",
                intake_id=intake_id,
                request_id=provisional_request_id,
                decision_id=decision_id,
                payload={
                    "outcome": decision.outcome,
                    "reason_codes": list(decision.reason_codes),
                },
            )
            return self._finish_nonexecuting_result(
                audit_start=audit_start,
                intake_id=intake_id,
                decision=decision,
                conflict_count=0,
                started=started,
            )

        try:
            validation_now = self.clock()
            request = load_decision_request_json(raw_request, now=validation_now)
        except RequestValidationError as exc:
            self._append(
                "REQUEST_REJECTED",
                intake_id=intake_id,
                request_id=provisional_request_id,
                decision_id=decision_id,
                payload={"reason_code": exc.reason_code},
            )
            decision = self._fail_closed_decision(
                decision_id=decision_id,
                request_id=provisional_request_id,
                request_sha256=raw_sha256,
                principal=principal,
                reason_code=exc.reason_code,
            )
            self._append(
                "DECISION_PRODUCED",
                intake_id=intake_id,
                request_id=decision.request_id,
                decision_id=decision_id,
                payload={
                    "outcome": decision.outcome,
                    "reason_codes": list(decision.reason_codes),
                },
            )
            return self._finish_nonexecuting_result(
                audit_start=audit_start,
                intake_id=intake_id,
                decision=decision,
                conflict_count=0,
                started=started,
            )
        except Exception as exc:
            self._append(
                "REQUEST_REJECTED",
                intake_id=intake_id,
                request_id=provisional_request_id,
                decision_id=decision_id,
                payload={
                    "reason_code": "REQUEST_VALIDATION_INTERNAL_FAILURE",
                    "stage": type(exc).__name__,
                },
            )
            decision = self._fail_closed_decision(
                decision_id=decision_id,
                request_id=provisional_request_id,
                request_sha256=raw_sha256,
                principal=principal,
                reason_code="REQUEST_VALIDATION_INTERNAL_FAILURE",
                decided_at=_fallback_utc_now(),
            )
            self._append(
                "DECISION_PRODUCED",
                intake_id=intake_id,
                request_id=provisional_request_id,
                decision_id=decision_id,
                payload={
                    "outcome": decision.outcome,
                    "reason_codes": list(decision.reason_codes),
                },
            )
            return self._finish_nonexecuting_result(
                audit_start=audit_start,
                intake_id=intake_id,
                decision=decision,
                conflict_count=0,
                started=started,
            )

        request_id = request.request_id
        request_sha256 = request.request_sha256()
        now = validation_now.astimezone(timezone.utc)
        self._append(
            "REQUEST_VALIDATED",
            intake_id=intake_id,
            request_id=request_id,
            decision_id=decision_id,
            payload={
                "schema_version": request.schema_version,
                "request_sha256": request_sha256,
                "requested_action_type": request.action.type.value,
                "requested_target_id": request.action.target,
                "requested_parameters_sha256": sha256_json(
                    request.action.parameters.to_dict()
                ),
            },
        )
        if (
            not principal.authenticated
            or principal.security_status != AgentSecurityStatus.TRUSTED
        ):
            reason = principal.authentication_reason_code or (
                "AGENT_NOT_AUTHENTICATED"
                if not principal.authenticated
                else "AGENT_SECURITY_STATUS_INVALID"
            )
            authority = AuthorityAssessment(
                authenticated=principal.authenticated,
                principal_id=principal.id,
                claimed_agent_id=request.agent.id,
                attributes_match=False,
                trusted_roles=tuple(sorted(principal.roles)),
                trusted_authority=tuple(sorted(principal.authority)),
                required_authority="unresolved",
                authorized=False,
                reason_codes=(reason,),
            )
            self._append(
                "IDENTITY_EVALUATED",
                intake_id=intake_id,
                request_id=request_id,
                decision_id=decision_id,
                payload=authority.to_dict(),
            )
            decision = self._fail_closed_decision(
                decision_id=decision_id,
                request_id=request_id,
                request_sha256=request_sha256,
                principal=principal,
                reason_code=reason,
                additional_reason_codes=(
                    "AGENT_NOT_AUTHENTICATED",
                    "AGENT_IDENTITY_MISMATCH",
                ),
                requested_action=request.action.to_dict(),
                decided_at=now,
            )
            self._append(
                "DECISION_PRODUCED",
                intake_id=intake_id,
                request_id=request_id,
                decision_id=decision_id,
                payload={
                    "outcome": decision.outcome,
                    "reason_codes": list(decision.reason_codes),
                    "decision_context_sha256": decision.decision_context_sha256,
                },
            )
            return self._finish_nonexecuting_result(
                audit_start=audit_start,
                intake_id=intake_id,
                decision=decision,
                conflict_count=0,
                started=started,
            )
        principal_claims_match = (
            principal.id == request.agent.id
            and principal.type == request.agent.type
            and set(principal.roles) == set(request.agent.roles)
            and set(principal.authority) == set(request.agent.authority)
            and principal.security_status == request.agent.security_status
            and request.agent.authenticated is True
        )
        if not principal_claims_match:
            authority = AuthorityAssessment(
                authenticated=True,
                principal_id=principal.id,
                claimed_agent_id=request.agent.id,
                attributes_match=False,
                trusted_roles=tuple(sorted(principal.roles)),
                trusted_authority=tuple(sorted(principal.authority)),
                required_authority="unresolved",
                authorized=False,
                reason_codes=("AGENT_ATTRIBUTE_MISMATCH",),
            )
            self._append(
                "IDENTITY_EVALUATED",
                intake_id=intake_id,
                request_id=request_id,
                decision_id=decision_id,
                payload=authority.to_dict(),
            )
            decision = self._fail_closed_decision(
                decision_id=decision_id,
                request_id=request_id,
                request_sha256=request_sha256,
                principal=principal,
                reason_code="AGENT_ATTRIBUTE_MISMATCH",
                requested_action=request.action.to_dict(),
                decided_at=now,
            )
            self._append(
                "DECISION_PRODUCED",
                intake_id=intake_id,
                request_id=request_id,
                decision_id=decision_id,
                payload={
                    "outcome": decision.outcome,
                    "reason_codes": list(decision.reason_codes),
                    "decision_context_sha256": decision.decision_context_sha256,
                },
            )
            return self._finish_nonexecuting_result(
                audit_start=audit_start,
                intake_id=intake_id,
                decision=decision,
                conflict_count=0,
                started=started,
            )
        try:
            request_time = datetime.fromisoformat(
                request.timestamp[:-1] + "+00:00"
                if request.timestamp.endswith("Z")
                else request.timestamp
            ).astimezone(timezone.utc)
            age_seconds = (now - request_time).total_seconds()
        except (TypeError, ValueError, OverflowError):
            age_seconds = MAX_REQUEST_AGE_SECONDS + 1

        preflight_reason = ""
        if age_seconds < -300:
            preflight_reason = "REQUEST_TIMESTAMP_FUTURE"
        elif age_seconds > MAX_REQUEST_AGE_SECONDS:
            preflight_reason = "REQUEST_TIMESTAMP_STALE"

        if preflight_reason:
            self._append(
                "REQUEST_REJECTED",
                intake_id=intake_id,
                request_id=request_id,
                decision_id=decision_id,
                payload={"reason_code": preflight_reason},
            )
            decision = self._fail_closed_decision(
                decision_id=decision_id,
                request_id=request_id,
                request_sha256=request_sha256,
                principal=principal,
                reason_code=preflight_reason,
                requested_action=request.action.to_dict(),
                decided_at=now,
            )
            self._append(
                "DECISION_PRODUCED",
                intake_id=intake_id,
                request_id=request_id,
                decision_id=decision_id,
                payload={
                    "outcome": decision.outcome,
                    "reason_codes": list(decision.reason_codes),
                },
            )
            return self._finish_nonexecuting_result(
                audit_start=audit_start,
                intake_id=intake_id,
                decision=decision,
                conflict_count=0,
                started=started,
            )

        try:
            target = self.policy.target_record(request.action.target)
            action_policy = self.policy.action_policy(request.action.type)
        except (KeyError, ValueError):
            self._append(
                "POLICY_EVALUATION_FAILED",
                intake_id=intake_id,
                request_id=request_id,
                decision_id=decision_id,
                payload={"reason_code": "TARGET_OR_ACTION_UNKNOWN"},
            )
            decision = self._fail_closed_decision(
                decision_id=decision_id,
                request_id=request_id,
                request_sha256=request_sha256,
                principal=principal,
                reason_code="TARGET_OR_ACTION_UNKNOWN",
                requested_action=request.action.to_dict(),
                decided_at=now,
            )
            self._append(
                "DECISION_PRODUCED",
                intake_id=intake_id,
                request_id=request_id,
                decision_id=decision_id,
                payload={
                    "outcome": decision.outcome,
                    "reason_codes": list(decision.reason_codes),
                },
            )
            return self._finish_nonexecuting_result(
                audit_start=audit_start,
                intake_id=intake_id,
                decision=decision,
                conflict_count=0,
                started=started,
            )

        try:
            ledger_state = self._control_ledger.claim_request(
                principal.id,
                request_id,
                request_sha256,
                claimed_at=now.isoformat(),
            )
        except ControlLedgerError:
            ledger_state = "UNAVAILABLE"
        if ledger_state != "NEW":
            preflight_reason = (
                "DUPLICATE_REQUEST"
                if ledger_state == "DUPLICATE"
                else (
                    "REQUEST_ID_CONFLICT"
                    if ledger_state == "CONFLICT"
                    else "CONTROL_LEDGER_UNAVAILABLE"
                )
            )
            self._append(
                "REQUEST_REJECTED",
                intake_id=intake_id,
                request_id=request_id,
                decision_id=decision_id,
                payload={"reason_code": preflight_reason},
            )
            decision = self._fail_closed_decision(
                decision_id=decision_id,
                request_id=request_id,
                request_sha256=request_sha256,
                principal=principal,
                reason_code=preflight_reason,
                requested_action=request.action.to_dict(),
                decided_at=now,
            )
            self._append(
                "DECISION_PRODUCED",
                intake_id=intake_id,
                request_id=request_id,
                decision_id=decision_id,
                payload={
                    "outcome": decision.outcome,
                    "reason_codes": list(decision.reason_codes),
                },
            )
            return self._finish_nonexecuting_result(
                audit_start=audit_start,
                intake_id=intake_id,
                decision=decision,
                conflict_count=0,
                started=started,
            )

        required_authority = (
            action_policy.tier_0_required_authority
            if target.criticality == "TIER_0"
            else action_policy.required_authority
        )
        authority = assess_authority(
            request, principal, required_authority=required_authority
        )
        self._append(
            "IDENTITY_EVALUATED",
            intake_id=intake_id,
            request_id=request_id,
            decision_id=decision_id,
            payload=authority.to_dict(),
        )

        try:
            evidence = assess_evidence(
                request,
                evidence_policy=self.policy.evidence,
                attestation_verifier=self.__evidence_attestation_verifier,
                evaluated_at=now,
            )
            self._append(
                "EVIDENCE_EVALUATED",
                intake_id=intake_id,
                request_id=request_id,
                decision_id=decision_id,
                payload=evidence.to_dict(),
            )
            consequence = assess_consequence(
                target=target,
                action_policy=action_policy,
                consequence_policy=self.policy.consequence,
                parameters=request.action.parameters.to_dict(),
            )
            self._append(
                "CONSEQUENCE_EVALUATED",
                intake_id=intake_id,
                request_id=request_id,
                decision_id=decision_id,
                payload=consequence.to_dict(),
            )
            decision = build_decision(
                request=request,
                principal=principal,
                policy=self.policy,
                evidence=evidence,
                consequence=consequence,
                target=target,
                action_policy=action_policy,
                decided_at=now,
                decision_id=decision_id,
                approval_requirement_factory=self.__approval_gate.issue_requirement,
            )
        except Exception as exc:
            self._append(
                "CONTROL_PLANE_FAILURE",
                intake_id=intake_id,
                request_id=request_id,
                decision_id=decision_id,
                payload={
                    "reason_code": "INTERNAL_CONTROL_FAILURE",
                    "stage": type(exc).__name__,
                },
            )
            decision = self._fail_closed_decision(
                decision_id=decision_id,
                request_id=request_id,
                request_sha256=request_sha256,
                principal=principal,
                reason_code="INTERNAL_CONTROL_FAILURE",
                requested_action=request.action.to_dict(),
                decided_at=now,
            )
            self._append(
                "DECISION_PRODUCED",
                intake_id=intake_id,
                request_id=request_id,
                decision_id=decision_id,
                payload={
                    "outcome": decision.outcome,
                    "reason_codes": list(decision.reason_codes),
                },
            )
            return self._finish_nonexecuting_result(
                audit_start=audit_start,
                intake_id=intake_id,
                decision=decision,
                conflict_count=0,
                started=started,
            )

        self._append(
            "POLICY_EVALUATED",
            intake_id=intake_id,
            request_id=request_id,
            decision_id=decision_id,
            payload={
                "policy_id": decision.policy_id,
                "policy_version": decision.policy_version,
                "policy_sha256": decision.policy_sha256,
                "outcome": decision.outcome,
                "applicable_rules": list(decision.applicable_rules),
                "reason_codes": list(decision.reason_codes),
            },
        )
        try:
            decision_verification = self.__decision_verifier.verify(
                request=request,
                principal=principal,
                principal_resolution=principal_resolution,
                policy=self.policy,
                target=target,
                decision=decision,
                evaluated_at=now,
            )
        except Exception as exc:
            self._append(
                "CONTROL_PLANE_FAILURE",
                intake_id=intake_id,
                request_id=request_id,
                decision_id=decision_id,
                payload={
                    "reason_code": "DECISION_VERIFIER_INTERNAL_FAILURE",
                    "stage": type(exc).__name__,
                },
            )
            decision = self._fail_closed_decision(
                decision_id=decision_id,
                request_id=request_id,
                request_sha256=request_sha256,
                principal=principal,
                reason_code="DECISION_VERIFIER_INTERNAL_FAILURE",
                requested_action=request.action.to_dict(),
                decided_at=now,
            )
            self._append(
                "DECISION_PRODUCED",
                intake_id=intake_id,
                request_id=request_id,
                decision_id=decision_id,
                payload={
                    "outcome": decision.outcome,
                    "reason_codes": list(decision.reason_codes),
                    "decision_context_sha256": decision.decision_context_sha256,
                },
            )
            return self._finish_nonexecuting_result(
                audit_start=audit_start,
                intake_id=intake_id,
                decision=decision,
                conflict_count=evidence.conflict_count,
                started=started,
            )
        self._append(
            "DECISION_VERIFIED",
            intake_id=intake_id,
            request_id=request_id,
            decision_id=decision_id,
            payload=decision_verification.to_dict(),
        )
        if not decision_verification.passed:
            explanation = dict(decision.explanation)
            reason_codes = tuple(
                list(decision.reason_codes) + ["DECISION_VERIFIER_FAILED"]
            )
            explanation.update(
                {
                    "decision": DecisionOutcome.DENY.value,
                    "reason_codes": list(reason_codes),
                    "verifier_blockers": list(
                        decision_verification.blocking_reason_codes
                    ),
                    "human_approval_requirement": None,
                }
            )
            decision = replace(
                decision,
                outcome=DecisionOutcome.DENY.value,
                reason_codes=reason_codes,
                applicable_rules=tuple(
                    list(decision.applicable_rules) + ["P3-FAIL-CLOSED-VERIFIER"]
                ),
                permitted_action=None,
                constraints=(),
                approval_requirement=None,
                explanation=explanation,
                decision_context_sha256=sha256_json(
                    {
                        "prior_context": decision.decision_context_sha256,
                        "outcome": DecisionOutcome.DENY.value,
                        "reason_codes": list(reason_codes),
                    }
                ),
            )

        if decision.outcome not in {
            DecisionOutcome.ALLOW.value,
            DecisionOutcome.ALLOW_CONSTRAINED.value,
        }:
            self._append(
                "DECISION_PRODUCED",
                intake_id=intake_id,
                request_id=request_id,
                decision_id=decision_id,
                payload=self._decision_audit_payload(decision),
            )
            if decision.approval_requirement is not None:
                self._append(
                    "APPROVAL_REQUIREMENT_PRODUCED",
                    intake_id=intake_id,
                    request_id=request_id,
                    decision_id=decision_id,
                    payload={
                        "approval_id": decision.approval_requirement.approval_id,
                        "issuer_instance_id": (
                            decision.approval_requirement.issuer_instance_id
                        ),
                        "request_id_bound": decision.approval_requirement.request_id,
                        "decision_id_bound": decision.approval_requirement.decision_id,
                        "decision_context_sha256": (
                            decision.approval_requirement.decision_context_sha256
                        ),
                        "policy_id": decision.approval_requirement.policy_id,
                        "policy_version": decision.approval_requirement.policy_version,
                        "policy_sha256": decision.approval_requirement.policy_sha256,
                        "action_type": decision.approval_requirement.action_type,
                        "target_id": decision.approval_requirement.target_id,
                        "parameters_sha256": (
                            decision.approval_requirement.parameters_sha256
                        ),
                        "evidence_sha256": (
                            decision.approval_requirement.evidence_sha256
                        ),
                        "reason_codes": list(
                            decision.approval_requirement.reason_codes
                        ),
                        "scope_sha256": decision.approval_requirement.scope_sha256,
                        "created_at": decision.approval_requirement.created_at,
                        "expires_at": decision.approval_requirement.expires_at,
                        "status": decision.approval_requirement.status,
                        "required_approving_authority": (
                            decision.approval_requirement.required_approving_authority
                        ),
                    },
                )
            return self._finish_nonexecuting_result(
                audit_start=audit_start,
                intake_id=intake_id,
                decision=decision,
                conflict_count=evidence.conflict_count,
                started=started,
            )

        try:
            state_before = self.observer.observe(target.id)
            token = self.__authorization_gate.issue(
                decision=decision,
                agent_id=principal.id,
                target_state_sha256=sha256_json(state_before),
                decision_verification=decision_verification,
            )
        except Exception as exc:
            self._append(
                "CONTROL_PLANE_FAILURE",
                intake_id=intake_id,
                request_id=request_id,
                decision_id=decision_id,
                payload={
                    "reason_code": "AUTHORIZATION_PRECONDITION_FAILURE",
                    "stage": type(exc).__name__,
                },
            )
            decision = self._fail_closed_decision(
                decision_id=decision_id,
                request_id=request_id,
                request_sha256=request_sha256,
                principal=principal,
                reason_code="AUTHORIZATION_PRECONDITION_FAILURE",
                requested_action=request.action.to_dict(),
                decided_at=now,
            )
            self._append(
                "DECISION_PRODUCED",
                intake_id=intake_id,
                request_id=request_id,
                decision_id=decision_id,
                payload={
                    "outcome": decision.outcome,
                    "reason_codes": list(decision.reason_codes),
                    "decision_context_sha256": decision.decision_context_sha256,
                },
            )
            return self._finish_nonexecuting_result(
                audit_start=audit_start,
                intake_id=intake_id,
                decision=decision,
                conflict_count=evidence.conflict_count,
                started=started,
            )

        self._append(
            "DECISION_PRODUCED",
            intake_id=intake_id,
            request_id=request_id,
            decision_id=decision_id,
            payload=self._decision_audit_payload(decision),
        )
        self._append(
            "AUTHORIZATION_PRODUCED",
            intake_id=intake_id,
            request_id=request_id,
            decision_id=decision_id,
            payload={
                "token_id": token.token_id,
                "agent_id": token.agent_id,
                "action_type": token.action_type,
                "target_id": token.target_id,
                "permitted_parameters": token.permitted_parameters,
                "parameters_sha256": sha256_json(token.permitted_parameters),
                "issued_at": token.issued_at,
                "expires_at": token.expires_at,
                "policy_id": token.policy_id,
                "policy_version": token.policy_version,
                "policy_sha256": token.policy_sha256,
                "decision_context_sha256": token.decision_context_sha256,
                "decision_sha256": decision_verification.decision_sha256,
                "request_sha256": decision_verification.request_sha256,
                "target_state_sha256": token.target_state_sha256,
            },
        )
        command = decision.to_dict()["permitted_action"] or {}
        decision_projection = decision.to_dict()
        authorization_projection = dict(decision_projection)
        authorization_projection.pop("latency_ms", None)
        authorization_projection.pop("explanation", None)
        authorization_projection.pop("approval_requirement", None)
        decision_authorization_sha256 = sha256_json(authorization_projection)
        recovery_summary = {
            "summary_version": "1",
            "principal_id": principal.id,
            "request_id": request_id,
            "request_sha256": request_sha256,
            "decision_id": decision_id,
            "decision_outcome": decision.outcome,
            "decision_sha256": decision.authorization_sha256(),
            "decision_context_sha256": decision.decision_context_sha256,
            "policy_sha256": decision.policy_sha256,
            "decided_at": decision.decided_at,
        }
        self._append(
            "BROKER_INVOKED",
            intake_id=intake_id,
            request_id=request_id,
            decision_id=decision_id,
            payload={
                "token_id": token.token_id,
                "action_type": command.get("type"),
                "target_id": command.get("target"),
                "parameters_sha256": sha256_json(command.get("parameters", {})),
            },
        )
        try:
            broker_result = self.__broker.execute(
                token=token,
                command=command,
                request_id=request_id,
                decision_id=decision_id,
                agent_id=principal.id,
                policy_id=self.policy.policy_id,
                policy_version=self.policy.version,
                policy_sha256=self._policy_sha256,
                decision_context_sha256=decision.decision_context_sha256,
                request_sha256=request_sha256,
                decision_authorization_sha256=decision_authorization_sha256,
                recovery_summary=recovery_summary,
            )
        except AuthorizationError as exc:
            self._append(
                "BROKER_REJECTED",
                intake_id=intake_id,
                request_id=request_id,
                decision_id=decision_id,
                payload={"token_id": token.token_id, "reason_code": exc.reason_code},
            )
            self._append(
                "ACTION_SKIPPED",
                intake_id=intake_id,
                request_id=request_id,
                decision_id=decision_id,
                payload={"operational_effects": 0, "reason_code": exc.reason_code},
            )
            self._append(
                "VERIFICATION_SKIPPED",
                intake_id=intake_id,
                request_id=request_id,
                decision_id=decision_id,
                payload={"status": "NOT_APPLICABLE", "reason_code": exc.reason_code},
            )
            # The closed broker authorizes before mutation, so an authorization
            # rejection cannot have changed the target. Reuse the trusted
            # pre-state rather than introducing another fallible dependency.
            final_state = state_before
            latency_ms = round((perf_counter() - started) * 1000.0, 6)
            decision = replace(decision, latency_ms=latency_ms)
            self._append(
                "FINAL_STATE_RECORDED",
                intake_id=intake_id,
                request_id=request_id,
                decision_id=decision_id,
                payload={
                    "outcome": decision.outcome,
                    "operational_effects": 0,
                    "target_state_sha256": sha256_json(final_state),
                },
            )
            self._metrics.record_decision(
                decision.outcome,
                policy_rules=decision.applicable_rules,
                evidence_conflicts=evidence.conflict_count,
                latency_ms=latency_ms,
            )
            return self._validated_result(
                Phase3Result(
                    decision=decision,
                    authorization=token,
                    broker_result=None,
                    verification=None,
                    final_state=final_state,
                    audit_records=self._audit_rows(audit_start),
                )
            )
        except Exception as exc:
            try:
                final_state = self.observer.observe(target.id)
                observation_failed = False
            except Exception:
                final_state = {
                    "target_id": token.target_id,
                    "state_unavailable": True,
                }
                observation_failed = True
            operational_effects = int(observation_failed or final_state != state_before)
            status = (
                VerificationStatus.ROLLBACK_REQUIRED.value
                if operational_effects
                else VerificationStatus.FAILED.value
            )
            attempt_id = getattr(exc, "attempt_id", None) or _deterministic_failure_id(
                "failed-attempt", token.token_id, request_id, decision_id
            )
            verification = PostActionVerification(
                verification_id=_deterministic_failure_id(
                    "verify", token.token_id, attempt_id
                ),
                request_id=request_id,
                decision_id=decision_id,
                attempt_id=attempt_id,
                token_id=token.token_id,
                action_type=token.action_type,
                target_id=token.target_id,
                parameters_sha256=sha256_json(token.permitted_parameters),
                status=status,
                expected_state={
                    "action_type": token.action_type,
                    "target_id": token.target_id,
                    "last_action_id": attempt_id,
                },
                observed_state=final_state,
                changed_fields=tuple(
                    sorted(
                        key
                        for key in set(state_before) | set(final_state)
                        if state_before.get(key) != final_state.get(key)
                    )
                ),
                unexpected_fields=(),
                rollback_required=bool(operational_effects),
                reason_codes=(
                    "BROKER_INTERNAL_FAILURE",
                    *(
                        ("POST_ACTION_OBSERVATION_FAILED",)
                        if observation_failed
                        else ()
                    ),
                    *(("ROLLBACK_REQUIRED",) if operational_effects else ()),
                ),
            )
            self._metrics.record_broker_rejection()
            self._metrics.record_verification_failure()
            self._append(
                "BROKER_FAILURE",
                intake_id=intake_id,
                request_id=request_id,
                decision_id=decision_id,
                payload={
                    "token_id": token.token_id,
                    "reason_code": "BROKER_INTERNAL_FAILURE",
                    "stage": type(exc).__name__,
                },
            )
            self._append(
                "ACTION_ATTEMPTED",
                intake_id=intake_id,
                request_id=request_id,
                decision_id=decision_id,
                payload={
                    "attempt_id": attempt_id,
                    "token_id": token.token_id,
                    "outcome_known": False,
                    "operational_effects": operational_effects,
                },
            )
            self._append(
                "VERIFICATION_PERFORMED",
                intake_id=intake_id,
                request_id=request_id,
                decision_id=decision_id,
                payload=verification.to_dict(),
            )
            latency_ms = round((perf_counter() - started) * 1000.0, 6)
            decision = replace(decision, latency_ms=latency_ms)
            self._append(
                "FINAL_STATE_RECORDED",
                intake_id=intake_id,
                request_id=request_id,
                decision_id=decision_id,
                payload={
                    "outcome": decision.outcome,
                    "verification_status": status,
                    "operational_effects": operational_effects,
                    "target_state_sha256": sha256_json(final_state),
                },
            )
            self._metrics.record_decision(
                decision.outcome,
                policy_rules=decision.applicable_rules,
                evidence_conflicts=evidence.conflict_count,
                latency_ms=latency_ms,
            )
            return self._validated_result(
                Phase3Result(
                    decision=decision,
                    authorization=token,
                    broker_result=None,
                    verification=verification,
                    final_state=final_state,
                    audit_records=self._audit_rows(audit_start),
                )
            )

        try:
            self._append(
                "ACTION_ATTEMPTED",
                intake_id=intake_id,
                request_id=request_id,
                decision_id=decision_id,
                payload=broker_result.to_dict(),
            )
        except Exception as exc:
            return self._close_post_effect_accounting_failure(
                failed_record_type="ACTION_ATTEMPTED",
                failure=exc,
                audit_start=audit_start,
                intake_id=intake_id,
                request_id=request_id,
                decision_id=decision_id,
                decision=decision,
                evidence_conflict_count=evidence.conflict_count,
                started=started,
                token=token,
                command=command,
                broker_result=broker_result,
                state_before=state_before,
            )
        try:
            verification = self.__target_verifier.verify(
                request_id=request_id,
                decision_id=decision_id,
                broker_result=broker_result,
                state_before=state_before,
                token=token,
                permitted_command=command,
            )
        except Exception as exc:
            try:
                observed_after_failure = self.observer.observe(token.target_id)
                observation_failed = False
            except Exception:
                observed_after_failure = {
                    "target_id": token.target_id,
                    "state_unavailable": True,
                }
                observation_failed = True
            state_changed = observation_failed or observed_after_failure != state_before
            self._metrics.record_verification_failure()
            verification = PostActionVerification(
                verification_id=_deterministic_failure_id(
                    "verify", token.token_id, broker_result.attempt_id
                ),
                request_id=token.request_id,
                decision_id=token.decision_id,
                attempt_id=broker_result.attempt_id,
                token_id=token.token_id,
                action_type=token.action_type,
                target_id=token.target_id,
                parameters_sha256=sha256_json(token.permitted_parameters),
                status=(
                    VerificationStatus.ROLLBACK_REQUIRED.value
                    if state_changed
                    else VerificationStatus.FAILED.value
                ),
                expected_state={
                    "action_type": token.action_type,
                    "target_id": token.target_id,
                    "last_action_id": broker_result.attempt_id,
                },
                observed_state=observed_after_failure,
                changed_fields=tuple(
                    sorted(
                        key
                        for key in set(state_before) | set(observed_after_failure)
                        if state_before.get(key) != observed_after_failure.get(key)
                    )
                ),
                unexpected_fields=(),
                rollback_required=state_changed,
                reason_codes=(
                    "VERIFIER_INTERNAL_FAILURE",
                    type(exc).__name__,
                    *(
                        ("POST_ACTION_OBSERVATION_FAILED",)
                        if observation_failed
                        else ()
                    ),
                    *(("ROLLBACK_REQUIRED",) if state_changed else ()),
                ),
            )
        try:
            self._append(
                "VERIFICATION_PERFORMED",
                intake_id=intake_id,
                request_id=request_id,
                decision_id=decision_id,
                payload=verification.to_dict(),
            )
        except Exception as exc:
            return self._close_post_effect_accounting_failure(
                failed_record_type="VERIFICATION_PERFORMED",
                failure=exc,
                audit_start=audit_start,
                intake_id=intake_id,
                request_id=request_id,
                decision_id=decision_id,
                decision=decision,
                evidence_conflict_count=evidence.conflict_count,
                started=started,
                token=token,
                command=command,
                broker_result=broker_result,
                state_before=state_before,
                verification=verification,
            )
        final_state = dict(verification.observed_state)
        operational_effects = int(final_state != state_before)
        latency_ms = round((perf_counter() - started) * 1000.0, 6)
        decision = replace(decision, latency_ms=latency_ms)
        try:
            self._append(
                "FINAL_STATE_RECORDED",
                intake_id=intake_id,
                request_id=request_id,
                decision_id=decision_id,
                payload={
                    "outcome": decision.outcome,
                    "verification_status": verification.status,
                    "operational_effects": operational_effects,
                    "target_state_sha256": sha256_json(final_state),
                },
            )
        except Exception as exc:
            return self._close_post_effect_accounting_failure(
                failed_record_type="FINAL_STATE_RECORDED",
                failure=exc,
                audit_start=audit_start,
                intake_id=intake_id,
                request_id=request_id,
                decision_id=decision_id,
                decision=decision,
                evidence_conflict_count=evidence.conflict_count,
                started=started,
                token=token,
                command=command,
                broker_result=broker_result,
                state_before=state_before,
                verification=verification,
            )
        self._metrics.record_decision(
            decision.outcome,
            policy_rules=decision.applicable_rules,
            evidence_conflicts=evidence.conflict_count,
            latency_ms=latency_ms,
        )
        return self._validated_result(
            Phase3Result(
                decision=decision,
                authorization=token,
                broker_result=broker_result,
                verification=verification,
                final_state=final_state,
                audit_records=self._audit_rows(audit_start),
            )
        )

    def metrics_snapshot(self) -> dict[str, Any]:
        return self._metrics.snapshot()

    def readiness_snapshot(self) -> dict[str, Any]:
        """Read-only integrity check for the bounded durable service profile."""

        with (
            self._exclusive_audit_execution(allow_pending_recovery=True),
            self._process_lock,
        ):
            policy_valid = (
                sha256_json(Phase3PolicyConfig.to_dict(self._policy))
                == self._policy_sha256
            )
            rows = self._audit.read_all()
            audit_valid, _audit_errors = validate_phase3_audit_chain(rows)
            pending_recovery = self._pending_recovery_tail(rows) is not None
            durable = (
                type(self._control_ledger) is SQLiteControlLedger
                and self._adapter_store is not None
                and self._audit.path is not None
            )
            if durable:
                self._assert_durable_store_correlation()
            ready = policy_valid and audit_valid and durable and not pending_recovery
            return {
                "status": "READY" if ready else "NOT_READY",
                "runtime_profile": "STAGE_A_SYNTHETIC_ONLY",
                "execution_mode": self.execution_mode,
                "live_actions_enabled": False,
                "durable_state_configured": durable,
                "policy_integrity_valid": policy_valid,
                "audit_chain_valid": audit_valid,
                "pending_recovery": pending_recovery,
            }

    def read_audit(self) -> tuple[dict[str, Any], ...]:
        if self._audit.path is None:
            return tuple(self._audit.read_all())
        with (
            self._exclusive_audit_execution(
                allow_pending_recovery=True,
                allow_incomplete_lifecycle=True,
            ),
            self._process_lock,
        ):
            return tuple(self._audit.read_all())

    def approve_for_reevaluation(
        self,
        *,
        requirement: ApprovalRequirement,
        credential: bytes,
        action_type: str,
        target_id: str,
        parameters: dict[str, Any],
        evidence_sha256: str,
    ) -> ApprovalReceipt:
        """Record exact human approval for later reevaluation; never execute."""

        with self._exclusive_audit_execution(), self._process_lock:
            matching_rows = [
                row
                for row in self._audit.read_all()
                if row.get("payload", {}).get("decision_id") == requirement.decision_id
            ]
            intake_id = (
                str(matching_rows[-1]["payload"]["intake_id"])
                if matching_rows
                else f"approval-{requirement.request_id}"
            )

            def commit_receipt(receipt: ApprovalReceipt) -> None:
                receipt_payload = {
                    "approval_id": requirement.approval_id,
                    "receipt_id": receipt.receipt_id,
                    "issuer_instance_id": receipt.issuer_instance_id,
                    "approver_id": receipt.approver_id,
                    "approving_authority": receipt.approving_authority,
                    "action_type": receipt.action_type,
                    "target_id": receipt.target_id,
                    "parameters_sha256": receipt.parameters_sha256,
                    "evidence_sha256": receipt.evidence_sha256,
                    "requirement_scope_sha256": (receipt.requirement_scope_sha256),
                    "status": receipt.status,
                    "approved_at": receipt.approved_at,
                    "reevaluation_required": True,
                    "authorization_produced": False,
                }
                existing = [
                    row
                    for row in self._audit.read_all()
                    if row.get("record_type") == "APPROVAL_RECORDED"
                    and row.get("payload", {}).get("approval_id")
                    == requirement.approval_id
                ]
                expected_full_payload = {
                    "intake_id": intake_id,
                    "request_id": requirement.request_id,
                    "decision_id": requirement.decision_id,
                    **receipt_payload,
                }
                if existing:
                    if len(existing) == 1 and canonical_json(
                        existing[0].get("payload")
                    ) == canonical_json(expected_full_payload):
                        return
                    raise ApprovalError(
                        "APPROVAL_AUDIT_CONFLICT",
                        "Approval audit already contains a conflicting receipt.",
                    )
                self._append(
                    "APPROVAL_RECORDED",
                    intake_id=intake_id,
                    request_id=requirement.request_id,
                    decision_id=requirement.decision_id,
                    payload=receipt_payload,
                )

            receipt = self.__approval_gate.approve(
                requirement=requirement,
                credential=credential,
                action_type=action_type,
                target_id=target_id,
                parameters=parameters,
                evidence_sha256=evidence_sha256,
                commit_receipt=commit_receipt,
            )
            return receipt
