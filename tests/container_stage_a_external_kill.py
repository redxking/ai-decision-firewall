from __future__ import annotations

import json
import os
from datetime import datetime
from pathlib import Path
import signal
import sys
from unittest.mock import patch

from adf_poc.audit import AuditLogger
from adf_poc.phase3.audit import validate_phase3_audit_chain
from adf_poc.phase3.scenarios import request_json
from adf_poc.stage_a import SQLiteControlLedger, SQLiteSyntheticAdapterStore
from tests.phase3_support import new_harness, workstation_case


CAMPAIGN_TIME = "2026-08-20T15:00:00+00:00"
STATE_ROOT = Path("/state")
CONTROL_ROOT = Path("/campaign-control")
BOUNDARIES = ("T1", "OBSERVATION", "T2", "AUDIT", "T3")


def _harness():
    return new_harness(
        now=datetime.fromisoformat(CAMPAIGN_TIME),
        audit_path=STATE_ROOT / "audit.jsonl",
        control_ledger_path=STATE_ROOT / "control.sqlite3",
        synthetic_adapter_path=STATE_ROOT / "adapter.sqlite3",
    )


def _request(harness, boundary: str) -> str:
    return request_json(
        workstation_case(
            harness,
            request_id=f"P3-STAGE-A-EXTERNAL-KILL-{boundary}",
        )
    )


def _mark_boundary(boundary: str) -> None:
    marker = CONTROL_ROOT / f"{boundary.lower()}.ready"
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0)
    descriptor = os.open(marker, flags, 0o600)
    try:
        os.write(descriptor, b"READY\n")
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    directory_descriptor = os.open(
        CONTROL_ROOT,
        os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_CLOEXEC", 0),
    )
    try:
        os.fsync(directory_descriptor)
    finally:
        os.close(directory_descriptor)
    while True:
        signal.pause()


def run_worker(boundary: str) -> None:
    if os.environ.get("ADF_CONTAINER_EXTERNAL_KILL_CAMPAIGN") != "1":
        raise RuntimeError(
            "External-kill worker requires the explicit campaign marker."
        )
    if boundary not in BOUNDARIES:
        raise ValueError(f"Unsupported external-kill boundary: {boundary}")
    harness = _harness()
    raw = _request(harness, boundary)

    if boundary == "T1":
        original = SQLiteControlLedger.consume_once

        def after_t1(self, *args, **kwargs):
            result = original(self, *args, **kwargs)
            _mark_boundary(boundary)
            return result  # pragma: no cover - the host kills the container

        target = SQLiteControlLedger
        attribute = "consume_once"
        replacement = after_t1
    elif boundary == "T2":
        original = SQLiteControlLedger.record_adapter_receipt

        def after_t2(self, *args, **kwargs):
            result = original(self, *args, **kwargs)
            _mark_boundary(boundary)
            return result  # pragma: no cover - the host kills the container

        target = SQLiteControlLedger
        attribute = "record_adapter_receipt"
        replacement = after_t2
    elif boundary == "OBSERVATION":
        original = SQLiteSyntheticAdapterStore.observe
        calls = 0

        def after_observation(self, *args, **kwargs):
            nonlocal calls
            result = original(self, *args, **kwargs)
            calls += 1
            if calls == 3:
                _mark_boundary(boundary)
            return result

        target = SQLiteSyntheticAdapterStore
        attribute = "observe"
        replacement = after_observation
    elif boundary == "AUDIT":
        original = AuditLogger.append

        def after_audit(self, record_type, payload):
            result = original(self, record_type, payload)
            if record_type == "FINAL_STATE_RECORDED":
                _mark_boundary(boundary)
            return result

        target = AuditLogger
        attribute = "append"
        replacement = after_audit
    else:
        original = SQLiteControlLedger.complete_request

        def after_t3(self, *args, **kwargs):
            result = original(self, *args, **kwargs)
            _mark_boundary(boundary)
            return result  # pragma: no cover - the host kills the container

        target = SQLiteControlLedger
        attribute = "complete_request"
        replacement = after_t3

    with patch.object(target, attribute, replacement):
        harness.firewall.process_json(raw, credential=harness.soc_credential)
    raise AssertionError("Worker returned without an external container kill.")


def verify_restart(boundary: str) -> dict[str, object]:
    if boundary not in BOUNDARIES:
        raise ValueError(f"Unsupported external-kill boundary: {boundary}")
    expected_receipts = 0 if boundary == "T1" else 1
    expected_state = "connected" if boundary == "T1" else "isolated"
    terminal = boundary == "T3"
    harness = _harness()
    raw = _request(harness, boundary)
    receipts_before = harness.firewall._adapter_store.receipt_count()
    observed_state = harness.firewall.observer.observe("WORKSTATION_042")[
        "network_state"
    ]
    if receipts_before != expected_receipts or observed_state != expected_state:
        raise AssertionError(
            f"Unexpected durable state after {boundary}: "
            f"receipts={receipts_before}, state={observed_state}"
        )

    lookup = harness.firewall.lookup_request_result(
        raw, credential=harness.soc_credential
    )
    if terminal:
        if lookup is None or lookup.disposition != "COMPLETED_VERIFIED":
            raise AssertionError(
                "T3 restart did not return the durable terminal result."
            )
        replay = harness.firewall.process_json(raw, credential=harness.soc_credential)
        if "DUPLICATE_REQUEST" not in replay.decision.reason_codes:
            raise AssertionError("T3 replay was not classified as an exact duplicate.")
        disposition = lookup.disposition
    else:
        if lookup is not None:
            raise AssertionError("Nonterminal restart exposed a terminal result.")
        recovered = harness.firewall.reconcile_request(
            raw,
            credential=harness.soc_credential,
            operator_asserted_quiesced=True,
        )
        if recovered is None or recovered.disposition != "UNKNOWN_EFFECT":
            raise AssertionError("Nonterminal restart did not close conservatively.")
        if recovered.new_effect:
            raise AssertionError("Recovery issued a new effect.")
        disposition = recovered.disposition

    receipts_after = harness.firewall._adapter_store.receipt_count()
    if receipts_after != expected_receipts:
        raise AssertionError("Restart or recovery duplicated the adapter effect.")
    valid, errors = validate_phase3_audit_chain(
        AuditLogger(STATE_ROOT / "audit.jsonl").read_all()
    )
    if not valid:
        raise AssertionError(errors)
    return {
        "audit_chain_valid": True,
        "boundary": boundary,
        "disposition": disposition,
        "network_state": observed_state,
        "receipts_after": receipts_after,
        "receipts_before": receipts_before,
    }


def main(argv: list[str]) -> int:
    if len(argv) != 3 or argv[1] not in {"worker", "verify"}:
        raise SystemExit(
            "usage: container_stage_a_external_kill.py worker|verify BOUNDARY"
        )
    mode, boundary = argv[1:]
    if mode == "worker":
        run_worker(boundary)
    else:
        print(json.dumps(verify_restart(boundary), sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
