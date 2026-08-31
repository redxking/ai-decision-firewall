from __future__ import annotations

from collections import Counter
from concurrent.futures import ThreadPoolExecutor
import os
from pathlib import Path
import tempfile
import threading
from time import perf_counter
import unittest

from adf_poc.audit import AuditLogger
from adf_poc.phase3.audit import validate_phase3_audit_chain
from adf_poc.phase3.scenarios import request_json
from tests.phase3_support import new_harness, workstation_case


REQUEST_COUNT = 16
WORKERS = 4
PER_OPERATION_DEADLINE_SECONDS = 30.0
CAMPAIGN_DEADLINE_SECONDS = 60.0
LOCK_ACQUISITION_TIMEOUT_MS = 20_000
MAX_ARTIFACT_BYTES = 16 * 1024 * 1024


def _descriptor_count() -> int | None:
    for candidate in (Path("/proc/self/fd"), Path("/dev/fd")):
        try:
            return len(tuple(candidate.iterdir()))
        except OSError:
            continue
    return None


class StageABoundedLoadTests(unittest.TestCase):
    def test_concurrent_intake_and_lookup_preserve_durable_invariants(self) -> None:
        self.assertLess(
            LOCK_ACQUISITION_TIMEOUT_MS / 1000,
            PER_OPERATION_DEADLINE_SECONDS,
        )
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            audit_path = root / "audit.jsonl"
            control_path = root / "control.sqlite3"
            adapter_path = root / "adapter.sqlite3"
            harness = new_harness(
                audit_path=audit_path,
                control_ledger_path=control_path,
                control_ledger_busy_timeout_ms=LOCK_ACQUISITION_TIMEOUT_MS,
                synthetic_adapter_path=adapter_path,
                synthetic_adapter_busy_timeout_ms=LOCK_ACQUISITION_TIMEOUT_MS,
            )
            requests = tuple(
                request_json(
                    workstation_case(
                        harness,
                        request_id=f"P3-STAGE-A-BOUNDED-LOAD-{index:03d}",
                    )
                )
                for index in range(REQUEST_COUNT)
            )
            baseline_threads = threading.active_count()
            baseline_descriptors = _descriptor_count()

            def process(raw: str):
                started = perf_counter()
                result = harness.firewall.process_json(
                    raw, credential=harness.soc_credential
                )
                return result, perf_counter() - started

            campaign_started = perf_counter()
            with ThreadPoolExecutor(max_workers=WORKERS) as executor:
                processed = tuple(executor.map(process, requests))
            intake_elapsed = perf_counter() - campaign_started

            results = tuple(row[0] for row in processed)
            intake_latencies = tuple(row[1] for row in processed)
            self.assertLess(intake_elapsed, CAMPAIGN_DEADLINE_SECONDS)
            self.assertLess(max(intake_latencies), PER_OPERATION_DEADLINE_SECONDS)
            self.assertEqual(
                Counter(result.decision.outcome for result in results),
                {"ALLOW": REQUEST_COUNT},
            )
            self.assertTrue(
                all(
                    result.verification is not None
                    and result.verification.status == "VERIFIED"
                    for result in results
                )
            )
            self.assertEqual(
                harness.firewall._adapter_store.receipt_count(), REQUEST_COUNT
            )

            outbox = harness.firewall._control_ledger.pending_outbox()
            self.assertEqual(len(outbox), REQUEST_COUNT * 7)
            self.assertEqual(
                Counter(row["event_type"] for row in outbox),
                {
                    "REQUEST_CLAIMED": REQUEST_COUNT,
                    "AUTHORIZATION_ISSUED": REQUEST_COUNT,
                    "ATTEMPT_RESERVED": REQUEST_COUNT,
                    "AUTHORIZATION_CONSUMED": REQUEST_COUNT,
                    "ADAPTER_RECEIPT_RECORDED": REQUEST_COUNT,
                    "ATTEMPT_TERMINAL": REQUEST_COUNT,
                    "REQUEST_TERMINAL": REQUEST_COUNT,
                },
            )

            def lookup(raw: str):
                started = perf_counter()
                result = harness.firewall.lookup_request_result(
                    raw, credential=harness.soc_credential
                )
                return result, perf_counter() - started

            with ThreadPoolExecutor(max_workers=WORKERS) as executor:
                looked_up = tuple(executor.map(lookup, reversed(requests)))
            lookup_latencies = tuple(row[1] for row in looked_up)
            self.assertLess(max(lookup_latencies), PER_OPERATION_DEADLINE_SECONDS)
            self.assertTrue(
                all(
                    row[0] is not None
                    and row[0].disposition == "COMPLETED_VERIFIED"
                    and row[0].new_effect is False
                    for row in looked_up
                )
            )
            self.assertEqual(
                harness.firewall._adapter_store.receipt_count(), REQUEST_COUNT
            )

            rows = AuditLogger(audit_path).read_all()
            valid, errors = validate_phase3_audit_chain(rows)
            self.assertTrue(valid, errors)
            types = Counter(row["record_type"] for row in rows)
            self.assertEqual(types["REQUEST_RECEIVED"], REQUEST_COUNT)
            self.assertEqual(types["FINAL_STATE_RECORDED"], REQUEST_COUNT)

            reopened = new_harness(
                now=harness.clock(),
                audit_path=audit_path,
                control_ledger_path=control_path,
                control_ledger_busy_timeout_ms=LOCK_ACQUISITION_TIMEOUT_MS,
                synthetic_adapter_path=adapter_path,
                synthetic_adapter_busy_timeout_ms=LOCK_ACQUISITION_TIMEOUT_MS,
            )
            self.assertEqual(
                reopened.firewall._adapter_store.receipt_count(), REQUEST_COUNT
            )
            self.assertEqual(
                len(reopened.firewall._control_ledger.pending_outbox()),
                REQUEST_COUNT * 7,
            )
            for path in (audit_path, control_path, adapter_path):
                self.assertGreater(path.stat().st_size, 0)
                self.assertLess(path.stat().st_size, MAX_ARTIFACT_BYTES)

            self.assertLessEqual(threading.active_count(), baseline_threads + 1)
            final_descriptors = _descriptor_count()
            if baseline_descriptors is not None and final_descriptors is not None:
                self.assertLessEqual(final_descriptors, baseline_descriptors + 8)


if __name__ == "__main__":
    unittest.main()
