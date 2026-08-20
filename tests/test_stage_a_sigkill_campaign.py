from __future__ import annotations

from datetime import datetime
import multiprocessing
import os
from pathlib import Path
import signal
import tempfile
import unittest
from unittest.mock import patch

from adf_poc.audit import AuditLogger
from adf_poc.phase3.scenarios import request_json
from adf_poc.stage_a import SQLiteControlLedger, SQLiteSyntheticAdapterStore
from tests.phase3_support import new_harness, workstation_case


def _terminate_after_committed_boundary(
    root_text: str,
    raw_request: str,
    now_text: str,
    boundary: str,
) -> None:
    """SIGKILL the worker immediately after one selected durable boundary."""

    root = Path(root_text)
    harness = new_harness(
        now=datetime.fromisoformat(now_text),
        audit_path=root / "audit.jsonl",
        control_ledger_path=root / "control.sqlite3",
        synthetic_adapter_path=root / "adapter.sqlite3",
    )

    if boundary == "CLAIM":
        original = SQLiteControlLedger.claim_request

        def after_claim(self, *args, **kwargs):
            result = original(self, *args, **kwargs)
            os.kill(os.getpid(), signal.SIGKILL)
            return result  # pragma: no cover - SIGKILL is uncatchable

        target = SQLiteControlLedger
        attribute = "claim_request"
        replacement = after_claim
    elif boundary == "AUTHORIZATION":
        original = SQLiteControlLedger.register

        def after_authorization(self, *args, **kwargs):
            result = original(self, *args, **kwargs)
            os.kill(os.getpid(), signal.SIGKILL)
            return result  # pragma: no cover - SIGKILL is uncatchable

        target = SQLiteControlLedger
        attribute = "register"
        replacement = after_authorization
    elif boundary == "T1":
        original = SQLiteControlLedger.consume_once

        def after_t1(self, *args, **kwargs):
            result = original(self, *args, **kwargs)
            os.kill(os.getpid(), signal.SIGKILL)
            return result  # pragma: no cover - SIGKILL is uncatchable

        target = SQLiteControlLedger
        attribute = "consume_once"
        replacement = after_t1
    elif boundary == "T2":
        original = SQLiteControlLedger.record_adapter_receipt

        def after_t2(self, *args, **kwargs):
            result = original(self, *args, **kwargs)
            os.kill(os.getpid(), signal.SIGKILL)
            return result  # pragma: no cover - SIGKILL is uncatchable

        target = SQLiteControlLedger
        attribute = "record_adapter_receipt"
        replacement = after_t2
    elif boundary == "OBSERVATION":
        original = SQLiteSyntheticAdapterStore.observe
        calls = 0

        def after_post_effect_observation(self, *args, **kwargs):
            nonlocal calls
            result = original(self, *args, **kwargs)
            calls += 1
            # The engine obtains one authorization pre-state and the broker
            # obtains its own precondition snapshot before this third,
            # post-effect observation.
            if calls == 3:
                os.kill(os.getpid(), signal.SIGKILL)
            return result

        target = SQLiteSyntheticAdapterStore
        attribute = "observe"
        replacement = after_post_effect_observation
    elif boundary == "AUDIT":
        original = AuditLogger.append

        def after_closed_audit(self, record_type, payload):
            result = original(self, record_type, payload)
            if record_type == "FINAL_STATE_RECORDED":
                os.kill(os.getpid(), signal.SIGKILL)
            return result

        target = AuditLogger
        attribute = "append"
        replacement = after_closed_audit
    elif boundary == "T3":
        original = SQLiteControlLedger.complete_request

        def after_t3(self, *args, **kwargs):
            result = original(self, *args, **kwargs)
            os.kill(os.getpid(), signal.SIGKILL)
            return result  # pragma: no cover - SIGKILL is uncatchable

        target = SQLiteControlLedger
        attribute = "complete_request"
        replacement = after_t3
    else:  # pragma: no cover - the parent supplies a closed boundary
        os._exit(98)

    with patch.object(target, attribute, replacement):
        harness.firewall.process_json(raw_request, credential=harness.soc_credential)
    os._exit(99)


class StageASigkillCampaignTests(unittest.TestCase):
    def test_sigkill_at_committed_boundaries_never_duplicates_effect(self) -> None:
        expected = {
            "CLAIM": (0, "connected", "ABORTED_NO_EFFECT"),
            "AUTHORIZATION": (0, "connected", "ABORTED_NO_EFFECT"),
            "T1": (0, "connected", "UNKNOWN_EFFECT"),
            "T2": (1, "isolated", "UNKNOWN_EFFECT"),
            "OBSERVATION": (1, "isolated", "UNKNOWN_EFFECT"),
            "AUDIT": (1, "isolated", "UNKNOWN_EFFECT"),
            "T3": (1, "isolated", "COMPLETED_VERIFIED"),
        }
        for boundary, (
            expected_receipts,
            expected_network_state,
            expected_disposition,
        ) in expected.items():
            with (
                self.subTest(boundary=boundary),
                tempfile.TemporaryDirectory() as directory,
            ):
                root = Path(directory).resolve()
                seed = new_harness()
                now = seed.clock()
                raw = request_json(
                    workstation_case(
                        seed,
                        request_id=f"P3-STAGE-A-SIGKILL-{boundary}",
                    )
                )
                context = multiprocessing.get_context("spawn")
                process = context.Process(
                    target=_terminate_after_committed_boundary,
                    args=(str(root), raw, now.isoformat(), boundary),
                )
                process.start()
                process.join(timeout=30)
                if process.is_alive():  # pragma: no cover - bounded cleanup
                    process.kill()
                    process.join(timeout=5)
                    self.fail(f"{boundary} SIGKILL worker exceeded its bound")
                self.assertEqual(process.exitcode, -signal.SIGKILL)

                reopened = new_harness(
                    now=now,
                    audit_path=root / "audit.jsonl",
                    control_ledger_path=root / "control.sqlite3",
                    synthetic_adapter_path=root / "adapter.sqlite3",
                )
                self.assertEqual(
                    reopened.firewall._adapter_store.receipt_count(),
                    expected_receipts,
                )
                self.assertEqual(
                    reopened.firewall.observer.observe("WORKSTATION_042")[
                        "network_state"
                    ],
                    expected_network_state,
                )

                lookup = reopened.firewall.lookup_request_result(
                    raw, credential=reopened.soc_credential
                )
                if expected_disposition == "COMPLETED_VERIFIED":
                    self.assertIsNotNone(lookup)
                    assert lookup is not None
                    self.assertEqual(lookup.disposition, "COMPLETED_VERIFIED")
                    replay = reopened.firewall.process_json(
                        raw, credential=reopened.soc_credential
                    )
                    self.assertIn("DUPLICATE_REQUEST", replay.decision.reason_codes)
                    self.assertIsNone(replay.broker_result)
                else:
                    self.assertIsNone(lookup)
                    recovered = reopened.firewall.reconcile_request(
                        raw,
                        credential=reopened.soc_credential,
                        operator_asserted_quiesced=True,
                    )
                    self.assertIsNotNone(recovered)
                    assert recovered is not None
                    self.assertEqual(recovered.disposition, expected_disposition)
                    self.assertFalse(recovered.new_effect)

                self.assertEqual(
                    reopened.firewall._adapter_store.receipt_count(),
                    expected_receipts,
                )


if __name__ == "__main__":
    unittest.main()
