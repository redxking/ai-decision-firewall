from __future__ import annotations

import copy
import json
import unittest
from datetime import datetime, timedelta, timezone

from adf_poc.lab_contracts import (
    COMMAND,
    OBSERVATION,
    RECEIPT,
    LabContractError,
    lab_message_sha256,
    load_authenticated_lab_message,
    observation_facts_sha256,
    sign_lab_message,
    validate_lab_channel_keys,
    validate_lab_message_correlation,
    validate_lab_message_dict,
)
from adf_poc.utils import canonical_json


NOW = datetime(2026, 8, 20, 18, 0, tzinfo=timezone.utc)
EXECUTOR_KEY = b"executor-channel-key".ljust(32, b"!")
OBSERVER_KEY = b"observer-channel-key".ljust(32, b"!")
EXECUTOR_KEY_ID = "LAB_EXECUTOR_KEY_001"
OBSERVER_KEY_ID = "LAB_OBSERVER_KEY_001"


def _timestamp(value: datetime) -> str:
    return value.astimezone(timezone.utc).replace(microsecond=0).isoformat()


def _unsigned_command() -> dict:
    return {
        "schema_version": "0.4.0",
        "message_type": COMMAND,
        "lab_session_id": "lab-session-001",
        "request_id": "request-001",
        "decision_id": "decision-001",
        "authorization_id": "authorization-001",
        "policy_sha256": "1" * 64,
        "adapter_contract_sha256": "2" * 64,
        "target_id": "LAB_ENDPOINT_001",
        "target_boot_id": "boot-001",
        "action": "NETWORK_ISOLATE",
        "parameters": {
            "duration_seconds": 300,
            "preserve_management": True,
            "network_profile": "LAB_BEACON_BLOCK_MANAGEMENT_ALLOW_V1",
        },
        "prestate_sha256": "3" * 64,
        "idempotency_key": "idempotency-001",
        "sequence": 1,
        "nonce": "4" * 32,
        "issued_at": _timestamp(NOW),
        "expires_at": _timestamp(NOW + timedelta(seconds=90)),
    }


def _command() -> dict:
    return sign_lab_message(
        _unsigned_command(),
        message_type=COMMAND,
        key_id=EXECUTOR_KEY_ID,
        key=EXECUTOR_KEY,
        now=NOW,
    )


def _unsigned_receipt(command: dict, *, status: str = "APPLIED") -> dict:
    outcomes = {
        "APPLIED": (True, "RULESET_APPLIED", "5" * 64),
        "NO_EFFECT": (False, "REJECTED_PRE_EFFECT", command["prestate_sha256"]),
        "PARTIAL": (True, "PARTIAL_RULESET", "6" * 64),
        "AMBIGUOUS": (True, "EFFECT_UNCERTAIN", "7" * 64),
    }
    effect_possible, reason_code, poststate = outcomes[status]
    return {
        "schema_version": "0.4.0",
        "message_type": RECEIPT,
        "lab_session_id": command["lab_session_id"],
        "request_id": command["request_id"],
        "decision_id": command["decision_id"],
        "authorization_id": command["authorization_id"],
        "command_sha256": lab_message_sha256(command),
        "idempotency_key": command["idempotency_key"],
        "target_id": command["target_id"],
        "target_boot_id": command["target_boot_id"],
        "sequence": command["sequence"],
        "status": status,
        "effect_possible": effect_possible,
        "reason_code": reason_code,
        "prestate_sha256": command["prestate_sha256"],
        "poststate_sha256": poststate,
        "executed_at": _timestamp(NOW + timedelta(seconds=1)),
        "recorded_at": _timestamp(NOW + timedelta(seconds=2)),
    }


def _receipt(command: dict, *, status: str = "APPLIED") -> dict:
    return sign_lab_message(
        _unsigned_receipt(command, status=status),
        message_type=RECEIPT,
        key_id=EXECUTOR_KEY_ID,
        key=EXECUTOR_KEY,
        now=NOW,
    )


def _unsigned_observation(command: dict, receipt: dict) -> dict:
    value = {
        "schema_version": "0.4.0",
        "message_type": OBSERVATION,
        "lab_session_id": command["lab_session_id"],
        "request_id": command["request_id"],
        "decision_id": command["decision_id"],
        "command_sha256": lab_message_sha256(command),
        "idempotency_key": command["idempotency_key"],
        "target_id": command["target_id"],
        "target_boot_id": command["target_boot_id"],
        "sequence": command["sequence"],
        "beacon_reachable": False,
        "management_reachable": True,
        "ruleset_sha256": receipt["poststate_sha256"],
        "observed_at": _timestamp(NOW + timedelta(seconds=3)),
        "recorded_at": _timestamp(NOW + timedelta(seconds=4)),
    }
    value["observation_facts_sha256"] = observation_facts_sha256(value)
    return value


def _observation(command: dict, receipt: dict) -> dict:
    return sign_lab_message(
        _unsigned_observation(command, receipt),
        message_type=OBSERVATION,
        key_id=OBSERVER_KEY_ID,
        key=OBSERVER_KEY,
        now=NOW,
    )


class IsolatedLabContractTests(unittest.TestCase):
    def test_signed_command_receipt_and_observation_round_trip(self) -> None:
        command = _command()
        receipt = _receipt(command)
        observation = _observation(command, receipt)

        decoded_command = load_authenticated_lab_message(
            canonical_json(command),
            message_type=COMMAND,
            expected_key_id=EXECUTOR_KEY_ID,
            key=EXECUTOR_KEY,
            now=NOW,
        )
        decoded_receipt = load_authenticated_lab_message(
            canonical_json(receipt),
            message_type=RECEIPT,
            expected_key_id=EXECUTOR_KEY_ID,
            key=EXECUTOR_KEY,
            now=NOW,
        )
        decoded_observation = load_authenticated_lab_message(
            canonical_json(observation),
            message_type=OBSERVATION,
            expected_key_id=OBSERVER_KEY_ID,
            key=OBSERVER_KEY,
            now=NOW,
        )

        self.assertEqual(decoded_command, command)
        self.assertEqual(decoded_receipt, receipt)
        self.assertEqual(decoded_observation, observation)
        validate_lab_message_correlation(
            command=command, receipt=receipt, observation=observation
        )

    def test_canonical_signatures_are_order_independent_and_domain_separated(
        self,
    ) -> None:
        source = _unsigned_command()
        reversed_source = dict(reversed(list(source.items())))
        first = sign_lab_message(
            source,
            message_type=COMMAND,
            key_id=EXECUTOR_KEY_ID,
            key=EXECUTOR_KEY,
            now=NOW,
        )
        second = sign_lab_message(
            reversed_source,
            message_type=COMMAND,
            key_id=EXECUTOR_KEY_ID,
            key=EXECUTOR_KEY,
            now=NOW,
        )
        self.assertEqual(first["authentication"], second["authentication"])

        with self.assertRaises(LabContractError) as raised:
            load_authenticated_lab_message(
                canonical_json(first),
                message_type=RECEIPT,
                expected_key_id=EXECUTOR_KEY_ID,
                key=EXECUTOR_KEY,
                now=NOW,
            )
        self.assertEqual(raised.exception.reason_code, "LAB_AUTHENTICATION_INVALID")

    def test_authentication_fails_before_substituted_fields_are_used(self) -> None:
        mutations = {
            "request": lambda row: row.__setitem__("request_id", "request-002"),
            "decision": lambda row: row.__setitem__("decision_id", "decision-002"),
            "authorization": lambda row: row.__setitem__(
                "authorization_id", "authorization-002"
            ),
            "policy": lambda row: row.__setitem__("policy_sha256", "9" * 64),
            "contract": lambda row: row.__setitem__(
                "adapter_contract_sha256", "9" * 64
            ),
            "target": lambda row: row.__setitem__("target_id", "ATTACKER_TARGET"),
            "boot": lambda row: row.__setitem__("target_boot_id", "boot-002"),
            "prestate": lambda row: row.__setitem__("prestate_sha256", "9" * 64),
            "idempotency": lambda row: row.__setitem__(
                "idempotency_key", "idempotency-002"
            ),
            "sequence": lambda row: row.__setitem__("sequence", 2),
            "nonce": lambda row: row.__setitem__("nonce", "9" * 32),
            "expiry": lambda row: row.__setitem__(
                "expires_at", _timestamp(NOW + timedelta(seconds=100))
            ),
            "parameter": lambda row: row["parameters"].__setitem__(
                "duration_seconds", 600
            ),
        }
        for label, mutate in mutations.items():
            with self.subTest(label=label):
                command = _command()
                mutate(command)
                with self.assertRaises(LabContractError) as raised:
                    load_authenticated_lab_message(
                        canonical_json(command),
                        message_type=COMMAND,
                        expected_key_id=EXECUTOR_KEY_ID,
                        key=EXECUTOR_KEY,
                        now=NOW,
                    )
                self.assertEqual(
                    raised.exception.reason_code, "LAB_AUTHENTICATION_INVALID"
                )

    def test_wrong_key_and_key_identifier_fail_closed(self) -> None:
        raw = canonical_json(_command())
        for key_id, key in (
            (EXECUTOR_KEY_ID, OBSERVER_KEY),
            (OBSERVER_KEY_ID, EXECUTOR_KEY),
        ):
            with self.subTest(key_id=key_id):
                with self.assertRaises(LabContractError) as raised:
                    load_authenticated_lab_message(
                        raw,
                        message_type=COMMAND,
                        expected_key_id=key_id,
                        key=key,
                        now=NOW,
                    )
                self.assertEqual(
                    raised.exception.reason_code, "LAB_AUTHENTICATION_INVALID"
                )

    def test_executor_and_observer_key_material_must_be_distinct(self) -> None:
        validate_lab_channel_keys(executor_key=EXECUTOR_KEY, observer_key=OBSERVER_KEY)
        with self.assertRaises(LabContractError) as raised:
            validate_lab_channel_keys(
                executor_key=EXECUTOR_KEY, observer_key=EXECUTOR_KEY
            )
        self.assertEqual(raised.exception.reason_code, "LAB_KEY_SEPARATION_INVALID")

    def test_command_has_no_free_form_target_or_network_selectors(self) -> None:
        variants = []
        wrong_target = _unsigned_command()
        wrong_target["target_id"] = "WORKSTATION_042"
        variants.append(wrong_target)
        arbitrary_interface = _unsigned_command()
        arbitrary_interface["parameters"]["interface"] = "eth0"
        variants.append(arbitrary_interface)
        arbitrary_address = _unsigned_command()
        arbitrary_address["parameters"]["destination"] = "0.0.0.0/0"
        variants.append(arbitrary_address)
        shell = _unsigned_command()
        shell["command"] = "iptables -F"
        variants.append(shell)

        for candidate in variants:
            with self.subTest(candidate=candidate):
                with self.assertRaises(LabContractError) as raised:
                    sign_lab_message(
                        candidate,
                        message_type=COMMAND,
                        key_id=EXECUTOR_KEY_ID,
                        key=EXECUTOR_KEY,
                        now=NOW,
                    )
                self.assertEqual(raised.exception.reason_code, "LAB_SCHEMA_INVALID")

    def test_duplicate_nonfinite_oversize_and_deep_json_fail_closed(self) -> None:
        raw = canonical_json(_command())
        duplicate = '{"schema_version":"attacker",' + raw[1:]
        nonfinite = raw[:-1] + ',"unknown":NaN}'
        oversize = raw + (" " * (16 * 1024))
        deep_value: object = "leaf"
        for _ in range(10):
            deep_value = {"next": deep_value}
        deep = json.loads(raw)
        deep["unknown"] = deep_value

        cases = (
            (duplicate, "LAB_JSON_INVALID"),
            (nonfinite, "LAB_JSON_INVALID"),
            (oversize, "LAB_MESSAGE_TOO_LARGE"),
            (json.dumps(deep), "LAB_MESSAGE_TOO_DEEP"),
        )
        for candidate, expected in cases:
            with self.subTest(expected=expected):
                with self.assertRaises(LabContractError) as raised:
                    load_authenticated_lab_message(
                        candidate,
                        message_type=COMMAND,
                        expected_key_id=EXECUTOR_KEY_ID,
                        key=EXECUTOR_KEY,
                        now=NOW,
                    )
                self.assertEqual(raised.exception.reason_code, expected)

    def test_command_requires_canonical_bounded_unexpired_time(self) -> None:
        noncanonical = _unsigned_command()
        noncanonical["issued_at"] = "2026-08-20T14:00:00-04:00"
        excessive = _unsigned_command()
        excessive["expires_at"] = _timestamp(NOW + timedelta(seconds=121))
        for candidate, expected in (
            (noncanonical, "LAB_TIMESTAMP_INVALID"),
            (excessive, "LAB_COMMAND_LIFETIME_INVALID"),
        ):
            with self.subTest(expected=expected):
                with self.assertRaises(LabContractError) as raised:
                    sign_lab_message(
                        candidate,
                        message_type=COMMAND,
                        key_id=EXECUTOR_KEY_ID,
                        key=EXECUTOR_KEY,
                        now=NOW,
                    )
                self.assertEqual(raised.exception.reason_code, expected)

        signed = _command()
        with self.assertRaises(LabContractError) as raised:
            load_authenticated_lab_message(
                canonical_json(signed),
                message_type=COMMAND,
                expected_key_id=EXECUTOR_KEY_ID,
                key=EXECUTOR_KEY,
                now=NOW + timedelta(seconds=91),
            )
        self.assertEqual(raised.exception.reason_code, "LAB_COMMAND_EXPIRED")

    def test_receipt_outcomes_are_closed_and_conservative(self) -> None:
        command = _command()
        for status in ("APPLIED", "NO_EFFECT", "PARTIAL", "AMBIGUOUS"):
            with self.subTest(status=status):
                self.assertEqual(_receipt(command, status=status)["status"], status)

        invalid = _unsigned_receipt(command, status="AMBIGUOUS")
        invalid["effect_possible"] = False
        with self.assertRaises(LabContractError) as raised:
            sign_lab_message(
                invalid,
                message_type=RECEIPT,
                key_id=EXECUTOR_KEY_ID,
                key=EXECUTOR_KEY,
                now=NOW,
            )
        self.assertEqual(raised.exception.reason_code, "LAB_RECEIPT_OUTCOME_INVALID")

    def test_no_effect_cannot_claim_a_changed_poststate(self) -> None:
        command = _command()
        invalid = _unsigned_receipt(command, status="NO_EFFECT")
        invalid["poststate_sha256"] = "9" * 64
        with self.assertRaises(LabContractError) as raised:
            validate_lab_message_dict(
                {
                    **invalid,
                    "authentication": {
                        "key_id": EXECUTOR_KEY_ID,
                        "mac_sha256": "0" * 64,
                    },
                },
                message_type=RECEIPT,
                now=NOW,
            )
        self.assertEqual(raised.exception.reason_code, "LAB_RECEIPT_OUTCOME_INVALID")

    def test_observation_digest_is_independent_and_exact(self) -> None:
        command = _command()
        receipt = _receipt(command)
        unsigned = _unsigned_observation(command, receipt)
        original = unsigned["observation_facts_sha256"]
        unsigned["beacon_reachable"] = True
        self.assertNotEqual(observation_facts_sha256(unsigned), original)

        with self.assertRaises(LabContractError) as raised:
            validate_lab_message_dict(
                {
                    **unsigned,
                    "authentication": {
                        "key_id": OBSERVER_KEY_ID,
                        "mac_sha256": "0" * 64,
                    },
                },
                message_type=OBSERVATION,
                now=NOW,
            )
        self.assertEqual(
            raised.exception.reason_code, "LAB_OBSERVATION_BINDING_INVALID"
        )

    def test_exactly_signed_but_mismatched_observation_fails_correlation(self) -> None:
        command = _command()
        receipt = _receipt(command)
        unsigned = _unsigned_observation(command, receipt)
        unsigned["target_boot_id"] = "boot-substituted"
        unsigned["observation_facts_sha256"] = observation_facts_sha256(unsigned)
        observation = sign_lab_message(
            unsigned,
            message_type=OBSERVATION,
            key_id=OBSERVER_KEY_ID,
            key=OBSERVER_KEY,
            now=NOW,
        )

        with self.assertRaises(LabContractError) as raised:
            validate_lab_message_correlation(
                command=command, receipt=receipt, observation=observation
            )
        self.assertEqual(raised.exception.reason_code, "LAB_CORRELATION_INVALID")

    def test_signing_does_not_mutate_callers_input(self) -> None:
        source = _unsigned_command()
        before = copy.deepcopy(source)
        sign_lab_message(
            source,
            message_type=COMMAND,
            key_id=EXECUTOR_KEY_ID,
            key=EXECUTOR_KEY,
            now=NOW,
        )
        self.assertEqual(source, before)
        self.assertNotIn("authentication", source)


if __name__ == "__main__":
    unittest.main()
