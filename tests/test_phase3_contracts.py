from __future__ import annotations

import copy
import json
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from adf_poc.phase3.attestation import sign_evidence_attestation
from adf_poc.phase3.config import Phase3PolicyConfig, PolicyValidationError
from adf_poc.phase3.contracts import (
    AgentSecurityStatus,
    AuthenticatedPrincipal,
    EvidenceItem,
    RequestValidationError,
    load_decision_request_json,
    validate_decision_request_dict,
)


ROOT = Path(__file__).resolve().parents[1]
POLICY_PATH = ROOT / "config" / "phase3_policy.json"


def _timestamp(value: datetime) -> str:
    return value.astimezone(timezone.utc).replace(microsecond=0).isoformat()


def _valid_request() -> dict:
    now = datetime.now(timezone.utc).replace(microsecond=0)
    payload = {
        "alert_type": "malware",
        "target_id": "WORKSTATION_042",
        "observed": True,
    }
    untrusted_text = "Synthetic EDR alert for contract validation."
    digest = EvidenceItem.calculate_content_sha256(payload, untrusted_text)
    observed_at = _timestamp(now - timedelta(minutes=1))
    provenance_id = "prov-contract-001"
    signature = sign_evidence_attestation(
        key=b"contract-source-attestation-key".ljust(32, b"!"),
        evidence_id="ev-contract-001",
        subject_target_id="WORKSTATION_042",
        source_type="endpoint",
        source_instance="EDR_PRIMARY",
        provenance_id=provenance_id,
        provenance_verified=True,
        integrity_status="VERIFIED",
        observed_at=observed_at,
        content_sha256=digest,
        supports=["COMPROMISE"],
        contradicts=[],
        relevance=1.0,
    )
    return {
        "schema_version": "0.3.0",
        "request_id": "req-contract-001",
        "timestamp": _timestamp(now),
        "agent": {
            "id": "soc-agent-01",
            "type": "SOC_AGENT",
            "authenticated": True,
            "roles": ["soc_automation"],
            "authority": ["endpoint_containment"],
            "security_status": "TRUSTED",
        },
        "action": {
            "type": "NETWORK_ISOLATE",
            "target": "WORKSTATION_042",
            "parameters": {
                "duration_seconds": 900,
                "preserve_management": True,
            },
        },
        "target": {
            "id": "WORKSTATION_042",
            "type": "WORKSTATION",
            "criticality": "LOW",
            "classification": "INTERNAL",
            "dependencies": [],
        },
        "evidence": [
            {
                "id": "ev-contract-001",
                "subject_target_id": "WORKSTATION_042",
                "source_type": "endpoint",
                "source_instance": "EDR_PRIMARY",
                "provenance": {
                    "id": provenance_id,
                    "verified": True,
                    "signature": signature,
                },
                "integrity": {
                    "status": "VERIFIED",
                    "content_sha256": digest,
                },
                "observed_at": observed_at,
                "reliability": 0.96,
                "trust_level": "HIGH",
                "supports": ["COMPROMISE"],
                "contradicts": [],
                "relevance": 1.0,
                "payload": payload,
                "untrusted_text": untrusted_text,
            }
        ],
        "agent_recommendation": "ISOLATE",
        "agent_confidence": 0.96,
        "context": {
            "incident_id": "inc-contract-001",
            "mode": "SYNTHETIC_SIMULATION",
        },
    }


class Phase3DecisionRequestContractTests(unittest.TestCase):
    def test_valid_request_strict_parses_and_round_trips(self) -> None:
        source = _valid_request()
        request = load_decision_request_json(json.dumps(source))

        self.assertEqual(request.to_dict(), source)
        self.assertEqual(request.action.target, request.target.id)
        self.assertTrue(request.evidence[0].content_digest_matches())
        self.assertEqual(len(request.request_sha256()), 64)

        principal = AuthenticatedPrincipal(
            id="soc-agent-01",
            type="SOC_AGENT",
            authenticated=True,
            roles=("soc_automation",),
            authority=("endpoint_containment",),
            security_status=AgentSecurityStatus.TRUSTED,
            identity_source="synthetic-agent-registry",
        )
        self.assertEqual(principal.id, request.agent.id)
        self.assertNotEqual(set(principal.to_dict()), set(request.agent.to_dict()))

    def test_duplicate_json_members_fail_before_schema_validation(self) -> None:
        raw = json.dumps(_valid_request())
        duplicated = '{"request_id":"attacker-value",' + raw[1:]

        with self.assertRaises(RequestValidationError) as raised:
            load_decision_request_json(duplicated)

        self.assertEqual(raised.exception.reason_code, "REQUEST_JSON_INVALID")

    def test_nonfinite_json_fails_before_schema_validation(self) -> None:
        source = _valid_request()
        source["agent_confidence"] = float("nan")
        raw = json.dumps(source, allow_nan=True)

        with self.assertRaises(RequestValidationError) as raised:
            load_decision_request_json(raw)

        self.assertEqual(raised.exception.reason_code, "REQUEST_JSON_INVALID")

    def test_missing_and_unknown_fields_fail_closed(self) -> None:
        missing = _valid_request()
        del missing["action"]["parameters"]["preserve_management"]
        unknown = _valid_request()
        unknown["agent"]["policy_override"] = "ALLOW"

        for label, candidate in (("missing", missing), ("unknown", unknown)):
            with self.subTest(label=label):
                with self.assertRaises(RequestValidationError) as raised:
                    validate_decision_request_dict(candidate)
                self.assertEqual(raised.exception.reason_code, "REQUEST_SCHEMA_INVALID")

    def test_invalid_naive_and_excessively_future_timestamps_fail(self) -> None:
        malformed = _valid_request()
        malformed["timestamp"] = "not-a-time"
        naive = _valid_request()
        naive["timestamp"] = datetime.now().replace(microsecond=0).isoformat()
        future = _valid_request()
        future["timestamp"] = "2999-01-01T00:00:00+00:00"

        for label, candidate, expected in (
            ("malformed", malformed, "REQUEST_TIMESTAMP_INVALID"),
            ("naive", naive, "REQUEST_TIMESTAMP_INVALID"),
            ("future", future, "REQUEST_TIMESTAMP_FUTURE"),
        ):
            with self.subTest(label=label):
                with self.assertRaises(RequestValidationError) as raised:
                    validate_decision_request_dict(candidate)
                self.assertEqual(raised.exception.reason_code, expected)

    def test_evidence_after_request_clock_skew_fails(self) -> None:
        source = _valid_request()
        request_time = datetime.fromisoformat(source["timestamp"])
        source["evidence"][0]["observed_at"] = _timestamp(
            request_time + timedelta(minutes=6)
        )

        with self.assertRaises(RequestValidationError) as raised:
            validate_decision_request_dict(source)

        self.assertEqual(raised.exception.reason_code, "EVIDENCE_TIMESTAMP_FUTURE")

    def test_schema_valid_content_digest_mismatch_is_deferred(self) -> None:
        source = _valid_request()
        source["evidence"][0]["integrity"]["content_sha256"] = "0" * 64

        request = validate_decision_request_dict(source)

        self.assertFalse(request.evidence[0].content_digest_matches())

    def test_unsupported_version_and_target_mismatch_have_stable_codes(self) -> None:
        unsupported = _valid_request()
        unsupported["schema_version"] = "0.4.0"
        mismatch = _valid_request()
        mismatch["action"]["target"] = "DOMAIN_CONTROLLER_01"

        for candidate, expected in (
            (unsupported, "UNSUPPORTED_SCHEMA_VERSION"),
            (mismatch, "TARGET_BINDING_MISMATCH"),
        ):
            with self.subTest(expected=expected):
                with self.assertRaises(RequestValidationError) as raised:
                    validate_decision_request_dict(candidate)
                self.assertEqual(raised.exception.reason_code, expected)


class Phase3PolicyContractTests(unittest.TestCase):
    def test_policy_loads_required_action_targets_evidence_and_ttls(self) -> None:
        policy = Phase3PolicyConfig.load(POLICY_PATH)

        self.assertEqual(policy.policy_id, "ADF-PHASE3-SOC-001")
        self.assertTrue(policy.authorization_single_use)
        self.assertEqual(policy.authorization_ttl_seconds, 120)
        self.assertEqual(policy.approval_ttl_seconds, 900)
        action = policy.action_policy("NETWORK_ISOLATE")
        self.assertTrue(action.reversible)
        self.assertEqual(action.required_authority, "endpoint_containment")
        domain_controller = policy.target_record("DOMAIN_CONTROLLER_01")
        self.assertEqual(domain_controller.criticality, "TIER_0")
        self.assertIn("AUTHENTICATION_SERVICE", domain_controller.dependencies)
        workstation = policy.target_record("WORKSTATION_042")
        self.assertEqual(
            (workstation.type, workstation.criticality), ("WORKSTATION", "LOW")
        )
        self.assertEqual(
            set(policy.evidence.required_source_types_by_action["NETWORK_ISOLATE"]),
            {"asset_inventory", "endpoint", "identity", "network", "threat_intel"},
        )
        self.assertNotIn("secret", POLICY_PATH.read_text(encoding="utf-8").lower())
        self.assertNotIn("signing_key", policy.to_dict())

    def test_malformed_policy_variants_fail_closed(self) -> None:
        source = json.loads(POLICY_PATH.read_text(encoding="utf-8"))
        variants: list[tuple[str, str, str]] = []

        duplicate_raw = POLICY_PATH.read_text(encoding="utf-8")
        duplicate_raw = '{"policy_id":"attacker-value",' + duplicate_raw.lstrip()[1:]
        variants.append(("duplicate", duplicate_raw, "POLICY_JSON_INVALID"))

        nonfinite = copy.deepcopy(source)
        nonfinite["evidence"]["minimum_reliability"] = float("nan")
        variants.append(
            ("nonfinite", json.dumps(nonfinite, allow_nan=True), "POLICY_JSON_INVALID")
        )

        missing = copy.deepcopy(source)
        del missing["approval"]
        variants.append(("missing", json.dumps(missing), "POLICY_SCHEMA_INVALID"))

        unknown = copy.deepcopy(source)
        unknown["signing_key"] = "must-not-be-accepted"
        variants.append(("unknown", json.dumps(unknown), "POLICY_SCHEMA_INVALID"))

        unsafe = copy.deepcopy(source)
        unsafe["target_inventory"]["DOMAIN_CONTROLLER_01"]["criticality"] = "LOW"
        variants.append(("unsafe", json.dumps(unsafe), "POLICY_SAFETY_INVARIANT"))

        for label, raw, expected in variants:
            with self.subTest(label=label), tempfile.TemporaryDirectory() as directory:
                path = Path(directory) / "policy.json"
                path.write_text(raw, encoding="utf-8")
                with self.assertRaises(PolicyValidationError) as raised:
                    Phase3PolicyConfig.load(path)
                self.assertEqual(raised.exception.reason_code, expected)


if __name__ == "__main__":
    unittest.main()
