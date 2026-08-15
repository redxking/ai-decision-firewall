from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from typing import Any, Callable

from adf_poc.replay import (
    ReplayConfig,
    ReplayHarness,
    evaluate_qualification_stop_conditions,
    load_gate_b_authorization,
    load_manifest_control,
)
from adf_poc.replay.gate_b import (
    CLASSIFIED_GATE_B_FAILURE_IDENTITIES,
    GateBStopConditionViolation,
    GateBValidationError,
)
from adf_poc.replay.gate_b_oracle import (
    ALLOWED_GATE_B_FAILURE_IDENTITIES,
    GateBFailureExpectation,
    GateBFailureIdentityError,
    matches_expected_failure,
    require_classified_failure,
)
from adf_poc.replay.payload_observer import observe_python_payload_access

from tests.test_gate_b import make_gate_b_repository, write_json


Mutation = Callable[[dict[str, Any]], None]


def _artifact_by_role(value: dict[str, Any], role: str) -> dict[str, Any]:
    return next(
        row
        for row in value["artifact_bindings"]["artifacts"]
        if row["role"] == role
    )


CAUSAL_MUTATIONS: tuple[
    tuple[str, Mutation, GateBFailureExpectation], ...
] = (
    (
        "STATUS_DRAFT",
        lambda value: value.__setitem__("status", "DRAFT"),
        GateBFailureExpectation(
            "AUTHORIZATION_METADATA", "GB.AUTH.STATUS_APPROVED", "NOT_APPROVED"
        ),
    ),
    (
        "MISSING_APPROVAL_ROLE",
        lambda value: value["approvals"].pop(),
        GateBFailureExpectation(
            "APPROVAL_SET",
            "GB.APPROVAL.REQUIRED_ROLE_COUNT",
            "CARDINALITY_MISMATCH",
        ),
    ),
    (
        "DUPLICATE_APPROVAL_ROLE",
        lambda value: value["approvals"][-1].__setitem__(
            "role", value["approvals"][0]["role"]
        ),
        GateBFailureExpectation(
            "APPROVAL_SET", "GB.APPROVAL.ROLE_UNIQUENESS", "DUPLICATE_VALUE"
        ),
    ),
    (
        "UNSUPPORTED_APPROVAL_ROLE",
        lambda value: value["approvals"][-1].__setitem__("role", "UNSUPPORTED"),
        GateBFailureExpectation(
            "APPROVAL_SET", "GB.APPROVAL.ROLE_MEMBERSHIP", "UNSUPPORTED_VALUE"
        ),
    ),
    (
        "MANIFEST_DIGEST_MISMATCH",
        lambda value: value.__setitem__("dataset_manifest_sha256", "1" * 64),
        GateBFailureExpectation(
            "ARTIFACT_BINDING", "GB.BINDING.MANIFEST_SHA256", "DIGEST_MISMATCH"
        ),
    ),
    (
        "MODEL_DIGEST_MISMATCH",
        lambda value: value["artifact_bindings"].__setitem__(
            "model_sha256", "1" * 64
        ),
        GateBFailureExpectation(
            "ARTIFACT_BINDING", "GB.BINDING.MODEL_SHA256", "DIGEST_MISMATCH"
        ),
    ),
    (
        "POLICY_DIGEST_MISMATCH",
        lambda value: value["artifact_bindings"].__setitem__(
            "policy_sha256", "1" * 64
        ),
        GateBFailureExpectation(
            "ARTIFACT_BINDING", "GB.BINDING.POLICY_SHA256", "DIGEST_MISMATCH"
        ),
    ),
    (
        "SOURCE_MAPPING_DIGEST_MISMATCH",
        lambda value: _artifact_by_role(value, "SOURCE_MAPPING").__setitem__(
            "sha256", "1" * 64
        ),
        GateBFailureExpectation(
            "ARTIFACT_BINDING",
            "GB.BINDING.SOURCE_MAPPING_SHA256",
            "DIGEST_MISMATCH",
        ),
    ),
    (
        "ADJUDICATION_PROTOCOL_DIGEST_MISMATCH",
        lambda value: _artifact_by_role(value, "ADJUDICATION_PROTOCOL").__setitem__(
            "sha256", "1" * 64
        ),
        GateBFailureExpectation(
            "ARTIFACT_BINDING",
            "GB.BINDING.ADJUDICATION_PROTOCOL_SHA256",
            "DIGEST_MISMATCH",
        ),
    ),
    (
        "PILOT_PROTOCOL_DIGEST_MISMATCH",
        lambda value: _artifact_by_role(value, "PILOT_PROTOCOL").__setitem__(
            "sha256", "1" * 64
        ),
        GateBFailureExpectation(
            "ARTIFACT_BINDING",
            "GB.BINDING.PILOT_PROTOCOL_SHA256",
            "DIGEST_MISMATCH",
        ),
    ),
    (
        "ACTION_CREDENTIALS_PRESENT",
        lambda value: value["controls"].__setitem__(
            "action_credentials_present", True
        ),
        GateBFailureExpectation(
            "DECLARED_RUNTIME_CONTROLS",
            "GB.CONTROL.ACTION_CREDENTIALS_ABSENT",
            "PROHIBITED_TRUE",
        ),
    ),
    (
        "LIVE_FEED_CONNECTED",
        lambda value: value["controls"].__setitem__("live_feed_connected", True),
        GateBFailureExpectation(
            "DECLARED_RUNTIME_CONTROLS",
            "GB.CONTROL.LIVE_FEED_ABSENT",
            "PROHIBITED_TRUE",
        ),
    ),
    (
        "WRITE_CONNECTOR_PRESENT",
        lambda value: value["controls"].__setitem__(
            "write_capable_connectors_present", True
        ),
        GateBFailureExpectation(
            "DECLARED_RUNTIME_CONTROLS",
            "GB.CONTROL.WRITE_CONNECTOR_ABSENT",
            "PROHIBITED_TRUE",
        ),
    ),
    (
        "NETWORK_EGRESS_ENABLED",
        lambda value: value["controls"].__setitem__(
            "network_egress_disabled", False
        ),
        GateBFailureExpectation(
            "DECLARED_RUNTIME_CONTROLS",
            "GB.CONTROL.NETWORK_EGRESS_DISABLED",
            "REQUIRED_TRUE_MISSING",
        ),
    ),
    (
        "DIRECT_IDENTIFIERS_NOT_REMOVED",
        lambda value: value["controls"].__setitem__(
            "direct_identifiers_removed", False
        ),
        GateBFailureExpectation(
            "DECLARED_RUNTIME_CONTROLS",
            "GB.CONTROL.DIRECT_IDENTIFIERS_REMOVED",
            "REQUIRED_TRUE_MISSING",
        ),
    ),
    (
        "REIDENTIFICATION_RISK_NOT_REVIEWED",
        lambda value: value["controls"].__setitem__(
            "reidentification_risk_reviewed", False
        ),
        GateBFailureExpectation(
            "DECLARED_RUNTIME_CONTROLS",
            "GB.CONTROL.REIDENTIFICATION_RISK_REVIEWED",
            "REQUIRED_TRUE_MISSING",
        ),
    ),
    (
        "OFFLINE_ONLY_DISABLED",
        lambda value: value["controls"].__setitem__("offline_only", False),
        GateBFailureExpectation(
            "DECLARED_RUNTIME_CONTROLS",
            "GB.CONTROL.OFFLINE_ONLY",
            "REQUIRED_TRUE_MISSING",
        ),
    ),
    (
        "RUNTIME_LABELS_NOT_SEPARATED",
        lambda value: value["controls"].__setitem__(
            "runtime_labels_separated", False
        ),
        GateBFailureExpectation(
            "DECLARED_RUNTIME_CONTROLS",
            "GB.CONTROL.RUNTIME_LABELS_SEPARATED",
            "REQUIRED_TRUE_MISSING",
        ),
    ),
    (
        "INCOMPLETE_INTAKE_REPORTING",
        lambda value: value["controls"].__setitem__(
            "complete_intake_reporting", False
        ),
        GateBFailureExpectation(
            "DECLARED_RUNTIME_CONTROLS",
            "GB.CONTROL.COMPLETE_INTAKE_REPORTING",
            "REQUIRED_TRUE_MISSING",
        ),
    ),
    (
        "RESTRICTED_HASH_HANDLING_DISABLED",
        lambda value: value["controls"].__setitem__(
            "restricted_hash_handling", False
        ),
        GateBFailureExpectation(
            "DECLARED_RUNTIME_CONTROLS",
            "GB.CONTROL.RESTRICTED_HASH_HANDLING",
            "REQUIRED_TRUE_MISSING",
        ),
    ),
    (
        "AUTHORIZATION_NOT_YET_VALID",
        lambda value: value.__setitem__("valid_from", "2098-12-31T00:00:00Z"),
        GateBFailureExpectation(
            "AUTHORIZATION_VALIDITY", "GB.AUTH.CURRENT_INTERVAL", "NOT_YET_VALID"
        ),
    ),
    (
        "AUTHORIZATION_EXPIRED",
        lambda value: (
            value.__setitem__("expires_at", "2026-08-14T00:00:00Z"),
            value["claim_control"].__setitem__(
                "expires_at", "2026-08-14T00:00:00Z"
            ),
        ),
        GateBFailureExpectation(
            "AUTHORIZATION_VALIDITY", "GB.AUTH.CURRENT_INTERVAL", "EXPIRED"
        ),
    ),
    (
        "REVIEWER_NOT_INDEPENDENT",
        lambda value: value["independent_review"].__setitem__(
            "reviewer_id", value["approvals"][0]["approver_id"]
        ),
        GateBFailureExpectation(
            "INDEPENDENT_REVIEW",
            "GB.REVIEW.INDEPENDENT_IDENTITY",
            "IDENTITY_COLLISION",
        ),
    ),
    (
        "CUSTODY_FREEZE_PREDATES_WINDOW",
        lambda value: value["custody"].__setitem__(
            "frozen_at", "2026-07-31T00:00:00Z"
        ),
        GateBFailureExpectation(
            "CUSTODY",
            "GB.CUSTODY.FROZEN_AFTER_WINDOW",
            "FREEZE_BEFORE_WINDOW_END",
        ),
    ),
)


class GateBFailureOracleTests(unittest.TestCase):
    def test_oracle_uses_the_complete_validator_owned_registry(self) -> None:
        stop_identity = (
            "POSTQUALIFICATION_STOP",
            "GB.STOP.OVERALL_QUARANTINE_RATE",
            "THRESHOLD_EXCEEDED",
        )
        exercised_identities = {
            expected.identity for _, _, expected in CAUSAL_MUTATIONS
        } | {stop_identity}
        self.assertIs(
            ALLOWED_GATE_B_FAILURE_IDENTITIES,
            CLASSIFIED_GATE_B_FAILURE_IDENTITIES,
        )
        self.assertEqual(len(CLASSIFIED_GATE_B_FAILURE_IDENTITIES), 25)
        self.assertEqual(exercised_identities, CLASSIFIED_GATE_B_FAILURE_IDENTITIES)

    def test_all_pre_payload_mutations_emit_exact_causal_identity(self) -> None:
        for mutation_id, mutate, expected in CAUSAL_MUTATIONS:
            with self.subTest(mutation_id=mutation_id), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                (
                    config_path,
                    authorization_path,
                    cases_path,
                    adjudications_path,
                ) = make_gate_b_repository(root)
                value = json.loads(authorization_path.read_text(encoding="utf-8"))
                pristine = json.dumps(value, sort_keys=True)
                mutate(value)
                self.assertNotEqual(json.dumps(value, sort_keys=True), pristine)
                write_json(authorization_path, value)
                with observe_python_payload_access(
                    {
                        cases_path: "cases",
                        adjudications_path: "adjudications",
                    }
                ) as observation:
                    with self.assertRaises(GateBValidationError) as caught:
                        ReplayHarness.from_config(
                            config_path,
                            repository_root=root,
                        ).validate_inputs()
                self.assertTrue(matches_expected_failure(caught.exception, expected))
                self.assertEqual(observation.accessed_roles, set())

    def test_generic_fail_shut_exception_cannot_satisfy_oracle(self) -> None:
        error = GateBValidationError("Unrelated failure.")
        with self.assertRaises(GateBFailureIdentityError):
            require_classified_failure(error)

    def test_unknown_identity_cannot_enter_the_closed_oracle(self) -> None:
        with self.assertRaises(GateBFailureIdentityError):
            GateBFailureExpectation("UNKNOWN", "GB.UNKNOWN", "UNKNOWN")
        error = GateBValidationError(
            "Unknown typed failure.",
            stage="UNKNOWN",
            control_id="GB.UNKNOWN",
            reason_code="UNKNOWN",
        )
        with self.assertRaises(GateBFailureIdentityError):
            require_classified_failure(error)

    def test_wrong_valid_identity_is_not_a_match(self) -> None:
        error = GateBValidationError(
            "Bound failure.",
            stage="ARTIFACT_BINDING",
            control_id="GB.BINDING.MODEL_SHA256",
            reason_code="DIGEST_MISMATCH",
        )
        wrong = GateBFailureExpectation(
            "ARTIFACT_BINDING", "GB.BINDING.POLICY_SHA256", "DIGEST_MISMATCH"
        )
        self.assertFalse(matches_expected_failure(error, wrong))

    def test_postqualification_stop_emits_the_registered_threshold_identity(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            config_path, authorization_path, _, _ = make_gate_b_repository(root)
            config = ReplayConfig.load(config_path)
            paths = config.resolve_paths(root)
            manifest = load_manifest_control(paths["dataset_manifest"])
            authorization = load_gate_b_authorization(
                authorization_path,
                repository_root=root,
                manifest=manifest,
                config=config,
                model_path=paths["model_path"],
                policy_path=paths["policy_path"],
            )
            rows = [
                {"status": "ACCEPTED", "error_category": ""},
                {"status": "ACCEPTED", "error_category": ""},
                {"status": "QUARANTINED", "error_category": "SYNTAX"},
            ]
            with self.assertRaises(GateBStopConditionViolation) as caught:
                evaluate_qualification_stop_conditions(authorization, rows)
            expected = GateBFailureExpectation(
                "POSTQUALIFICATION_STOP",
                "GB.STOP.OVERALL_QUARANTINE_RATE",
                "THRESHOLD_EXCEEDED",
            )
            self.assertTrue(matches_expected_failure(caught.exception, expected))


if __name__ == "__main__":
    unittest.main()
