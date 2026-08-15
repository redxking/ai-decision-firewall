from __future__ import annotations

from collections import Counter
from datetime import datetime, timezone
from typing import Any, Iterable

from adf_poc.audit import AuditLogger
from adf_poc.utils import sha256_json


def validate_phase3_audit_chain(
    rows: Iterable[dict[str, Any]],
) -> tuple[bool, list[str]]:
    """Validate the generic hash chain plus Phase 3 contiguous sequencing."""

    records = list(rows)
    valid, errors = AuditLogger.verify_rows(records)
    for index, row in enumerate(records):
        if row.get("sequence") != index:
            errors.append(f"Record {index} sequence is not contiguous from zero.")
    return valid and not errors, errors


def validate_phase3_lifecycle(
    rows: Iterable[dict[str, Any]],
) -> tuple[bool, list[str]]:
    """Validate one closed, ordered, correlated Phase 3 request lifecycle."""

    records = list(rows)
    errors: list[str] = []
    if not records:
        return False, ["Phase 3 lifecycle is empty."]
    types = [str(row.get("record_type", "")) for row in records]
    approval_recorded_suffix = bool(types and types[-1] == "APPROVAL_RECORDED")
    core_types = types[:-1] if approval_recorded_suffix else types
    if types[0] != "REQUEST_RECEIVED":
        errors.append("Lifecycle must begin with REQUEST_RECEIVED.")
    if not core_types or core_types[-1] != "FINAL_STATE_RECORDED":
        errors.append(
            "Lifecycle must close with FINAL_STATE_RECORDED before any approval suffix."
        )
    payloads = [row.get("payload") for row in records]
    if any(not isinstance(payload, dict) for payload in payloads):
        errors.append("Every lifecycle record must contain an object payload.")
        return False, errors
    counts = Counter(types)
    if any(count != 1 for count in counts.values()):
        errors.append("Lifecycle record types must occur exactly once.")
    intake_ids = {str(payload.get("intake_id", "")) for payload in payloads}
    decision_ids = {str(payload.get("decision_id", "")) for payload in payloads}
    if len(intake_ids) != 1 or "" in intake_ids:
        errors.append("Lifecycle intake_id correlation is incomplete or inconsistent.")
    if len(decision_ids) != 1 or "" in decision_ids:
        errors.append(
            "Lifecycle decision_id correlation is incomplete or inconsistent."
        )

    stable_request_id = ""
    if "REQUEST_VALIDATED" in types:
        validated_index = types.index("REQUEST_VALIDATED")
        stable_request_id = str(payloads[validated_index].get("request_id", ""))
        if not stable_request_id or any(
            str(payload.get("request_id", "")) != stable_request_id
            for payload in payloads[validated_index:]
        ):
            errors.append(
                "Validated lifecycle must use one stable request_id after validation."
            )
    else:
        request_ids = {str(payload.get("request_id", "")) for payload in payloads}
        if len(request_ids) != 1 or "" in request_ids:
            errors.append("Rejected lifecycle request_id correlation is inconsistent.")

    normal_prefix = [
        "REQUEST_RECEIVED",
        "REQUEST_VALIDATED",
        "IDENTITY_EVALUATED",
        "EVIDENCE_EVALUATED",
        "CONSEQUENCE_EVALUATED",
        "POLICY_EVALUATED",
        "DECISION_VERIFIED",
        "DECISION_PRODUCED",
    ]
    early_prefixes = [
        ["REQUEST_RECEIVED", "REQUEST_REJECTED", "DECISION_PRODUCED"],
        [
            "REQUEST_RECEIVED",
            "REQUEST_VALIDATED",
            "REQUEST_REJECTED",
            "DECISION_PRODUCED",
        ],
        [
            "REQUEST_RECEIVED",
            "REQUEST_VALIDATED",
            "IDENTITY_EVALUATED",
            "DECISION_PRODUCED",
        ],
        [
            "REQUEST_RECEIVED",
            "REQUEST_VALIDATED",
            "POLICY_EVALUATION_FAILED",
            "DECISION_PRODUCED",
        ],
    ]
    control_failure_prefixes = [
        [
            "REQUEST_RECEIVED",
            "REQUEST_VALIDATED",
            "IDENTITY_EVALUATED",
            *optional,
            "CONTROL_PLANE_FAILURE",
            "DECISION_PRODUCED",
        ]
        for optional in (
            [],
            ["EVIDENCE_EVALUATED"],
            ["EVIDENCE_EVALUATED", "CONSEQUENCE_EVALUATED"],
            [
                "EVIDENCE_EVALUATED",
                "CONSEQUENCE_EVALUATED",
                "POLICY_EVALUATED",
            ],
            [
                "EVIDENCE_EVALUATED",
                "CONSEQUENCE_EVALUATED",
                "POLICY_EVALUATED",
                "DECISION_VERIFIED",
            ],
        )
    ]

    prefix: list[str] | None = None
    if core_types[: len(normal_prefix)] == normal_prefix:
        prefix = list(normal_prefix)
        if (
            len(core_types) > len(prefix)
            and core_types[len(prefix)] == "APPROVAL_REQUIREMENT_PRODUCED"
        ):
            prefix.append("APPROVAL_REQUIREMENT_PRODUCED")
    else:
        for candidate in early_prefixes + control_failure_prefixes:
            if core_types[: len(candidate)] == candidate:
                prefix = candidate
                break
    if prefix is None:
        errors.append("Lifecycle control-plane stage order is not a closed template.")
        prefix = []

    nonexecuting_tail = [
        "AUTHORIZATION_NOT_ISSUED",
        "BROKER_SKIPPED",
        "ACTION_SKIPPED",
        "VERIFICATION_SKIPPED",
        "FINAL_STATE_RECORDED",
    ]
    executed_tail = [
        "AUTHORIZATION_PRODUCED",
        "BROKER_INVOKED",
        "ACTION_ATTEMPTED",
        "VERIFICATION_PERFORMED",
        "FINAL_STATE_RECORDED",
    ]
    rejected_tail = [
        "AUTHORIZATION_PRODUCED",
        "BROKER_INVOKED",
        "BROKER_REJECTED",
        "ACTION_SKIPPED",
        "VERIFICATION_SKIPPED",
        "FINAL_STATE_RECORDED",
    ]
    failure_tail = [
        "AUTHORIZATION_PRODUCED",
        "BROKER_INVOKED",
        "BROKER_FAILURE",
        "ACTION_ATTEMPTED",
        "VERIFICATION_PERFORMED",
        "FINAL_STATE_RECORDED",
    ]
    post_effect_action_accounting_tail = [
        "AUTHORIZATION_PRODUCED",
        "BROKER_INVOKED",
        "POST_EFFECT_ACCOUNTING_FAILURE",
        "FINAL_STATE_RECORDED",
    ]
    post_effect_verification_accounting_tail = [
        "AUTHORIZATION_PRODUCED",
        "BROKER_INVOKED",
        "ACTION_ATTEMPTED",
        "POST_EFFECT_ACCOUNTING_FAILURE",
        "FINAL_STATE_RECORDED",
    ]
    post_effect_final_accounting_tail = [
        "AUTHORIZATION_PRODUCED",
        "BROKER_INVOKED",
        "ACTION_ATTEMPTED",
        "VERIFICATION_PERFORMED",
        "POST_EFFECT_ACCOUNTING_FAILURE",
        "FINAL_STATE_RECORDED",
    ]
    tail = core_types[len(prefix) :]
    if tail not in (
        nonexecuting_tail,
        executed_tail,
        rejected_tail,
        failure_tail,
        post_effect_action_accounting_tail,
        post_effect_verification_accounting_tail,
        post_effect_final_accounting_tail,
    ):
        errors.append("Lifecycle action-path stage order is not a closed template.")

    by_type = {row["record_type"]: row["payload"] for row in records}
    decision_payload = by_type.get("DECISION_PRODUCED", {})
    final_payload = by_type.get("FINAL_STATE_RECORDED", {})
    if decision_payload.get("outcome") != final_payload.get("outcome"):
        errors.append("Final outcome does not match the authoritative decision record.")
    approval_present = "APPROVAL_REQUIREMENT_PRODUCED" in by_type
    if approval_present != (decision_payload.get("outcome") == "ESCALATE"):
        errors.append("Approval requirement presence does not match ESCALATE outcome.")

    policy_payload = by_type.get("POLICY_EVALUATED", {})
    verification_payload = by_type.get("DECISION_VERIFIED", {})
    request_payload = by_type.get("REQUEST_VALIDATED", {})
    identity_payload = by_type.get("IDENTITY_EVALUATED", {})
    if policy_payload and "CONTROL_PLANE_FAILURE" not in by_type:
        if verification_payload.get("passed") is True:
            if decision_payload.get("outcome") != policy_payload.get(
                "outcome"
            ) or decision_payload.get("reason_codes") != policy_payload.get(
                "reason_codes"
            ):
                errors.append(
                    "Authoritative decision does not match the evaluated policy result."
                )
            exact_decision_bindings = (
                ("decision_context_sha256", "decision_context_sha256"),
                ("decision_sha256", "decision_sha256"),
                ("request_sha256", "request_sha256"),
                ("principal_id", "principal_id"),
                ("policy_sha256", "policy_sha256"),
            )
            if any(
                not decision_payload.get(decision_name)
                or decision_payload.get(decision_name)
                != verification_payload.get(verification_name)
                for decision_name, verification_name in exact_decision_bindings
            ):
                errors.append(
                    "Authoritative decision does not bind the verified decision projection."
                )
        elif decision_payload.get(
            "outcome"
        ) != "DENY" or "DECISION_VERIFIER_FAILED" not in decision_payload.get(
            "reason_codes", []
        ):
            errors.append(
                "Verifier disagreement did not produce an authoritative DENY."
            )
        if any(
            not decision_payload.get(name)
            or decision_payload.get(name) != policy_payload.get(name)
            for name in ("policy_id", "policy_version", "policy_sha256")
        ):
            errors.append("Authoritative decision does not bind the evaluated policy.")
        if not decision_payload.get("request_sha256") or decision_payload.get(
            "request_sha256"
        ) != request_payload.get("request_sha256"):
            errors.append("Authoritative decision does not bind the validated request.")
        if not decision_payload.get("principal_id") or decision_payload.get(
            "principal_id"
        ) != identity_payload.get("principal_id"):
            errors.append(
                "Authoritative decision does not bind the resolved principal."
            )
        requested_action_bindings = (
            "requested_action_type",
            "requested_target_id",
            "requested_parameters_sha256",
        )
        if any(
            not decision_payload.get(name)
            or decision_payload.get(name) != request_payload.get(name)
            for name in requested_action_bindings
        ):
            errors.append(
                "Authoritative decision does not bind the validated request action."
            )
        if decision_payload.get("outcome") in {"ALLOW", "ALLOW_CONSTRAINED"} and (
            decision_payload.get("action_type")
            != decision_payload.get("requested_action_type")
            or decision_payload.get("target_id")
            != decision_payload.get("requested_target_id")
        ):
            errors.append(
                "Permitted action type or target differs from the validated request."
            )
    if approval_present:
        requirement_payload = by_type.get("APPROVAL_REQUIREMENT_PRODUCED", {})
        policy_payload = by_type.get("POLICY_EVALUATED", {})
        if (
            requirement_payload.get("request_id_bound") != stable_request_id
            or requirement_payload.get("decision_id_bound")
            != decision_payload.get("decision_id")
            or not requirement_payload.get("decision_context_sha256")
            or requirement_payload.get("decision_context_sha256")
            != decision_payload.get("decision_context_sha256")
            or requirement_payload.get("reason_codes")
            != decision_payload.get("reason_codes")
            or requirement_payload.get("status") != "PENDING"
        ):
            errors.append(
                "Approval requirement does not bind the authoritative decision."
            )
        if any(
            not requirement_payload.get(name)
            or requirement_payload.get(name) != policy_payload.get(name)
            for name in ("policy_id", "policy_version", "policy_sha256")
        ):
            errors.append("Approval requirement does not bind the evaluated policy.")
        if (
            requirement_payload.get("action_type")
            != decision_payload.get("requested_action_type")
            or requirement_payload.get("target_id")
            != decision_payload.get("requested_target_id")
            or requirement_payload.get("parameters_sha256")
            != decision_payload.get("requested_parameters_sha256")
        ):
            errors.append(
                "Approval requirement does not bind the requested action scope."
            )
        try:
            requirement_scope = {
                "approval_id": requirement_payload["approval_id"],
                "issuer_instance_id": requirement_payload["issuer_instance_id"],
                "request_id": requirement_payload["request_id_bound"],
                "decision_id": requirement_payload["decision_id_bound"],
                "decision_context_sha256": requirement_payload[
                    "decision_context_sha256"
                ],
                "policy_id": requirement_payload["policy_id"],
                "policy_version": requirement_payload["policy_version"],
                "policy_sha256": requirement_payload["policy_sha256"],
                "action_type": requirement_payload["action_type"],
                "target_id": requirement_payload["target_id"],
                "parameters_sha256": requirement_payload["parameters_sha256"],
                "evidence_sha256": requirement_payload["evidence_sha256"],
                "reason_codes": tuple(requirement_payload["reason_codes"]),
                "required_approving_authority": requirement_payload[
                    "required_approving_authority"
                ],
                "created_at": requirement_payload["created_at"],
                "expires_at": requirement_payload["expires_at"],
                "status": requirement_payload["status"],
            }
            expected_scope_sha256 = sha256_json(requirement_scope)
        except (KeyError, TypeError, ValueError):
            expected_scope_sha256 = ""
        if (
            not expected_scope_sha256
            or expected_scope_sha256 != requirement_payload.get("scope_sha256")
        ):
            errors.append("Approval requirement scope digest is invalid.")
    if approval_recorded_suffix:
        requirement_payload = by_type.get("APPROVAL_REQUIREMENT_PRODUCED", {})
        approval_payload = by_type.get("APPROVAL_RECORDED", {})
        if decision_payload.get("outcome") != "ESCALATE" or not approval_present:
            errors.append("Only a closed ESCALATE lifecycle may record approval.")
        exact_bindings = (
            ("approval_id", "approval_id"),
            ("scope_sha256", "requirement_scope_sha256"),
            ("issuer_instance_id", "issuer_instance_id"),
            ("action_type", "action_type"),
            ("target_id", "target_id"),
            ("parameters_sha256", "parameters_sha256"),
            ("evidence_sha256", "evidence_sha256"),
            ("required_approving_authority", "approving_authority"),
        )
        if any(
            not requirement_payload.get(requirement_name)
            or requirement_payload.get(requirement_name)
            != approval_payload.get(approval_name)
            for requirement_name, approval_name in exact_bindings
        ):
            errors.append(
                "Approval receipt does not bind the exact recorded requirement."
            )
        if (
            not approval_payload.get("receipt_id")
            or not approval_payload.get("approver_id")
            or approval_payload.get("status") != "APPROVED_FOR_REEVALUATION"
            or approval_payload.get("reevaluation_required") is not True
            or approval_payload.get("authorization_produced") is not False
            or final_payload.get("operational_effects") != 0
        ):
            errors.append(
                "Approval receipt disposition or no-effect boundary is invalid."
            )
        try:
            created_at = datetime.fromisoformat(
                str(requirement_payload["created_at"])
            ).astimezone(timezone.utc)
            expires_at = datetime.fromisoformat(
                str(requirement_payload["expires_at"])
            ).astimezone(timezone.utc)
            approved_at = datetime.fromisoformat(
                str(approval_payload["approved_at"])
            ).astimezone(timezone.utc)
            if not (created_at <= approved_at < expires_at):
                errors.append(
                    "Approval receipt time is outside the requirement interval."
                )
        except (KeyError, TypeError, ValueError, OverflowError):
            errors.append("Approval lifecycle timestamps are invalid.")

    if "AUTHORIZATION_PRODUCED" in by_type:
        if decision_payload.get("outcome") not in {"ALLOW", "ALLOW_CONSTRAINED"}:
            errors.append("Authorization exists for a non-allow decision.")
        authorization_payload = by_type["AUTHORIZATION_PRODUCED"]
        broker_payload = by_type.get("BROKER_INVOKED", {})
        accounting_payload = by_type.get("POST_EFFECT_ACCOUNTING_FAILURE", {})
        action_payload = by_type.get("ACTION_ATTEMPTED", {})
        recorded_verification_payload = by_type.get("VERIFICATION_PERFORMED", {})
        post_verification_payload = recorded_verification_payload
        token_id = str(authorization_payload.get("token_id", ""))
        if accounting_payload:
            embedded_action = accounting_payload.get("action")
            embedded_verification = accounting_payload.get("verification")
            if not action_payload and isinstance(embedded_action, dict):
                action_payload = embedded_action
            if isinstance(embedded_verification, dict):
                if (
                    accounting_payload.get("failed_record_type")
                    == "FINAL_STATE_RECORDED"
                ):
                    immutable_verification_fields = (
                        "verification_id",
                        "request_id",
                        "decision_id",
                        "attempt_id",
                        "token_id",
                        "action_type",
                        "target_id",
                        "parameters_sha256",
                        "expected_state",
                        "observed_state",
                        "changed_fields",
                        "unexpected_fields",
                    )
                    recorded_projection = {
                        name: recorded_verification_payload.get(name)
                        for name in immutable_verification_fields
                    }
                    embedded_projection = {
                        name: embedded_verification.get(name)
                        for name in immutable_verification_fields
                    }
                    if not recorded_verification_payload or sha256_json(
                        recorded_projection
                    ) != sha256_json(embedded_projection):
                        errors.append(
                            "Post-effect final-accounting verification does not bind "
                            "the durable verification record."
                        )
                    post_verification_payload = embedded_verification
                elif not post_verification_payload:
                    post_verification_payload = embedded_verification
            if "VERIFICATION_PERFORMED" in by_type:
                expected_failed_type = "FINAL_STATE_RECORDED"
            elif "ACTION_ATTEMPTED" in by_type:
                expected_failed_type = "VERIFICATION_PERFORMED"
            else:
                expected_failed_type = "ACTION_ATTEMPTED"
            if (
                accounting_payload.get("failed_record_type") != expected_failed_type
                or not accounting_payload.get("failure_type")
                or accounting_payload.get("token_id") != token_id
                or accounting_payload.get("attempt_id")
                != action_payload.get("attempt_id")
                or accounting_payload.get("operational_effects")
                != final_payload.get("operational_effects")
            ):
                errors.append(
                    "Post-effect accounting failure record is incomplete or inconsistent."
                )
        if not token_id or str(broker_payload.get("token_id", "")) != token_id:
            errors.append("Authorization and broker token correlation is incomplete.")
        decision_to_authorization = (
            ("principal_id", "agent_id"),
            ("action_type", "action_type"),
            ("target_id", "target_id"),
            ("parameters_sha256", "parameters_sha256"),
            ("policy_id", "policy_id"),
            ("policy_version", "policy_version"),
            ("policy_sha256", "policy_sha256"),
            ("decision_context_sha256", "decision_context_sha256"),
            ("decision_sha256", "decision_sha256"),
            ("request_sha256", "request_sha256"),
        )
        if any(
            not decision_payload.get(decision_name)
            or decision_payload.get(decision_name)
            != authorization_payload.get(authorization_name)
            for decision_name, authorization_name in decision_to_authorization
        ):
            errors.append(
                "Authorization does not bind the authoritative decision scope."
            )
        try:
            authorization_parameters_sha256 = sha256_json(
                authorization_payload["permitted_parameters"]
            )
        except (KeyError, TypeError, ValueError):
            authorization_parameters_sha256 = ""
        if (
            not authorization_parameters_sha256
            or authorization_parameters_sha256
            != authorization_payload.get("parameters_sha256")
        ):
            errors.append("Authorization parameter projection is inconsistent.")
        for name in ("action_type", "target_id", "parameters_sha256"):
            if not broker_payload.get(name) or broker_payload.get(
                name
            ) != authorization_payload.get(name):
                errors.append(
                    "Broker invocation does not bind the authorization scope."
                )
                break
        for stage, payload in (
            ("ACTION_ATTEMPTED", action_payload),
            ("VERIFICATION_PERFORMED", post_verification_payload),
        ):
            if payload and str(payload.get("token_id", "")) != token_id:
                errors.append(f"{stage} token correlation is incomplete.")
        if action_payload and post_verification_payload:
            attempt_id = str(action_payload.get("attempt_id", ""))
            if (
                not attempt_id
                or str(post_verification_payload.get("attempt_id", "")) != attempt_id
            ):
                errors.append(
                    "Action and verification attempt correlation is incomplete."
                )
            if final_payload.get(
                "verification_status"
            ) != post_verification_payload.get("status"):
                errors.append("Final verification status is inconsistent.")
            scoped_payloads = [(post_verification_payload, "Post-action verification")]
            if action_payload.get("outcome_known") is not False:
                scoped_payloads.insert(0, (action_payload, "Action attempt"))
            elif "BROKER_FAILURE" not in by_type:
                errors.append(
                    "Unknown action outcome is not paired with a broker failure."
                )
            for payload, label in scoped_payloads:
                for name in ("action_type", "target_id"):
                    if not payload.get(name) or payload.get(
                        name
                    ) != authorization_payload.get(name):
                        errors.append(f"{label} does not bind the authorization scope.")
                        break
            if action_payload.get("parameters") is not None:
                try:
                    action_parameters_sha256 = sha256_json(action_payload["parameters"])
                except (TypeError, ValueError):
                    action_parameters_sha256 = ""
                if action_parameters_sha256 != authorization_payload.get(
                    "parameters_sha256"
                ):
                    errors.append("Action parameters do not bind the authorization.")
            if post_verification_payload.get(
                "parameters_sha256"
            ) != authorization_payload.get("parameters_sha256"):
                errors.append(
                    "Post-action verification parameters do not bind the authorization."
                )
            observed_state = post_verification_payload.get("observed_state")
            if isinstance(observed_state, dict):
                if observed_state.get("target_id") != authorization_payload.get(
                    "target_id"
                ):
                    errors.append(
                        "Independent observed state does not bind the authorization target."
                    )
                observed_state_sha256 = sha256_json(observed_state)
                if (
                    action_payload.get("state_after_sha256") is not None
                    and action_payload.get("state_after_sha256")
                    != observed_state_sha256
                ):
                    errors.append(
                        "Action result does not match independent observed state."
                    )
                if final_payload.get("target_state_sha256") != observed_state_sha256:
                    errors.append("Final state does not match independent observation.")
            else:
                errors.append(
                    "Post-action verification lacks an observed state object."
                )
            expected_state = post_verification_payload.get("expected_state")
            if not isinstance(expected_state, dict) or (
                expected_state.get("action_type")
                != authorization_payload.get("action_type")
                or expected_state.get("target_id")
                != authorization_payload.get("target_id")
            ):
                errors.append(
                    "Post-action expected state does not bind the authorization scope."
                )
            elif expected_state.get("parameters") is not None:
                try:
                    expected_parameters_sha256 = sha256_json(
                        expected_state["parameters"]
                    )
                except (TypeError, ValueError):
                    expected_parameters_sha256 = ""
                if expected_parameters_sha256 != authorization_payload.get(
                    "parameters_sha256"
                ):
                    errors.append(
                        "Post-action expected parameters do not bind the authorization."
                    )
            before_sha256 = action_payload.get("state_before_sha256")
            after_sha256 = action_payload.get("state_after_sha256")
            if before_sha256 is not None and after_sha256 is not None:
                if before_sha256 != authorization_payload.get("target_state_sha256"):
                    errors.append(
                        "Authorization target-state precondition does not match the action."
                    )
                try:
                    issued_at = datetime.fromisoformat(
                        str(authorization_payload["issued_at"])
                    ).astimezone(timezone.utc)
                    executed_at = datetime.fromisoformat(
                        str(action_payload["executed_at"])
                    ).astimezone(timezone.utc)
                    expires_at = datetime.fromisoformat(
                        str(authorization_payload["expires_at"])
                    ).astimezone(timezone.utc)
                    if not (issued_at <= executed_at < expires_at):
                        errors.append(
                            "Action time is outside the authorization interval."
                        )
                except (KeyError, TypeError, ValueError, OverflowError):
                    errors.append("Authorization or action timestamp is invalid.")
                expected_effects = int(before_sha256 != after_sha256)
                if final_payload.get("operational_effects") != expected_effects:
                    errors.append(
                        "Final operational-effect count does not match the state transition."
                    )
            status = post_verification_payload.get("status")
            rollback_required = post_verification_payload.get("rollback_required")
            reason_codes = post_verification_payload.get("reason_codes")
            if (
                status
                not in {
                    "VERIFIED",
                    "FAILED",
                    "PARTIAL",
                    "UNEXPECTED_EFFECT",
                    "ROLLBACK_REQUIRED",
                }
                or type(rollback_required) is not bool
                or not isinstance(reason_codes, (list, tuple))
            ):
                errors.append("Post-action verification disposition is invalid.")
            elif status == "VERIFIED":
                permitted = authorization_payload.get("permitted_parameters", {})
                verified_semantics = (
                    action_payload.get("attempted") is True,
                    action_payload.get("accepted") is True,
                    action_payload.get("reported_success") is True,
                    isinstance(observed_state, dict),
                    isinstance(expected_state, dict),
                    (
                        observed_state.get("network_state") == "isolated"
                        if isinstance(observed_state, dict)
                        else False
                    ),
                    (
                        observed_state.get("management_channel")
                        == permitted.get("preserve_management")
                        if isinstance(observed_state, dict)
                        and isinstance(permitted, dict)
                        else False
                    ),
                    (
                        observed_state.get("isolation_expires_at")
                        == expected_state.get("isolation_expires_at")
                        if isinstance(observed_state, dict)
                        and isinstance(expected_state, dict)
                        else False
                    ),
                    (
                        observed_state.get("last_action_id")
                        == action_payload.get("attempt_id")
                        if isinstance(observed_state, dict)
                        else False
                    ),
                    tuple(post_verification_payload.get("unexpected_fields", ())) == (),
                    rollback_required is False,
                    tuple(reason_codes) == ("EXPECTED_STATE_OBSERVED",),
                    final_payload.get("operational_effects") == 1,
                )
                if not all(verified_semantics):
                    errors.append(
                        "VERIFIED disposition does not match the recorded state transition."
                    )
            elif status in {"PARTIAL", "UNEXPECTED_EFFECT", "ROLLBACK_REQUIRED"}:
                if (
                    rollback_required is not True
                    or "ROLLBACK_REQUIRED" not in reason_codes
                ):
                    errors.append(
                        "Non-verified effect disposition is missing rollback semantics."
                    )
            elif status == "FAILED" and rollback_required is not False:
                errors.append(
                    "FAILED disposition cannot conceal a rollback requirement."
                )
    elif decision_payload.get("outcome") in {"ALLOW", "ALLOW_CONSTRAINED"}:
        errors.append("Allowed lifecycle is missing authorization.")

    def contains_secret(value: Any) -> bool:
        if isinstance(value, dict):
            return any(
                str(key).lower() in {"signature", "signing_key", "secret"}
                or contains_secret(child)
                for key, child in value.items()
            )
        if isinstance(value, list):
            return any(contains_secret(child) for child in value)
        return False

    if any(contains_secret(row) for row in records):
        errors.append("Lifecycle contains secret or reusable signature material.")
    return not errors, errors
