from __future__ import annotations

import argparse
import time
import uuid
from dataclasses import replace
from pathlib import Path
from typing import Any

from .actions import ActionBroker, AuthorizationError, AuthorizationGate, PostActionVerifier, SimulatedIdentityProvider
from .audit import AuditLogger
from .evidence import assess_evidence
from .execution import ExecutionMode, SafetyInvariantError
from .model import LogisticRiskModel
from .policy import DecisionProposal, PolicyConfig, PolicyEngine
from .schemas import Disposition, IdentityCase
from .utils import read_jsonl, sha256_json, utc_now_iso, write_jsonl
from .verifier import IndependentVerifier


class DecisionFirewallEngine:
    def __init__(
        self,
        *,
        model: LogisticRiskModel,
        policy_config: PolicyConfig,
        audit_logger: AuditLogger,
        execution_mode: ExecutionMode | str = ExecutionMode.SYNTHETIC_SIMULATION,
    ) -> None:
        self.model = model
        self.policy_config = policy_config
        self.audit = audit_logger
        self.execution_mode = ExecutionMode(execution_mode)
        self.policy_engine = PolicyEngine(policy_config)
        self.verifier = IndependentVerifier(policy_config)
        self.post_action_verifier = PostActionVerifier()
        self.gate: AuthorizationGate | None = None
        self.target: SimulatedIdentityProvider | None = None
        self.broker: ActionBroker | None = None

        if not self.execution_mode.is_read_only:
            self.gate = AuthorizationGate(policy_config)
            self.target = SimulatedIdentityProvider()
            self.broker = ActionBroker(self.gate, self.target)

    def _require_simulation_wiring(self) -> tuple[AuthorizationGate, ActionBroker]:
        if self.execution_mode.is_read_only:
            raise SafetyInvariantError(
                f"Execution wiring is prohibited in {self.execution_mode.value} mode."
            )
        if self.gate is None or self.broker is None or self.target is None:
            raise SafetyInvariantError("Synthetic simulation execution wiring is incomplete.")
        return self.gate, self.broker

    def process(self, case: IdentityCase) -> dict[str, Any]:
        started = time.perf_counter()
        self.audit.append("CASE_RECEIVED", {
            "case_id": case.case_id,
            "subject_id": case.subject_id,
            "event_ids": [event.event_id for event in case.events],
        })

        evidence = assess_evidence(case)
        self.audit.append("EVIDENCE_ASSESSED", {"case_id": case.case_id, **evidence.to_dict()})

        model_assessment = self.model.assess(case)
        self.audit.append("MODEL_ASSESSED", {"case_id": case.case_id, **model_assessment.to_dict()})

        proposal = self.policy_engine.propose(case, model_assessment, evidence)
        policy_audit_payload = proposal.to_dict()
        if self.execution_mode.is_read_only:
            policy_audit_payload["counterfactual_actions"] = list(policy_audit_payload["executable_actions"])
            policy_audit_payload["executable_actions"] = []
        self.audit.append("POLICY_PROPOSED", {"case_id": case.case_id, **policy_audit_payload})

        verification = self.verifier.verify(case, model_assessment, evidence, proposal)
        self.audit.append("INDEPENDENTLY_VERIFIED", {"case_id": case.case_id, **verification.to_dict()})

        original_disposition = proposal.disposition
        if proposal.executable_actions and not verification.passed:
            proposal = DecisionProposal(
                disposition=Disposition.INVESTIGATE.value,
                executable_actions=[],
                recommended_human_actions=[],
                investigation_actions=["resolve_independent_verifier_failure", "collect_additional_evidence"],
                rationale=proposal.rationale + ["Independent verification failed; the action proposal was downgraded to investigation."],
                policy_rules_applied=proposal.policy_rules_applied + ["FAIL-SAFE-VERIFIER-DOWNGRADE"],
                evidence_event_ids=proposal.evidence_event_ids,
                required_authority="read_only_automation",
                rollback_plan={},
            )

        counterfactual_actions: list[str] = []
        token = None
        authorization_error = ""
        authorization_attempted = False
        broker_invocations = 0

        if self.execution_mode.is_read_only:
            counterfactual_actions = list(proposal.executable_actions)
            proposal = replace(
                proposal,
                executable_actions=[],
                required_authority="read_only_observation",
                rollback_plan={},
            )
            self.audit.append("EXECUTION_SUPPRESSED", {
                "case_id": case.case_id,
                "execution_mode": self.execution_mode.value,
                "reason": "Historical replay and shadow modes are observation-only.",
                "counterfactual_actions": counterfactual_actions,
                "authorization_attempted": False,
                "broker_invocations": 0,
                "operational_effects": 0,
            })
        else:
            gate, _ = self._require_simulation_wiring()
            authorization_attempted = True
            try:
                token = gate.authorize(case, proposal, verification)
            except AuthorizationError as exc:
                authorization_error = str(exc)
        self.audit.append("AUTHORIZATION_EVALUATED", {
            "case_id": case.case_id,
            "execution_mode": self.execution_mode.value,
            "attempted": authorization_attempted,
            "issued": token is not None,
            "token_id": token.token_id if token else "",
            "permitted_actions": token.permitted_actions if token else [],
            "error": authorization_error,
        })

        action_results: list[dict[str, Any]] = []
        if token is not None:
            _, broker = self._require_simulation_wiring()
            for action in proposal.executable_actions:
                broker_invocations += 1
                try:
                    result = broker.execute(case, action, token)
                    action_results.append(result.to_dict())
                    self.audit.append("ACTION_EXECUTED", {"case_id": case.case_id, **result.to_dict()})
                except AuthorizationError as exc:
                    failure = {
                        "action": action,
                        "success": False,
                        "state_before": {},
                        "state_after": {},
                        "message": str(exc),
                        "rollback_reference": "none",
                    }
                    action_results.append(failure)
                    self.audit.append("ACTION_REJECTED", {"case_id": case.case_id, **failure})

        action_result_objects = []
        if action_results:
            from .actions import ActionResult
            action_result_objects = [ActionResult(**row) for row in action_results]
        if self.execution_mode.is_read_only:
            post_action = {
                "applicable": False,
                "status": "NOT_APPLICABLE",
                "passed": None,
                "checks": [],
            }
        else:
            verification_result = self.post_action_verifier.verify(action_result_objects)
            post_action = {
                "applicable": bool(action_result_objects),
                "status": (
                    "VERIFIED" if verification_result["passed"] else "FAILED"
                )
                if action_result_objects
                else "NOT_APPLICABLE",
                **verification_result,
            }
        if action_results:
            self.audit.append("POST_ACTION_VERIFIED", {"case_id": case.case_id, **post_action})

        operational_effects = (
            0
            if self.execution_mode.is_read_only
            else sum(1 for result in action_results if result.get("success") is True)
        )

        latency_ms = round((time.perf_counter() - started) * 1000.0, 3)
        decision_core = {
            "decision_id": f"dec-{uuid.uuid4()}",
            "case_id": case.case_id,
            "subject_id": case.subject_id,
            "asset_id": case.asset_id,
            "asset_criticality": case.asset_criticality,
            "break_glass": case.break_glass,
            "created_at": utc_now_iso(),
            "policy_id": self.policy_config.policy_id,
            "policy_version": self.policy_config.version,
            "model_version": model_assessment.model_version,
            "execution_mode": self.execution_mode.value,
            "original_disposition": original_disposition,
            "final_disposition": proposal.disposition,
            "counterfactual_actions": counterfactual_actions,
            "compromise_probability": model_assessment.compromise_probability,
            "evidence_assessment": evidence.to_dict(),
            "model_assessment": model_assessment.to_dict(),
            "proposal": proposal.to_dict(),
            "independent_verification": verification.to_dict(),
            "authorization": {
                "issued": token is not None,
                "token_id": token.token_id if token else "",
                "decision_hash": token.decision_hash if token else "",
                "permitted_actions": token.permitted_actions if token else [],
                "error": authorization_error,
            },
            "action_results": action_results,
            "post_action_verification": post_action,
            "execution_control": {
                "mode": self.execution_mode.value,
                "read_only": self.execution_mode.is_read_only,
                "status": "SUPPRESSED_READ_ONLY" if self.execution_mode.is_read_only else "SYNTHETIC_SIMULATION",
                "authorization_attempted": authorization_attempted,
                "broker_invocations": broker_invocations,
                "operational_effects": operational_effects,
            },
            "latency_ms": latency_ms,
            "traceability": {
                "input_event_ids": [event.event_id for event in case.events],
                "cited_evidence_event_ids": proposal.evidence_event_ids,
                "feature_trace": model_assessment.feature_trace,
            },
        }
        decision_core["decision_record_hash"] = sha256_json(decision_core)
        self.audit.append("DECISION_FINALIZED", {
            "case_id": case.case_id,
            "decision_id": decision_core["decision_id"],
            "final_disposition": proposal.disposition,
            "decision_record_hash": decision_core["decision_record_hash"],
        })
        return decision_core


def run_engine(
    *,
    cases_path: str | Path,
    model_path: str | Path,
    policy_path: str | Path,
    decisions_path: str | Path,
    audit_path: str | Path,
    execution_mode: ExecutionMode | str = ExecutionMode.SYNTHETIC_SIMULATION,
) -> list[dict[str, Any]]:
    audit_target = Path(audit_path)
    if audit_target.exists():
        audit_target.unlink()
    model = LogisticRiskModel.load(model_path)
    policy = PolicyConfig.load(policy_path)
    audit = AuditLogger(audit_target)
    engine = DecisionFirewallEngine(
        model=model,
        policy_config=policy,
        audit_logger=audit,
        execution_mode=execution_mode,
    )
    cases = [IdentityCase.from_dict(row) for row in read_jsonl(cases_path)]
    decisions = [engine.process(case) for case in cases]
    write_jsonl(decisions_path, decisions)
    return decisions


def main() -> None:
    parser = argparse.ArgumentParser(description="Run the AI Decision Firewall POC.")
    parser.add_argument("--cases", required=True)
    parser.add_argument("--model", required=True)
    parser.add_argument("--policy", required=True)
    parser.add_argument("--decisions", required=True)
    parser.add_argument("--audit", required=True)
    args = parser.parse_args()
    decisions = run_engine(
        cases_path=args.cases,
        model_path=args.model,
        policy_path=args.policy,
        decisions_path=args.decisions,
        audit_path=args.audit,
    )
    print(f"Processed {len(decisions)} cases.")


if __name__ == "__main__":
    main()
