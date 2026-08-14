from __future__ import annotations

import hashlib
import hmac
import os
import uuid
from dataclasses import asdict, dataclass
from datetime import datetime, timedelta, timezone
from typing import Any

from .policy import DecisionProposal, PolicyConfig
from .schemas import IdentityCase
from .utils import canonical_json, sha256_json
from .verifier import VerificationResult


class AuthorizationError(RuntimeError):
    pass


@dataclass(slots=True)
class AuthorizationToken:
    token_id: str
    case_id: str
    decision_hash: str
    permitted_actions: list[str]
    issued_at: str
    expires_at: str
    signature: str

    def unsigned_dict(self) -> dict[str, Any]:
        value = asdict(self)
        value.pop("signature", None)
        return value

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(slots=True)
class ActionResult:
    action: str
    success: bool
    state_before: dict[str, Any]
    state_after: dict[str, Any]
    message: str
    rollback_reference: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class AuthorizationGate:
    def __init__(self, config: PolicyConfig, signing_key: str | None = None) -> None:
        self.config = config
        self.signing_key = (signing_key or os.getenv("ADF_POC_SIGNING_KEY") or "synthetic-poc-not-for-production").encode("utf-8")

    def _sign(self, payload: dict[str, Any]) -> str:
        return hmac.new(self.signing_key, canonical_json(payload).encode("utf-8"), hashlib.sha256).hexdigest()

    def authorize(
        self,
        case: IdentityCase,
        proposal: DecisionProposal,
        verification: VerificationResult,
    ) -> AuthorizationToken | None:
        if not proposal.executable_actions:
            return None
        if not verification.passed:
            raise AuthorizationError("Independent verification failed; authorization token cannot be issued.")
        now = datetime.now(timezone.utc).replace(microsecond=0)
        expires = now + timedelta(seconds=int(self.config.safety["authorization_token_ttl_seconds"]))
        decision_hash = sha256_json({
            "case_id": case.case_id,
            "disposition": proposal.disposition,
            "actions": proposal.executable_actions,
            "rules": proposal.policy_rules_applied,
            "evidence_event_ids": proposal.evidence_event_ids,
        })
        unsigned = {
            "token_id": f"auth-{uuid.uuid4()}",
            "case_id": case.case_id,
            "decision_hash": decision_hash,
            "permitted_actions": list(proposal.executable_actions),
            "issued_at": now.isoformat(),
            "expires_at": expires.isoformat(),
        }
        signature = self._sign(unsigned)
        return AuthorizationToken(signature=signature, **unsigned)

    def validate(self, token: AuthorizationToken, case_id: str, action: str) -> None:
        expected = self._sign(token.unsigned_dict())
        if not hmac.compare_digest(expected, token.signature):
            raise AuthorizationError("Authorization token signature is invalid.")
        if token.case_id != case_id:
            raise AuthorizationError("Authorization token does not match the case.")
        if action not in token.permitted_actions:
            raise AuthorizationError("Action is not permitted by the authorization token.")
        if datetime.now(timezone.utc) > datetime.fromisoformat(token.expires_at):
            raise AuthorizationError("Authorization token has expired.")


class SimulatedIdentityProvider:
    """In-memory action target. It cannot connect to a real identity system."""

    def __init__(self) -> None:
        self.states: dict[str, dict[str, Any]] = {}

    def initialize_case(self, case: IdentityCase) -> None:
        if case.case_id not in self.states:
            self.states[case.case_id] = {
                "subject_id": case.subject_id,
                "active_sessions": 2,
                "step_up_required": False,
                "monitoring_level": "baseline",
                "account_enabled": True,
            }

    def get_state(self, case_id: str) -> dict[str, Any]:
        return dict(self.states[case_id])

    def apply(self, case_id: str, action: str) -> ActionResult:
        state = self.states[case_id]
        before = dict(state)
        deterministic_failure = int(hashlib.sha256(f"{case_id}:{action}".encode("utf-8")).hexdigest()[:8], 16) % 53 == 0
        if deterministic_failure:
            return ActionResult(
                action=action,
                success=False,
                state_before=before,
                state_after=dict(state),
                message="Synthetic downstream control-plane failure; no state change occurred.",
                rollback_reference="not_required_no_change",
            )
        if action == "revoke_active_sessions":
            state["active_sessions"] = 0
            rollback = "reauthentication_required"
        elif action == "force_step_up_auth":
            state["step_up_required"] = True
            rollback = "remove_temporary_step_up_policy"
        elif action == "increase_monitoring":
            state["monitoring_level"] = "enhanced"
            rollback = "restore_baseline_monitoring"
        else:
            raise AuthorizationError(f"The simulator does not implement action: {action}")
        return ActionResult(
            action=action,
            success=True,
            state_before=before,
            state_after=dict(state),
            message="Synthetic action applied to the in-memory identity state.",
            rollback_reference=rollback,
        )


class ActionBroker:
    def __init__(self, gate: AuthorizationGate, target: SimulatedIdentityProvider) -> None:
        self.gate = gate
        self.target = target

    def execute(self, case: IdentityCase, action: str, token: AuthorizationToken | None) -> ActionResult:
        if token is None:
            raise AuthorizationError("No authorization token was supplied.")
        self.gate.validate(token, case.case_id, action)
        self.target.initialize_case(case)
        return self.target.apply(case.case_id, action)


class PostActionVerifier:
    EXPECTED_STATE = {
        "revoke_active_sessions": ("active_sessions", 0),
        "force_step_up_auth": ("step_up_required", True),
        "increase_monitoring": ("monitoring_level", "enhanced"),
    }

    def verify(self, results: list[ActionResult]) -> dict[str, Any]:
        checks: list[dict[str, Any]] = []
        for result in results:
            field, expected = self.EXPECTED_STATE[result.action]
            actual = result.state_after.get(field)
            passed = result.success and actual == expected
            checks.append({
                "action": result.action,
                "passed": passed,
                "field": field,
                "expected": expected,
                "actual": actual,
            })
        return {"passed": all(row["passed"] for row in checks) if checks else True, "checks": checks}
