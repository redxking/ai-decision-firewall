from __future__ import annotations

import copy
import hashlib
import hmac
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from threading import Lock
from typing import Any, Mapping

from adf_poc.phase3.approval import HumanApprovalGate
from adf_poc.phase3.attestation import (
    EvidenceAttestationVerifier,
    sign_evidence_attestation,
)
from adf_poc.phase3.authorization import AuthorizationGate
from adf_poc.phase3.config import Phase3PolicyConfig
from adf_poc.phase3.consequence import assess_consequence
from adf_poc.phase3.contracts import (
    AuthenticatedPrincipal,
    EvidenceItem,
    load_decision_request_json,
)
from adf_poc.phase3.decision import build_decision
from adf_poc.phase3.engine import Phase3DecisionFirewall
from adf_poc.phase3.evidence import assess_evidence
from adf_poc.phase3.identity import ResolvedPrincipal, TrustedPrincipalResolver
from adf_poc.phase3.metrics import Phase3Metrics
from adf_poc.phase3.models import (
    AuthorizationToken,
    DecisionRecord,
    DecisionVerification,
)
from adf_poc.phase3.scenarios import (
    anonymous_principal,
    request_json,
    synthetic_invocation_credential,
    synthetic_source_keys,
    tier0_human_principal,
    trusted_soc_principal,
    valid_domain_controller_request,
    workstation_request,
)
from adf_poc.phase3.simulation import (
    ActionBroker,
    IndependentTargetVerifier,
    TargetStateObserver,
    build_simulated_execution_boundary,
)
from adf_poc.phase3.verifier import IndependentDecisionVerifier
from adf_poc.utils import sha256_json


ROOT = Path(__file__).resolve().parents[1]
POLICY_PATH = ROOT / "config" / "phase3_policy.json"
TEST_SIGNING_KEY = b"phase3-authorization-test-key-2026".ljust(32, b"!")
SOURCE_MASTER_KEY = b"phase3-source-attestation-test-key".ljust(32, b"!")
INVOCATION_MASTER_KEY = b"phase3-invocation-test-master-key".ljust(32, b"!")
APPROVAL_SIGNING_KEY = hmac.new(
    TEST_SIGNING_KEY, b"phase3-human-approval", hashlib.sha256
).digest()
VERIFIER_SIGNING_KEY = hmac.new(
    TEST_SIGNING_KEY, b"phase3-decision-verifier", hashlib.sha256
).digest()


class MutableClock:
    def __init__(self, value: datetime | None = None) -> None:
        self._value = (
            (value or datetime.now(timezone.utc))
            .astimezone(timezone.utc)
            .replace(microsecond=0)
        )
        self._lock = Lock()

    def __call__(self) -> datetime:
        with self._lock:
            return self._value

    def set(self, value: datetime) -> None:
        with self._lock:
            self._value = value.astimezone(timezone.utc).replace(microsecond=0)

    def advance(self, **values: float) -> None:
        with self._lock:
            self._value = self._value + timedelta(**values)


class DeterministicIdFactory:
    def __init__(self) -> None:
        self._counter = 0
        self._lock = Lock()

    def __call__(self, prefix: str) -> str:
        with self._lock:
            self._counter += 1
            return f"{prefix}-test-{self._counter:05d}"


def trusted_principal_without_authority() -> AuthenticatedPrincipal:
    value = trusted_soc_principal().to_dict()
    value["id"] = "SOC_AGENT_LIMITED_01"
    value["authority"] = []
    return AuthenticatedPrincipal.from_dict(value)


def tier_0_human_approver() -> AuthenticatedPrincipal:
    return tier0_human_principal()


def tier_0_human_without_authority() -> AuthenticatedPrincipal:
    value = tier0_human_principal().to_dict()
    value["id"] = "HUMAN_ANALYST_NO_TIER0_01"
    value["authority"] = []
    return AuthenticatedPrincipal.from_dict(value)


def _credential(principal: AuthenticatedPrincipal) -> bytes:
    return synthetic_invocation_credential(INVOCATION_MASTER_KEY, principal)


@dataclass(slots=True)
class Phase3Harness:
    policy: Phase3PolicyConfig
    clock: MutableClock
    id_factory: DeterministicIdFactory
    source_keys: dict[str, bytes]
    resolver: TrustedPrincipalResolver
    credential: bytes
    soc_credential: bytes
    human_credential: bytes
    human_without_authority_credential: bytes
    compromised_credential: bytes
    authority_limited_credential: bytes
    invalid_credential: bytes
    fault_modes: dict[str, str]
    firewall: Phase3DecisionFirewall


def new_harness(
    *,
    now: datetime | None = None,
    fault_modes: Mapping[str, str] | None = None,
    audit_path: str | Path | None = None,
    control_ledger_path: str | Path | None = None,
    control_ledger_busy_timeout_ms: int = 1000,
    principal: AuthenticatedPrincipal | None = None,
) -> Phase3Harness:
    policy = Phase3PolicyConfig.load(POLICY_PATH)
    clock = MutableClock(now)
    id_factory = DeterministicIdFactory()
    source_keys = synthetic_source_keys(SOURCE_MASTER_KEY)

    soc = trusted_soc_principal()
    human = tier0_human_principal()
    human_without_authority = tier_0_human_without_authority()
    compromised_value = soc.to_dict()
    compromised_value["id"] = "SOC_AGENT_COMPROMISED_01"
    compromised_value["security_status"] = "COMPROMISED"
    compromised = AuthenticatedPrincipal.from_dict(compromised_value)
    authority_limited = trusted_principal_without_authority()

    soc_credential = _credential(soc)
    human_credential = _credential(human)
    human_without_authority_credential = _credential(human_without_authority)
    compromised_credential = _credential(compromised)
    authority_limited_credential = _credential(authority_limited)
    records = (
        (soc_credential, soc),
        (human_credential, human),
        (human_without_authority_credential, human_without_authority),
        (compromised_credential, compromised),
        (authority_limited_credential, authority_limited),
    )
    resolver = TrustedPrincipalResolver(records)
    invalid_credential = b"unregistered-phase3-invocation".ljust(32, b"!")

    selected = principal or soc
    if selected == soc:
        invocation_credential = soc_credential
    elif selected == human:
        invocation_credential = human_credential
    elif selected == human_without_authority:
        invocation_credential = human_without_authority_credential
    elif selected == compromised:
        invocation_credential = compromised_credential
    elif selected == authority_limited:
        invocation_credential = authority_limited_credential
    elif selected == anonymous_principal():
        invocation_credential = invalid_credential
    else:
        raise ValueError(
            "The selected test principal is not registered by the fixture."
        )

    configured_faults = dict(fault_modes or {})
    firewall = Phase3DecisionFirewall(
        policy=policy,
        signing_key=TEST_SIGNING_KEY,
        evidence_attestation_keys=source_keys,
        principal_resolver=resolver,
        audit_path=audit_path,
        control_ledger_path=control_ledger_path,
        control_ledger_busy_timeout_ms=control_ledger_busy_timeout_ms,
        clock=clock,
        id_factory=id_factory,
        fault_modes=configured_faults,
    )
    return Phase3Harness(
        policy=policy,
        clock=clock,
        id_factory=id_factory,
        source_keys=source_keys,
        resolver=resolver,
        credential=invocation_credential,
        soc_credential=soc_credential,
        human_credential=human_credential,
        human_without_authority_credential=human_without_authority_credential,
        compromised_credential=compromised_credential,
        authority_limited_credential=authority_limited_credential,
        invalid_credential=invalid_credential,
        fault_modes=configured_faults,
        firewall=firewall,
    )


def workstation_case(harness: Phase3Harness, **values: Any) -> dict[str, Any]:
    return workstation_request(
        harness.clock(), source_keys=harness.source_keys, **values
    )


def domain_controller_case(harness: Phase3Harness, **values: Any) -> dict[str, Any]:
    return valid_domain_controller_request(
        harness.clock(), source_keys=harness.source_keys, **values
    )


def resign_evidence(
    item: dict[str, Any],
    source_keys: Mapping[str, bytes],
    *,
    update_content_digest: bool = False,
) -> None:
    if update_content_digest:
        item["integrity"]["content_sha256"] = EvidenceItem.calculate_content_sha256(
            item["payload"], item["untrusted_text"]
        )
    item["provenance"]["signature"] = sign_evidence_attestation(
        key=source_keys[item["source_instance"]],
        evidence_id=item["id"],
        subject_target_id=item["subject_target_id"],
        source_type=item["source_type"],
        source_instance=item["source_instance"],
        provenance_id=item["provenance"]["id"],
        provenance_verified=item["provenance"]["verified"],
        integrity_status=item["integrity"]["status"],
        observed_at=item["observed_at"],
        content_sha256=item["integrity"]["content_sha256"],
        supports=item["supports"],
        contradicts=item["contradicts"],
        relevance=item["relevance"],
    )


@dataclass(slots=True)
class UnconsumedAuthorization:
    harness: Phase3Harness
    principal: AuthenticatedPrincipal
    principal_resolution: ResolvedPrincipal
    request: Any
    decision: DecisionRecord
    decision_verification: DecisionVerification
    gate: AuthorizationGate
    metrics: Phase3Metrics
    observer: TargetStateObserver
    broker: ActionBroker
    target_verifier: IndependentTargetVerifier
    token: AuthorizationToken
    command: dict[str, Any]
    state_before: dict[str, Any]

    def validation_arguments(self) -> dict[str, Any]:
        return {
            "request_id": self.decision.request_id,
            "decision_id": self.decision.decision_id,
            "agent_id": self.principal.id,
            "action_type": self.command["type"],
            "target_id": self.command["target"],
            "parameters": copy.deepcopy(self.command["parameters"]),
            "policy_id": self.decision.policy_id,
            "policy_version": self.decision.policy_version,
            "policy_sha256": self.decision.policy_sha256,
            "decision_context_sha256": self.decision.decision_context_sha256,
            "target_state_sha256": sha256_json(self.state_before),
        }

    def broker_arguments(self) -> dict[str, Any]:
        return {
            "token": self.token,
            "command": copy.deepcopy(self.command),
            "request_id": self.decision.request_id,
            "decision_id": self.decision.decision_id,
            "agent_id": self.principal.id,
            "policy_id": self.decision.policy_id,
            "policy_version": self.decision.policy_version,
            "policy_sha256": self.decision.policy_sha256,
            "decision_context_sha256": self.decision.decision_context_sha256,
        }


def mint_unconsumed_authorization(
    harness: Phase3Harness,
    *,
    request_value: dict[str, Any] | None = None,
) -> UnconsumedAuthorization:
    principal = trusted_soc_principal()
    principal_resolution = harness.resolver.resolve(harness.soc_credential)
    source = request_value or workstation_case(
        harness, request_id=harness.id_factory("request")
    )
    request = load_decision_request_json(request_json(source))
    target = harness.policy.target_record(request.action.target)
    action_policy = harness.policy.action_policy(request.action.type)
    attestation_verifier = EvidenceAttestationVerifier(
        harness.source_keys,
        required_source_instances=set(harness.policy.evidence.trusted_sources),
    )
    approval_gate = HumanApprovalGate(
        signing_key=APPROVAL_SIGNING_KEY,
        ttl_seconds=harness.policy.approval_ttl_seconds,
        principal_resolver=harness.resolver,
        clock=harness.clock,
        id_factory=harness.id_factory,
    )
    evidence = assess_evidence(
        request,
        evidence_policy=harness.policy.evidence,
        attestation_verifier=attestation_verifier,
        evaluated_at=harness.clock(),
    )
    consequence = assess_consequence(
        target=target,
        action_policy=action_policy,
        consequence_policy=harness.policy.consequence,
        parameters=request.action.parameters.to_dict(),
    )
    decision = build_decision(
        request=request,
        principal=principal,
        policy=harness.policy,
        evidence=evidence,
        consequence=consequence,
        target=target,
        action_policy=action_policy,
        decided_at=harness.clock(),
        decision_id=harness.id_factory("decision"),
        approval_requirement_factory=approval_gate.issue_requirement,
    )
    verifier = IndependentDecisionVerifier(
        signing_key=VERIFIER_SIGNING_KEY,
        attestation_verifier=attestation_verifier,
        approval_gate=approval_gate,
        principal_resolver=harness.resolver,
        clock=harness.clock,
        id_factory=harness.id_factory,
    )
    decision_verification = verifier.verify(
        request=request,
        principal=principal,
        principal_resolution=principal_resolution,
        policy=harness.policy,
        target=target,
        decision=decision,
        evaluated_at=harness.clock(),
    )
    if not decision_verification.passed or decision.permitted_action is None:
        raise AssertionError(
            "Boundary-test fixture did not produce a verified allowed decision."
        )
    metrics = Phase3Metrics()
    gate = AuthorizationGate(
        signing_key=TEST_SIGNING_KEY,
        decision_verification_key=VERIFIER_SIGNING_KEY,
        verifier_instance_id=verifier.verifier_instance_id,
        ttl_seconds=harness.policy.authorization_ttl_seconds,
        metrics=metrics,
        clock=harness.clock,
        id_factory=harness.id_factory,
    )
    observer, broker, target_verifier = build_simulated_execution_boundary(
        target_inventory=harness.policy.target_inventory,
        gate=gate,
        metrics=metrics,
        fault_modes=harness.fault_modes,
        clock=harness.clock,
        id_factory=harness.id_factory,
    )
    state_before = observer.observe(target.id)
    token = gate.issue(
        decision=decision,
        agent_id=principal.id,
        target_state_sha256=sha256_json(state_before),
        decision_verification=decision_verification,
    )
    command = decision.to_dict()["permitted_action"]
    if not isinstance(command, dict):
        raise AssertionError("Boundary-test decision has no executable command.")
    return UnconsumedAuthorization(
        harness=harness,
        principal=principal,
        principal_resolution=principal_resolution,
        request=request,
        decision=decision,
        decision_verification=decision_verification,
        gate=gate,
        metrics=metrics,
        observer=observer,
        broker=broker,
        target_verifier=target_verifier,
        token=token,
        command=copy.deepcopy(command),
        state_before=state_before,
    )


def audit_record_types(result: Any) -> list[str]:
    return [row["record_type"] for row in result.audit_records]
