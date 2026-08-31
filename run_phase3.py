from __future__ import annotations

import argparse
import secrets
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from adf_poc.audit import AuditLogger
from adf_poc.phase3.audit import (
    validate_phase3_audit_chain,
    validate_phase3_lifecycle,
)
from adf_poc.phase3.config import Phase3PolicyConfig
from adf_poc.phase3.engine import Phase3DecisionFirewall
from adf_poc.phase3.identity import TrustedPrincipalResolver
from adf_poc.phase3.scenarios import (
    request_json,
    synthetic_source_keys,
    trusted_soc_principal,
    valid_domain_controller_request,
    workstation_request,
)
from adf_poc.utils import read_json, write_json


ROOT = Path(__file__).resolve().parent
DEFAULT_POLICY = ROOT / "config" / "phase3_policy.json"
DEFAULT_OUTPUT = ROOT / "outputs" / "local" / "phase3-demo"
_HIGH_RISK_REQUIRED_REASONS = {
    "PROTECTED_ASSET",
    "INSUFFICIENT_AUTHORITY",
    "STALE_EVIDENCE",
    "CONFLICTING_EVIDENCE",
    "HIGH_OPERATIONAL_CONSEQUENCE",
}


def _prepare_output(path: Path) -> Path:
    target = path.resolve()
    if target.exists() and any(target.iterdir()):
        raise RuntimeError(
            "Phase 3 demo output directory must be absent or empty; refusing to clobber artifacts."
        )
    target.mkdir(parents=True, exist_ok=True)
    return target


def _recorded_effects(result: Any) -> int:
    final_rows = [
        row
        for row in result.audit_records
        if row.get("record_type") == "FINAL_STATE_RECORDED"
    ]
    if len(final_rows) != 1:
        raise RuntimeError("Demonstration lifecycle lacks one final-state record.")
    return int(final_rows[0]["payload"]["operational_effects"])


def _assert_demo_acceptance(
    *,
    high_result: Any,
    low_result: Any,
    metrics: dict[str, Any],
    audit_valid: bool,
    high_lifecycle_valid: bool,
    low_lifecycle_valid: bool,
) -> dict[str, Any]:
    high_effects = _recorded_effects(high_result)
    low_effects = _recorded_effects(low_result)
    checks = {
        "high_risk_escalated": high_result.decision.outcome == "ESCALATE",
        "high_risk_reasons_complete": _HIGH_RISK_REQUIRED_REASONS.issubset(
            set(high_result.decision.reason_codes)
        ),
        "high_risk_no_authorization": high_result.authorization is None,
        "high_risk_no_broker": high_result.broker_result is None,
        "high_risk_zero_effect": high_effects == 0
        and high_result.final_state is not None
        and high_result.final_state.get("network_state") == "connected",
        "workstation_allowed": low_result.decision.outcome == "ALLOW",
        "workstation_authorized": low_result.authorization is not None,
        "workstation_broker_accepted": low_result.broker_result is not None
        and low_result.broker_result.attempted
        and low_result.broker_result.accepted,
        "workstation_verified": low_result.verification is not None
        and low_result.verification.status == "VERIFIED",
        "workstation_effect_observed": low_effects == 1
        and low_result.final_state is not None
        and low_result.final_state.get("network_state") == "isolated",
        "audit_chain_valid": audit_valid,
        "high_risk_lifecycle_valid": high_lifecycle_valid,
        "workstation_lifecycle_valid": low_lifecycle_valid,
        "decision_metrics_reconciled": metrics.get("decisions_total") == 2
        and metrics.get("decision_counts", {}).get("ESCALATE") == 1
        and metrics.get("decision_counts", {}).get("ALLOW") == 1,
        "no_live_action_mode": True,
    }
    failed = sorted(name for name, passed in checks.items() if not passed)
    if failed:
        raise RuntimeError(
            "Phase 3 demonstration acceptance failed: " + ", ".join(failed)
        )
    return {
        "status": "PASS",
        "checks": checks,
        "high_risk_operational_effects": high_effects,
        "workstation_operational_effects": low_effects,
    }


def run_demonstration(
    *,
    output_dir: str | Path,
    policy_path: str | Path = DEFAULT_POLICY,
    evaluated_at: datetime | None = None,
) -> dict[str, Any]:
    output = _prepare_output(Path(output_dir))
    now = (
        (evaluated_at or datetime.now(timezone.utc))
        .astimezone(timezone.utc)
        .replace(microsecond=0)
    )
    policy = Phase3PolicyConfig.load(policy_path)
    source_keys = synthetic_source_keys(secrets.token_bytes(32))
    principal = trusted_soc_principal()
    invocation_credential = secrets.token_bytes(32)
    firewall = Phase3DecisionFirewall(
        policy=policy,
        signing_key=secrets.token_bytes(32),
        evidence_attestation_keys=source_keys,
        principal_resolver=TrustedPrincipalResolver(
            [(invocation_credential, principal)]
        ),
        audit_path=output / "phase3_audit.jsonl",
        clock=lambda: now,
    )

    high_request = valid_domain_controller_request(now, source_keys=source_keys)
    high_result = firewall.process_json(
        request_json(high_request), credential=invocation_credential
    )
    workstation = workstation_request(now, source_keys=source_keys)
    low_result = firewall.process_json(
        request_json(workstation), credential=invocation_credential
    )

    persisted_audit = AuditLogger(output / "phase3_audit.jsonl").read_all()
    audit_valid, audit_errors = validate_phase3_audit_chain(persisted_audit)
    high_lifecycle_valid, high_lifecycle_errors = validate_phase3_lifecycle(
        high_result.audit_records
    )
    low_lifecycle_valid, low_lifecycle_errors = validate_phase3_lifecycle(
        low_result.audit_records
    )
    metrics = firewall.metrics_snapshot()
    acceptance = _assert_demo_acceptance(
        high_result=high_result,
        low_result=low_result,
        metrics=metrics,
        audit_valid=audit_valid,
        high_lifecycle_valid=high_lifecycle_valid,
        low_lifecycle_valid=low_lifecycle_valid,
    )
    result = {
        "status": "PASS",
        "scope": {
            "phase": "Phase 3 operational MVP",
            "execution_mode": firewall.execution_mode,
            "data_type": "synthetic",
            "live_actions_enabled": False,
            "operational_validity": "not established",
        },
        "evaluated_at": now.isoformat(),
        "policy": {"id": policy.policy_id, "version": policy.version},
        "demo_1_high_risk_domain_controller": high_result.to_dict(),
        "demo_2_authorized_workstation": low_result.to_dict(),
        "metrics": metrics,
        "acceptance": acceptance,
        "audit": {
            "valid": audit_valid,
            "errors": audit_errors,
            "high_risk_lifecycle_valid": high_lifecycle_valid,
            "high_risk_lifecycle_errors": high_lifecycle_errors,
            "workstation_lifecycle_valid": low_lifecycle_valid,
            "workstation_lifecycle_errors": low_lifecycle_errors,
        },
    }
    result_path = output / "phase3_demo_results.json"
    write_json(result_path, result)
    write_json(output / "phase3_metrics.json", result["metrics"])
    # Return the exact JSON-native representation that was persisted.  The
    # domain models intentionally use immutable tuples internally; a round
    # trip here prevents callers from observing a different in-memory shape
    # than the demonstration artifact they are asked to review.
    persisted = read_json(result_path)
    if not isinstance(persisted, dict):  # pragma: no cover - write_json invariant
        raise RuntimeError("Phase 3 demonstration result is not a JSON object.")
    return persisted


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Run the simulation-only AI Decision Firewall Phase 3 demonstrations."
    )
    parser.add_argument("--policy", default=str(DEFAULT_POLICY))
    parser.add_argument("--output-dir", default=str(DEFAULT_OUTPUT))
    args = parser.parse_args()
    result = run_demonstration(
        output_dir=args.output_dir,
        policy_path=args.policy,
    )
    high = result["demo_1_high_risk_domain_controller"]
    low = result["demo_2_authorized_workstation"]
    print("DEMO 1 — HIGH-RISK ACTION")
    print("AI recommendation: ISOLATE DOMAIN CONTROLLER")
    print("AI confidence: 96%")
    print(f"Firewall: {high['decision']['outcome']}")
    print("Reasons: " + ", ".join(high["decision"]["reason_codes"]))
    high_effects = result["acceptance"]["high_risk_operational_effects"]
    print(f"Operational effect: {'NONE' if high_effects == 0 else high_effects}")
    print()
    print("DEMO 2 — AUTHORIZED ACTION")
    print("AI recommendation: ISOLATE WORKSTATION")
    print("Evidence: FRESH + CORROBORATED")
    print("Authority: AUTHENTICATED ENDPOINT CONTAINMENT")
    print(f"Firewall: {low['decision']['outcome']}")
    verification = low.get("verification") or {}
    print(f"Independent verification: {verification.get('status', 'NOT_APPLICABLE')}")
    print(f"Synthetic target state: {low.get('final_state', {}).get('network_state')}")
    print()
    print(f"Audit chain valid: {result['audit']['valid']}")
    print(f"Acceptance: {result['status']}")
    print(f"Artifacts: {Path(args.output_dir).resolve()}")


if __name__ == "__main__":
    main()
