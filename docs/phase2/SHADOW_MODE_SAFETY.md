# Phase 2 Shadow-Mode Safety Case

## Top-level claim

Under the built-in runner, canonical adapter, and tested repository configuration, Phase 2 replay and shadow modes can produce evidence assessments, model scores, policy dispositions, verifier results, and counterfactual actions, while the read-only engine path does not construct an authorization gate, broker, or target and reports zero authorization attempts, broker invocations, or operational effects.

This CE-2 controlled-behavior claim applies only to the repository-controlled path and exact configuration identified by the run evidence. The starter is a same-process Python program, not an OS-enforced sandbox against arbitrary imported code. The claim does not authorize a live data connection. The included fixture is synthetic, `historical_case_count=0`, and no live-feed connector or action capability exists.

## Safety invariants

| Invariant | Required enforcement |
|---|---|
| Read-only modes only | Phase 2 accepts `historical_replay` and `shadow_read_only`; no live-action mode exists |
| No authorization path | Read-only engine construction excludes the authorization gate |
| No broker path | Read-only engine construction excludes the action broker and target |
| No action credential | No action secret, target credential, or write-capable client is loaded |
| Counterfactual-only containment | Proposed actions are recorded separately; executable actions are empty |
| Zero effects | Authorization attempts, broker invocations, and operational effects remain zero |
| Fail-closed configuration | Unknown modes and action-enabling settings fail before case processing |
| Governed input only | Historical records without approval and de-identification attestation are rejected |
| No label leakage | Adjudications remain outside runtime evidence and load only after decisions close |
| Audited suppression and finalization | Each read-only decision has exactly one suppression record, one no-authorization record, and one finalization record bound to the recomputed decision hash |

An operator cannot convert a replay decision into an action by changing a threshold, policy disposition, evidence score, or input field. The code path itself must lack the objects needed to authorize or execute.

## Implementation-aware execution record

The read-only decision shape preserves the counterfactual result while making non-execution explicit:

```json
{
  "execution_mode": "historical_replay",
  "counterfactual_actions": ["revoke_active_sessions"],
  "proposal": {
    "executable_actions": []
  },
  "authorization": {
    "issued": false,
    "token_id": "",
    "decision_hash": "",
    "permitted_actions": [],
    "error": ""
  },
  "action_results": [],
  "post_action_verification": {
    "applicable": false,
    "status": "NOT_APPLICABLE",
    "passed": null,
    "checks": []
  },
  "execution_control": {
    "mode": "historical_replay",
    "read_only": true,
    "status": "SUPPRESSED_READ_ONLY",
    "authorization_attempted": false,
    "broker_invocations": 0,
    "operational_effects": 0
  }
}
```

The engine audit includes execution-suppression, no-authorization, and decision-finalization events for every read-only case. The harness recomputes the decision-record hash and cross-checks the finalization payload. Exact field and status values are governed by `src/adf_poc/execution.py`, `src/adf_poc/engine.py`, and their tests.

## Threats and controls

| Threat or failure | Phase 2 consequence | Required control | Residual risk |
|---|---|---|---|
| Mode confusion or permissive default | Read-only case enters an execution-capable branch | Explicit execution enum; unknown or contradictory configuration fails closed | A future code change could weaken the boundary without regression tests |
| Direct gate or broker injection | Caller bypasses harness intent | Engine construction exposes no gate/broker injection parameter and does not construct those objects in read-only modes | V0.1 components remain in the same Python package for synthetic simulation |
| Arbitrary same-process extension | Imported code performs an unreported side effect and forges compliant local evidence | No public runner/adapter injection parameter; public evidence claim is restricted to the built-in runner and canonical adapter | Python process isolation is not implemented; untrusted extensions require an OS sandbox, no network, and scoped filesystem permissions |
| Counterfactual recommendation reused as a command | Human or downstream system treats analysis as authority | Separate fields, explicit suppression status, no dispatch interface, handling warning | Screenshots or copied text can lose context |
| Manifest path traversal | Read outside the approved snapshot | Relative paths, resolved-path confinement, no glob or URL fetch | Files within the approved directory still require governance review |
| Input tampering or time-of-check/time-of-use replacement | Evaluate substituted evidence, model, policy, or labels | Copy all declared inputs into a run snapshot; verify digests/counts on copy, after engine execution, and before finalization; load only snapshot bytes | Mutable source files and the repository manifest still require an external custody record for approved work |
| Direct identifiers in replay data | Privacy or operational exposure | Approval, attestation, field prohibitions, access and retention controls | De-identification attestation is not proof against reidentification |
| Canonical-context disagreement | Understate break-glass or mission criticality | Fail-closed cross-field validation before the decision engine | Source authority can be ambiguous in real environments |
| Embedded label or hindsight | Artificially improve decisions or contaminate evaluation | Runtime label prohibition and post-decision adjudication loading | Operational context can indirectly reveal outcomes |
| Poisoned free text | Influence an agent or operator | Preserve v0.1 untrusted-text isolation and abstention rules | Pattern-based detection is incomplete |
| Audit rewriting | Conceal changes after execution | Hash-chain validation and artifact digests | Current chain lacks independent signature, external anchor, or WORM storage |
| Resource exhaustion | Prevent evaluation or distort availability | File and record limits, bounded parsing, explicit failure accounting | Starter performance limits do not establish production capacity |

## Governance boundary

Historical replay is prohibited until a data owner approves the purpose, source, fields, retention, access, deletion, and incident-response procedure. Privacy/legal and security reviewers must approve the de-identification approach. The manifest records an approval reference and de-identification attestation; it neither creates nor contains the complete external approval record.

The public repository must retain synthetic fixtures only. Historical records, local mappings, approval evidence containing sensitive details, and analyst adjudications remain outside version control and under the approved handling plan.

## Shadow-mode interpretation

In this starter, `shadow_read_only` means that the decision engine uses the no-effect execution path. It does not mean that the repository is connected to live telemetry. A live Phase 3 shadow service would require separate approval and controls, including:

- read-only service identities with no action permissions;
- defined tenant and network boundaries;
- ingestion stop conditions and a kill switch for data collection;
- retention, deletion, monitoring, and incident-response procedures;
- source-specific mapping validation and schema-drift handling;
- assurance that no action credential is present in the deployment.

Those controls still would not authorize operational action.

## Audit interpretation

A successful `AuditLogger.verify()` result means that records are internally consistent with the chain presented for verification. It does not prove independent custody or prevent a process with write access from replacing and recomputing the complete chain. Phase 2 reports must retain this limitation beside any audit-validity result.

## Prohibited Phase 2 changes

Phase 2 must not introduce:

- a `live` or `production` execution mode;
- a write-capable identity, endpoint, network, cloud, or ticketing connector;
- action credentials, secrets-manager integration for actions, or target configuration;
- a command-line or configuration override that enables effects;
- automatic transfer of counterfactual actions to an operator queue or orchestration platform;
- historical or live data in the public fixture.

Any work on non-production actions belongs to a separately authorized later phase and requires a new safety case, threat model, test evidence, and approval decision.

## Safety nonclaims

Zero effects in the starter do not establish safe future action, operational model performance, privacy compliance, production isolation, monitor effectiveness, or resilience against strategic or arbitrary same-process misuse. They establish only the narrow behavior recorded for the built-in Phase 2 path under the tested configurations. See [`CLAIM_EVIDENCE_STANDARD.md`](CLAIM_EVIDENCE_STANDARD.md) for the required evidence and prohibited inferences.
