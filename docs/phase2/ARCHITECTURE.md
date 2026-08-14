# Phase 2 Architecture

## Purpose and boundary

The Phase 2 architecture adds a governed replay path around the v0.1 evidence, model, policy, and verifier pipeline. It does not extend the action surface. In the built-in runner and canonical adapter, historical replay and shadow mode terminate at a recorded counterfactual decision; the tested read-only path does not construct an authorization gate, broker, or target.

The starter uses a local synthetic fixture only. `historical_case_count` is `0`, there is no live-feed adapter, and there are no production credentials or connectors.

## Logical flow

```mermaid
flowchart TD
    M["Versioned local replay manifest"] --> P["Path confinement and file-digest verification"]
    MP["Configuration, model, and policy"] --> P
    P --> I["Frozen run-input snapshot"]
    I --> C["Governance and runtime-case validation"]
    C -->|"invalid manifest or case"| R["Fail closed before engine invocation"]
    C -->|"case set accepted"| N["Canonical normalization and temporal ordering"]
    N --> E["Evidence-quality assessment"]
    E --> A["Advisory risk model"]
    A --> D["Deterministic policy"]
    D --> V["Independent verifier"]
    V --> X["Read-only execution controller"]
    X --> S["Counterfactual decision and suppression record"]
    S --> O["Hash-bound final decision, boundary audit, and diagnostics"]
    J["Separate adjudication file"] -. "digest and count only before decisions" .-> P
    J -. "decoded only after decisions and audit close" .-> Q["Post-run evaluator"]
    O --> Q
    Q --> RI["Reverify complete input snapshot"]
    RI --> F["Comparisons, replay metrics, and completed run manifest"]
    Q -->|"invalid adjudication"| RA["Abort evaluation; retain decision and audit evidence"]
    X -.- B["No authorization gate, broker, target, or external effect"]
```

## Component allocation

| Component | Allocation | Phase 2 responsibility |
|---|---|---|
| Execution mode | `src/adf_poc/execution.py` | Define `historical_replay` and `shadow_read_only`; reject unknown or effect-capable modes |
| Replay contracts | `contracts/v0.2.0/` and `src/adf_poc/replay/contracts.py` | Validate versions, structure, semantics, governance, and prohibited label fields |
| Local snapshot adapter | `src/adf_poc/replay/adapters.py` | Read manifest-referenced local JSONL only; no network or vendor client |
| Normalizer | `src/adf_poc/replay/normalizer.py` | Produce canonical cases, retain mapping warnings, and sort valid events deterministically |
| Replay harness | `src/adf_poc/replay/harness.py` | Freeze and reverify run inputs; enforce complete case-set validation, deferred adjudication decoding, decision/audit binding, decision-only execution, safety checks, and artifact generation |
| Replay metrics | `src/adf_poc/replay/metrics.py` | Report scope, disposition, adjudication-comparison, and read-only assurance measures |
| Phase 1 engine | `src/adf_poc/engine.py` | Supply evidence, model, policy, and verifier behavior under an explicit execution boundary |
| Command entry point | `run_phase2.py` | Expose only read-only Phase 2 modes and local paths |
| Starter fixture | `data/phase2_starter/` | Exercise the framework with synthetic records and `historical_case_count: 0` |

## Execution boundary

Phase 1 simulation includes an authorization gate, an action broker, and an in-memory identity target. Phase 2 read-only modes must bypass that branch structurally rather than rely on an empty action list or operator intent.

The intended execution controller has three relevant properties:

1. Phase 1 synthetic simulation remains an explicit, separate mode for the existing POC.
2. Replay and shadow modes do not construct or receive an authorization gate, broker, target, or action credential.
3. A policy proposal may retain `CONTAIN_REVERSIBLE`, but proposed actions are copied only to `counterfactual_actions`; the execution record shows that authorization and effects were suppressed.

An illustrative decision fragment is:

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

The `final_disposition` remains a counterfactual policy result for compatibility. It must not be interpreted as an executed containment.

## Trust boundaries

### 1. Dataset boundary

Replay inputs are untrusted. Every declared file must pass path, digest, count, and bounded-read checks and then be copied into a run-owned snapshot. The engine and evaluator load only snapshot bytes, whose digests and counts are rechecked after execution and before finalization. Governance and runtime cases must pass structural and semantic checks before the engine runs. Adjudication semantics are evaluated only after decisions and boundary-audit validation close. A manifest is evidence about a dataset, not a trust anchor; its approval and digest provenance must be established outside the mutable replay directory for approved historical work.

### 2. Canonical-context boundary

V0.1 trusts top-level `break_glass` and `asset_criticality` values. Phase 2 therefore requires cross-field validation against authoritative asset-inventory evidence. Missing or contradictory safety-critical context rejects the record; it is not resolved by choosing the less restrictive value.

### 3. Label boundary

Runtime evidence envelopes cannot contain compromise labels, expected dispositions, ground truth, or adjudications. A separate evaluator may load adjudications only after decision output is closed. Historical review outcomes are adjudications with uncertainty, not automatically ground truth.

### 4. Decision-to-effect boundary

The built-in replay and shadow outputs contain recommendations and evidence traces only. The read-only engine construction has no route to the Phase 1 authorization gate or simulator and the canonical adapter has no external-system interface. This boundary is tested with exact empty authorization state, zero-token, zero-broker, zero-effect, and no-action-audit assertions. The single Python process is not an OS-enforced sandbox for arbitrary imported code; extensions require a separate trust and isolation argument.

### 5. Audit boundary

The current audit design is a SHA-256-linked consistency chain. The harness also requires exactly one suppression, no-authorization, and decision-finalization record per case; it recomputes each decision hash and cross-checks the finalization payload. These checks detect ordinary modification and incomplete local evidence when verified against an unchanged chain, but the chain is not externally signed, WORM-protected, or resistant to wholesale recomputation by a writer. Phase 2 must preserve this limitation in reports and cannot use `audit_chain_valid=true` as proof of independent custody.

## Validation and failure behavior

| Condition | Required behavior |
|---|---|
| Unsupported manifest or case-contract version | Reject before decision processing |
| Absolute path, parent traversal, or resolved path outside manifest directory | Abort before reading the declared file content |
| File digest or declared record-count mismatch | Abort the complete run |
| Source input changes during processing | Continue only from the verified run snapshot; abort if any snapshot digest/count changes |
| Missing approval or de-identification attestation for a historical dataset | Abort before engine invocation |
| Label or adjudication embedded in runtime input | Abort before engine invocation with the detected field path |
| Duplicate identifiers, case/event mismatch, invalid range, or unsafe context disagreement | Abort before engine invocation with a specific reason |
| Valid but out-of-order events | Sort by the canonical key and preserve `EVENT_ORDER_NORMALIZED` diagnostics |
| Unknown execution mode or action-enabling configuration | Fail closed before engine construction |
| Policy proposes containment in a read-only mode | Record counterfactual actions and suppress authorization and execution |
| Missing, duplicate, or mismatched decision-finalization audit record | Abort before completed run evidence is emitted |
| One malformed case in an otherwise valid case file | Abort the declared case set before engine invocation; partial-file recovery and a rejection artifact are planned, not implemented |
| Malformed or inconsistent adjudication | Abort post-run evaluation before comparisons, metrics, or completed run manifest; retain decision and audit evidence |

## Deployment view

The starter is an offline, single-host development harness. `shadow_read_only` is a semantic execution mode, not a deployed service and not a connection to live telemetry. Any Phase 3 live shadow deployment requires a separately approved architecture with a read-only service identity, network and tenant controls, data-retention rules, ingestion stop conditions, monitoring, and incident response. None of those future controls grants Phase 2 action authority.

## Architectural nonclaims

The starter does not demonstrate process isolation between policy and verification, sandboxing against arbitrary same-process code, cryptographic evidence provenance, externally anchored audit custody, privacy effectiveness, vendor semantics, production-scale availability, agentic alignment, monitor effectiveness, or safe operational action. Those are future validation obligations, not implicit capabilities.
