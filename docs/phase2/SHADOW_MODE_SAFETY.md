# Phase 2 Shadow-Mode Safety Case

> **Release boundary.** `0.2.0-alpha.5` / Phase 2.4 is the prior published evidence baseline. Phase 2.5 source-to-decision controls were present at predecessor untagged `0.2.0-alpha.6` design-freeze Commit `08ce203c`, whose historical CI and Dependency Graph results remain bound to that commit. This package candidate adds bounded local-write controls, selected Gate B causal-test scaffolding, and packaging; its Phase 2.5 technical suite passed 222/222, the separate public-site module passed 9/9, and the combined repository aggregate passed 231/231. The site module is outside Phase 2.5 and shadow-mode evidence. The candidate includes a generated-and-verified integrity manifest and inspected final-source status renders. Package publication and GitHub CI on the exact published package commit remain external gates. No live shadow feed, historical pilot, action authority, tagged alpha.6 release, evidence package, or `P2-CE-005` result exists.

## Top-level claim

Under the built-in runner, canonical adapter, and tested repository configuration, Phase 2 replay and shadow modes can produce evidence assessments, model scores, policy dispositions, verifier results, and counterfactual actions, while the read-only engine path does not construct an authorization gate, broker, or target and reports zero authorization attempts, broker invocations, or operational effects.

This CE-2 controlled-behavior claim applies only to the repository-controlled path and exact configuration identified by the run evidence. The starter is a same-process Python program, not an OS-enforced sandbox against arbitrary imported code. The claim does not authorize a live data connection. The included fixture is synthetic, `historical_case_count=0`, and no live-feed connector or action capability exists.

Phase 2.4 adds a separate CE-1 implementation-conformance boundary: modeled attributes require exact types and authorized sources, canonical inventory context is bound exactly, and a separately implemented in-process projector must reproduce the serialized 20-feature values and traces before evaluation metrics or a completed run manifest. The fixed `P2-CE-004` campaign adds narrow SELF-reviewed CE-2 evidence for 32 commit-bound synthetic attempts. It does not expand the replay no-effect claim or authorize historical, live, shadow-feed, or action use.

Phase 2.5 adds a second same-process, project-controlled reference path across the deterministic evidence, model, policy, verifier, and read-only final-decision surfaces. A successful semantic receipt does not cover volatile decision UUID/time/latency/hash instance fields; the completed run manifest separately co-binds the raw decisions and eight-stage audit. The planned `P2-CE-005` campaign remains CE-0 `NOT_EVALUATED`. Neither the implementation nor its plan expands the no-effect claim or authorizes live use.

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
| Typed/source-authorized modeled signals | A model-driving attribute must have its exact JSON type/range and appear only under a code-authorized source role; opaque attributes cannot become features |
| Finite structured numbers | Every JSON number anywhere in an accepted case is finite before engine invocation, including otherwise opaque attributes |
| Explicit non-feature evidence input | `source_conflict` is an exact JSON Boolean authorized only for `network`; `QUARANTINE_RECORD` maps wrong source to `SEMANTICS / UNAUTHORIZED_DECISION_SIGNAL` and wrong type to `SEMANTICS / INVALID_BOOLEAN`; it may affect evidence quality but is outside reference feature recomputation |
| Exact canonical inventory binding | Every asset-inventory event must contain and exactly match case `asset_id`, `privilege_level`, `break_glass`, and `asset_criticality` |
| No label leakage | Adjudications remain outside runtime evidence; historical label bytes are integrity-frozen inside the harness but their path and contents are withheld from the runner, and semantic loading occurs only after decisions close |
| Audited suppression and finalization | Each read-only decision has exactly one suppression record, one no-authorization record, and one finalization record bound to the recomputed decision hash |
| Separate reference projection | After complete decision/audit validation, separately reconstruct all 20 feature values/traces; a mismatch prevents assurance, evaluator, metrics, and completed-manifest output |
| Separate source-to-decision recomputation | After Phase 2.4 succeeds in memory, separately compare `EVIDENCE`, `MODEL`, `POLICY`, `VERIFIER`, and `FINAL_SURFACE`; any mismatch publishes neither receipt and prevents evaluator and completed-run finalization |
| Explicit completion boundary | Intermediate artifacts, including a manifest written before a failed final check, are incomplete; only successful harness return after final revalidation establishes completion |

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

The engine audit includes exactly one canonical ordered trace for every read-only case: `CASE_RECEIVED`, `EVIDENCE_ASSESSED`, `MODEL_ASSESSED`, `POLICY_PROPOSED`, `INDEPENDENTLY_VERIFIED`, `EXECUTION_SUPPRESSED`, `AUTHORIZATION_EVALUATED`, and `DECISION_FINALIZED`. The harness enforces closed row and payload shapes, global sequence and timestamp rules, code-owned suppression content, exact frozen-policy action binding, and decision identifier/hash cross-binding. Exact field and status values are governed by `src/adf_poc/execution.py`, `src/adf_poc/engine.py`, `src/adf_poc/replay/harness.py`, and their tests.

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
| Type coercion or source spoofing | A truthy string, invalid count, or modeled key under an unrelated source becomes a model feature | Exact JSON type/range and source-authority matrix; stable fail/quarantine taxonomy; no generic truthiness or string-to-number coercion | An authorized assertion can still be false, incomplete, or semantically mis-mapped |
| Non-finite or wrongly sourced evidence-control value | Nonstandard numeric behavior or coerced `source_conflict` changes evidence assessment | Reject any non-finite case number; accept `source_conflict` only as a network Boolean | Reference feature agreement does not recompute evidence-quality correctness |
| Coherent decision and audit forgery | Feature values/traces are changed while decision hashes and the audit chain are recomputed | Separate in-process reconstruction from normalized cases after full audit validation | Same process, project, runtime, and normalized inputs can retain correlated defects; no external custody |
| Coherent downstream semantic forgery | Evidence, model, policy, verifier, final decision, decision hash, and audit chain are changed consistently | Recompute five ordered semantic surfaces from frozen case/model/policy bytes; co-bind receipts, raw decisions, and audit in the completed manifest | Shared process, project, specification, and governance can retain correlated defects; not independent assurance |
| Late artifact mutation | Validated outputs are changed after a check or during manifest construction/finalization | Strict-parse, structurally compare, and exact-freeze every deterministic output after write; separately exact-freeze raw decisions/audit; recheck the full set before manifest construction, after construction, and after manifest write in ordinary and descriptor-bound historical paths | The manifest is not self-hashed; a failure can leave intermediate files or a written manifest, and external custody and atomic publication are not provided |
| Embedded label or hindsight | Artificially improve decisions or contaminate evaluation | Runtime label prohibition; adjudication bytes frozen inside the harness but withheld from runner arguments and paths until post-decision semantic loading | Same-process isolation is not an OS security boundary, and operational context can indirectly reveal outcomes |
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

A successful `AuditLogger.verify()` and eight-stage harness result means that the presented rows are internally consistent with the presented chain, decisions, and bound policy actions under the tested mutation set. This is CE-1 implementation conformance. It does not independently recompute evidence, model, complete policy, verifier, or source-to-decision correctness; establish externally trusted timestamps or custody; or prevent a process with write access from replacing and recomputing the complete chain. Phase 2 reports must retain these limitations beside any audit-validity result.

## Reference-assurance interpretation

Reference assurance begins only after read-only decision validation, deterministic decision serialization, and the complete audit check. A successful `reference_feature_assurance.jsonl` row means that the separate projector reproduced the serialized feature values and traces for the named normalized case. The row is closed and metadata-only: it contains the case identifier, normalized-case digest, expected/observed projection digests, and `matched=true`. Metrics and the run manifest bind its count and digest.

A mismatch raises a stable code-owned error and emits no reference-assurance artifact, qualification/rejection publication, adjudication comparison, metrics, or completed run manifest. Raw/normalized/deterministic decisions and the audit may already exist and must remain visibly incomplete rather than being treated as a completed replay.

This check does not prove that source assertions are authentic or true, recompute `source_conflict` or evidence quality, recompute model probability, validate policy/disposition/verifier correctness, provide external custody, or constitute independent replication. `P2-CE-004` observed only the fixed synthetic result recorded in its evidence bundle; it does not broaden any of those claims.

Phase 2.5 runs only after the feature check succeeds in memory. It recomputes evidence, model, policy, verifier, and read-only final semantic surfaces in order and writes `source_to_decision_assurance.jsonl` only on complete agreement. The receipt excludes volatile decision UUID, creation time, latency, and record-hash instance fields; the completed manifest separately binds raw decisions and the eight-stage audit. A receipt alone may repeat across semantically equivalent runs and is not custody evidence.

The full output set comprises normalized cases, normalization diagnostics, raw engine decisions, deterministic replay decisions, replay audit, both reference receipts, adjudication comparison, replay metrics, and qualification accounting and rejections when enabled. Both output paths freeze and recheck that complete set at the three manifest boundaries. The run manifest is not self-hashed; successful harness return after the final check is the completion signal.

A Phase 2.5 mismatch publishes neither reference receipt and stops before qualification/rejection publication, adjudication decoding, comparisons, metrics, or completed-run finalization. Earlier decision/audit files are incomplete. A later error can leave additional artifacts or a manifest file; file presence never overrides the failed return state.

This broader calculation check remains same-process, same-project, and project-controlled. It does not establish source truth, outcome correctness, policy fitness, efficacy, privacy authority, historical/live performance, organizational independence, OS isolation, network nonuse, exhaustive coverage, or a statistical failure bound. `P2-CE-005` remains CE-0 `NOT_EVALUATED`.

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

Zero effects in the starter do not establish safe future action, operational model performance, privacy compliance, production isolation, monitor effectiveness, or resilience against strategic or arbitrary same-process misuse. The Phase 2.4 and Phase 2.5 checks do not establish source truth, outcome correctness, policy fitness or efficacy, external independence/custody, exhaustive coverage, a bounded failure rate, OS-level isolation/non-egress, target-side proof, production readiness, or alignment/misalignment/sabotage robustness. They establish only narrow implementation behavior for the built-in Phase 2 path under tested configurations. `P2-CE-005` has no result. See [`CLAIM_EVIDENCE_STANDARD.md`](CLAIM_EVIDENCE_STANDARD.md) for required evidence and prohibited inferences.
