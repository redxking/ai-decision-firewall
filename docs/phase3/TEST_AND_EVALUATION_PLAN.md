# Phase 3 Operational MVP Test and Evaluation Plan

## Status and purpose

This document separates the original acceptance design from the published
`0.3.0-alpha.1` observations as of 2026-08-15. The requirements and
detailed matrix
remain the test oracle. “Observed passing” means a project-controlled run over
synthetic inputs; it is CE-1 implementation conformance only. Phase 3 exact
Commit `423685d105be813056617db738297eba83d3d9d0` is published on `main`, and
exact-commit CI and Dependency Graph checks passed. Existing Phase 1 and Phase 2/2.5 claims retain the boundaries
described in the [current repository test plan](../TEST_AND_EVALUATION_PLAN.md)
and [Security and Safety Case](../SECURITY_AND_SAFETY_CASE.md).

Published Phase 2.5 Commit
`854b15c56397a81de6326b719d3d7d1dc847608f` is on `main` and its exact-commit CI
and Dependency Graph checks passed. `P2-CE-005` was not executed and remains
CE-0 `NOT_EVALUATED`; none of the Phase 3 observations changes that state.

Test count is not a success criterion. Acceptance depends on demonstrated
mission behavior, closed safety boundaries, meaningful negative paths, and a
reproducible end-to-end result.

## Published Phase 3 state

| Scope | Published observation | Evidence boundary |
|---|---|---|
| Focused Phase 3 controls | 57/57 contract, decision, authorization, adversarial, end-to-end, corpus-runner, and release-blocker tests passed | CE-1 implementation conformance; exact-commit CI passed |
| Required demonstrations | Both raw-request demos passed: Tier-0 domain controller `ESCALATE` with no effect; authorized workstation `ALLOW` with one simulated effect and `VERIFIED` readback | Synthetic simulation only |
| Systematic adversarial corpus | 46/46 declared scenarios passed | Project-controlled deterministic cases; not exhaustive/statistical assurance |
| Full repository regression | 288/288 passed after the final release-blocker fixes | Then-current exact-commit regression boundary |
| Commit and CI | Exact Commit `423685d`; CI and Dependency Graph passed | Published Phase 3 implementation boundary |
| Operational validation | Not evaluated | No live action, efficacy, safety, or external-independence claim |

Adversarial review found and closed release-blocking defects across consequence,
evidence binding, credential/trust-material handling, exact-type construction,
machine-policy invariants, replay/receipt atomicity, dependency-failure closure,
and post-effect audit semantics. The 57-test focused result includes the
dedicated release-blocker regressions. The complete settled-candidate repository
suite subsequently passed 288/288 locally and in exact-commit CI. Later
executable or test changes do not alter that version-bound result and require a
new count for the changed tree.

Reproduce the focused suite and corpus:

```bash
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src python3 -m unittest \
  tests.test_phase3_contracts \
  tests.test_phase3_decision_path \
  tests.test_phase3_authorization_boundary \
  tests.test_phase3_adversarial \
  tests.test_phase3_end_to_end \
  tests.test_phase3_corpus \
  tests.test_phase3_release_blockers -v

corpus_dir="$(mktemp -d /tmp/adf-phase3-corpus.XXXXXX)"
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src python3 run_phase3_corpus.py \
  --output-dir "$corpus_dir"
```

## Objectives

The Phase 3 test program must establish that:

1. an external agent can submit a raw, versioned proposed-action request;
2. schema, credential-resolved identity, evidence, policy, consequence, and
   authority are evaluated separately from the agent's recommendation and
   confidence;
3. the firewall returns one deterministic `ALLOW`, `DENY`, `ESCALATE`, or
   `ALLOW_CONSTRAINED` decision with structured reasons;
4. only a narrow, valid, unexpired, single-use authorization reaches the
   simulation broker;
5. direct broker and target bypass attempts fail;
6. functionally separate same-project target readback determines execution
   outcome;
7. complete lifecycle audit and required metrics exist; and
8. no live operational action path is present or selectable.

## Scope

### In scope

- Raw JSON request ingestion and contract validation.
- Opaque invocation credentials, trusted principal resolver, source, target,
  action, policy, and clock fixtures.
- Deterministic evidence, policy, authority, and consequence evaluation.
- All four Phase 3 decisions and structured explanation.
- Scoped authorization, expiration, context binding, and replay prevention.
- Simulation broker, synthetic target state, and fault injection.
- Functionally separate same-project pre/post target observation.
- Bound human-approval requirements.
- Hash-linked lifecycle audit and in-process observability.
- The two required SOC demonstrations and adversarial corpus.
- Regression of existing Phase 1 and Phase 2/2.5 tests.

### Out of scope

- Live EDR, IAM, network, cloud, Kubernetes, or OT/ICS actions.
- Production credentials or vendor APIs.
- Real-user or historical operational data.
- Production HA, distributed execution, enterprise approval UI, and dashboards.
- Real-world detection accuracy or operational-safety claims.

## Test architecture

Use a testing pyramid:

- **Unit tests** cover strict contracts, trusted-context resolution, evidence,
  policy, consequence, reason codes, authorization validation, verifier state
  classification, audit, and counters.
- **Integration tests** cross each control-plane boundary and inject failures at
  every stage that could otherwise lead to authorization or execution.
- **End-to-end tests** begin with raw request bytes and terminate with decision,
  optional authorization, broker attempt, functionally separate verification, final
  target state, audit, and metrics.
- **Adversarial tests** systematically mutate safety-relevant fields and attempt
  architectural bypass. Expected results come from a declarative oracle, not
  the policy implementation under test.

Implemented test modules:

```text
tests/
  phase3_support.py
  test_phase3_contracts.py
  test_phase3_decision_path.py
  test_phase3_authorization_boundary.py
  test_phase3_adversarial.py
  test_phase3_end_to_end.py
  test_phase3_corpus.py
  test_phase3_release_blockers.py
```

`phase3_support.py` provides a frozen firewall-owned clock, runtime-only
synthetic keys, opaque credentials and a trusted principal resolver,
source/asset/action policy, a metrics and audit boundary, an in-memory target
registry, and a separate read-only target observer. End-to-end tests enter
through strict raw-JSON decoding plus credential resolution; constructing an
internal request or principal object alone is not treated as boundary evidence.

## Release-blocking invariants

1. Request fields cannot carry the invocation credential, authenticate the
   agent, or grant roles or authority; only a firewall-resolved signed principal
   is accepted.
2. Request fields cannot lower target criticality, hide dependencies, declare
   reversibility, or promote evidence trust.
3. Agent recommendation and confidence cannot create authorization.
4. Every unresolved input or pre-execution internal failure returns `DENY` or
   `ESCALATE`, with no authorization, broker call, or target effect.
5. A non-allow decision never produces an authorization.
6. Authorization binds request, decision, authenticated agent, exact action,
   exact target, canonical parameters, expiration, policy, and decision context.
7. Authorization is consumed atomically at most once, including after an
   attempted but failed action.
8. Missing, altered, expired, replayed, wrong-scope, or prior-process
   authorization is rejected.
9. Direct broker invocation without valid authorization fails.
10. Direct target mutation without an internal broker capability fails.
11. Only an approved simulated target adapter can be constructed.
12. The broker result cannot determine verification status; functionally
    separate same-project target readback is required.
13. Unavailable or conflicting post-action observation never becomes
    `VERIFIED`.
14. Approval cannot change the action, target, parameters, evidence context, or
    required approving authority that was reviewed.
15. Policy validation rejects rule duplication/reordering, untrusted or
    zero-floor evidence, conflicts permitted for automation, removed severe
    consequence floors, and any domain controller not treated as protected
    Tier-0.
16. Signing, evidence-source, and invocation-credential trust material cannot
    be reused across domains.
17. All lifecycle events carry stable correlation identifiers and executed-path
    state/effect/verification semantics; post-effect failures cannot erase an
    attempt or fabricate success, and required counters update exactly once.
18. Existing Phase 2 replay and shadow modes remain structurally read only.

## Detailed test matrix

### Request, identity, and trusted context

| ID | Test | Required result |
|---|---|---|
| P3-CON-001 | Valid closed-schema raw JSON request | Accepted for evaluation; schema version recorded. |
| P3-CON-002 | Malformed JSON, duplicate members, non-finite numbers, missing required fields, wrong types, unknown fields, or unsupported version | Fail closed; structured reason; no authorization, broker call, or effect. |
| P3-CON-003 | Invalid, future, or out-of-window timestamps and oversized request/evidence bounds | Fail closed and audit the validation category without trusting nested content. |
| P3-CON-004 | Same request ID reused with identical content | Idempotent result or explicit duplicate rejection; never a second execution. |
| P3-CON-005 | Same request ID reused with different content | `DENY`; request-ID conflict reason; zero effect. |
| P3-ID-001 | Request claims authenticated Tier-0 agent but the opaque invocation credential is absent, malformed, or unregistered | `DENY`; self-assertion supplies no authority. |
| P3-ID-002 | Request agent ID differs from the credential-resolved signed principal | `DENY`; identity-mismatch reason. |
| P3-ID-003 | Credential resolves to a revoked or compromised agent | `DENY`; zero authorization. |
| P3-ID-004 | Registered credential resolves to a principal with workstation-containment authority | Authority accepted only for the permitted action and target class. |
| P3-ID-005 | Caller supplies a fabricated principal/resolution object or reuses signing/evidence key material as an invocation credential | Rejected at the trusted boundary; no authorization or effect. |

### Evidence assurance

| ID | Test | Required result |
|---|---|---|
| P3-EV-001 | Fresh, relevant evidence from multiple distinct registered sources | Corroboration and freshness recorded without using agent confidence. |
| P3-EV-002 | Evidence just inside, exactly at, and just outside the freshness limit | Deterministic boundary result against the firewall-owned decision time. |
| P3-EV-003 | Repeated events from one source or sensor instance | Does not inflate distinct-source corroboration. |
| P3-EV-004 | Missing provenance, unregistered source, or request-inflated trust | Cannot become trusted evidence; automation is blocked when required. |
| P3-EV-005 | Canonical content changed after integrity value was created | Integrity failure or manipulation reason; no autonomous authorization. |
| P3-EV-006 | Trusted sources contradict the compromise hypothesis | Conflict recorded; high-risk automation blocked. |
| P3-EV-007 | Required action-specific evidence missing or irrelevant evidence added | Missing evidence remains explicit; irrelevant evidence does not raise strength. |
| P3-EV-008 | Prompt or policy-injection text in evidence, recommendation, context, or parameters | Text remains inert data and cannot alter authority or rule evaluation. |
| P3-EV-009 | Evidence order changes | Same semantic assessment, decision, and ordered reason-code set. |
| P3-EV-010 | Same request with confidence 0.0, 0.96, and 1.0 and opposing recommendation strings | Same policy decision and authorization scope. |
| P3-EV-011 | Validly signed evidence is replayed for a different target than its signed subject | Subject-target mismatch; fail closed; no authorization or effect. |

### Policy, consequence, and decision

| ID | Test | Required result |
|---|---|---|
| P3-POL-001 | One canonical request for each four-way outcome | Exact `ALLOW`, `DENY`, `ESCALATE`, and `ALLOW_CONSTRAINED` coverage. |
| P3-POL-002 | Request labels a trusted Tier-0 domain controller as low criticality | Trusted catalog wins; mismatch is reasoned and audited. |
| P3-POL-003 | Authentication-service dependency, excessive blast radius, irreversibility, downtime, cascade, mission, or safety impact | Configured deny/escalation rule applies with structured consequence findings. |
| P3-POL-004 | Unsupported action or privilege beyond agent authority | `DENY`; no authorization. |
| P3-POL-005 | Isolation duration exceeds the allowed bound | `ALLOW_CONSTRAINED`; authorization contains only the bounded value. |
| P3-POL-006 | Missing, malformed, unknown-version, or contradictory policy | Fail closed; no authorization or effect. |
| P3-POL-007 | Multiple rules match | Stable precedence; deny/safety constraint cannot be overridden by a permissive match. |
| P3-POL-008 | Identical request, trusted context, policy, and frozen time evaluated repeatedly | Identical semantic decision and reason ordering. |
| P3-POL-009 | Duplicate/reordered permissive rule, nonzero untrusted weight, zero evidence floor, conflicts allowed for automation, severe approval floor removed, or downgraded domain controller | Policy rejected with `POLICY_SAFETY_INVARIANT`; no request is authorized. |

### Authorization, broker, and target boundary

| ID | Test | Required result |
|---|---|---|
| P3-AUTH-001 | Authorization issued after `ALLOW` | Binds token/nonce, request, decision, principal, action, target, canonical parameters, time, policy digest, and context/precondition digest. |
| P3-AUTH-002 | `DENY` or `ESCALATE` decision | No authorization object. |
| P3-AUTH-003 | Mutate each bound field or signature independently | Every mutation rejected and audited. |
| P3-AUTH-004 | Authorization just before and at expiration | Valid before; invalid when current time is equal to or later than expiry. |
| P3-AUTH-005 | Sequential replay | First permitted attempt consumes authorization; replay rejected. |
| P3-AUTH-006 | Concurrent replay | Exactly one attempt reaches the target; all competing attempts are rejected. |
| P3-AUTH-007 | Token from prior process/gate instance | Rejected unless a durable ledger proves validity and non-use; no constant-key replay. |
| P3-AUTH-008 | Wrong agent, target, action, parameter, policy, or decision context | Scope mismatch; zero target effect. |
| P3-BRK-001 | Direct broker call with no token, arbitrary object, unsigned token, or decision object | Rejected; broker-rejection and authorization-failure counters updated. |
| P3-BRK-002 | Direct target mutation without broker-issued execution capability | Rejected; target state unchanged. |
| P3-BRK-003 | Attempt to inject a non-simulation target or select a live mode | Construction/configuration rejected before execution wiring. |
| P3-BRK-004 | Simulated downstream command fails | Token remains consumed; no retry with the same authorization; no false success. |
| P3-BRK-005 | Decision context or target precondition changes before broker execution | Authorization rejected or reauthorization required. |

### Human approval and functionally separate verification

| ID | Test | Required result |
|---|---|---|
| P3-HIL-001 | `ESCALATE` decision | Approval requirement binds decision, action, target, evidence digest, reason, required authority, and expiry. |
| P3-HIL-002 | Unregistered/non-human credential, expired approval, changed target/action/parameters/evidence, or replay | Approval rejected; no authorization or effect. |
| P3-HIL-003 | Valid exact-scope approval from a credential-resolved trusted human | Signed receipt is atomically recorded and permits reevaluation only; it is not accepted as an action authorization and cannot invoke the broker. |
| P3-HIL-004 | Receipt-ID or audit-append failure while recording approval | Requirement remains retryable; no orphan receipt, false audit event, authorization, or effect. |
| P3-VER-001 | Exact expected state transition observed through the functionally separate same-project readback path | `VERIFIED`. |
| P3-VER-002 | Broker reports success but target state is unchanged | `FAILED`; verification-failure counter. |
| P3-VER-003 | Only part of a multi-field expected transition occurs | `PARTIAL`. |
| P3-VER-004 | Expected transition plus unrelated protected-field change | `UNEXPECTED_EFFECT` or `ROLLBACK_REQUIRED` according to policy. |
| P3-VER-005 | Broker reports failure but target changed | `UNEXPECTED_EFFECT` or `ROLLBACK_REQUIRED`; never `VERIFIED`. |
| P3-VER-006 | Expected state appears on another target | Wrong-target failure; requested target remains unverified. |
| P3-VER-007 | Observer is unavailable or returns conflicting reads | `FAILED` or `ROLLBACK_REQUIRED`; authorization remains consumed. |

### Audit and observability

| ID | Test | Required result |
|---|---|---|
| P3-AUD-001 | Allowed lifecycle | Ordered receipt, validation, identity, evidence, policy, consequence, decision, authorization, broker, attempt, verification, and final-state events share stable IDs. |
| P3-AUD-002 | Denied, escalated, malformed, broker-rejected, and verifier-failed lifecycles | Each records its applicable terminal path; no fabricated downstream event. |
| P3-AUD-003 | Modify, insert, reorder, substitute, or remove an interior audit row | Integrity/lifecycle validation fails. |
| P3-AUD-004 | Audit append fails before authorization or execution | Fail closed; no authorization or target effect. |
| P3-AUD-005 | Audit output inspection | No signing key, raw secret, or reusable credential material is recorded. |
| P3-AUD-006 | Post-effect observer, verifier, identifier, clock, or audit dependency fails | Attempt/effect remains honestly accounted; a prewrite append failure at `ACTION_ATTEMPTED`, `VERIFICATION_PERFORMED`, or `FINAL_STATE_RECORDED` produces exactly one `POST_EFFECT_ACCOUNTING_FAILURE`, returns `ROLLBACK_REQUIRED`, and reconciles one decision plus one verification failure; no false `VERIFIED` state is emitted. |
| P3-AUD-007 | Executed-path request/decision/token/attempt/target/state/effect/verification field is substituted | Lifecycle validation fails; returned result cannot contradict the validated audit semantics. |
| P3-MET-001 | Mixed decision and failure batch | Exact counts for four outcomes, matched rules, conflicts, authorization failures, broker rejections, and verification failures. |
| P3-MET-002 | Allowed decision followed by action/verification failure | One `ALLOW` plus the applicable failure counter; decision history is not rewritten. |
| P3-MET-003 | Decision latency | Present and nonnegative; timing source cannot influence decision semantics. |

## Systematic adversarial corpus

The implemented corpus uses immutable scenario specifications with separately
declared expected results. Its shape is equivalent to:

```python
@dataclass(frozen=True)
class Scenario:
    scenario_id: str
    base_id: str
    mutations: tuple[str, ...]
    expected_decision: str
    expected_reason_codes: frozenset[str]
    authorization_expected: bool
    broker_attempts: int
    expected_verification: str
    expected_effects: int
```

The frozen local catalog contains 46 unique meaningful cases spanning:

- **4 canonical cases:** workstation allow, domain-controller escalate,
  unauthenticated deny, and workstation allow-constrained.
- **16 single-factor safety mutations:** correct decision, false-positive AI
  confidence, false-negative AI confidence, stale, missing, conflicting,
  manipulated, malformed, and poisoned evidence; compromised and unauthorized
  agents; excessive privilege; protected assets; dependency and cascading
  consequences; and policy manipulation.
- **10 authorization and bypass mutations:** missing authorization, signature
  mutation, sequential and concurrent replay, expiry, wrong target, wrong
  action, wrong parameters, context/policy mismatch, and direct target access.
- **6 broker/verifier faults:** failed action, partial effect, unexpected effect,
  forged success report, unavailable observer, and rollback-required effect.
- **6 metamorphic variants:** confidence variation, recommendation wording,
  evidence reordering, irrelevant evidence, same-source duplication, and
  canonical parameter ordering.
- **4 combined high-value attacks:** Tier-0 plus stale/conflicting evidence and
  high confidence; authorized agent plus manipulated evidence; constrained
  authorization plus parameter tampering; and duplicate request plus replay.

The catalog uses explicit deterministic enumeration, stable scenario IDs, and a
frozen clock. Expected outcomes are declared in the scenario specifications,
not produced by calling the implementation under test. The persisted summary
omits reusable token signatures and runtime keys and refuses to overwrite a
nonempty destination.

Every corpus case enforces these cross-cutting assertions:

- non-allow decisions issue no authorization and have zero effect;
- rejected execution preserves all target state;
- one authorization causes at most one target attempt;
- all decisions contain structured reasons and policy identity;
- recommendation wording, confidence, and evidence order do not create
  authority;
- every completed request has a correlated, internally valid audit lifecycle;
  and
- no caught or uncaught component failure becomes implicit permission.

The local runner reported 46/46 scenarios passing. That denominator is the
complete declared project-controlled corpus, not a sample from an operational
attack distribution and not proof of exhaustive coverage.

## Required demonstrations

### Demo 1 — high-risk domain controller

Input conditions:

- proposed `NETWORK_ISOLATE` against `DOMAIN_CONTROLLER_01`;
- AI recommendation `ISOLATE` and confidence `0.96`;
- trusted Tier-0 target with authentication-service dependencies;
- one stale source and one source contradicting compromise; and
- requesting agent lacks Tier-0 containment authority.

The frozen policy requires `ESCALATE` because an identified higher human
authority could review the action. The acceptance assertions are:

- reason codes cover protected asset, insufficient authority, stale evidence,
  conflicting evidence, and high operational consequence;
- a scope-bound approval requirement is created;
- no authorization is issued;
- the broker and target mutation path are not invoked;
- all target state is byte-for-byte or structurally unchanged; and
- decision, audit, and metrics are complete.

Changing the AI confidence or recommendation must not change this outcome.

**Local observation:** passed. The request returned `ESCALATE`; reasons include
protected asset, insufficient authority, stale/conflicting evidence,
authentication-service dependency, cascading-effect possibility, high
operational consequence, human approval required, and reversibility. It issued
no authorization, invoked no broker, and left the domain controller unchanged.

### Demo 2 — authorized workstation

Input conditions:

- proposed reversible `NETWORK_ISOLATE` against a low-criticality workstation;
- fresh, integrity-verified evidence from multiple distinct registered sources;
- authenticated agent with the exact workstation-containment authority; and
- acceptable target dependencies and consequence.

The acceptance assertions are:

- decision is `ALLOW`;
- one exact, short-lived, single-use authorization is issued;
- the broker executes only the authorization-bound simulated command;
- functionally separate same-project readback observes the workstation
  transition from connected to isolated;
- verification is `VERIFIED`;
- the complete lifecycle is correlated in audit; and
- required metrics increment exactly once.

Both demonstrations must start at the external raw-request boundary, use only
synthetic evidence and targets, and be reproducible through one documented
command or script. They are implementation-conformance evidence only.

**Local observation:** passed. The request returned `ALLOW`; one short-lived
authorization was consumed; the broker changed only the in-memory workstation;
and separate observation returned `VERIFIED`. Both lifecycle slices and the
complete presented audit chain validated locally.

Reproduce both with:

```bash
demo_dir="$(mktemp -d /tmp/adf-phase3-demo.XXXXXX)"
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src python3 run_phase3.py \
  --output-dir "$demo_dir"
```

## Fail-closed fault campaign

Inject an exception or unavailable dependency at request decoding, schema
validation, identity resolution, evidence evaluation, policy loading/evaluation,
consequence evaluation, pre-action verification, authorization issuance,
audit-before-execution, metrics-before-execution, and broker validation. Each
pre-execution failure must produce no token, broker attempt, or effect.

Faults after a simulated attempt are different: they cannot erase the attempt.
Observer or final-record failures must prevent `VERIFIED`, preserve the consumed
authorization, and retain the honest observed effect/state. A prewrite append
failure at `ACTION_ATTEMPTED`, `VERIFICATION_PERFORMED`, or
`FINAL_STATE_RECORDED` must emit exactly one `POST_EFFECT_ACCOUNTING_FAILURE`,
return `ROLLBACK_REQUIRED`, and leave exactly one original decision plus one
verification failure in metrics. This is conservative accounting and recovery
escalation, not an automated rollback mechanism.

## Acceptance gates

The published baseline satisfies the implemented mission-path gates below at
exact Commit `423685d`:

1. all existing non-obsolete Phase 1 and Phase 2/2.5 tests pass unchanged;
2. all Phase 3 release-blocking tests pass on the exact candidate commit;
3. all four decisions and every authorization-rejection class have direct test
   coverage;
4. every functionally separate verifier status has direct state-based coverage;
5. both required demonstrations pass from raw request through final audit;
6. all denial, escalation, bypass, replay, expiry, and wrong-scope cases record
   zero unauthorized target effects;
7. simulation-only construction and absence of a live execution mode are
   verified;
8. audit lifecycle and required metrics reconcile exactly; and
9. no known defect invalidates the AI reasoning, decision/control, and execution
   plane separation.

Lower-severity deficiencies should be entered as technical debt rather than
driving indefinite hardening. The post-MVP items are listed in the
[Phase 3 Gap Analysis](GAP_ANALYSIS.md#post-mvp-technical-debt).

Current gate disposition:

| Gate | State |
|---|---|
| Focused Phase 3 implementation tests | 57/57 passed for exact Commit `423685d` |
| Two end-to-end raw-request demonstrations | Acceptance checks PASS at the published boundary |
| 46-case adversarial corpus | 46/46 passed at the published boundary |
| Existing Phase 1/2 and public-site regressions | Then-current repository suite passed 288/288 |
| Exact Phase 3 commit | `423685d105be813056617db738297eba83d3d9d0` published on `main` |
| Exact-commit CI and Dependency Graph | Passed |
| Operational or externally independent validation | Not evaluated and outside this MVP |

## Evidence and reporting boundary

Report separately:

- test design present;
- test implemented;
- local test observed passing;
- exact-commit CI observed passing;
- demonstration observed; and
- operational validation, which remains **not evaluated** in Phase 3.

Do not infer a completed demonstration from code presence, fixture generation,
test discovery, or a prior-commit result. The Stage A observations below are
bound to exact implementation Commit `8818d5d2`, its verified implementation
manifest, and exact-SHA automation. Do not represent those simulation results as
live containment, production safety, measured operational efficacy, or external
independent assurance.

## Stage A two-store durability qualification

The unreleased `0.4.0-alpha.2` implementation is published on `main` at exact
Commit
[`8818d5d2d40faebced66a254d58b1f0d04c9f8b4`](https://github.com/redxking/ai-decision-firewall/commit/8818d5d2d40faebced66a254d58b1f0d04c9f8b4).
That exact implementation checkout produced these project-controlled
observations:

| Verification surface | Local observation |
|---|---|
| `tests.test_stage_a_receipt_recovery` plus `tests.test_stage_a_durable_control_ledger` | 43/43 passed in 8.248 seconds |
| `tests.test_production_readiness_gate` | 18/18 passed; strict 18-domain matrix valid; derived gate `BLOCKED` |
| Full `tests/test_*.py` discovery with warnings promoted to errors | 360/360 passed in 48.995 seconds |
| Focused Phase 3 implementation suite | 57/57 passed |
| Deterministic Phase 3 adversarial corpus | 46/46 passed; `live_actions_possible=false` |
| Integrated shared-audit exact-once process race | 5/5 parallel outer repetitions passed |
| Implementation `MANIFEST.sha256` | 307/307 passed |
| Exact-SHA CI run `31953570779` | Success on Python 3.11 and 3.12 |
| Exact-SHA Dependency Graph run `31953572482` | Success |

These results are not independent evaluation, historical/live validation,
owner acceptance, operational effectiveness, or production authorization. No
tag or GitHub Release was created, no deployment occurred, and no exact-SHA
Pages run was observed. The exact commands, results, and limitations are
recorded in
[`ADF-STAGE-A-ER-002`](../production/STAGE_A_RECEIPT_RESULT_EVIDENCE_RECORD.md).

The focused qualification now exercises:

- all three authoritative paths before missing-artifact creation; query-only
  existing-store preflight; control schema v2 and adapter schema v1; exact
  closed schema/row/result/receipt semantics; link/type/mode/sidecar safety;
  WAL-visible validation without preflight mutation; and refusal of legacy,
  future, partial, aliased, corrupt, or unsafe state;
- stable canonical adapter binding over principal, request/digest,
  decision/context, token/issuer, exact command/target/precondition, policy,
  fixed adapter contract, and synthetic execution mode, excluding the random
  attempt ID;
- one immutable adapter receipt and durable synthetic transition per exact
  binding, exact-repeat receipt replay without a second effect, and hard
  conflict for a changed binding, receipt, provenance, or target-state fact;
- closed receipt dispositions (`APPLIED`, `NO_EFFECT`, `PARTIAL`,
  `AMBIGUOUS`) without treating a receipt or adapter-reported success as
  independent verification;
- monotonic request, authorization (`ISSUED`, `CONSUMED`, `REVOKED`), attempt,
  receipt, and target chronology, including rejection of token reuse, backdated
  or unlinked transitions, and a revoked authorization closed with the wrong
  disposition;
- a closed canonical sanitized `RequestLookupResult`, recursive exclusion of
  token/nonce/signature/credential/signing/raw-audit/executable authority,
  digest verification on read, exact principal/request/digest access, and
  nondisclosure on changed principal or digest;
- `process_json` duplicate denial remains separate from authority-free terminal
  lookup; response loss and exact lookup create no decision, authorization,
  attempt, command, adapter mutation, effect, or token reissue;
- cross-store correlation at startup, processing, and terminal lookup for
  overlapping request, decision/context, authority, policy, receipt, provenance,
  and terminal target facts, including missing required and orphan receipts;
- valid read-back normal JSONL lifecycle closure before T3, and exact recovery
  closure as a contiguous `RECOVERY_STARTED`, `RECOVERY_EVIDENCE_ASSESSED`,
  `RECOVERY_FINALIZED` trio before recovery T3;
- truthful original-lifecycle status (`COMPLETE`, `INCOMPLETE`, `UNRESOLVED`),
  restart-idempotent recovery prefixes, append/readback-failure suppression of
  T3, pending-owner fencing against request/approval/unrelated recovery writers,
  and identical audit-inert replay after T3;
- exact recovery outcomes for affirmative `NO_EFFECT`, applied/partial/
  ambiguous, absent, mismatched, corrupt, locked, and unavailable receipts or
  stores, with no automatic command, retry, token reopening/replacement,
  verification fabrication, success, or rollback; and
- bounded cooperative same-host serialization for direct store first creation,
  shared-audit request races, approval, lookup, and recovery, plus selected real
  process termination before/after T2 and around response/T3 recovery.

Named release-blocker regressions include
`test_direct_store_first_creation_is_process_serialized`,
`test_independent_processes_create_one_effect_receipt_and_terminal_result`,
`test_cross_store_missing_receipt_blocks_reopen_and_live_terminal_lookup`,
`test_cross_store_orphan_receipt_fails_closed`,
`test_cross_store_overlapping_provenance_substitution_fails_closed`,
`test_cross_store_terminal_target_substitution_fails_closed`,
`test_recovery_audit_prewrite_failure_suppresses_t3_until_exact_retry`,
`test_recovery_audit_readback_failure_leaves_exact_retryable_trio`,
`test_recovery_audit_prefix_is_restart_idempotent_at_every_record`, and
`test_pending_recovery_fences_request_and_approval_audit_writers`.

Even with this exact-commit qualification and automation passing, queue behavior, bounded
load/retention, multi-node partitions/failover, distributed execution fencing,
external audit export,
managed-key lifecycle, process isolation/authenticated IPC, independently
custodied eventual target readback, vendor semantics, and executable rollback
remain release blockers in the
[`failure/recovery matrix`](../production/FAILURE_RECOVERY_MATRIX.md). The
machine production gate remains `BLOCKED`; passing this local plan cannot grant
live integration or operational authority.
