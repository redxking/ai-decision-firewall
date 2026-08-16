# Phase 3 security and safety case

## Claim boundary

Published Phase 3 `0.3.0-alpha.1` at exact Commit
`423685d105be813056617db738297eba83d3d9d0` demonstrates that the implemented
Python control path can enforce selected identity, evidence, policy, decision,
authorization, broker, audit, and synthetic-target invariants under 57 focused
tests, two demonstration acceptance checks, and a 46-scenario adversarial
corpus. The claim level is simulation-only CE-1 implementation conformance.
Exact-commit CI and Dependency Graph checks passed.

This safety case does not establish production security, operational efficacy,
live-containment safety, exhaustive attack coverage, a failure-rate bound,
external assurance, or authorizing-official acceptance.

The provisional, unreleased Stage A `0.4.0-alpha.2` addendum is a separate
production-development boundary. ADR-015 defines local durable control state, a
separately pathed offline synthetic-adapter state/receipt database, and an
authority-free terminal lookup. At the 2026-08-16 local source freeze, 43/43
focused Stage A tests, 18/18 readiness-gate tests, 360/360 repository tests, and
46/46 deterministic corpus scenarios passed; the corpus reported
`live_actions_possible=false`. These are project-controlled mechanism
observations without an exact candidate commit, regenerated manifest, CI,
independent verification, owner acceptance, operational effectiveness, or
production authorization. The machine gate remains `BLOCKED`.

## Top-level safety claim

Within the tested simulation-only boundary, an untrusted agent request cannot
cause the in-memory `NETWORK_ISOLATE` effect unless trusted identity, evidence,
policy, consequence, and target facts produce an allowed decision; a
functionally separate verifier accepts that decision; a short-lived exact-scope
authorization is issued and consumed by the mandatory broker; and the target's
private execution capability and state precondition are valid. A broker report
alone cannot create a successful verification result.

## Argument

**S1 — Agent output is not authority.** The request may carry recommendation,
confidence, roles, authority, and target claims, but it cannot carry the
invocation credential. The firewall resolves that opaque credential through a
trusted resolver, verifies the signed `ResolvedPrincipal`, and resolves target
facts from validated policy. Confidence and recommendation variations do not
change authorization scope.

**S2 — Evidence is cryptographically bound and separately evaluated.** Each
synthetic source item has a canonical content digest and runtime HMAC
attestation over its source
identity/type, provenance, observation time, semantic support/contradiction,
relevance, content, and subject target. Source trust comes from the policy
registry. Stale, missing, conflicting, poisoned, manipulated, unsigned, or
cross-target evidence blocks automation according to deterministic rules.

**S3 — Consequence can override apparent confidence.** Trusted target
criticality, dependencies, blast radius, downtime, mission/safety/availability
impact, reversibility, human-approval requirement, and cascading effects are
evaluated independently of the agent. The Tier-0 domain-controller case
therefore escalates with no authorization or effect despite `0.96` confidence.

**S4 — Policy is explicit and fail closed.** Policy is external JSON validated
against a closed schema plus code-owned safety invariants. These invariants
enforce exact unique rule precedence; strictly ordered trust weights with zero
weight for untrusted evidence; positive evidence and consequence floors; zero
conflicts for automation; severe-factor approval floors; and Tier-0 protected
classification for every domain controller. Missing, malformed, unsafe, or
internally inconsistent policy prevents permission. Stable reason codes and
precedence make safety-deny/escalation conditions visible.

**S5 — Authorization is exact scope and single use.** The signed token binds
issuer instance, request, decision, agent, action, target, canonical parameters,
time, policy identity/digest, decision context, target precondition, and nonce.
Missing, altered, expired, replayed, prior-instance, or wrong-scope tokens are
rejected. Consumption occurs before the attempt and remains consumed after a
simulated failure.

**S6 — The broker and target path are mandatory within the application.** The
Phase 3 engine creates the broker from the exact in-memory environment. Target
mutation requires a private capability held by that broker, and the target
checks its state precondition while holding the mutation lock. No live or
generic adapter can be selected.

**S7 — Effect verification is state based.** A separate read-only observer
supplies post-action state to the target verifier. The verifier classifies
failed, partial, unexpected, and rollback-required outcomes rather than trusting
the broker's reported success.

**S8 — Escalation does not become execution.** An `ESCALATE` decision creates a
signed, registered, exact, expiring approval requirement and no authorization.
The human-approval gate resolves a separate opaque credential to a trusted
human, requires exact authority/scope, rejects replay, and atomically records
only `APPROVED_FOR_REEVALUATION`. It cannot mint a token, cause reevaluation, or
invoke the broker.

**S9 — Lifecycle state is explicit and measurable.** Correlated hash-linked
audit records distinguish validation failure, decision, authorization,
suppression, broker rejection, attempt, observation, and final state. Executed
paths bind the request, decision, token, attempt, target, pre/post state, and
verification semantics; post-effect failures close conservatively rather than
erasing an attempt or fabricating success. When a prewrite append fails at the
attempt, verification, or final-state boundary, one
`POST_EFFECT_ACCOUNTING_FAILURE` records the honest observed effect/state, the
result is `ROLLBACK_REQUIRED`, and metrics retain one original decision plus one
verification failure. This triggers recovery responsibility; it does not
perform rollback.

## Safety invariants

- No live action mode, connector, credential, or generic target adapter.
- No action token for `DENY` or `ESCALATE`.
- No token without deterministic decision-verifier acceptance.
- No authority from self-asserted agent fields, AI recommendation, confidence,
  target labels, source trust, or free text.
- No automation when evidence integrity, provenance, subject binding,
  freshness, corroboration, conflict, or action-specific sufficiency fails the
  configured boundary.
- No protected/high-consequence action without the required authority and
  human-review path.
- No broker attempt without a valid exact-scope token.
- No second attempt from sequential/concurrent replay or a prior gate instance.
- No direct target mutation without the internal broker capability.
- No authorization reuse after a failed simulated attempt.
- No `VERIFIED` result based only on a broker success report.
- No human approval that changes reviewed action, target, parameters, evidence,
  approving authority, or expiry.
- No reusable token signature or key material in demo, corpus, or audit output.
- No signing, evidence-source, or invocation-credential key reuse across trust
  domains.
- No schema-valid policy that weakens the closed rule sequence, evidence floors,
  zero-conflict automation, severe-consequence floors, or Tier-0
  domain-controller treatment.
- No executed-path audit record whose identifiers, state digests, effect count,
  or verification meaning contradicts the returned result.

## Evidence supporting the published claim

For exact Commit `423685d105be813056617db738297eba83d3d9d0`, **57/57 focused Phase 3 tests** passed, both
raw-request demonstration acceptance checks reported **PASS**, and the
deterministic corpus reported **46/46** scenario passes. The full repository
suite passed **288/288** locally and in exact-commit CI. See the
[Phase 3 T&E plan](TEST_AND_EVALUATION_PLAN.md) and
[traceability matrix](REQUIREMENTS_TRACEABILITY.csv).

The review found and closed release-blocking defects in multiple control
surfaces. The negative regression set now covers cascading-consequence and
evidence subject-target binding; credential resolution and trust-domain key
separation; exact JSON scalar and deep-immutability boundaries; policy-rule,
evidence-floor, severe-consequence, and Tier-0 invariants; replay namespace,
token/verifier/approval receipt use, and failure atomicity; fail-closed clock,
identifier, verifier, authorization, broker, observer, and audit dependencies;
and executed-path/post-effect audit semantic correlation. Their correction is
CE-1 implementation evidence, not proof that no other defect remains.

## Residual risk and explicit nonclaims

### Application boundary, not process security

Private attributes, exact-type construction, and an unforgeable-by-ordinary-API
Python object capability constrain the designed application path. They do not
isolate hostile code already executing in the same interpreter, constrain OS
calls, prevent introspection/monkey-patching, create a privilege boundary, or
replace process/container/host controls.

### Published process-local state and Stage A local durability

In the published Phase 3 baseline, the authorization and request ledgers are in
memory. Stage A replaces that narrow optional path with a local durable
control database and a separate durable synthetic-adapter database. It still
is not replicated or shared across service nodes and has no distributed
idempotency, consensus, lease/epoch/fencing, failover, or cross-store atomic
transaction.

### Synthetic HMAC source trust

Evidence HMAC keys are supplied at runtime and derived deterministically only
inside synthetic tests/corpus where reproducibility is needed. The candidate
rejects reuse across signing, evidence-source, and invocation-credential trust
domains. HMAC proves
possession of a shared test key within the modeled boundary; it does not prove
device identity, vendor authenticity, independent collection, hardware-rooted
provenance, key custody, revocation, rotation, or nonrepudiation.

### Same-project verification

The decision verifier and read-only target verifier are separately implemented
non-model components, but they share the project, process, requirements,
policy, simulated environment, and governance. Their results are not an
external oracle, independent source reconstruction, separate custody boundary,
or organizationally independent assurance.

### Self-custodied audit and metrics

Hash linking detects changes to the presented chain when the original root is
trusted. It does not prevent complete chain replacement, truncation, or
authorized rewriting and has no external timestamp/anchor or WORM custody.
In-process metrics are diagnostic, not an independent operational record.

### No operational representativeness or calibration

The two targets, evidence sources, timing, policies, and injected faults are
synthetic. They do not represent vendor API semantics, real topology,
eventual consistency, partial network partitions, production race conditions,
identity-provider behavior, rollback feasibility, human workflow, or mission
outcomes. A 46/46 project-controlled result is not a statistical risk estimate,
efficacy measure, or calibration result.

## Required controls before any external integration

- separate approved threat model and action-specific safety analysis;
- authenticated non-production data/use authority and privacy/custody controls;
- isolated service/process identity and least-privilege credential boundary;
- managed asymmetric or source-specific key infrastructure, rotation,
  revocation, and independent attestation/custody;
- durable distributed authorization consumption and idempotency;
- vendor-specific broker semantics, independent target-side readback, timeout,
  retry, reconciliation, rollback, circuit-breaker, and kill-switch behavior;
- externally anchored security audit and operational monitoring;
- adversarial concurrency, property/fuzz, resource-exhaustion, and recovery
  testing;
- human-approval workflow with separation of duties; and
- explicit change-control and authorizing-official acceptance.

## Stage A safety-case addendum

### Bounded claim

For an explicitly configured Stage A path, the control database binds the
authenticated principal, request ID, and canonical request digest before
authority is issued. Authorization consumption and exact attempt reservation
are one local transaction. A second, separately pathed database owned by the
offline synthetic adapter validates a stable idempotency binding, updates only
durable synthetic target state, and inserts one immutable receipt before
returning. An exact repeated adapter call returns the existing receipt without
another state change; a changed binding under the same key fails closed.

After same-project read-only observation, the control database may atomically
close the request/attempt and insert one sanitized `RequestLookupResult`, but
only after the valid normal JSONL lifecycle is closed and read back. The
separate authenticated lookup requires the exact principal, request ID, and
request digest and returns no token, nonce, signature, credential, raw audit
history, executable command, or new authority. The `process_json` processing
contract remains fail closed on duplicates and does not turn lookup into a
fresh decision.

Before any missing authoritative artifact is created, all three paths are
preflighted and existing stores are queried without mutation for exact schema,
semantics, path/link/type/mode, sidecar, and integrity constraints. Cross-store
validation correlates overlapping request, authority, decision/context,
policy, receipt, and terminal-target facts and rejects missing required or
orphan receipts and recomputed substitutions. Bounded cooperative same-host
fencing serializes direct store initialization and durable processing, lookup,
approval, and recovery. These are tested candidate mechanism claims, not
operational results or an OS/distributed security boundary.

### Failure honesty

Unknown schema, unsafe or aliased paths, integrity failure, or a lock extending
beyond the bounded timeout prevents new authority and target invocation. The
control database, adapter transaction, observation, JSONL audit, and terminal
control result are separate boundaries; no partial sequence may be represented
as cross-store atomic or complete.

Reconciliation is explicit and operator-asserted quiescent, never automatic in
a constructor. An exact affirmative `NO_EFFECT` receipt can support
`FAILED_NO_EFFECT`. `APPLIED`, `PARTIAL`, or `AMBIGUOUS` receipt evidence without
separately durable verification, or no receipt at all, remains
`UNKNOWN_EFFECT` with `recovery_required=true`; absence proves neither no effect
nor retry safety. Corrupt, unavailable, or mismatched
adapter evidence halts reconciliation without a state transition. Exact receipt
and terminal-result repeats are idempotent; changed payloads conflict.
Reconciliation never invokes the adapter command, mints a replacement token,
reopens authorization, fabricates verification, or declares rollback. Before
T3 it writes and reads back exactly one contiguous `RECOVERY_STARTED`,
`RECOVERY_EVIDENCE_ASSESSED`, `RECOVERY_FINALIZED` trio. The trio truthfully
records the correlated original lifecycle as `COMPLETE`, `INCOMPLETE`, or
`UNRESOLVED`, with no command and no new effect. Append/readback failure
suppresses T3; an exact prefix resumes without duplicate rows; a pending
recovery commit fences request, approval, and unrelated recovery writers; and a
post-T3 repeat is an identical audit-inert replay. A receipt never becomes
verification.

### Residual risk

This is a single-host synthetic mechanism. Its durable receipt is
adapter-reported and same-project/same-store custodied; it is not independent
target evidence, vendor semantics, or proof of operational effect. The
same-project observer does not change that custody boundary. T1 authority
reservation, T2 adapter state/receipt, observation, JSONL audit, and T3
terminal result can diverge. Operator-asserted quiescence and bounded
cooperative same-host fencing do not create a distributed lease, epoch,
consensus, or execution-ownership guarantee. SQLite availability can deny
service and supplies no quorum, failover, or split-brain protection.
Same-process compromise can
still subvert broker, adapter, observer, keys, both databases, and application
audit. The sanitized lookup solves neither action-level idempotency across
different request identities nor recovery of `UNKNOWN_EFFECT`. The detailed
threat/control/residual-risk mapping is in
[`../production/THREAT_CONTROL_REGISTER.md`](../production/THREAT_CONTROL_REGISTER.md).
These residual risks continue to prohibit production use. The machine
production gate remains `BLOCKED`, and no live connector, credential, target,
deployment, or operational authority is granted.
