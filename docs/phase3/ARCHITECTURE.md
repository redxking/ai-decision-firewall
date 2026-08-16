# Phase 3 architecture

## Purpose and scope

Published Phase 3 `0.3.0-alpha.1` at exact Commit `423685d` adds an end-to-end operational
control transaction while keeping every input, identity, target, and effect
synthetic. It is additive:
Phase 1 compatibility behavior and Phase 2 `historical_replay` /
`shadow_read_only` semantics retain their existing boundaries. Phase 2 never
routes through the Phase 3 broker.

## Logical components

| Component | Responsibility | Trust boundary |
|---|---|---|
| v0.3.0 request contract | Strict raw-JSON decoding, closed-schema validation, size/depth/time bounds, request/action/target consistency | Request bytes and request-supplied claims are untrusted |
| Opaque credential resolver and trusted registries | Resolve an invocation credential to a signed `ResolvedPrincipal`; resolve agent status/authority, source properties, action properties, and target facts | Credential is supplied outside request JSON; runtime resolver and validated policy are authoritative for this synthetic candidate |
| Evidence attestation verifier | Validate runtime HMAC bindings over source, provenance, content, semantics, observation time, and subject target | Synthetic runtime keys only; no enterprise trust root |
| Evidence evaluator | Calculate freshness, reliability, relevance, corroboration, conflicts, missing sources, manipulation, and poisoning findings | Does not accept request-asserted trust as authority |
| Consequence evaluator | Assess reversibility, target criticality, dependencies, cascade, downtime, blast radius, and mission/safety/availability impact | Uses trusted policy inventory rather than target self-description |
| Decision engine | Apply deterministic rule precedence and return one of four outcomes with structured reasons and constraints | Recommendation/confidence cannot grant authority |
| Functionally separate decision verifier | Recompute allow/non-allow invariants and sign a one-time verification receipt before authorization | Same project/process/configuration; not external independence |
| Authorization gate | Sign and validate exact request/decision/agent/action/target/parameters/time/policy/context/state scope | Process-local key and in-memory single-use ledger |
| Action broker | Require and consume the scoped token, execute only its bound synthetic command | Mandatory route to target mutation; no selectable live adapter |
| Simulated target environment | Hold in-memory workstation/domain-controller state and inject deterministic faults | Private-capability application boundary, not OS/process security |
| Read-only target observer and verifier | Read state separately from broker results and classify the observed transition | Functionally separate read path, same simulated environment |
| Human approval gate | Resolve a separate opaque human credential, validate exact expiring escalation scope, and atomically emit/register a signed single-use reevaluation receipt | Cannot authorize or execute an action |
| Audit and metrics | Correlate lifecycle records and count decisions, rule matches, conflicts, authorization/broker/verification failures, and latency | In-process and self-custodied |

## Request-to-effect flow

```text
Untrusted raw request + opaque invocation credential
                    |
                    v
 strict decode/schema/time checks + trusted credential resolution
                    |
                    v
 trusted identity + source attestation + evidence assessment
                    |
                    v
 trusted target/action lookup + consequence assessment
                    |
                    v
 deterministic policy decision + structured explanation
                    |
                    v
 functionally separate decision verification
                    |
          +---------+----------+
          |                    |
 DENY / ESCALATE        ALLOW / ALLOW_CONSTRAINED
          |                    |
 no token/effect      scoped signed authorization
          |                    |
          |             mandatory broker
          |                    |
          |          in-memory synthetic target
          |                    |
          +---------+----------+
                    |
 functionally separate same-project target observation
                    |
   final verification + audit + metrics + final state
```

`ESCALATE` may carry a signed, registered human-approval requirement. A valid
approval receipt returns the reviewed request to a separately governed
reevaluation; the receipt is deliberately not accepted as an authorization
token and does not itself cause reevaluation or execution.

## Authoritative versus non-authoritative fields

| Claim | Authoritative source in the candidate | Request field behavior |
|---|---|---|
| Agent identity, authentication, roles, and authority | Firewall-owned opaque-credential resolver and signed `ResolvedPrincipal` | Request has no credential field; claims must match and cannot self-elevate |
| Target type, criticality, classification, dependencies, consequences, and current state | Validated policy inventory and read-only observer | Mismatch is reasoned; trusted state wins |
| Action reversibility, required privilege, allowed target types, and parameter limits | Validated action policy | Cannot relax constraints |
| Source identity, type, reliability, and trust | Policy source registry plus runtime HMAC attestation | Cannot inflate trust or change source type |
| Evidence content/semantics/subject/time binding | Canonical digest and runtime HMAC attestation | Tampering or cross-target replay fails closed |
| Current time and expiry | Firewall clock | Request timestamps are validated but do not control time |
| Policy identity and digest | Loaded validated policy bytes | Request cannot select or rewrite policy |
| AI recommendation and confidence | Untrusted advisory inputs | Recorded for explanation; never authority |

## Machine-enforced policy safety floor

Schema-valid policy is necessary but not sufficient. Code-owned invariants
also require:

- strictly descending `HIGH > MEDIUM > LOW > UNTRUSTED = 0` evidence weights,
  positive reliability/relevance/strength floors, at least two corroborating
  sources, and zero conflicts for automation;
- no registered trusted source marked `UNTRUSTED` or below the reliability
  floor;
- positive consequence-factor weights, monotonically increasing severity
  weights, and `HIGH < CRITICAL` thresholds;
- explicit approval floors for high/critical consequence and isolation,
  critical mission/availability impact, high safety impact, enterprise blast
  radius, downtime above 60 minutes, cascading effect, and `HIGH`/`TIER_0`
  target criticality;
- one exact closed, ordered decision-rule sequence with unique rule IDs; and
- every domain-controller inventory record classified `TIER_0`, marked for
  human approval, assigned high/critical isolation consequence, and bound to an
  authentication-service dependency.

The loaded policy is deep-copied into immutable runtime objects and bound into
the decision, verifier receipt, authorization, audit, and final result.

## Decision semantics

- `DENY` is terminal for invalid, unauthenticated, compromised, unsupported,
  manipulated, conflicting-identifier, or otherwise prohibited requests.
- `ESCALATE` records an exact approval requirement when a separately
  credential-resolved trusted human authority could review a high-consequence
  request. It issues no token.
- `ALLOW` preserves the requested parameters when evidence, authority,
  consequence, and policy all permit them.
- `ALLOW_CONSTRAINED` replaces requested parameters with policy-bounded values;
  only those canonical permitted parameters enter the token and broker command.

## Authorization and execution binding

The Phase 3 token binds:

- issuer instance, token ID, nonce, request ID, and decision ID;
- authenticated agent ID;
- exact action, target, and canonical permitted parameters;
- issue and expiration times;
- policy ID, version, and SHA-256 digest;
- decision-context digest; and
- pre-action target-state digest.

Validation occurs at broker entry and the token is consumed atomically before
the simulated action attempt. Consumption remains final when the simulated
downstream command fails. A token from another gate/process instance is
rejected even when the same signing key is reused. The target rechecks the
state precondition while holding its mutation lock to close the modeled
in-process time-of-check/time-of-use interval.

For the published Phase 3 baseline, this is not a distributed transaction and
the ledger is not durable across process crashes, shared among nodes, or backed
by an idempotency store. The optional Stage A addendum below replaces only that
narrow local storage path; it does not create a distributed transaction.

## Verification boundary

The broker reports what it attempted; it does not determine success. The target
verifier compares a functionally separate same-project post-state observation
with the captured pre-state and authorization-bound expected transition. It can
return:

- `VERIFIED` — the exact allowed transition is observed;
- `FAILED` — the expected transition is absent or observation is unavailable;
- `PARTIAL` — only part of the expected transition is present;
- `UNEXPECTED_EFFECT` — state changed outside the expected transition; or
- `ROLLBACK_REQUIRED` — an unexpected protected effect requires recovery.

In the published Phase 3 baseline, the observer and verifier are same-project,
same-process components over the same in-memory environment. Stage A changes
the observed state source to the separate durable synthetic-adapter database,
but retains same-project and same-store custody. In either path, functional
separation prevents success from being inferred from the broker return value;
it is not external target evidence or organizational independence.

## Lifecycle and observability

Every request slice starts with `REQUEST_RECEIVED`, produces exactly one
`DECISION_PRODUCED`, records one authorization outcome, and ends with
`FINAL_STATE_RECORDED`. Allowed paths record broker invocation, action attempt,
state observation, and verification with exact request/decision/token/attempt/
target correlation. Nonexecuting paths explicitly record broker, action, and
verification suppression. Broker rejection after token issuance records a
terminal skipped path without fabricating an action attempt. A post-effect
dependency or audit-append failure cannot erase an attempt or synthesize
`VERIFIED`. A prewrite append failure at `ACTION_ATTEMPTED`,
`VERIFICATION_PERFORMED`, or `FINAL_STATE_RECORDED` closes with exactly one
`POST_EFFECT_ACCOUNTING_FAILURE` recovery record containing the honest observed
effect and state, returns `ROLLBACK_REQUIRED`, and reconciles one decision plus
one verification failure. This is accounting and escalation, not automated
rollback.

Audit rows share intake, request, and decision identifiers and participate in
the repository's SHA-256 chain. Reusable signatures and secret material are
omitted. Metrics cover all four outcomes, matched policy rules, evidence
conflicts, authorization failures, broker rejections, verification failures,
and decision latency.

## Deployment boundary

There is no deployment architecture in this candidate. The published Phase 3
construction accepts only the exact in-memory simulation environment. The
optional Stage A construction accepts only the fixed offline synthetic adapter
and separately pathed local databases. Neither exposes a live-mode flag,
generic/vendor adapter, operational credential path, or network call. A later
non-production integration would require a new trust model, process isolation,
durable distributed authorization/idempotency, managed keys, external audit
custody, vendor-specific independent readback, rollback orchestration,
rate/circuit controls, and separate operational authorization.

## Stage A durability addendum

The provisional, unreleased `0.4.0-alpha.2` production-development candidate
retains the ADR-014 opt-in control ledger and adopts ADR-015's separately
pathed offline synthetic-adapter database. The logical sequence is:

```text
T1 control DB: consume authority + reserve exact-bound attempt
                         |
                         v
T2 adapter DB: validate precondition/binding + update synthetic state
               + insert immutable adapter receipt
                         |
                         v
same-project read-only observation of durable adapter state
                         |
                         v
valid read-back normal JSONL lifecycle closure
                         |
                         v
T3 control DB: terminal attempt/request + sanitized lookup + outbox

recovery alternative: exact read-back three-record JSONL closure before T3
```

No control-database transaction remains open across adapter I/O. T1, T2, T3,
observation, and the JSONL audit are not one atomic transaction. The adapter
owns the receipt write and returns the existing immutable receipt for an exact
repeated idempotency binding without changing state again. Reusing the key with
a changed principal/request/decision/token/command/target/precondition/policy/
adapter binding is a hard conflict. The random attempt identifier is
correlation metadata and is excluded from the stable idempotency digest.

The control database, adapter database, and JSONL lifecycle audit are three
authoritative artifacts. Before a missing artifact is created, all three paths
are preflighted, and existing stores are opened query-only for exact closed
schema/version, semantic, path/link/type/mode, sidecar, and integrity checks.
Bounded cooperative same-host fencing serializes direct store initialization
and durable processing, lookup, approval, and recovery operations. Cross-store
validation correlates overlapping principal, request, decision/context,
authority, policy, receipt, and terminal-target facts and rejects missing
required or orphan receipts and recomputed substitutions.

The adapter receipt distinguishes `APPLIED`, `NO_EFFECT`, `PARTIAL`, and
`AMBIGUOUS` adapter-reported outcomes. It cannot by itself establish independent
verification, target-side custody, successful rollback, or operational effect.
Normal request closure follows same-project read-only observation and persists
a closed `RequestLookupResult`, not a serialized `Phase3Result`. Authenticated
lookup requires the exact principal, request identifier, and canonical request
digest; the result contains no token, nonce, signature, credential, raw audit
rows, or executable authority and states that the lookup created no decision,
authorization, attempt, or effect. `process_json` remains fail closed for an
exact duplicate and does not return a union type.

Authorization is monotonic (`ISSUED` to `CONSUMED` with reservation or to
`REVOKED` during explicit recovery). Attempt states distinguish reservation,
receipt recording, verified effect, affirmative failed-no-effect, recovery
required, and unknown effect. Reconciliation is explicit and operator-asserted
quiescent, never automatic in a constructor. An exact `NO_EFFECT` receipt can
close failed-no-effect; applied, partial, ambiguous, or absent receipt evidence
without separately durable verification closes as `UNKNOWN_EFFECT` with
`recovery_required=true`; absence is neither no-effect evidence nor retry
authority. Corrupt, mismatched, or unavailable adapter evidence halts recovery
without a state transition. No recovery path invokes the command, reopens or
replaces authority, fabricates verification, or claims rollback. Before T3,
recovery must append and read back one exact contiguous trio:
`RECOVERY_STARTED`, `RECOVERY_EVIDENCE_ASSESSED`, and `RECOVERY_FINALIZED`.
The trio records the correlated original normal lifecycle status as `COMPLETE`,
`INCOMPLETE`, or `UNRESOLVED`, plus `command_invoked=false`, `new_effect=false`,
and `control_commit_pending=true`. An append or readback failure suppresses T3;
an exact partial prefix resumes without duplication; the pending recovery owner fences other
durable writers; and a repeat after T3 returns the identical audit-inert result.

This addendum narrows same-host response-loss and replay ambiguity only. The
broker, adapter, observer, and keys remain same-process; the observer and
receipt remain same-project/same-store custodied; cooperative same-host fencing
and an operator quiescence assertion are not a distributed lease, epoch, or
execution-ownership proof; the audit exporter is absent; and the two SQLite
databases do not provide cross-store atomicity, consensus, distributed
idempotency, HA, or disaster recovery. The decisions and remaining gates are
recorded in [ADR-014](../adr/014_stage_a_durable_transaction_spine.md) and
[ADR-015](../adr/015_durable_synthetic_adapter_receipt_and_result_lookup.md).
The machine production gate remains `BLOCKED`; this architecture grants no live
connector, credential, target, deployment, or operational authority.

At the 2026-08-16 source-freeze checkout, local project-controlled observations
were 43/43 focused Stage A tests, 18/18 readiness-gate tests, 360/360 repository
tests, and 46/46 deterministic corpus scenarios with
`live_actions_possible=false`. Direct public-store first-creation stress passed
10/10 sequential and 5/5 parallel repetitions; the integrated exact-once race
passed 5/5 parallel repetitions. These results establish only the tested local
mechanism. No exact candidate commit, regenerated manifest, CI, independent
verification, owner acceptance, operational effectiveness, or production
authorization is claimed.
