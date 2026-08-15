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

This is not a distributed transaction. The ledger is not durable across
process crashes, shared among nodes, or backed by an idempotency store.

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

The observer and verifier are same-project, same-process components over the
same in-memory environment. Their separation prevents success from being
inferred from the broker return value, but it is not external target evidence
or organizational independence.

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

There is no deployment architecture in this candidate. Construction accepts
only the exact in-memory simulation environment type and exposes no live-mode
flag, generic adapter, vendor client, credential path, or network call. A later
non-production integration would require a new trust model, process isolation,
durable authorization/idempotency store, managed keys, external audit custody,
vendor-specific independent readback, rollback orchestration, rate/circuit
controls, and separate operational authorization.
