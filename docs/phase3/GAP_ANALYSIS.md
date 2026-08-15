# Phase 3 operational MVP gap analysis

## Status

This analysis began as the design-to-implementation gap assessment and now
records the published `0.3.0-alpha.1` baseline's closure state as of 2026-08-15.
“Observed” means the behavior was exercised against synthetic fixtures and
bound to exact Commit `423685d105be813056617db738297eba83d3d9d0`; exact-commit
CI and Dependency Graph checks passed. It is CE-1 implementation-conformance
evidence, not live-system validation or external assurance.

Phase 2.5 is separately published on `main` at exact Commit
`854b15c56397a81de6326b719d3d7d1dc847608f`, with exact-commit CI and Dependency
Graph success. That publication did not run `P2-CE-005`; it remains CE-0
`NOT_EVALUATED`. Phase 3 is additive and separately published.

## Closure assessment

| Required capability | Initial gap | Local candidate state | Remaining evidence or production gap |
|---|---|---|---|
| Strict external JSON boundary | Existing utilities but no Phase 3 contract | Closed v0.3.0 raw-request schema; duplicate/non-finite/size/depth/time/version failures tested fail closed | Exact-candidate CI, fuzz/property/resource campaigns |
| Trusted requesting-agent identity | Missing | An opaque invocation credential is resolved by a firewall-owned registry to a signed `ResolvedPrincipal`; request claims must match, and absent/unregistered/compromised/self-elevating identities are denied | Enterprise IAM/device identity and external authentication evidence |
| Trusted target and action facts | Missing | Validated policy inventory/action catalog override request claims; current state comes from read-only observer | Enterprise CMDB/action catalog authenticity and vendor semantics |
| Evidence assurance | Existing but insufficient | Runtime HMAC attestation, content digest, subject-target binding, source registry, freshness-at-decision, relevance, corroboration, conflicts, missing sources, and poisoned text are evaluated | Enterprise source identity, key custody/rotation/revocation, external provenance and source-truth validation |
| AI/model separation from authority | Existing principle | Recommendation and confidence are recorded but do not grant authority; metamorphic tests preserve decision scope | Testing against real agent/tool behavior; no general alignment claim |
| Deterministic external policy | Incomplete Phase 1/2 vocabulary | Closed externally loaded Phase 3 policy defines trusted sources, action bounds, targets, token/approval TTLs, and a code-owned safety floor for exact rules, evidence trust/strength/conflicts, severe consequences, and Tier-0 domain controllers | Formal conflict analysis, change governance, organization-specific policy validation |
| Consequence evaluation | Missing | Dedicated assessment covers reversibility, criticality, dependencies, blast radius, downtime, cascade, mission/safety/availability, and approval | Validated operational consequence models and recovery/rollback evidence |
| Four Phase 3 outcomes | Historical outcomes incompatible | `ALLOW`, `DENY`, `ESCALATE`, and `ALLOW_CONSTRAINED` implemented without changing Phase 1/2 records | Field decision-quality and cost validation |
| Structured explanation | Incomplete | Stable reason codes, rules, evidence, authority, consequence, constraints, approval, policy and context bindings returned | Human-factors/usability and external schema stability review |
| Independent pre-action verification | Partial | Functionally separate deterministic verifier rechecks the authorization surface | External/organizationally independent verification and separated custody |
| Scoped authorization | Prior token under-scoped/reusable | Token binds issuer instance, request, decision, agent, action, target, parameters, time, policy/digest, decision context, target state, and nonce; signed and single use | Durable distributed ledger, managed keys, rotation, recovery, cross-node concurrency |
| Mandatory broker | Partial | Exact-scope validation/consumption required; missing, altered, expired, replayed, prior-instance, and wrong-scope tokens rejected | Vendor-specific idempotency, timeout, retry, rate/circuit and kill-switch controls |
| Direct target-bypass prevention | Prior simulator callable | Mutation requires a broker-held private capability and state precondition | OS/process isolation and adversarial same-process resistance |
| Simulated SOC targets | Missing | In-memory Tier-0 domain controller and low-criticality workstation implement `NETWORK_ISOLATE` plus fault injection | Non-production vendor integration and operational state semantics |
| Independent post-action readback | Prior verifier trusted broker state | Separate read-only observer drives `VERIFIED`, `FAILED`, `PARTIAL`, `UNEXPECTED_EFFECT`, and `ROLLBACK_REQUIRED` | External target-side readback, eventual consistency, reconciliation and executable rollback |
| Human approval | Missing | Exact expiring approval requirement and trusted-human/scope/single-use gate; receipt permits reevaluation only | Production workflow, separation of duties, identity proof and authorizing-official process |
| Lifecycle audit | Partial | Complete correlated request-to-final-state hash-linked lifecycle, including rejection/suppression, exact executed-path semantic binding, approval receipts, and one honest `POST_EFFECT_ACCOUNTING_FAILURE` / `ROLLBACK_REQUIRED` closure when a required post-effect prewrite fails | Automated rollback; external anchor/WORM custody, trusted time, and truncation/whole-chain replacement protection |
| Required metrics | Partial | Four outcomes, policy matches, evidence conflict, auth failure, broker rejection, verification failure and latency counters | Durable telemetry, exporters, reconciliation and production SLOs |
| Preserve Phase 2 read-only modes | Existing | Phase 3 is a separate package/path; Phase 2 does not construct or route to the Phase 3 broker | Exact freeze aggregate and CI regression |
| No-live-action boundary | Existing principle | Engine accepts only exact in-memory simulation environment; no live/generic mode or adapter | OS/network-egress evidence and deployment hardening if a later service exists |
| Required SOC demonstrations | Missing | Both raw-request demo acceptance checks reported PASS with required decisions, effects, audit and metrics | Exact-commit CI rerun; no operational efficacy inference |
| Systematic adversarial corpus | Partial prior negatives | Declarative deterministic 46-scenario corpus observed 46/46 passing | Independent red team, fuzz/property/load campaigns and broader attack surface |

## Safety defects found and closed before freeze

The candidate review found and closed release-blocking defects across these
control classes:

1. **Consequence and evidence binding:** cascading dependency was made
   release-blocking, and signed evidence now binds the exact subject target.
2. **Identity and trust material:** callers now present opaque credentials to a
   firewall-owned resolver; signing, evidence-source, and invocation credential
   keys must be exact bytes and cannot be reused across trust domains.
3. **Closed policy and immutable semantics:** exact JSON scalar/deep-copy
   boundaries prevent polymorphic or late-mutated security objects, while
   code-owned policy invariants preserve exact rule precedence, evidence floors,
   zero-conflict automation, severe-consequence floors, and Tier-0 treatment for
   every domain controller.
4. **Replay and lifecycle atomicity:** request IDs are principal namespaced;
   tokens, verifier receipts, approval requirements, and approval receipts are
   exact-scope/single-use; failed receipt creation is retryable without an orphan
   audit event; and pre-effect failures close without permission, while a
   post-effect prewrite failure preserves honest effect/state in exactly one
   `POST_EFFECT_ACCOUNTING_FAILURE`, returns `ROLLBACK_REQUIRED`, and reconciles
   metrics once without fabricating success.
5. **Executed-path correlation:** lifecycle validation binds request, decision,
   token, attempt, target, state digests, effect counts, and verification
   semantics so a returned result cannot contradict its validated audit slice.

These closures are simulation-only CE-1 implementation evidence; they do not establish
exhaustive correctness.

## Trust-source rule

The external request communicates claims but does not create authority:

| Request-supplied claim | Firewall-owned source |
|---|---|
| Agent ID, authentication, roles, authority, and security status | Opaque-credential resolver and signed `ResolvedPrincipal` |
| Target type, criticality, classification, dependencies, consequences | Validated target inventory |
| Current target state | Read-only observer |
| Action reversibility, privilege, target class, and parameter bounds | Validated action catalog and policy |
| Evidence source type, reliability, and trust | Validated source registry |
| Evidence provenance/content/semantics/time/subject integrity | Runtime HMAC attestation and canonical digest |
| Current time and expiration | Firewall clock |
| Policy version, precedence, and digest | Loaded validated policy artifact |

Agent recommendation, confidence, free text, requested labels, and asserted
trust/authority remain non-authoritative even when schema valid.

## Preservation constraints

- Do not reinterpret or regenerate Phase 1/2 artifacts as Phase 3 evidence.
- Do not weaken Phase 2 structural read-only construction or tests.
- Keep Phase 3 request, policy, decision, authorization, audit, and corpus
  contracts separate from historical formats.
- Do not add a live connector, production credential, network action, IAM
  mutation, generic plugin, or enablement flag to close a documentation gap.
- Do not call local synthetic results production safety, operational efficacy,
  independent assurance, or a bounded failure rate.

## Published baseline and next gates

1. Preserve exact Commit `423685d` and its 57/57 focused, then-current 288/288
   full-suite, and 46/46 corpus result as the immutable Phase 3 boundary.
2. Keep Phase 3.1 model evaluation synthetic-only until its distinct data,
   performance-threshold, and promotion authorities exist.
3. Require a separate exact commit and exact-commit CI for any later increment.

## Post-MVP technical debt

- enterprise IAM/device identity and managed, separated source/token keys;
- durable distributed request/token consumption and idempotency;
- externally custodied or WORM audit with independent anchors;
- production approval workflow and separation of duties;
- vendor-specific broker/readback, eventual consistency, retries, rollback,
  rate limiting, circuit breakers, and kill switches;
- OS/process isolation and network-egress controls;
- property-based fuzzing, load/resource-exhaustion and multi-node concurrency;
- formal policy-conflict analysis and independent red-team review; and
- historical/live data, efficacy, calibration, decision-quality, workflow,
  consequence, and operational-safety evaluation under separate authority.

The [Phase 3 T&E plan](TEST_AND_EVALUATION_PLAN.md) separates locally observed
checks from remaining acceptance evidence.

## Stage A production-development delta

Exact-baseline restart testing demonstrated that process-local request and
authorization state allowed the same completed request to cause a second
synthetic effect after reconstruction. The Stage A candidate closes that
specific path with opt-in SQLite/WAL authority state and tests request conflict,
verified-decision replay, atomic token/attempt reservation, independent-process
races, storage-lock failure, and conservative post-effect recovery.

This moves the single-host durable-ledger item from `Missing` to
`Integration tested` for the named synthetic boundary only. The following
parts of the original gap remain open: terminal full-result retrieval, durable
adapter receipts, crash injection at every instruction boundary, bounded load,
retention/compaction, outbox export, process isolation, managed keys, external
audit custody, multi-node consensus/fencing, failover, partitions, HA/DR, and
vendor semantics. The 18-domain release gate in
[`../production/PRODUCTION_READINESS.md`](../production/PRODUCTION_READINESS.md)
therefore derives `BLOCKED`.
