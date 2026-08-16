# Concept of Operations — Privileged Identity Decision Firewall

> **Version boundary.** This document preserves the v0.1 and Phase 2 concepts
> while adding the published Phase 3 simulation-only operational-MVP concept. Exact
> Phase 2.5 Commit `854b15c56397a81de6326b719d3d7d1dc847608f` is published on
> `main`, and its exact-commit CI and Dependency Graph checks passed.
> `P2-CE-005` was not executed and remains CE-0 `NOT_EVALUATED`. Phase 3
> `0.3.0-alpha.1` is published at exact Commit
> `423685d105be813056617db738297eba83d3d9d0`; exact-commit CI and Dependency
> Graph checks passed. Its simulation-only CE-1 boundary includes 57/57 focused
> tests, two demo acceptance checks PASS, 46/46 corpus scenarios, and the
> then-current 288/288 repository suite. No
> Gate B package, historical-data approval, live feed, production/test-tenant
> integration, operational credential, or live-action authority exists. The
> unreleased Stage A candidate adds only opt-in local durability through
> separate control and offline synthetic-adapter SQLite databases plus a
> sanitized result lookup. The provisional version is `0.4.0-alpha.2`. At its
> 2026-08-16 local source freeze, 43/43 focused Stage A, 18/18 readiness-gate,
> 360/360 repository, and 46/46 corpus checks passed; the corpus reported
> `live_actions_possible=false`. These are project-controlled mechanism
> observations without an exact candidate commit, regenerated manifest, CI,
> owner acceptance, operational validation, or production authority. Its
> production gate remains `BLOCKED`.

## Mission objective

Reduce the time and analyst effort required to decide whether suspicious privileged-identity activity warrants closure, further investigation, reversible containment, or human-authorized high-impact response, while preventing a probabilistic model from directly exercising operational authority.

## Operational actors

The evidence producer supplies identity, endpoint, network, asset,
threat-intelligence, change-management, and workforce-context events. The
decision firewall evaluates evidence and trusted context, applies deterministic
policy, and independently verifies action eligibility. In the v0.1
`synthetic_simulation` compatibility path, the broker can execute legacy
reversible actions against its in-memory identity simulator. In both Phase 2
read-only modes, the authorization gate, broker, and target are not constructed;
proposed actions remain counterfactual.

In Phase 3, an external synthetic agent submits a raw v0.3.0 proposed-action
request plus an opaque invocation credential outside the request JSON. A
firewall-owned resolver maps that credential to a signed `ResolvedPrincipal`;
runtime registries supply authoritative source/action/target facts. A
functionally separate decision verifier precedes exact-scope authorization;
the mandatory broker can change only an in-memory target; and a functionally
separate same-project read-only observer determines the final effect
classification. A human decision authority must use a separately resolved
opaque credential and may approve an exact escalation scope for a signed
reevaluation-only receipt. Approval cannot execute, mint an authorization, or
itself cause reevaluation.

When the optional Stage A path is explicitly configured, the broker remains
offline and synthetic but routes the exact-bound command to a separate durable
synthetic-adapter database instead of process-local target state. The adapter
updates its synthetic target state and inserts an immutable receipt in one
store-local transaction. A same-project read-only observer reads that adapter
store, after which the control ledger may persist one sanitized terminal
lookup result. The receipt and observer are not independent target evidence,
and no transaction spans the control database, adapter database, or JSONL
audit.

## Operational modes

| Mode | Current status | Data and action boundary |
|---|---|---|
| Development / `synthetic_simulation` | Implemented v0.1 compatibility path | Synthetic data, in-memory simulator-only reversible actions, instrumentation, and model retraining |
| Offline `historical_replay` semantics | Implemented and tested with synthetic fixtures only | Read-only counterfactual decisions; zero historical cases, authorization tokens, broker calls, or effects |
| Gate B historical-pilot preflight | Machine contract and synthetic negative-control evidence implemented | No authenticated organizational package is approved; no historical payload is authorized or stored |
| `shadow_read_only` semantics | Implemented as a code-owned read-only mode | No live feed or deployed service exists; the name describes execution semantics only |
| Phase 3 simulation-only operational MVP | Published `0.3.0-alpha.1` at exact Commit `423685d`; 57/57 focused tests, then-current 288/288 repository tests, demo acceptance PASS, corpus 46/46; exact-commit CI/Dependency Graph passed | Raw synthetic requests; opaque synthetic invocation credentials; in-memory `NETWORK_ISOLATE`; exact-scope token; separate same-project readback; no live connector or operational credential |
| Phase 3.1 synthetic model evaluation | Published `0.3.1-alpha.1` exact Commit `bb6b8f28`; synthetic temporal baseline/challenger mechanism only | Digest-bound repository fixtures; no historical/live adapter, action path, owner threshold, promotion authority, or operational claim |
| Stage A two-store offline durability | Provisional unreleased `0.4.0-alpha.2`; optional single-host control database, separately pathed synthetic-adapter database, JSONL lifecycle audit, and sanitized terminal lookup; local source-freeze mechanism checks passed | Offline synthetic execution only; receipt/readback remain same-project and cross-store non-atomic; no external identity, connector, target, deployment, distributed replay claim, exact candidate commit/CI, or operational authority; production gate `BLOCKED` |
| Controlled test-tenant mode | Planned | Requires separately approved non-production architecture, process isolation, managed credentials, durable idempotency, vendor-independent readback, rollback, stop conditions, and change control |
| Limited pilot mode | Planned | Would require a bounded approved population, human authorization, operational evidence, and an authorizing-official decision |

The current repository contains only synthetic fixtures. “Historical replay” and “shadow read only” do not imply that historical or live data has been processed.

## Decision outcomes

Phase 1/2 preserve the historical outcome vocabulary below:

`NO_ACTION` closes the case because evidence is decision-grade, risk is below the closure threshold, and no severe indicator exists.

`INVESTIGATE` is an explicit abstention. The system identifies missing, stale, contradictory, low-integrity, or adversarial evidence. Phase 2 records any evidence-collection action only as a read-only counterfactual recommendation; it does not issue a task to an operational system.

`CONTAIN_REVERSIBLE` applies to allow-listed, reversible, low-impact simulator actions in the v0.1 synthetic path when risk, evidence quality, corroboration, asset criticality, and independent verification all satisfy policy. Phase 2 may retain this disposition and its proposed actions only as counterfactual output.

`ESCALATE_HUMAN` recommends transfer to an identified human role because risk is high but the asset, identity, or proposed action exceeds the encoded boundary. The POC does not create an operational escalation ticket or transfer authority through an external workflow.

The separate Phase 3 external boundary uses:

- `ALLOW` — execute the exact requested parameters in the synthetic target;
- `ALLOW_CONSTRAINED` — replace the request with canonical policy-bounded
  parameters and authorize only that scope;
- `DENY` — terminal prohibition or fail-closed invalid/untrusted condition; and
- `ESCALATE` — no authorization or effect; create an exact expiring human-review
  requirement when higher authority can reevaluate the request.

## V0.1 synthetic-simulation sequence

1. Receive a case containing normalized evidence events and case metadata.
2. Validate event schema and isolate free text.
3. Score provenance, integrity, freshness, source trust, diversity, completeness, and conflicts.
4. Extract only allow-listed structured features and retain event-level traceability.
5. Obtain a compromise probability and feature contributions from the replaceable model.
6. Apply deterministic policy to produce one of four dispositions.
7. Execute independent non-model verification.
8. Mint a short-lived token only when a reversible action is independently approved.
9. Execute through the credential-isolated broker.
10. Verify the target state and record all evidence, decisions, tokens, actions, and outcomes in the audit chain.

This sequence applies only to the in-memory v0.1 simulator. It is not the Phase 2 replay sequence and must not be represented as a production identity-control workflow.

## Current Phase 2 read-only sequence

1. Read configuration and manifest control bytes. For a historical origin, require a current, exact, externally governed Gate B package before any payload access.
2. Confine and freeze the authorized input, control, model, policy, mapping, and protocol bytes; keep adjudication bytes outside runner inputs.
3. Validate or qualify the complete case set with exact accounting, typed/source-authorized modeled inputs, finite-number checks, and canonical inventory binding.
4. Normalize accepted cases and execute only the evidence, model, policy, verifier, and counterfactual-decision path.
5. Structurally suppress authorization and execution; emit no token, broker call, target call, action result, or operational effect.
6. Validate the exact eight-stage decision/audit trace and deterministic decision projection.
7. Run the Phase 2.4 reference feature projection. In the alpha.6 candidate, then separately recompute the ordered `EVIDENCE`, `MODEL`, `POLICY`, `VERIFIER`, and `FINAL_SURFACE` stages from frozen bytes.
8. Publish the release-required metadata-only assurance receipts only after all required reference checks match. Any mismatch fails the run before evaluator output and completed-run finalization.
9. Materialize and decode evaluator-only adjudications, produce comparisons and metrics, revalidate every binding, and return success only after final artifact checks. File presence alone does not establish a completed run.

## Phase 3 simulation-only sequence

1. Receive raw v0.3.0 JSON plus an opaque invocation credential; strictly
   validate syntax, schema, time, bounds, and request identity.
2. Resolve the credential to a signed principal and resolve agent
   status/authority and target/action/source facts from firewall-owned validated
   registries rather than request assertions.
3. Validate HMAC-attested synthetic evidence, including its subject target, and
   assess freshness, relevance, corroboration, conflicts, missing sources,
   integrity, and poisoned text.
4. Assess action consequence using trusted criticality, dependencies,
   reversibility, cascade, blast radius, downtime, and mission/safety/
   availability impact.
5. Apply deterministic policy with code-owned rule, evidence, consequence, and
   Tier-0 safety floors and return a structured four-way decision. AI
   recommendation and confidence remain advisory.
6. Recheck the decision through a functionally separate deterministic verifier.
7. For `ALLOW` or `ALLOW_CONSTRAINED`, issue one short-lived exact-scope token,
   consume it at the mandatory broker, and attempt only `NETWORK_ISOLATE` on the
   in-memory target. For `DENY` or `ESCALATE`, explicitly suppress execution.
8. Observe post-state through the functionally separate same-project read-only
   target interface and classify the transition without trusting the broker
   return value.
9. Record a correlated hash-linked lifecycle whose executed path binds the
   request, decision, authorization, attempt, target state, effect, and
   verification semantics. If an audit prewrite fails after effect, close with
   one honest `POST_EFFECT_ACCOUNTING_FAILURE`, return `ROLLBACK_REQUIRED`, and
   reconcile metrics exactly once; recovery remains a human/operational action.

The two local demos exercise Tier-0 escalation/no effect and workstation
allow/verified synthetic isolation. This sequence is not a deployment or live
SOC procedure. The private capability is an application-level control, the
token ledger is process local, evidence keys are synthetic runtime HMAC keys,
and the verifiers are same-project rather than externally independent.

## Optional Stage A offline sequence

1. Resolve the authenticated principal, parse the exact request, and claim the
   `(principal, request_id, request digest)` binding in the control database.
2. For an allowed, verified decision, register one exact-bound authorization.
   Atomically consume it, reserve the attempt, and advance the request before
   invoking the adapter.
3. Invoke only the offline synthetic adapter with a stable idempotency key. In
   its separate database transaction, validate the precondition and binding,
   update durable synthetic target state, and insert one immutable receipt.
4. Read target state through the separate read-only interface and classify the
   transition. This is functional separation inside the same project/store
   custody, not independent verification.
5. Close and read back the valid normal JSONL lifecycle. Only then atomically
   close the attempt/request, insert the sanitized terminal lookup result, and
   add its metadata-only outbox event in the control database (T3).
6. After response loss, an authenticated read-only lookup may return the
   authority-free stored projection. It creates no new decision, authorization,
   broker invocation, or effect and never returns a signed token.

The control database, adapter database, and JSONL audit are three authoritative
artifacts. T1, T2, observation, audit closure, and T3 are deliberately not one
transaction. A store-local commit does not prove that another store or the
audit reached the corresponding point. Before a missing artifact is created,
the three paths and every existing store are preflighted without mutating
existing main/WAL/SHM artifacts. Bounded cooperative same-host fencing covers
startup and durable processing, lookup, approval, and recovery. Cross-store
checks correlate overlapping request, authority, decision/context, policy,
receipt, and terminal-target facts.

## Off-nominal behavior

Prompt-injection strings, missing provenance, failed integrity, conflicting sensors, multiple missing expected sources, break-glass identities, and critical assets force abstention or human escalation. In v0.1, an action-command failure does not produce a false success; post-action verification fails and the audit record preserves the failed outcome for operator recovery. Automated escalation after execution failure is not implemented.

In Phase 2, any authority, binding, type/source, qualification, audit, reference-assurance, adjudication, or late-artifact failure stops the protected sequence. Earlier files may remain as incomplete diagnostic material and must not be reported as completed replay evidence. See [`phase2/README.md`](phase2/README.md) and [`phase2/SHADOW_MODE_SAFETY.md`](phase2/SHADOW_MODE_SAFETY.md) for the current implementation boundary.

In Phase 3, malformed/untrusted input, principal mismatch, compromised identity,
evidence attestation/content/subject failure, insufficient or conflicting
evidence, unsafe consequence, verifier failure, token mismatch/expiry/replay,
target precondition drift, and internal pre-execution faults fail closed without
an unauthorized effect. A failed simulated attempt still consumes its token.
Post-attempt observation failure cannot undo the attempt and must never become
`VERIFIED`; partial or protected unexpected effects select the applicable
failure or rollback-required state. See [`phase3/README.md`](phase3/README.md)
and [`phase3/SECURITY_AND_SAFETY_CASE.md`](phase3/SECURITY_AND_SAFETY_CASE.md).

In Stage A, an exact receipt or terminal-result repeat is idempotent and a
changed binding is a conflict. Recovery is an explicit quiesced operation: an
affirmative exact `NO_EFFECT` receipt may close `FAILED_NO_EFFECT`; an applied,
partial, ambiguous, or absent receipt without separately durable verification
closes `UNKNOWN_EFFECT` with `recovery_required=true`. Absence does not prove no
effect and does not permit retry. Corrupt, mismatched, or
unavailable adapter evidence halts reconciliation without a state change.
Recovery never invokes the command, reopens or replaces a token, fabricates
verification, or declares rollback. Before T3, it writes and reads back the
exact contiguous `RECOVERY_STARTED`, `RECOVERY_EVIDENCE_ASSESSED`, and
`RECOVERY_FINALIZED` records, including the original lifecycle status
`COMPLETE`, `INCOMPLETE`, or `UNRESOLVED`. Audit append/readback failure
suppresses T3, an existing exact prefix resumes without duplicate rows, a
pending recovery fences other durable writers, and a repeat after T3 returns
the identical audit-inert result. Operator-asserted quiescence plus the
cooperative same-host fence is not a distributed lease, epoch, or execution-
ownership mechanism.
