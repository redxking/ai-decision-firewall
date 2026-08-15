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
> integration, operational credential, or live-action authority exists.

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

## Operational modes

| Mode | Current status | Data and action boundary |
|---|---|---|
| Development / `synthetic_simulation` | Implemented v0.1 compatibility path | Synthetic data, in-memory simulator-only reversible actions, instrumentation, and model retraining |
| Offline `historical_replay` semantics | Implemented and tested with synthetic fixtures only | Read-only counterfactual decisions; zero historical cases, authorization tokens, broker calls, or effects |
| Gate B historical-pilot preflight | Machine contract and synthetic negative-control evidence implemented | No authenticated organizational package is approved; no historical payload is authorized or stored |
| `shadow_read_only` semantics | Implemented as a code-owned read-only mode | No live feed or deployed service exists; the name describes execution semantics only |
| Phase 3 simulation-only operational MVP | Published `0.3.0-alpha.1` at exact Commit `423685d`; 57/57 focused tests, then-current 288/288 repository tests, demo acceptance PASS, corpus 46/46; exact-commit CI/Dependency Graph passed | Raw synthetic requests; opaque synthetic invocation credentials; in-memory `NETWORK_ISOLATE`; exact-scope token; separate same-project readback; no live connector or operational credential |
| Phase 3.1 synthetic model evaluation | Working `0.3.1-alpha.1` candidate; synthetic temporal baseline/challenger mechanism only | Digest-bound repository fixtures; no historical/live adapter, action path, owner threshold, promotion authority, or operational claim |
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
