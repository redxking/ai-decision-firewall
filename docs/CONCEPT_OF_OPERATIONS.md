# Concept of Operations — Privileged Identity Decision Firewall

> **Version boundary.** This document preserves the v0.1 synthetic-simulation concept of operations and identifies the current transition path. `0.2.0-alpha.5` is the prior published evidence baseline. Exact Commit `08ce203c` is the predecessor untagged `0.2.0-alpha.6` design-freeze baseline, with historical CI and Dependency Graph success bound to that commit. This package candidate's Phase 2.5 technical suite passed 222/222; the separate public-site module passed 9/9; and the combined repository aggregate passed 231/231. The site module is outside Phase 2.5 evidence. The candidate includes a generated-and-verified integrity manifest and inspected final-source status renders. Package publication and GitHub CI on the exact published package commit remain external gates. Tracked data, model, and baseline outputs remain at their committed bytes. No tag or release/evidence package exists, and `P2-CE-005` is CE-0 `NOT_EVALUATED`. No Gate B package, historical-data approval, live feed, test-tenant integration, or operational-action authority exists.

## Mission objective

Reduce the time and analyst effort required to decide whether suspicious privileged-identity activity warrants closure, further investigation, reversible containment, or human-authorized high-impact response, while preventing a probabilistic model from directly exercising operational authority.

## Operational actors

The evidence producer supplies identity, endpoint, network, asset, threat-intelligence, change-management, and workforce-context events. The decision firewall normalizes and evaluates evidence, obtains a risk estimate from a replaceable model, applies deterministic policy, and independently verifies action eligibility. In the v0.1 `synthetic_simulation` compatibility path only, the authorization gate can issue a short-lived scoped token for an approved reversible action and the action broker can execute against the in-memory POC simulator. In both Phase 2 read-only modes, the authorization gate, broker, and target are not constructed; proposed actions remain counterfactual. The human decision authority receives escalation recommendations. The evaluator compares completed read-only decisions with separately stored adjudications only after the decision and audit close.

## Operational modes

| Mode | Current status | Data and action boundary |
|---|---|---|
| Development / `synthetic_simulation` | Implemented v0.1 compatibility path | Synthetic data, in-memory simulator-only reversible actions, instrumentation, and model retraining |
| Offline `historical_replay` semantics | Implemented and tested with synthetic fixtures only | Read-only counterfactual decisions; zero historical cases, authorization tokens, broker calls, or effects |
| Gate B historical-pilot preflight | Machine contract and synthetic negative-control evidence implemented | No authenticated organizational package is approved; no historical payload is authorized or stored |
| `shadow_read_only` semantics | Implemented as a code-owned read-only mode | No live feed or deployed service exists; the name describes execution semantics only |
| Controlled test-tenant mode | Planned | Would require a separately approved non-production architecture, credentials, rollback, independent readback, stop conditions, and change control |
| Limited pilot mode | Planned | Would require a bounded approved population, human authorization, operational evidence, and an authorizing-official decision |

The current repository contains only synthetic fixtures. “Historical replay” and “shadow read only” do not imply that historical or live data has been processed.

## Decision outcomes

`NO_ACTION` closes the case because evidence is decision-grade, risk is below the closure threshold, and no severe indicator exists.

`INVESTIGATE` is an explicit abstention. The system identifies missing, stale, contradictory, low-integrity, or adversarial evidence. Phase 2 records any evidence-collection action only as a read-only counterfactual recommendation; it does not issue a task to an operational system.

`CONTAIN_REVERSIBLE` applies to allow-listed, reversible, low-impact simulator actions in the v0.1 synthetic path when risk, evidence quality, corroboration, asset criticality, and independent verification all satisfy policy. Phase 2 may retain this disposition and its proposed actions only as counterfactual output.

`ESCALATE_HUMAN` recommends transfer to an identified human role because risk is high but the asset, identity, or proposed action exceeds the encoded boundary. The POC does not create an operational escalation ticket or transfer authority through an external workflow.

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

## Off-nominal behavior

Prompt-injection strings, missing provenance, failed integrity, conflicting sensors, multiple missing expected sources, break-glass identities, and critical assets force abstention or human escalation. In v0.1, an action-command failure does not produce a false success; post-action verification fails and the audit record preserves the failed outcome for operator recovery. Automated escalation after execution failure is not implemented.

In Phase 2, any authority, binding, type/source, qualification, audit, reference-assurance, adjudication, or late-artifact failure stops the protected sequence. Earlier files may remain as incomplete diagnostic material and must not be reported as completed replay evidence. See [`phase2/README.md`](phase2/README.md) and [`phase2/SHADOW_MODE_SAFETY.md`](phase2/SHADOW_MODE_SAFETY.md) for the current implementation boundary.
