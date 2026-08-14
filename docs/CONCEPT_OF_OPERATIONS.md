# Concept of Operations — Privileged Identity Decision Firewall

## Mission objective

Reduce the time and analyst effort required to decide whether suspicious privileged-identity activity warrants closure, further investigation, reversible containment, or human-authorized high-impact response, while preventing a probabilistic model from directly exercising operational authority.

## Operational actors

The evidence producer supplies identity, endpoint, network, asset, threat-intelligence, change-management, and workforce-context events. The decision firewall normalizes and evaluates evidence, obtains a risk estimate from a replaceable model, applies deterministic policy, and independently verifies action eligibility. The authorization gate issues a short-lived scoped token only for approved reversible actions. The action broker executes against the POC simulator. The human decision authority receives escalations. The evaluator compares decisions with separately stored labels.

## Operational modes

**Development mode:** Synthetic data, simulator-only actions, unrestricted instrumentation, and model retraining.

**Replay mode:** De-identified historical cases, no live actions, labels hidden until adjudication, and counterfactual evaluation.

**Shadow mode:** Live read-only telemetry, no operational action, recommendations compared with analysts in real time.

**Controlled test-tenant mode:** Reversible actions against non-production identities under explicit change control and stop conditions.

**Limited pilot mode:** Small approved population, human approval required for all actions until statistical and operational gates are met.

## Decision outcomes

`NO_ACTION` closes the case because evidence is decision-grade, risk is below the closure threshold, and no severe indicator exists.

`INVESTIGATE` is an explicit abstention. The system identifies missing, stale, contradictory, low-integrity, or adversarial evidence and issues only read-only evidence-collection tasks.

`CONTAIN_REVERSIBLE` applies only to allow-listed, reversible, low-impact actions when risk, evidence quality, corroboration, asset criticality, and independent verification all satisfy policy.

`ESCALATE_HUMAN` transfers authority to an identified human role because risk is high but the asset, identity, or proposed action exceeds the autonomous boundary.

## Nominal operational sequence

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

## Off-nominal behavior

Prompt-injection strings, missing provenance, failed integrity, conflicting sensors, multiple missing expected sources, break-glass identities, and critical assets force abstention or human escalation. An action-command failure does not produce a false success; post-action verification fails and the audit record preserves the failed outcome for operator recovery. Automated escalation after execution failure is not implemented in v0.1.
