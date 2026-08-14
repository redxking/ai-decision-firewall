# Engineering Roadmap

## Phase 0 — Concept convergence

Completed. The broad problem of autonomous SOC agents was narrowed to a measurable decision boundary: privileged-identity containment. The product thesis is that the durable value lies in evidence and authority control rather than in a proprietary language model.

## Phase 1 — Synthetic executable baseline (v0.1)

Completed in this package. Deliverables include the scenario generator, learned risk model, evidence-quality engine, four-way policy, independent verifier, signed token gate, simulated action broker, post-action verification, hash-chained audit log, baseline metrics, diagrams, tests, and engineering documentation.

**Exit condition:** Safety invariants are executable and reproducible. Operational efficacy is not claimed.

## Phase 2 — Historical replay and data-contract discovery (v0.2)

**Starter status:** Implemented and validated against the included synthetic fixture. The repository now includes a code-owned historical-replay and shadow-read-only boundary, canonical contracts and adapter scaffolding, integrity-bound replay manifests, a deterministic harness, synthetic Phase 2 fixtures, safety tests, and a claim-evidence/requirements package. Authorization, brokering, target construction, and operational effects are suppressed in both read-only modes. There is no live execution mode. This closes the starter increment, not Phase 2 or any historical-performance gate.

The starter contains zero historical cases and makes no claim about operational performance. The next increment is to ingest an approved, de-identified corpus of historical incidents and benign administrative cases; measure missing fields, source delays, analyst disagreement, false contextual assumptions, and calibration; then determine whether the available evidence can support a defensible shadow experiment.

**Decision point:** Determine whether identity containment remains the best entry use case and whether available evidence supports reliable abstention and escalation.

## Phase 3 — Live shadow mode (v0.3)

Connect read-only feeds in a lab or approved tenant. Produce recommendations without action. Compare the system with analysts, track decision latency and evidence requests, and conduct counterfactual review.

**Exit condition:** No data-handling violations; stable schemas; acceptable traceability; measured analyst agreement; statistically bounded false-containment risk.

## Phase 4 — Controlled test-tenant actions (v0.4)

Enable signed reversible actions against non-production accounts under change control. Add enterprise identity-provider adapters, secrets management, mutual TLS, token replay protection, rate limits, and kill switches.

**Exit condition:** Action idempotency, rollback, post-action verification, and stop conditions validated under failure injection.

## Phase 5 — Limited operational pilot (v0.5)

Restrict to a small approved identity population. Require human approval for all actions initially. Gradually evaluate selected low-impact actions only after evidence-based release gates are met.

**Exit condition:** Authorizing official accepts the residual risk and approved action classes have sufficient adjudicated volume to establish defensible lower confidence bounds.

## Phase 6 — Productization

Add multi-tenant policy packs, vendor-neutral integrations, model-comparison harnesses, continuous calibration, secure update and supply-chain controls, compliance mappings, operator workflows, and sector-specific mission consequence models.
