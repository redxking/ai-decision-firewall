# Engineering Roadmap

## Phase 0 — Concept convergence

Completed. The broad problem of autonomous SOC agents was narrowed to a measurable decision boundary: privileged-identity containment. The product thesis is that the durable value lies in evidence and authority control rather than in a proprietary language model.

## Phase 1 — Synthetic executable baseline (v0.1)

Completed in this package. Deliverables include the scenario generator, learned risk model, evidence-quality engine, four-way policy, independent verifier, signed token gate, simulated action broker, post-action verification, hash-chained audit log, baseline metrics, diagrams, tests, and engineering documentation.

**Exit condition:** Safety invariants are executable and reproducible. Operational efficacy is not claimed.

## Phase 2 — Historical replay and data-contract discovery (v0.2)

Replace 25–50% of the synthetic cases with de-identified historical incidents and benign administrative cases. Build vendor adapters and a canonical event contract. Measure missing fields, source delays, analyst disagreement, false contextual assumptions, and model calibration.

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
