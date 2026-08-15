# ADR 008: Add a separate source-to-decision reference path before replay finalization

**Status:** Accepted at predecessor untagged `0.2.0-alpha.6` / Phase 2.5 design-freeze Commit `08ce203c`; not a release or evidence package

## Context

ADR 007 checks the 20 model feature values and traces but deliberately does not recompute `source_conflict`, evidence quality, model probability and ordered factors, policy disposition and actions, verifier checks and fail-safe downgrade, or the final read-only semantic decision surface. A decision and audit can therefore remain internally consistent, and its feature projection can match, while a downstream calculation defect or coherent mutation survives.

The additional assurance must preserve the existing Phase 2 authority boundary. It cannot add a live execution mode, authorization token, broker, target, action credential, or operational effect. It must also avoid presenting a same-project implementation as an external oracle or independent evaluation.

## Decision

The alpha.6 design freeze adds `src/adf_poc/replay/reference_decision.py`, a standard-library-only implementation that does not import the production evidence, feature, model, policy, verifier, engine, action, harness, or metrics calculation paths. Its public API accepts frozen bytes for normalized cases, serialized production decisions, the exact model, and the exact policy.

The parser shall reject invalid UTF-8, duplicate object members, non-finite numbers, malformed or nonclosed records, invalid identifiers or timestamps, non-read-only modes, invalid model or policy ranges, duplicate cases or decisions, unequal case sets, and code-owned resource-limit violations.

For each case, the reference path shall reconstruct and compare these deterministic semantic surfaces in order:

1. `EVIDENCE`;
2. `MODEL`;
3. `POLICY`;
4. `VERIFIER`; and
5. `FINAL_SURFACE`.

The first mismatch shall produce a stable stage-specific failure. Production and reference arithmetic shall use one explicit ordered specification where rounding can affect serialized decisions:

- evidence provenance, integrity, freshness, and trust aggregates use ordered `math.fsum(values) / count` before defined rounding; and
- model contributions use the frozen 20-feature order and `math.fsum`, followed by the intercept, clamped sigmoid, and defined probability/factor rounding.

This rule reduces interpreter/library reduction-order ambiguity. It does not establish exact equivalence across every future Python build, processor, or math library; evidence runs must bind and record their runtime environment.

The harness ordering shall be:

1. freeze and validate normalized cases, raw decisions, deterministic decisions, and the exact eight-stage audit;
2. run the Phase 2.4 feature projection in memory;
3. run the source-to-decision comparison in memory;
4. validate complete, unique, sorted, cross-bound receipt sets;
5. write and freeze both release-required reference artifacts only after both checks succeed;
6. publish qualification/rejection artifacts when enabled, then decode evaluator-only adjudications and produce comparisons and metrics; and
7. repeatedly revalidate every bound input and replay artifact through manifest construction, manifest write, final checks, and successful harness return.

A source-to-decision mismatch shall publish neither reference receipt and shall stop before adjudication decoding or completed-run finalization. A later failure may leave receipts, metrics, or even a manifest file. File presence is never the completion criterion; only successful return after every final check establishes a completed run.

`source_to_decision_assurance.jsonl` shall contain one closed metadata-only receipt per case. It binds the normalized case, model, policy, read-only mode, expected and observed stage digests, and ordered path digest. It deliberately excludes volatile `decision_id`, `created_at`, `latency_ms`, and `decision_record_hash` instance fields. The completed manifest separately co-binds exact raw decision and audit bytes.

## Implementation, evidence, and release boundary

The source-to-decision predecessor design-freeze implementation passed the 193-test review-local suite, and CI succeeded for exact Commit `08ce203c` on 2026-08-15. That supports CE-1 calculation-consistency wording for the exact commit only. This package candidate adds bounded controls, documentation, visuals, and packaging outside that predecessor commit; its Phase 2.5 technical suite passed 222/222, the separate public-site module passed 9/9, and the combined repository aggregate passed 231/231. The site module is outside this ADR and Phase 2.5 evidence. The candidate includes a generated-and-verified integrity manifest and inspected final-source status renders. The tracked data, campaign-bound model, and baseline outputs remain at committed bytes. Alpha.6 is not tagged and has no release or evidence package. Package publication and exact-package GitHub CI remain external release gates.

`P2-CE-005-SOURCE-TO-DECISION-SYNTHETIC` remains CE-0 `NOT_EVALUATED`. Its ten planned clean/mutant pairs per run, two planned runs, 40-attempt denominator, zero retries/exclusions, and expected stage outcomes are design constants, not observations. CE-2 requires a clean Commit A freeze, exact detached execution, invalidation on any actor/task/scorer/generator/validator defect, a separate evidence-only Commit B, and fresh frozen-evaluator validation.

No Phase 2.5 implementation or campaign statement may be used to claim historical/live behavior, source authenticity or truth, evidence completeness, outcome correctness, policy fitness, model efficacy or calibration, privacy or processing authority, OS isolation, network nonuse, external custody, organizational independence, exhaustive coverage, a statistical failure bound, production readiness, alignment, misalignment, scheming, sandbagging, sabotage robustness, monitor efficacy, or safe autonomous action.

## Consequences

- The tested calculation-consistency boundary expands beyond features without expanding action authority.
- Explicit arithmetic and ordered stage comparison improve deterministic diagnosis and prevent a later-stage mismatch from concealing an earlier one.
- Both reference implementations and the production path must remain aligned to a reviewed specification; differential, rounding-boundary, coherent-mutation, and late-mutation regressions become release gates.
- The duplicated implementation increases maintenance cost and can still share specification, governance, runtime, or test defects.
- Metadata-only receipts reduce disclosure but remain linkable and do not provide anonymization, external custody, or complete replay evidence by themselves.

## Final package and evidence conditions

The architectural decision is accepted at the predecessor design-freeze boundary. A final alpha.6 package and campaign Commit A additionally require:

1. the intended campaign CLI confinement controls and regression tests remain incorporated;
2. the completed 222/222 Phase 2.5 technical result and separate 9/9 public-site result, together forming the 231/231 repository aggregate, are followed by GitHub CI success on the exact published package commit;
3. documentation, schemas, metrics, visuals, outputs, manifests, and completion semantics agree with that exact implementation;
4. any tagged release or evidence package is explicitly created and independently distinguished from the predecessor design freeze; and
5. `P2-CE-005` remains explicitly CE-0 unless its separate evidence protocol is completed.

## Alternatives considered

**Broaden the Phase 2.4 feature projector in place.** Rejected because feature assurance has a published, version-bound claim and artifact contract that should not be retroactively expanded.

**Treat the production decision and audit as their own oracle.** Rejected because coherent downstream changes can preserve both.

**Describe the separate path as independent assurance.** Rejected because it shares process, project, specification, governance, runtime, inputs, and custody with production.
