# ADR 007: Require a separate reference feature projection before replay evaluation

**Status:** Accepted for published Phase 2.4 / `0.2.0-alpha.5`

## Context

The Phase 2.3 replay contract bounded event structure but did not assign exact JSON types and authorized source roles to every modeled attribute. Production feature extraction also relied on generic Python coercion. A schema-valid string, non-finite number, Boolean used as a number, or modeled signal asserted by an unrelated source could therefore change the 20-feature projection.

Decision and audit self-consistency was not sufficient to detect a coherent downstream mutation. A changed feature value or feature-to-event trace could be accompanied by a recomputed decision hash and a fully rechained audit. Reusing the production feature extractor as the checker would preserve the same calculation and orchestration defects.

## Decision

Phase 2.4 shall enforce a code-owned modeled-signal contract before engine invocation:

- exact JSON Boolean handling for Boolean modeled attributes;
- a finite integral `failed_logins` value in the reviewed `0..1,000,000` range;
- exact authorized source roles for every modeled key;
- finite JSON numbers throughout each accepted case;
- a separately governed, network-only Boolean `source_conflict` evidence input; and
- exact equality of `asset_id`, `privilege_level`, `break_glass`, and `asset_criticality` between every asset-inventory assertion and canonical case context.

After read-only decision validation, deterministic decision serialization, and the complete eight-stage audit check, the harness shall invoke `src/adf_poc/replay/reference_features.py`. The reference projector:

- uses the Python standard library only;
- does not import the production feature extractor, feature contract, engine, model, policy, verifier, harness, or metrics calculation paths;
- separately reconstructs all 20 serialized feature values and their event traces from normalized cases;
- requires exact, unique case sets and normalized-case digest binding; and
- returns a closed metadata-only matched record per case.

On any projection, trace, case-set, digest, schema, or completeness mismatch, the run shall stop before qualification/rejection publication, adjudication decoding, comparison, metrics, or completed-run finalization. Earlier normalized cases, decisions, and audit files may remain only as incomplete diagnostic material.

On success, `reference_feature_assurance.jsonl` is hash/count-bound into metrics and the completed run manifest. The receipt contains no raw feature values, source payloads, paths, or free-form errors.

## Evidence and claim boundary

Implementation and regression tests support only CE-1 conformance for the exact tested checkout. The separate `P2-CE-004` evidence record preserves a narrow SELF synthetic CE-2 result against its exact bound commit and artifacts. Neither evidence class establishes source truth, evidence-quality correctness, model probability, policy or verifier correctness, historical/live performance, external custody, organizational independence, exhaustive coverage, a statistical failure bound, or production readiness.

The committed `P2-CE-001` and `P2-CE-002` bundles predate this decision. Their original version-bound claims remain valid as recorded, but they contain no reference-feature receipt and are not retroactively upgraded.

## Consequences

- Modeled-signal semantics become explicit and fail closed instead of depending on Python truthiness or numeric coercion.
- A coherent mutation that survives legacy decision/audit checks can be detected at the feature projection boundary.
- Replay finalization gains an additional required artifact and binding.
- The project carries duplicated calculation logic that must remain specification-aligned through differential and metamorphic tests.
- Same-process, same-project execution can retain correlated requirements, implementation, runtime, and governance defects; the word “independent” shall not be used for this assurance boundary.

## Alternatives considered

**Call the production feature extractor from the validator.** Rejected because the validator would share the calculation path it is intended to check.

**Validate only the serialized decision hash and audit chain.** Rejected because a coherent forger or defective writer can recompute both around changed feature content.

**Persist raw expected and observed features for review.** Rejected for the public evidence boundary because it unnecessarily duplicates potentially sensitive decision input. Closed digests and restricted diagnostic handling provide the required comparison without widening disclosure.
