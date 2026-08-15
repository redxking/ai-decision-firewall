# Phase 2.5 Source-to-Decision Assurance

> **Status.** Exact Phase 2.5 Commit
> `854b15c56397a81de6326b719d3d7d1dc847608f` is published on `main`; its
> exact-commit CI/Dependency Graph checks passed. Its package boundary includes
> the 222/222 technical suite and 21/21 campaign module. The separate 9/9 site
> result and then-current 231/231 aggregate do not extend source-to-decision
> evidence. No tag or campaign evidence package exists. `P2-CE-005` was not
> executed or published and remains CE-0 `NOT_EVALUATED` until the two-commit
> protocol completes.

## Objective and current evidence state

Phase 2.5 checks whether a separately implemented reference path can reconstruct the deterministic read-only decision recorded by the production path from the exact normalized case, model, policy, and execution mode. It extends Phase 2.4 beyond feature values and traces to five ordered calculation surfaces:

1. `EVIDENCE` — evidence quality, provenance, integrity, freshness, source diversity and trust, corroboration, missing-source, conflict, poisoning, event-citation, and rationale fields;
2. `MODEL` — the 20 feature values and traces, standardized contributions, probability, model version, and ordered top positive and negative factors;
3. `POLICY` — original and final dispositions, counterfactual actions, proposal fields, applied rules, required authority, cited evidence, and rollback content;
4. `VERIFIER` — the exact ordered checks, pass state, and blocking reasons, including fail-safe downgrade behavior; and
5. `FINAL_SURFACE` — the bounded read-only decision surface, including case/context and version bindings, dispositions, authorization suppression, empty action results, non-applicable post-action verification, execution-control counters, and traceability.

Published exact Commit `854b15c` supports narrow CE-1 implementation-conformance wording through its 222/222 Phase 2.5 technical result and green exact-commit CI; the separate 9/9 public-site result does not extend the source-to-decision claim. The planned `P2-CE-005-SOURCE-TO-DECISION-SYNTHETIC` campaign is **CE-0 `NOT_EVALUATED`**. Its plan, contracts, published code, and implementation tests do not establish a result. CE-2 wording is prohibited until a governed final Commit-A implementation/plan/validator/confinement freeze is evaluated from that exact clean commit and a separate evidence-only Commit B is published and validated.

## Reference implementation boundary

`src/adf_poc/replay/reference_decision.py` is standard-library-only and does not import the production evidence, feature, model, policy, verifier, engine, metrics, action, or harness calculation paths. Its public API accepts frozen bytes for:

- normalized cases JSONL;
- serialized engine decisions JSONL;
- the exact model JSON; and
- the exact policy JSON.

Parsing rejects invalid UTF-8, duplicate object members, non-finite numbers, malformed JSON/JSONL, closed-shape violations, invalid identifiers or timestamps, non-read-only modes, invalid model/policy ranges, duplicate cases or decisions, and unequal case sets. The reference path validates the serialized decision-record hash before comparing any calculation surface.

The reference parser also enforces code-owned ceilings: 64 MiB for each model or policy document; 512 MiB total for each JSONL input; one MiB per physical JSONL line; 100,000 nonblank JSONL records; JSON nesting depth 128; 10,000 events per case; 16,384 characters of untrusted text per event; 256 KiB each for an event `attributes` object and model `training_metadata`; and at most 256 model-limitations entries with 64 KiB total canonical size. Any breach fails closed with a stable error. These are parser-safety bounds, not production-scale, availability, or performance validation.

The implementation is separate in code but not independent in the organizational, runtime, custody, or statistical sense. It runs in the same Python process, repository, project governance, and evaluation environment and consumes the same normalized case, model, and policy bytes. Correlated requirements, specification, implementation, or test defects can therefore remain.

## Deterministic numeric rule

Evidence provenance, integrity, freshness, and source-trust aggregates use the same explicit ordered `math.fsum(values) / event_count` rule in the production and reference paths. Model contributions are evaluated in the frozen 20-feature order. Both paths use `math.fsum` over that ordered contribution sequence and then add the model intercept. The sigmoid input is clamped to `[-30, 30]`, and the serialized evidence, probability, and factor fields retain their defined rounding.

This removes dependence on a library-specific reduction order for cancellation-heavy valid model parameters and gives the two implementations one explicit summation rule. It is an algorithmic consistency control, not a claim of exact reproducibility across every Python build, processor, math library, or future dependency set. Any environment used for evidence must record its runtime fingerprint and verify the exact serialized result.

## Ordered comparison and receipt

For each case, the reference path computes canonical SHA-256 digests for the expected and observed surfaces and compares them in this order:

```text
EVIDENCE -> MODEL -> POLICY -> VERIFIER -> FINAL_SURFACE
```

The first unequal surface raises a stable stage-specific error. Only after all five surfaces agree does the implementation construct an ordered source-to-decision path digest. Successful records are sorted by `case_id` and validated against `contracts/v0.2.0/source-to-decision-assurance.schema.json`.

Each `source_to_decision_assurance.jsonl` row is closed and metadata-only. It contains the case and execution-mode bindings, normalized-case/model/policy source digests, expected and observed digest pairs for all five surfaces and the complete ordered path, `read_only=true`, and `matched=true`. It contains no raw case, evidence value, feature value, policy content, verifier detail, path, or free-form exception.

The receipt binds the deterministic semantic decision surface. It deliberately excludes volatile instance fields such as `decision_id`, `created_at`, `latency_ms`, and `decision_record_hash`; therefore semantically equivalent runs may produce an identical receipt. The completed run manifest separately co-binds the exact raw decision and eight-stage audit bytes and their counts. A receipt by itself is neither complete replay evidence nor proof of custody. Its digests can remain linkable and are not anonymization or independent custody.

## Harness ordering

The nonhistorical and Gate B historical paths enforce the same semantic order, with the historical path additionally using descriptor-bound owner-only output and repeated Gate B/current-validity checks:

1. qualify and normalize accepted cases;
2. write and freeze `normalized_cases.jsonl` and `normalization_diagnostics.json`;
3. execute the read-only production path, producing `engine_decisions.jsonl` and `replay_audit.jsonl`;
4. freeze the exact engine-decision and audit bytes, validate read-only decision invariants, and write/freeze `replay_decisions.jsonl`;
5. validate the complete eight-stage audit trace;
6. revalidate the normalized, raw-decision, deterministic-decision, and audit bindings;
7. run Phase 2.4 reference-feature recomputation in memory;
8. run Phase 2.5 source-to-decision recomputation from the frozen normalized-case, decision, model, and policy bytes;
9. validate complete, unique, sorted receipt sets and their cross-binding; only then write and freeze both reference-assurance artifacts;
10. write and freeze qualification/rejection artifacts when enabled;
11. materialize and decode evaluator-only adjudications, then write and freeze `adjudication_comparison.jsonl` and `replay_metrics.json`;
12. revalidate the full bound output set—normalized cases, normalization diagnostics, raw engine decisions, deterministic decisions, replay audit, both reference receipts, adjudication comparison, replay metrics, and, when enabled, qualification accounting and rejections;
13. pass those exact digests into manifest construction, which refuses bytes other than the previously checked values; revalidate the full set after construction and again after the manifest is written; the historical path additionally rechecks Gate B validity before publication and the retained output-directory bindings before success.

The completed run manifest binds the count and digest of `source_to_decision_assurance.jsonl` and the exact digests/counts of the other run outputs. The manifest is not self-hashed; successful harness return after the post-write checks is the completion boundary. Metrics require `cases_checked = matched_cases = decisions`, `mismatched_cases = 0`, and `complete=true`.

## Failure and incomplete-artifact semantics

Source-to-decision assurance fails closed. A stage mismatch occurs after production decisions and audit have been created but before either reference-assurance artifact is written. In that case:

- normalized cases and diagnostics may exist;
- raw and deterministic decisions and the replay audit may exist;
- no `reference_feature_assurance.jsonl` or `source_to_decision_assurance.jsonl` is published;
- qualification/rejection artifacts are not published;
- adjudications are not decoded and no comparison, metrics, or completed run manifest is produced; and
- every retained file is incomplete diagnostic material, not replay evidence.

A later failure can occur after one or both assurance artifacts, qualification records, comparisons, metrics, or even a manifest file have been written—for example, if any member of the full bound output set changes during construction or final revalidation. The run is complete only when the harness returns successfully after all final checks. A file's presence, including `replay_run_manifest.json`, is insufficient after an exception. The nontransactional output directory must be retained or quarantined for diagnosis and must never be reused as a new run target.

## `P2-CE-005` planned campaign

The fixed plan names the oracle `SEPARATE_SOURCE_TO_DECISION_RECOMPUTATION` and the bounded claim scope `EVIDENCE_MODEL_POLICY_VERIFIER_READ_ONLY_FINAL`. It contains ten clean/mutant pairs per run and two deterministic same-process runs: 40 planned attempt observations, zero retries, and zero exclusions. Each run is designed to contain ten clean reference-path matches and exactly two blocks at each of `EVIDENCE`, `MODEL`, `POLICY`, `VERIFIER`, and `FINAL_SURFACE`.

The clean and mutant in each pair share one pre-mutation production decision and audit baseline. The generator therefore creates and directly instruments ten production baselines per run, not 20: engine, evidence, model, policy, and verifier calls are each budgeted at ten per run and 20 across both runs. It presents both the clean and mutant form to the reference path, so reference recomputation is budgeted at 20 calls per run and 40 total. The 40-attempt denominator must not be described as 40 independent production executions.

The campaign contract separates two forms of accounting. Direct instrumentation counts authorization-gate, broker, and target construction or invocation plus target-effect and scoped decision/audit/manifest/filesystem-write calls. Decision-derived fields record whether serialized output reports an authorization attempt or token, broker invocation, action result, or operational effect. The frozen plan requires zero in both groups, but none of those zeros is observed while the campaign remains CE-0.

Every mutant must first pass the legacy read-only decision validator, exact eight-stage audit assurance, and Phase 2.4 reference-feature assurance. Mutations coherently rehash the decision and rechain the audit so the Phase 2.5 path, rather than a shallow legacy check, is the intended detector. The `P07` control, `VERIFIER_FALSE_BLOCKER_WITHOUT_DOWNGRADE_REHASH`, forges the `CONTAIN-NO-CONFLICT` check as false with the exact blocker and `passed=false` while deliberately retaining the containment policy/final/counterfactual surfaces. Its expected result is a `VERIFIER` mismatch, testing a fail-safe downgrade-bypass forgery.

## Post-design-freeze campaign CLI destination guard

Published Phase 2.5 Commit `854b15c` adds a bounded operator-error preflight for campaign CLI destinations. It resolves `--output-dir` and optional `--record` against the repository root and rejects the repository root itself, paths outside the repository, any `.git` path component, existing symbolic-link traversal, overlapping output/record destinations, a nonempty or non-directory output target, and an existing or symbolic-link record target. Check mode additionally requires every expected artifact leaf and optional record to be a singly linked regular file, rejects symbolic links, directories, and multiply linked artifact leaves before any artifact read or campaign rebuild, and applies the configured size bounds before reading. Generation accepts an absent or empty output directory and requires the record path to be absent, preventing ordinary accidental clobber through the CLI.

Three focused regressions—`test_cli_destination_preflight_accepts_only_repo_confined_fresh_paths`, `test_cli_destination_preflight_rejects_escape_symlink_and_overlap`, and `test_cli_rejects_outside_destination_before_campaign_execution`—passed 3/3. `test_check_rejects_unsafe_leaf_aliases_before_read_or_rebuild` separately covered the check-mode leaf rules. A negative sensitivity regression, `test_reference_scope_constructor_instrumentation_is_sensitive`, injected construction of `AuthorizationGate`, `ActionBroker`, and `SimulatedIdentityProvider` during a reference attempt, observed one of each, forced the result to `matched=false`, and proved that the closed campaign schema rejects the row. The complete campaign test module passed 21/21 in an isolated clean clone, and all five campaign-delta tests are included in the 222/222 Phase 2.5 technical suite. The separate public-site tests are outside this assurance result. Exact package Commit `854b15c56397a81de6326b719d3d7d1dc847608f` was published on `main` and its exact-commit CI/Dependency Graph checks passed. The RTM remains partial only where the requirement deliberately exceeds this bounded operator-error/Python-instrumentation evidence; publication is no longer an open gate.

The CLI control is only a destination guard, and the constructor control observes only the named Python construction paths during a reference attempt. They are not an OS sandbox, mount-namespace boundary, adversarial race or TOCTOU guarantee, general allocation monitor, target-side proof, or protection against another process with the same account. The CLI does not confine direct programmatic calls to `generate_artifacts`. The tests do not perform the governed clean detached exact-Commit-A evidence execution or create/publish an eligible evidence package; they do not change the CE-0 `NOT_EVALUATED` state.

The required publication sequence is:

1. Final Commit A freezes implementation, plan, schemas, generator, validator, and CLI confinement. Published package Commit `854b15c` contains the intended controls and green CI but was not designated or executed as governed `P2-CE-005` Commit A.
2. A clean detached checkout of that exact commit executes the fixed campaign with no retries.
3. Any defect in the actor, task, expected outcomes, scorer, generator, or validator invalidates the package; it is not repaired in place or counted as evidence.
4. Commit B contains only the validated evidence bundle, claim record, documentation, and integrity updates.
5. The claim validator binds Commit A and freshly reruns the frozen evaluator.

Until all five steps are complete, `P2-CE-005` remains CE-0 `NOT_EVALUATED`; planned denominators and expected outcomes must never be reported as observations.

## Research-to-design mapping

Primary research is used only as evaluation-design input:

- [Anthropic Agentic Misalignment](https://www.anthropic.com/research/agentic-misalignment) motivates controlled fictional simulations, matched controls, repeated trials, and explicit limits on real-deployment inference.
- [Anthropic Sabotage Evaluations](https://www.anthropic.com/research/sabotage-evaluations) motivates coherent decision, code, sandbagging, and oversight-undermining controls while treating artificial preparatory evaluations as something other than robustness proof.
- [OpenAI's third-party evaluation playbook](https://openai.com/index/trustworthy-third-party-evaluations-foundations/) motivates exact system, harness, budget, scorer, raw-evidence, validity-hazard, exclusion, and review bindings.
- [OpenAI's coding-evaluation analysis](https://openai.com/index/separating-signal-from-noise-coding-evaluations/) motivates direct inspection and negative testing of tasks, expected answers, test logic, and scorers.
- [OpenAI's internal coding-agent monitoring report](https://openai.com/index/how-we-monitor-internal-coding-agents-misalignment/) motivates keeping easy-control success separate from open-ended false-negative claims and treating monitoring as one defense-in-depth layer.

None of those publications evaluates this repository or transfers its results to this system.

## Nonclaims

Phase 2.5 agreement does not establish source authenticity or truth, evidence completeness, outcome correctness, policy fitness, model efficacy or calibration, operational utility, privacy or processing authority, historical or live performance, external custody, organizational independence, OS isolation, network nonuse, target-side outcomes, exhaustive coverage, a statistical failure bound, production readiness, or safe autonomous action. It is not an alignment, misalignment, scheming, sandbagging, sabotage-robustness, or monitor-efficacy evaluation. Live actions remain structurally disabled, and no live execution mode exists.
