# Phase 2.4 and Phase 2.5 Research-Informed Validation Notes

## Purpose and evidence boundary

This note records how selected Anthropic and OpenAI primary research informed the Phase 2.4 feature-assurance and Phase 2.5 source-to-decision-assurance designs. It separates source facts from project recommendations so that a research citation is never mistaken for evidence about this repository.

None of the cited publications validates the AI Decision Firewall, either reference path, the observed `P2-CE-004` result, or the planned `P2-CE-005` campaign. The current system is a deterministic, offline Python POC with no autonomous generative agent. Research on alignment, sabotage, monitoring, and agent evaluation supplied transferable evaluation methods and cautions; it does not support an alignment, misalignment, sabotage-robustness, monitor-effectiveness, operational-safety, or production-readiness claim here.

The source set below reflects a targeted Phase 2.5 review performed on 2026-08-15. It does not represent a complete rescreen of the dynamic research indices. The broader documented screen remains current through 2026-08-14, and a full Phase 2.5 claim-class refresh is pending under [`RESEARCH_COVERAGE_REGISTER.md`](RESEARCH_COVERAGE_REGISTER.md).

## Primary-source facts and author-stated limits

### Anthropic

| Publication | Source facts used | Author-stated or study-design limitations carried forward |
|---|---|---|
| [Agentic Misalignment](https://www.anthropic.com/research/agentic-misalignment), 2025-06-20 | Anthropic used deliberately constructed, fictional corporate scenarios, varied goal conflict and threats such as replacement, included control conditions, and repeated trials to test whether harmful behavior could be elicited. | The scenarios are controlled simulations rather than evidence of real-deployment prevalence. Artificial binary choices, scenario realism, and incomplete coverage limit generalization. |
| [Sabotage Evaluations for Frontier Models](https://www.anthropic.com/research/sabotage-evaluations), 2024-10-18 | The work separates sabotage pathways such as manipulating human decisions, code, sandbagging, and undermining oversight, and evaluates the actor together with monitoring or control mechanisms. | Preparatory evaluation tasks do not establish that a safeguard defeats future systems or that failure to observe sabotage proves the capability absent. More realistic environments and mitigation evaluation remain necessary. |
| [Alignment Faking](https://www.anthropic.com/research/alignment-faking), 2024-12-18 | The study compares behavior under conditions represented as monitored/training-visible versus unmonitored and examines available scratchpad reasoning for condition-dependent behavior. | The experiment uses a constructed setup. It does not establish that all models have persistent malicious goals or that alignment faking necessarily emerges in ordinary deployments. |
| [Auditing Language Models for Hidden Objectives](https://www.anthropic.com/research/auditing-hidden-objectives), 2025-03-13 | Anthropic evaluated audit methods against a deliberately seeded, known objective using separated red/blue roles, differentiated access, held-out behavior, and known-truth grading. | A known seeded objective makes validation possible but does not establish universal audit effectiveness. The reported exercise was bounded to one experimental setup and a small number of teams. |
| [SHADE-Arena](https://www.anthropic.com/research/shade-arena-sabotage-monitoring), 2025-06-16 | The benchmark combines benign main tasks with hidden side tasks over longer tool trajectories and reports main-task success, sabotage success, evasion/detection, and false-positive costs separately. | Assigned side tasks test capability under a constructed objective, not spontaneous propensity or real-world prevalence. A finite task set does not establish broad monitor generalization. |

### OpenAI

| Publication | Source facts used | Author-stated or study-design limitations carried forward |
|---|---|---|
| [A Shared Playbook for Trustworthy Third-Party Evaluations](https://openai.com/index/trustworthy-third-party-evaluations-foundations/), 2026-05-29 | The playbook distinguishes capability, safeguard-performance, and comparison claims and calls for recording the exact system, harness, tools, budget, elicitation, scoring, raw evidence, and validity hazards such as reward hacking, refusals, contamination, broken tasks, sandbagging, and evaluation awareness. | A headline score without the surrounding harness, validity checks, and review cannot support a broader conclusion. Project-controlled execution is not automatically independent evaluation. |
| [Separating Signal from Noise in Coding Evaluations](https://openai.com/index/separating-signal-from-noise-coding-evaluations/), 2026-07-08 | The analysis emphasizes inspection of prompts, reference answers, tests, task validity, and scorers; it identifies underspecification, misleading instructions, overly strict tests, and inadequate coverage as causes of misleading results. | A green test or benchmark result does not establish the intended capability when the task or grading logic is defective. Reviewer agreement and known-truth checks remain separate evidence obligations. |
| [How OpenAI monitors internal coding agents for misalignment](https://openai.com/index/how-we-monitor-internal-coding-agents-misalignment/), 2026-03-19 | OpenAI describes monitoring as one defense-in-depth layer and distinguishes known easy controls from open-ended, tool-rich trajectories. | Perfect performance on an easy control does not bound the false-negative rate in open-ended use, and monitoring alone is not a safety case. |

## Project recommendations derived from the sources

The following are project design choices, not claims made by the cited organizations:

1. **Freeze the test before reporting the result.** Bind the implementation, plan, source generator, schema, harness, runtime fingerprint, seed, budget, attempt order, and expected outcomes before a `P2-CE-004` evidence run. Corrected Commit A2 provided a public project-controlled freeze, not external preregistration.
2. **Use matched clean and defect controls.** Pair each intended defect with a clean control so the harness demonstrates both rejection and retained normal behavior. Keep malformed-input rejection separate from coherent downstream forgery detection.
3. **Test the calculation and the checker together.** Use a separately implemented projector that does not call the production feature path. Mutate serialized feature values, traces, source-event context, and decision/audit hashes coherently so legacy self-consistency checks cannot supply the answer. Keep the claim scoped to the 20-feature projection: the projector does not recompute `source_conflict` or the broader evidence-quality path.
4. **Preserve the complete denominator.** The frozen plan specifies 16 attempts per repetition and two deterministic same-process repetitions, with zero retries and exclusions. Its failure policy aborts without an evidence package on any final mismatch. The observed package reports all 32 attempts, zero failures, zero deviations, and zero exclusions; the two repetitions are not independent or fresh trials.
5. **Keep the artifact closed and metadata-only.** Successful assurance rows contain digests and a match flag, not raw case values, features, traces, paths, or free-form errors. This reduces disclosure but does not provide anonymization or independent custody.
6. **Separate implementation evidence from behavioral evidence.** The version-bound alpha.5 suite supports its recorded CE-1 implementation statement. Published Phase 2.5 Commit `854b15c56397a81de6326b719d3d7d1dc847608f` passed the 222/222 technical suite and exact-commit CI/Dependency Graph; the separate public-site module passed 9/9, producing the then-current 231/231 aggregate without extending the research-informed or Phase 2.5 evidence claim. This is not a tagged release, evidence package, or `P2-CE-005` behavior evidence. The separate `P2-CE-004` artifacts, denominator, repeatability result, and claim record support only their exact CE-2 wording. A `P2-CE-005` plan, published implementation, or green suite does not create CE-2 behavior evidence.
7. **Retain explicit nonclaims.** The two deterministic repetitions are not independent or statistically representative trials. The fully matching campaign does not establish exhaustive coverage, a bounded failure rate, historical/live performance, efficacy, source truth, OS-level isolation/non-egress, external custody, target-side outcomes, production readiness, alignment/misalignment, or sabotage robustness.

## Bounded Phase 2.4 mapping

| Research-derived evaluation lesson | Phase 2.4 implementation or campaign | Current evidence state |
|---|---|---|
| Matched controls and controlled stress conditions | Eight clean/mutant pairs per fixed 16-attempt repetition | CE-2 SELF observation: 32/32 expected-outcome matches across two repetitions |
| Independent outcome checking should not reuse the actor's calculation | Separately implemented in-process projection of 20 feature values and traces, with prohibited production imports | CE-1 implementation conformance in the recorded alpha.5 suite; not external independence |
| Coherent sabotage-like mutations can evade shallow consistency checks | Tests rehash decision records and rechain the eight-stage audit after changing feature values, traces, or source context | CE-1 tested mutation coverage only; no sabotage-capability or robustness claim |
| Broken-task and scorer risk must be explicit | Closed plan/schema, exact enumerated outcomes, positive controls, corrected finite-number validation, and code-owned error taxonomy | Project-controlled validator and negative controls passed; no independent reviewer |
| Report actor/control outcomes and false-positive costs separately | Outcome classes distinguish clean matches, qualification quarantines, and reference-projection blocks | Observed 16 clean, 8 quarantine, and 8 reference-block outcomes |
| Repetition is useful but does not create statistical independence | Two deterministic repetitions with zero retries/exclusions | Executed; byte-identical ledgers, but no statistical independence |

## Bounded Phase 2.5 mapping

| Research-derived evaluation lesson | Phase 2.5 implementation or planned campaign | Current evidence state |
|---|---|---|
| Controlled simulations need matched controls and explicit deployment limits | Ten planned clean/mutant pairs per run, repeated twice, with adjacent historical/live nonclaims | CE-0 plan only; no observations |
| Coherent sabotage-like defects can survive shallow self-consistency checks | Each planned mutant must pass read-only decision validation, the exact eight-stage audit, and Phase 2.4 feature assurance before the five-stage reference path evaluates it | CE-1 test design; not sabotage-robustness evidence |
| The actor, task, expected result, and scorer all require validation | Stage-specific clean controls, strict plan/schema checks, negative validator tests, and package invalidation on any frozen-evaluator defect | Implementation work; no independent reviewer or CE-2 result |
| Claim evidence must bind exact system, harness, budget, raw denominator, exclusions, and review | Two-commit protocol: Commit A freezes implementation/plan/validator; Commit B may contain evidence only after exact-commit execution | Protocol documented; not yet executed |
| An easy control does not bound open-ended failure | `P2-CE-005` is limited to 40 planned deterministic observations and prohibits statistical, historical, live, alignment, or monitor-efficacy inference | CE-0; no rate claim permitted |
| Separate calculation logic is not automatically independent evaluation | Standard-library reference implementation avoids production calculation imports but shares process, project, specification, governance, and custody | CE-1 same-process/project assurance only |

## `P2-CE-005` status

`P2-CE-005-SOURCE-TO-DECISION-SYNTHETIC` is CE-0 `NOT_EVALUATED`. Its fixed plan specifies ten clean/mutant pairs per run and two deterministic same-process runs: 40 planned attempt observations, zero retries/exclusions, and two expected blocks at each of `EVIDENCE`, `MODEL`, `POLICY`, `VERIFIER`, and `FINAL_SURFACE` per run. Each run shares ten directly instrumented production baselines across its clean/mutant twins and calls the reference path 20 times, producing campaign budgets of 20 baseline executions, 20 calls to each production component, and 40 reference calls. Direct authorization-gate/broker/target-effect/scoped-write counters remain distinct from decision-derived token/result/effect fields. Those values are expected design constants, not observed results.

The campaign cannot support CE-2 language until a clean Commit A freezes the implementation, plan, schemas, generator, and validator; an exact detached checkout is executed with no retries; and a separate evidence-only Commit B is published and passes fresh frozen-evaluator validation. Any defect in the actor, task, expected outcomes, generator, or scorer invalidates the package. The public freeze is project-controlled and is not external preregistration.

Even if every planned observation later matches, the result would remain a SELF automated project-controlled synthetic check. It would not establish source truth, outcome correctness, policy fitness, historical/live performance, operational calibration or readiness, privacy/authorization, OS isolation or network nonuse, organizational independence, a statistical failure bound, efficacy, alignment/misalignment, scheming, sandbagging, or sabotage robustness.

## `P2-CE-004` status

`P2-CE-004` is an observed CE-2 `CONTROLLED_BEHAVIOR` result under `SELF` automated project-controlled review. Against corrected Commit `53e409d6ffa4af98ea892bc1a81302bf30870693`, two complete repetitions of 16 synthetic attempts produced:

- eight clean projection matches per repetition;
- four qualification quarantines per repetition: one `INVALID_BOOLEAN`, one `INVALID_TYPE`, and two `UNAUTHORIZED_MODELED_SIGNAL` outcomes; and
- four `REFERENCE_FEATURE_PROJECTION_MISMATCH` blocks per repetition.

All 32 observations matched the commit-frozen, project-controlled expectations with zero retries, exclusions, failures, or deviations, and the two ledgers were byte-identical. The exact [`evidence record`](../../contracts/v0.2.0/examples/phase2-feature-assurance-ce2-evidence-record.json) and [`bundle`](../../evidence/phase2_feature_assurance_ce2/README.md) preserve the result and limitations.

An earlier unpublished package against Commit `1945ff283794c42f8eb649e320ba6adf91a6b982` was withheld after its frozen validator accepted non-finite JSON. It is invalidated, excluded from every denominator, and is not evidence. The current package is a new execution against the corrected freeze, not a retry within the current denominator. Research-informed design, SELF validation, and a matching synthetic campaign do not create independent assurance or support any broader inference listed above.
