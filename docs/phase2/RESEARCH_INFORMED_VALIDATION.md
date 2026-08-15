# Phase 2.4 Research-Informed Validation Notes

## Purpose and evidence boundary

This note records how selected Anthropic and OpenAI primary research informed the Phase 2.4 feature-assurance design. It separates source facts from project recommendations so that a research citation is never mistaken for evidence about this repository.

None of the cited publications validates the AI Decision Firewall, its feature contract, its reference projector, or the planned `P2-CE-004` campaign. The current system is a deterministic, offline Python POC with no autonomous generative agent. Research on alignment, sabotage, monitoring, and agent evaluation supplies transferable evaluation methods and cautions; it does not support an alignment, misalignment, sabotage-robustness, monitor-effectiveness, operational-safety, or production-readiness claim here.

The source screen below reflects the pages available through 2026-08-15. The broader dynamic research screen and refresh triggers remain in [`RESEARCH_COVERAGE_REGISTER.md`](RESEARCH_COVERAGE_REGISTER.md).

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

## Project recommendations derived from the sources

The following are project design choices, not claims made by the cited organizations:

1. **Freeze the test before reporting the result.** Bind the implementation, plan, source generator, schema, harness, runtime fingerprint, seed, budget, attempt order, and expected outcomes before a `P2-CE-004` evidence run. The current plan/scaffold is not external preregistration.
2. **Use matched clean and defect controls.** Pair each intended defect with a clean control so the harness demonstrates both rejection and retained normal behavior. Keep malformed-input rejection separate from coherent downstream forgery detection.
3. **Test the calculation and the checker together.** Use a separately implemented projector that does not call the production feature path. Mutate serialized feature values, traces, source-event context, and decision/audit hashes coherently so legacy self-consistency checks cannot supply the answer. Keep the claim scoped to the 20-feature projection: the projector does not recompute `source_conflict` or the broader evidence-quality path.
4. **Preserve the complete denominator.** The frozen plan specifies 16 attempts per repetition and two deterministic same-process repetitions, with zero retries and exclusions. Its failure policy aborts without an evidence package on any final mismatch. Report every attempt, failure, and deviation before any rate; the two repetitions are not independent or fresh trials.
5. **Keep the artifact closed and metadata-only.** Successful assurance rows contain digests and a match flag, not raw case values, features, traces, paths, or free-form errors. This reduces disclosure but does not provide anonymization or independent custody.
6. **Separate implementation evidence from behavioral evidence.** The 147-test suite can support CE-1 implementation conformance for the identified checkout. It is not an observed `P2-CE-004` denominator, repeatability result, or CE-2 claim.
7. **Retain explicit nonclaims.** Two deterministic repetitions would not be independent or statistically representative trials. Even a fully matching campaign would not establish exhaustive coverage, a bounded failure rate, historical/live performance, efficacy, source truth, OS-level isolation/non-egress, external custody, target-side outcomes, production readiness, alignment/misalignment, or sabotage robustness.

## Bounded Phase 2.4 mapping

| Research-derived evaluation lesson | Phase 2.4 implementation or plan | Current evidence state |
|---|---|---|
| Matched controls and controlled stress conditions | Eight clean/mutant pairs per planned 16-attempt repetition | Plan/scaffold only; not evaluated |
| Independent outcome checking should not reuse the actor's calculation | Separately implemented in-process projection of 20 feature values and traces, with prohibited production imports | CE-1 implementation conformance in the 147-test local suite; not external independence |
| Coherent sabotage-like mutations can evade shallow consistency checks | Tests rehash decision records and rechain the eight-stage audit after changing feature values, traces, or source context | CE-1 tested mutation coverage only; no sabotage-capability or robustness claim |
| Broken-task and scorer risk must be explicit | Closed plan/schema, exact enumerated outcomes, positive controls, and code-owned error taxonomy | Plan and test scaffolding exist; no campaign result or independent reviewer |
| Report actor/control outcomes and false-positive costs separately | Planned outcome classes distinguish clean matches, qualification quarantines, and reference-projection blocks | Planned denominator only; no observed counts |
| Repetition is useful but does not create statistical independence | Two planned deterministic repetitions with zero retries/exclusions | Not executed; no repeatability evidence |

## `P2-CE-004` status

`P2-CE-004` is `NOT_EVALUATED`. Its fixed plan calls for two repetitions of 16 synthetic attempts each:

- eight clean projection matches per repetition;
- four qualification quarantines per repetition: one `INVALID_BOOLEAN`, one `INVALID_TYPE`, and two `UNAUTHORIZED_MODELED_SIGNAL` outcomes; and
- four `REFERENCE_FEATURE_PROJECTION_MISMATCH` blocks per repetition.

No run ledger, summary, evidence record, observed 32-attempt denominator, repeatability result, Commit-B evidence binding, or GitHub CI conclusion exists. Any later evidence record must bind the exact evaluated commit and artifacts and must preserve every limitation above.
