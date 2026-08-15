# Phase 2.4 Typed Feature and Reference-Projection Assurance

## Objective

Phase 2.4 strengthens the boundary between replay evidence and modeled signals. It addresses a concrete defect in the Phase 2.3 baseline: event `attributes` were structurally bounded but not typed or authorized by source, while feature extraction used generic `bool()` and `float()` coercion. As a result, schema-valid values such as `credential_dumping: "false"`, `failed_logins: "nan"`, or a modeled endpoint signal asserted by an unrelated source could become positive model features.

The Phase 2.4 objective is narrower than model validation:

> A modeled feature may be produced only from a code-owned, correctly typed signal asserted by an authorized source, and a separately implemented projector must reproduce the feature values and event trace recorded in each read-only decision.

This increment remains synthetic, offline, and read-only. It does not introduce a generative agent, network connector, action credential, authorization token, broker, target, or live execution mode.

## Current status

The typed/source-authorized production contract, exact four-field inventory binding, separately implemented in-process reference projector, closed metadata-only assurance schema, harness integration, metrics/manifest bindings, and negative tests are implemented in the recorded Phase 2.4 release. That release's 147-test count remains version-bound. Separately, the predecessor Phase 2.5 design-freeze implementation passed 193/193 tests in a review-local run, and CI succeeded for exact Commit `08ce203c` on 2026-08-15. This package candidate's Phase 2.5 technical suite passed 222/222; the separate public-site module passed 9/9, yielding a 231/231 repository aggregate, but is outside the feature-assurance evidence claim. Exact-package GitHub CI remains a post-publication gate. These are narrow CE-1 implementation-conformance observations within their stated boundaries—not a tagged alpha.6 release, release/evidence package, or `P2-CE-005` evidence.

Phase 2.5 adds a separate source-to-decision path after this feature check. See [`SOURCE_TO_DECISION_ASSURANCE.md`](SOURCE_TO_DECISION_ASSURANCE.md). It does not retroactively broaden `P2-CE-004` or make the Phase 2.4 projector independent.

Separately, [`P2-CE-004`](../../contracts/v0.2.0/examples/phase2-feature-assurance-ce2-evidence-record.json) is CE-2 controlled-behavior evidence for the fixed campaign against corrected implementation Commit [`53e409d6`](https://github.com/redxking/ai-decision-firewall/commit/53e409d6ffa4af98ea892bc1a81302bf30870693). Two complete deterministic same-process repetitions produced 32/32 matches to commit-frozen, project-controlled expectations: 16 clean matches, eight qualification quarantines, and eight reference-projector blocks, with zero retries, exclusions, failures, or deviations and byte-identical ledgers. Review is `SELF`, automated, project-controlled, and self-custodied.

An earlier unpublished package against Commit `1945ff283794c42f8eb649e320ba6adf91a6b982` was withheld after review found that its frozen validator accepted non-finite JSON. It is invalidated, excluded from every claim denominator, and is not evidence. The current package is one new execution against the corrected A2 freeze, not a retry within its 32-attempt denominator.

## Threat and failure model

The boundary must fail closed against:

- truthy strings, numeric strings, non-finite numbers, Boolean-as-number values, negative counts, and out-of-range counts;
- a source asserting a modeled signal outside its permitted evidence role;
- canonical case context that disagrees with the asset-inventory assertion it is traced to;
- an extractor silently coercing or clamping a value that the contract did not authorize;
- a self-consistent decision and audit trace whose recorded feature values or feature-to-event trace do not match the normalized input;
- a validator that merely calls the production extractor and therefore shares the same orchestration defect;
- a test suite that rejects malformed cases but also rejects legitimate opaque context, or fails to notice when that context changes the 20-feature projection.

The reference projector is deliberately separate from the production extractor. It uses only the Python standard library and does not import the production feature extractor, feature-contract implementation, engine, model, policy, verifier, replay harness, or replay metrics. It still executes in the same Python process and project and therefore is not organizationally or externally independent.

## Modeled-signal authority matrix

Unrecognized attributes remain bounded opaque context. They may be retained for traceability but cannot become model inputs. A key that is modeled is no longer opaque and is subject to this matrix. Separately governed non-feature evidence inputs are not opaque merely because they are outside the 20-feature vector.

| Source type | Authorized modeled attributes | Required type or range |
|---|---|---|
| `identity` | `failed_logins`, `new_device`, `impossible_travel`, `mfa_fatigue`, `token_reuse`, `after_hours`, `strong_mfa`, `oauth_grant` | `failed_logins` is a finite, non-negative integral JSON number within the code-owned bound; all others are JSON Booleans |
| `endpoint` | `credential_dumping`, `unusual_admin_action`, `edr_malware`, `device_noncompliant` | JSON Boolean |
| `network` | `threat_ip`, `lateral_movement`, `known_vpn` | JSON Boolean |
| `threat_intel` | `threat_ip` | JSON Boolean |
| `user_context` | `approved_travel` | JSON Boolean |
| `change_management` | `maintenance_window`, `service_account_baseline` | JSON Boolean |
| `asset_inventory` | canonical `asset_id`, `asset_criticality`, `break_glass`, and `privilege_level` assertions | Must be present, correctly typed, and equal to the corresponding case-level context |
| any other source | none | Modeled keys are prohibited; bounded non-modeled attributes remain opaque |

Presence of a Boolean attribute is still traceable even when its value is `false`; presence alone must never turn it into a positive feature. A legitimate opaque attribute must not change the 20-feature values or traces.

`source_conflict` is a separate decision-driving evidence-quality input, not one of the 20 model features and not opaque. Phase 2.4 requires it to be an exact JSON Boolean asserted only by `network`. Under `QUARANTINE_RECORD`, the code-owned taxonomy is `SEMANTICS / UNAUTHORIZED_DECISION_SIGNAL` for a wrong-source assertion and `SEMANTICS / INVALID_BOOLEAN` for a non-Boolean network assertion. The reference feature projector does not recompute this evidence-quality path, so its agreement cannot establish that conflict handling, evidence grading, or the resulting disposition is correct.

## Dual implementation boundary

### Production path

The canonical replay validator and feature extractor enforce the same public contract:

1. validate modeled-key type, numeric finiteness/range, and source authority;
2. reject any non-finite JSON number anywhere in the accepted case before engine invocation, including within otherwise opaque attributes;
3. validate the network-only Boolean `source_conflict` evidence input and canonical inventory context before either can affect a decision;
4. reject invalid modeled attributes without applying Python truthiness, string-to-number conversion, or silent numeric clamping;
5. extract only the code-owned feature set and retain the contributing event identifiers.

For `FAIL_DATASET`, any violation aborts the dataset. For `QUARANTINE_RECORD`, reviewed record-local type, range, source-authority, and canonical-context defects may be quarantined only under a stable code-owned taxonomy; integrity, leakage, duplicate-identifier, and classifier-completeness failures remain fatal.

### Reference path

The reference projector receives the normalized case records and serialized decisions, not evaluator labels. It separately reconstructs the 20 feature values and their event traces from the normalized input. For each case it emits a closed metadata-only record containing:

- schema version and case identifier;
- normalized-case SHA-256;
- expected and observed feature-projection SHA-256 values;
- a Boolean exact-match result.

The normalized-case digest is SHA-256 over the UTF-8 bytes of `json.dumps(normalized_case, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False)` with no trailing newline. Accepted cases have already passed the all-number finiteness gate.

Raw feature values, raw attributes, free-form validator errors, and source paths are excluded from this artifact. Persisted JSONL is read back with duplicate-member rejection. The check executes only after read-only decision validation, deterministic decision serialization, and complete eight-stage audit validation. On a mismatch, no `reference_feature_assurance.jsonl`, qualification/rejection publication, adjudication comparison, metrics, or completed run manifest is emitted. Raw/normalized/deterministic decisions and audit artifacts may already exist and must be treated as incomplete evidence. On success, metrics record checked/matched/mismatched/completeness counts and the run manifest hash/count-binds the assurance artifact and checked/matched counts.

This is a separate in-process orchestration check, not an independently developed model, organizationally independent evaluation, or external ground-truth oracle. Common project assumptions, shared input bytes, and common Python runtime behavior remain possible correlated failure modes.

## Metamorphic and adversarial test design

The frozen `P2-CE-004` plan contains eight clean/mutant pairs per repetition. Each 16-attempt repetition predeclares eight clean projection matches, four qualification quarantines (`INVALID_BOOLEAN`, `INVALID_TYPE`, and two `UNAUTHORIZED_MODELED_SIGNAL` cases), and four `REFERENCE_FEATURE_PROJECTION_MISMATCH` blocks covering a feature-value rehash, feature-trace rehash, input-event-order rehash, and cross-case named-feature-value rehash. The two completed deterministic same-process repetitions produced all 32 expected observations with zero retries or exclusions. The failure policy was `ABORT_WITHOUT_EVIDENCE_NO_RETRY`; the repetitions are not independent or fresh statistical trials.

The fixed controls cover:

1. JSON Boolean `false` remains feature value `0.0` and Boolean `true` becomes `1.0` only for an authorized source.
2. String `"false"`, string `"true"`, numeric strings, `"nan"`, non-finite values, Boolean counts, negative counts, fractional counts, and values above the reviewed count bound fail closed.
3. Each modeled key is rejected when moved to or duplicated under an unauthorized source.
4. Required inventory context is rejected when missing or inconsistent with the case-level value.
5. Adding, removing, or reordering bounded opaque attributes does not change the 20-feature values or traces; separately governed evidence inputs such as `source_conflict` are tested under their own type/source contract.
6. Permuting event input order produces the same normalized feature values and disposition while retaining the canonical trace order.
7. A decision whose feature values are changed and whose decision hash and eight-stage audit chain are coherently recomputed is rejected by the reference projector.
8. The same coherent forgery is rejected when only the feature trace, source-event binding, or traceability copy is changed.
9. Clean regenerated decisions with different allowed volatile identifiers, timestamps, latency, and chain hashes are accepted when semantic content is unchanged.
10. Every rejected input or forged output is counted; no scenario may be silently removed from the denominator.

The campaign plan, corpus, oracle, expected outcomes, seed, budget, runtime fingerprint, and result schema must be frozen before the reported evidence run. A second execution must reproduce the deterministic result ledger. Any retry or post-freeze change requires a new implementation freeze or an explicit deviation record.

## Implementation and campaign gates

The implementation gates are satisfied locally when all of the following are true:

- every committed replay fixture and baseline case satisfies both schema and runtime feature contracts;
- schema/runtime differential tests cover every modeled key, source role, type, and numeric boundary;
- production extraction contains no generic coercion for modeled inputs;
- the separately implemented projector imports none of the prohibited production calculation modules;
- every accepted case has exactly one matching reference-projection record;
- any mismatch prevents metrics and run-manifest completion;
- the reference artifact is hash/count-bound in the run manifest and revalidated before finalization;
- coherent downstream rehashing and audit rechaining cannot hide a feature-value or trace mutation;
- existing Phase 1 and Phase 2 tests remain green.

The following campaign evidence gates were satisfied by the bound `P2-CE-004` package and remain separate from the implementation tests:

- the plan, implementation, harness, corpus/generator, runtime fingerprint, seed, budget, and expected outcomes are bound to corrected Commit A2 `53e409d6ffa4af98ea892bc1a81302bf30870693`;
- both complete 16-attempt repetitions executed with no retry, exclusion, failure, deviation, or post-freeze change;
- both raw 16-row ledgers, the summary, receipts, and byte-identical repeatability evidence are preserved;
- the `P2-CE-004` claim-evidence record validates with `SELF` review, environment limits, finite expiry, and every prohibited inference; and
- the release CI is configured to validate the exact committed record and perform fresh frozen-evaluator re-execution.

Public-branch, final-manifest, and CI status are release-state observations and must be verified separately rather than inferred from this document.

## Evidence and claim boundary

Implementation existence is CE-1. The exact fixed, commit-bound `P2-CE-004` campaign supplies CE-2 controlled-behavior evidence for this wording:

> Across two complete executions of P2-CE-004's fixed 16-attempt synthetic campaign and exact bound source/configuration, all 32 attempt observations matched the 16 commit-frozen, project-controlled expected outcomes (16/16 per run): each run produced eight clean qualification and reference-projection matches, four typed or source-unauthorized modeled signals quarantined before production projection, and four locally rehashed projection mutations blocked by the separately implemented in-process reference projector. The two sanitized result ledgers were byte-identical. Within the scoped campaign calls, no model, policy, verifier, decision-engine, authorization, broker, target-effect, or operational-effect boundary was reached; this is project-controlled SELF-reviewed synthetic CE-2 evidence only.

The result must not be described as:

- historical or live identity-detection performance;
- feature correctness for unobserved source systems or vendor mappings;
- proof that source assertions are truthful, authentic, or complete;
- model calibration, disposition correctness, abstention quality, or operational efficacy;
- correctness of `source_conflict`, evidence-quality grading, or any other decision input outside the 20-feature projection;
- complete protection from evaluator, monitor, code, or data sabotage;
- an independent replication, external audit, or externally preregistered study;
- independent, fresh, or statistically representative trials from the two same-process repetitions;
- OS-level process isolation, non-egress, tamper resistance, or independent custody;
- alignment, misalignment, scheming, sandbagging, or hidden-objective evidence;
- a bounded failure probability, zero risk, production readiness, or authorization for historical/live processing.

## Research basis

The design applies four transferable lessons while preserving their limits:

- [Anthropic Agentic Misalignment](https://www.anthropic.com/research/agentic-misalignment) supports deliberate stress testing, matched controls, repeated trials, and explicit separation of controlled simulation from real-world prevalence.
- [Anthropic Sabotage Evaluations](https://www.anthropic.com/research/sabotage-evaluations) motivates testing the actor and oversight path together, including coherent code or evaluation manipulation rather than only malformed inputs.
- [OpenAI Separating Signal from Noise in Coding Evaluations](https://openai.com/index/separating-signal-from-noise-coding-evaluations/) motivates auditing the task, answer key, scorer, and negative controls so a green result reflects the intended property rather than an underspecified or low-coverage test.
- [OpenAI Internal Coding-Agent Misalignment Monitoring](https://openai.com/index/how-we-monitor-internal-coding-agents-misalignment/) explicitly treats monitor matches as insufficient to quantify open-ended false negatives without dedicated control evaluations and red teaming; this increment therefore makes no general monitor-effectiveness claim.

These publications do not validate this implementation. They inform the evaluation design and the prohibited inferences. See [`RESEARCH_INFORMED_VALIDATION.md`](RESEARCH_INFORMED_VALIDATION.md) for the dated source-fact and project-recommendation mapping.
