# AI Decision Firewall

- **Published Phase 2.5 baseline:** exact Commit [`854b15c56397a81de6326b719d3d7d1dc847608f`](https://github.com/redxking/ai-decision-firewall/commit/854b15c56397a81de6326b719d3d7d1dc847608f) is on `main`; exact-commit CI and Dependency Graph checks passed. The package preserves the 222/222 Phase 2.5 technical result, separate 9/9 public-site result, and 231/231 then-current repository aggregate at that boundary.
- **Phase 2 evidence boundary:** published `P2-CE-001` through `P2-CE-004` retain their version-bound claims. `P2-CE-005` was not executed or published and remains CE-0 `NOT_EVALUATED`; the Phase 2.5 commit and green CI do not create that campaign result.
- **Published Phase 3 baseline:** exact Commit [`423685d105be813056617db738297eba83d3d9d0`](https://github.com/redxking/ai-decision-firewall/commit/423685d105be813056617db738297eba83d3d9d0) is on `main`; exact-commit [CI](https://github.com/redxking/ai-decision-firewall/actions/runs/31908090324) and [Dependency Graph](https://github.com/redxking/ai-decision-firewall/actions/runs/31908091856) checks passed. Its simulation-only boundary includes 57/57 focused Phase 3 tests, both demonstration checks PASS, a 46/46 deterministic corpus, and the then-current 288/288 repository aggregate. These are CE-1 implementation-conformance observations, not operational validation.
- **Published Phase 3.1 baseline:** exact Commit [`bb6b8f28afba0961bb97b24e6050fccaa94d5702`](https://github.com/redxking/ai-decision-firewall/commit/bb6b8f28afba0961bb97b24e6050fccaa94d5702) is on `main`; exact-commit [CI](https://github.com/redxking/ai-decision-firewall/actions/runs/31911161052) passed on Python 3.11 and 3.12 and the [Dependency Graph](https://github.com/redxking/ai-decision-firewall/actions/runs/31911162048) check passed. Its `0.3.1-alpha.1` synthetic-only evaluation mechanism passed 11/11 focused and 299/299 then-current repository tests. Model promotion remains unconditionally `NOT_AUTHORIZED`. No Phase 3.1 tag or GitHub Release exists.
- **Published Stage A implementation boundary:** the unreleased `0.4.0-alpha.2` implementation is on `main` at exact Commit [`8818d5d2d40faebced66a254d58b1f0d04c9f8b4`](https://github.com/redxking/ai-decision-firewall/commit/8818d5d2d40faebced66a254d58b1f0d04c9f8b4). It corrects a verified cross-restart request replay and implements the ADR-015 two-database offline design: an opt-in single-host control ledger, a separate durable synthetic-adapter state/receipt store, the existing JSONL lifecycle audit, and a sanitized authenticated terminal-result lookup. The two databases and audit are three distinct authoritative artifacts; T1 reservation, T2 adapter commit, normal or recovery audit closure, and T3 terminal commit are not one cross-store transaction. Startup and durable operations use bounded cooperative same-host fencing and strict store/correlation checks, but this is not a distributed lease, epoch, consensus, or cross-store atomicity guarantee. The enforceable 18-domain production gate remains `BLOCKED`. This increment adds no historical/live data, connector, operational credential, live target, process isolation, independently custodied target verification, HA, deployment, or operational authority.
- **Stage A exact-commit verification boundary:** against exact Commit `8818d5d2`, local verification passed 43/43 focused Stage A tests in 8.248 seconds, 18/18 production-readiness-gate tests, the complete warning-fatal 360/360 repository suite in 48.995 seconds, 57/57 focused Phase 3 tests, and the deterministic 46/46 corpus with `live_actions_possible=false`; the 307-entry implementation manifest verified 307/307. Exact-SHA [CI run 31953570779](https://github.com/redxking/ai-decision-firewall/actions/runs/31953570779) succeeded on Python 3.11 and 3.12, and [Dependency Graph run 31953572482](https://github.com/redxking/ai-decision-firewall/actions/runs/31953572482) succeeded. These are project-controlled mechanism observations, not historical/live evaluation, independent verification, operational effectiveness, owner acceptance, or production authorization. No tag or GitHub Release was created, no deployment occurred, and no exact-SHA Pages run was observed. See [`ADF-STAGE-A-ER-002`](docs/production/STAGE_A_RECEIPT_RESULT_EVIDENCE_RECORD.md).
- **Validated baseline:** v0.1.0 synthetic proof of concept
- **Decision domain:** privileged-identity containment
- **Operational status:** synthetic only. Phase 2 remains read-only; the published Phase 3 path can change only in-memory synthetic target state. The opt-in Stage A candidate can change only its separate local durable synthetic-adapter database and return authority-free lookup results. No organizational historical data, approved Gate B package, live feed, production/test-tenant connector, or operational credential is included.
- **Safety boundary:** not approved for production integration, operational decision-making, or live containment

AI systems can rank alerts and recommend actions, but consequential operations require a stronger control boundary: the system must determine whether the available evidence is trustworthy and sufficient, whether an action is within delegated authority, and whether the intended effect actually occurred.

This repository implements an **AI Decision Firewall**—a model-separated control-plane POC between AI-assisted analysis and operational execution. The present implementation uses one deterministic logistic-risk model and one canonical adapter; model portability is an architectural objective, not a validated capability. The first bounded decision is:

> Based on the available evidence, should suspicious privileged-identity activity result in no action, further investigation, reversible low-impact containment, or escalation to a human authority?

The model is advisory. Deterministic policy, a functionally separate deterministic non-model verifier, scoped authorization, and post-action verification control the action boundary. The verifier is not organizationally independent.

## Why this problem matters

An alert score or model confidence is not action authority. Real telemetry can be stale, incomplete, contradictory, duplicated, or adversarially manipulated. The operational cost of a false containment can also differ radically by identity, asset, mission, and timing.

The POC therefore treats the decision as an evidence-and-authority problem, not merely a classification problem. It is designed to make five questions explicit and testable:

1. What evidence supports the decision, and where did it come from?
2. Is that evidence fresh, intact, corroborated, and sufficient for the proposed consequence?
3. Is the proposed action permitted for this case, identity, asset, and risk level?
4. Did a functionally separate deterministic non-model control agree before authorization was issued?
5. Did the target reach the intended state, or did execution fail or remain uncertain?

## POC scope

Version 0.1 implements a complete synthetic decision transaction for privileged identities:

- deterministic generation of benign, malicious, ambiguous, degraded-telemetry, break-glass, sensor-conflict, and evidence-poisoning scenarios;
- separate runtime evidence and evaluator-only ground-truth files;
- structured evidence from simulated identity, endpoint, network, threat-intelligence, CMDB, change-management, workforce, travel, and ticketing sources;
- evidence-quality assessment for provenance, integrity, freshness, source diversity, corroboration, missing telemetry, conflicts, and adversarial instructions;
- an interpretable logistic risk model used only as an advisory component;
- deterministic selection of `NO_ACTION`, `INVESTIGATE`, `CONTAIN_REVERSIBLE`, or `ESCALATE_HUMAN`;
- functionally separate deterministic non-model verification of the decision and action boundary, not organizationally independent review;
- HMAC-SHA-256-signed, short-lived, case-bound, action-scoped authorization tokens;
- an in-memory identity-provider simulator for session revocation, step-up authentication, and increased monitoring;
- deliberate downstream failure injection and post-action state verification against the simulator result;
- a SHA-256 hash-chained audit log, evaluation reports, requirements traceability, and automated safety tests.

There are no production credentials, production connectors, or external action interfaces in this repository.

## Phase 2: replay boundary, qualification, and Gate B preflight

Phase 2 begins the transition from generator-consistent evidence to evidence-realism testing, without expanding action authority. The starter adds:

- a code-owned execution-mode boundary containing only `synthetic_simulation`, `historical_replay`, and `shadow_read_only`;
- structural suppression in both read-only modes: the authorization gate, action broker, and target are not constructed or called;
- counterfactual action capture for evaluation, with zero tokens, broker invocations, or operational effects;
- versioned replay-envelope and manifest contracts, adapter and normalizer boundaries, deterministic replay metrics, and a command-line harness;
- fail-closed validation for governance attestations, runtime-label separation, file digests and counts, path confinement, timestamps, identifiers, numeric ranges, and canonical-context consistency;
- a per-run input snapshot that binds the exact configuration, manifest, model, policy, cases, and adjudications used, with integrity checks before and after engine execution;
- pre-decision freezing of adjudication bytes inside the harness, with semantic decoding and loading deferred until the decision and audit close, so labels are neither placed beside nor passed to the decision runner;
- one-to-one suppression, authorization, and decision-finalization audit checks, including recomputation of each decision-record hash;
- a research-informed claim-evidence standard, machine-readable evidence schema, worked evidence record, and adversarial-evaluation backlog;
- a small, explicitly synthetic starter fixture and automated regression tests.

Phase 2.1 adds an explicit, cases-only qualification policy for offline historical-replay runs:

- `FAIL_DATASET` preserves the original whole-dataset behavior and remains the default;
- `QUARANTINE_RECORD` is permitted only with `HISTORICAL_REPLAY`, never `SHADOW_READ_ONLY`;
- code-owned fatal conditions abort the complete qualification call, while reviewed record-local defects produce sanitized `QUARANTINED` entries;
- a closed metadata-only ledger binds every nonblank source occurrence by source digest, physical line, nonblank ordinal, and raw-line digest without copying rejected payloads or exception text;
- the harness independently revalidates `input = accepted + quarantined`, requires the rejection artifact to equal the ordered quarantined projection, and requires one decision per accepted case before it finalizes evidence.

Phase 2.2 adds the machine-enforced Gate B preflight needed before any future historical pilot:

- a historical manifest cannot trigger an open, hash, count, decode, or parse of cases or adjudications until a separate Gate B package passes;
- the package must be current and `APPROVED`, include exactly five accountable approval roles plus an approved independent review, and bind the manifest, model, policy, contract, adapter, source mapping, adjudication protocol, and pilot protocol;
- the runtime requires offline `HISTORICAL_REPLAY`, `QUARANTINE_RECORD`, no live feed, no action credentials, no write-capable connector, disabled egress, label separation, complete-intake reporting, and frozen sampling and stop conditions;
- control bytes are frozen before payload processing and revalidated from owner-only, descriptor-bound run snapshots before and after engine execution; authorization validity is rechecked before payload access, before and after the runner, and before final evidence completion;
- governed JSON rejects duplicate object members, the audit boundary accepts only the exact code-owned record types, and the historical runner receives only in-memory accepted cases plus bound model and policy bytes, never output or evaluator-label paths; and
- the public example is deliberately `DRAFT` and non-authorizing. Machine conformance cannot establish approver authority, signature authenticity, effective de-identification, custody truth, or historical efficacy.

Phase 2.3 adds two deliberately separate assurance results:

- **CE-1 audit implementation conformance.** The replay harness now requires exactly one, correctly ordered eight-stage audit trace per accepted case: `CASE_RECEIVED`, `EVIDENCE_ASSESSED`, `MODEL_ASSESSED`, `POLICY_PROPOSED`, `INDEPENDENTLY_VERIFIED`, `EXECUTION_SUPPRESSED`, `AUTHORIZATION_EVALUATED`, and `DECISION_FINALIZED`. It rejects missing, duplicate, reordered, noncanonical, or decision/policy-inconsistent records. This establishes implementation conformance for the tested mutation set; it does not independently recompute source-to-decision correctness, establish trusted time or custody, or make the self-custodied hash chain resistant to wholesale replacement.
- **CE-2 Gate B controlled behavior.** [`P2-CE-003`](contracts/v0.2.0/examples/phase2-gate-b-ce2-evidence-record.json) records two complete repetitions of 16 fixed synthetic scenarios against implementation Commit [`e8aa8b0`](https://github.com/redxking/ai-decision-firewall/commit/e8aa8b0efc7d54efdf74f49fb3d10ee067f2b49b). All 32 observations matched the commit-frozen, project-controlled expectations: two test-only validate-only passes, 28 structural pre-payload blocks with no governed payload-role open/read attempt observed by the declared hooks during harness invocation, and two quarantine-threshold blocks after qualification but before the engine. No engine, authorization, broker, or target-effect boundary was reached, and no completed run manifest, decision artifact, or audit artifact was observed.

The CE-2 result is a SELF automated project-controlled check over a fixed synthetic registry. The two repetitions are not independent or statistically representative trials, and the public Commit A freeze is not external preregistration. The instrumentation is not an OS-level nonaccess or non-egress proof, and the absence of target-effect calls is not target-side outcome verification.

Phase 2.4 adds a bounded feature-assurance layer without changing the action boundary:

- modeled attributes must have exact JSON types and may be asserted only by code-authorized source types; `failed_logins` is limited to a finite integral JSON number in `0..1,000,000`;
- every JSON number anywhere in an accepted case must be finite before engine invocation;
- every asset-inventory event must contain `asset_id`, `privilege_level`, `break_glass`, and `asset_criticality`, and all four values must match the canonical case context exactly;
- unrecognized opaque attributes remain available for context and traceability but cannot enter the 20-feature model projection; the separately governed network-only Boolean `source_conflict` can affect evidence quality but is outside the reference feature recomputation;
- a separately implemented in-process reference projector reconstructs the 20 feature values and feature-to-event trace from normalized cases and compares them with the serialized decision after the complete eight-stage audit check;
- a successful check emits one closed, metadata-only `reference_feature_assurance.jsonl` row per case and binds its digest/count into metrics and the run manifest; and
- a mismatch stops the run before qualification/rejection publication, adjudication loading, comparisons, metrics, or completed run-manifest finalization. Raw/normalized/deterministic decisions and the audit may already exist and must be treated as incomplete evidence.

The fixed [`P2-CE-004`](contracts/v0.2.0/examples/phase2-feature-assurance-ce2-evidence-record.json) campaign is now a narrow CE-2 `CONTROLLED_BEHAVIOR` result against corrected implementation Commit [`53e409d6`](https://github.com/redxking/ai-decision-firewall/commit/53e409d6ffa4af98ea892bc1a81302bf30870693). Two deterministic same-process repetitions of 16 synthetic attempts produced 32/32 matches to commit-frozen, project-controlled expectations with zero retries, exclusions, failures, or deviations: 16 clean qualification/reference matches, eight qualification quarantines, and eight reference-projection blocks. The two sanitized ledgers were byte-identical. No model, policy, verifier, decision engine, authorization, broker, target-effect, or operational-effect boundary was reached. This is SELF automated project-controlled evidence only; the implementation suite remains separate CE-1 conformance evidence.

An earlier unpublished package against Commit `1945ff283794c42f8eb649e320ba6adf91a6b982` was withheld after review found that its frozen validator accepted non-finite JSON. That package is invalidated, excluded from every claim denominator, and is not evidence. The published package is one new execution against the corrected A2 freeze, not a retry within its 32-attempt denominator.

Phase 2.5 extends the separately implemented reference path across the deterministic read-only decision calculation without adding action authority:

- strict frozen-byte parsing binds the exact normalized cases, serialized decisions, model, policy, and execution mode and rejects duplicate members, non-finite values, invalid closed shapes, and unequal case sets;
- the reference path recomputes and compares five ordered surfaces: `EVIDENCE`, `MODEL`, `POLICY`, `VERIFIER`, and `FINAL_SURFACE`;
- production and reference evidence paths use ordered `math.fsum(values) / event_count` for provenance, integrity, freshness, and source-trust aggregates;
- production and reference model paths use the same explicit ordered `math.fsum` logit rule before the intercept and clamped sigmoid, avoiding dependence on a library reduction order;
- a successful run emits one closed, metadata-only `source_to_decision_assurance.jsonl` receipt per case, with expected/observed stage and ordered-path digests bound into metrics and the run manifest. The receipt covers the deterministic semantic surface, not volatile UUID/time/latency/hash instance fields; the manifest separately co-binds raw decisions and audit bytes; and
- a stage mismatch stops before either reference artifact is published, before qualification/rejection publication, adjudication decoding, comparisons, metrics, or completed-run finalization. Earlier normalized, decision, and audit artifacts may remain and are incomplete diagnostic material only.

The reference implementation is separate in code but remains same-process, same-project, project-controlled assurance—not an external oracle, organizationally independent evaluation, or separate custody boundary. The planned `P2-CE-005-SOURCE-TO-DECISION-SYNTHETIC` campaign is **CE-0 `NOT_EVALUATED`**. Its fixed 40-attempt design uses ten directly instrumented production baselines per run, each shared by its clean/mutant twin, and 20 reference-path calls per run. Across both planned runs that is 20 baseline executions and 20 calls to each production component—engine, evidence, model, policy, and verifier—plus 40 reference calls, not 40 independent production executions. These are budgets and expected outcomes, not observed results; CE-2 wording is prohibited until the two-commit freeze, exact-commit execution, evidence-only publication, and fresh frozen-evaluator validation are complete.

Published Phase 2.5 Commit `854b15c` adds campaign CLI destination preflight for ordinary operator mistakes: repository-root/outside/`.git` paths, existing symlink traversal, output/record overlap, nonempty output reuse, and record overwrite are rejected. Check mode additionally rejects symbolic-link, directory, and multiply linked artifact leaves and a symbolic-link record before any artifact read or campaign rebuild. Its three focused CLI regressions passed 3/3, a separate check-leaf safety regression and constructor-instrumentation sensitivity regression passed, and the campaign test module passed 21/21. These five campaign-delta tests are included in the 222/222 Phase 2.5 technical suite; the separate 9/9 public-site module contributes only to the then-current 231/231 aggregate and is outside this assurance claim. Exact-commit CI passed. This is not OS or mount containment, adversarial TOCTOU/race resistance, direct `generate_artifacts` confinement, a governed exact-Commit-A evidence execution, or eligible evidence.

Every reference attempt now instruments construction of `AuthorizationGate`, `ActionBroker`, and `SimulatedIdentityProvider` in addition to the existing invocation/effect counters. The sensitivity regression injects all three constructions, observes nonzero counts, forces an expected-row mismatch, and confirms that the closed campaign schema rejects the row. This supports only the named Python construction boundary; it is not a general object-allocation monitor, OS-level containment proof, or observed campaign result.

Published Phase 2.5 Commit `854b15c` also narrows routine `run_poc.py` writes to `data/local/**` and `outputs/local/**` inside the repository, while permitting explicitly selected external destinations. `--allow-tracked-artifact-overwrite` expands the repository scope only to `data/**` and `outputs/baseline/**` for an explicitly reviewed freeze workflow; other repository paths, symlink redirects, and data/output overlap remain rejected. Preflight enumerates every generated leaf, including `run_manifest.json`, rejects an existing symlink, nonregular file, or multiply linked leaf, and the local run manifest SHA-256-binds its seven non-self-referential outputs. Fourteen focused tests passed, including the case-variant repository-alias regression on the case-insensitive development volume. This is a local operator interlock, not an OS or mount boundary, adversarial TOCTOU/race or comprehensive hard-link guarantee, or confinement of direct library writers.

Published Phase 2.5 Commit `854b15c` also adds CE-1-only Gate B scaffolding: validator-owned closed `(stage, control_id, reason_code)` identities, an exact-match oracle that rejects unclassified failures, and a bounded observer for `builtins.open`, `io.open`, `os.open`, `Path.open`, `Path.read_bytes`, and `Path.read_text`. The registry contains 25 selected identities; tests cover 24 selected pre-payload mutations with zero observed `cases` or `adjudications` roles through those enumerated APIs, plus one postqualification threshold identity. This is not a complete Gate B failure taxonomy, reference monitor, sandbox, syscall monitor, OS-level nonaccess proof, or successor campaign result. No successor Gate B campaign has executed.

The included Phase 2 fixture contains **zero historical cases**. It exercises the framework; it does not establish historical replay performance, analyst agreement, operational calibration, or readiness for live shadow deployment. See [`docs/phase2/`](docs/phase2/) for the architecture, data contract, requirements, safety case, and validation plan.

The committed starter fixture provides a small deterministic integration check:

| Phase 2 starter measure | Included result |
|---|---:|
| Synthetic fixture cases | 3 |
| Historical cases | 0 |
| Dispositions | 1 `NO_ACTION`, 1 `INVESTIGATE`, 1 `CONTAIN_REVERSIBLE` |
| Counterfactual actions retained | 3 |
| Execution-suppression audit records | 3 |
| Authorization-evaluation / decision-finalization records | 3 / 3 |
| Authorization attempts or tokens | 0 |
| Broker invocations or operational effects | 0 |
| Action or post-action audit records | 0 |
| Presented audit chain | Valid, 24 records; eight exact ordered stages per case |
| Predecessor Phase 2.5 design-freeze suite | **193/193 passed in the review-local run; CI and Dependency Graph succeeded for exact Commit `08ce203c` on 2026-08-15** |
| Phase 2.5 technical suite | **222/222 passed for published exact Commit `854b15c`; exact-commit CI and Dependency Graph also passed** |
| Separate public-site module | **9/9 passed after rebasing onto published `github/main@c3400e0`; outside Phase 2.5 and `P2-CE-005` evidence** |
| Phase 2.5 repository aggregate | **231/231 at published exact Commit `854b15c`; exact-commit GitHub CI passed** |
| Alpha.6 release/evidence package | **Code/package commit published; no tag and no `P2-CE-005` evidence package** |

The predecessor Phase 2.5 design-freeze implementation is bound to Commit `08ce203c0965e8d43b7653454d4ea8315996021f`; its historical 193-test local run and successful commit-bound CI support narrow CE-1 implementation-conformance wording only. Published exact Commit `854b15c` passed the 222/222 Phase 2.5 technical suite and exact-commit CI/Dependency Graph. The separate public-site module passed 9/9, bringing the then-current aggregate to 231/231, but neither the site nor its tests extend the Phase 2.5 claim. The generated-and-verified integrity manifest, frozen-renderer chart check, paired final-source DOCX/PDF rebuild, and 15-page inspection complete the package gates. None creates a `P2-CE-005` campaign result, a tagged alpha.6 release, an evidence package, or safeguard-effectiveness evidence; the separate campaign protocol was not entered.

The fixture's three adjudications are test expectations, not historical ground truth. Agreement or classification measures calculated from these three synthetic records are wiring checks and must not be represented as efficacy evidence.

The separate Phase 2.1 qualification campaign is also synthetic and predeclared:

| Phase 2.1 qualification measure | Included result |
|---|---:|
| Nonblank input records | 7 |
| Accepted / quarantined | 3 / 4 |
| Quarantine reasons | 1 invalid JSON, 1 missing field, 1 invalid timestamp, 1 canonical-context mismatch |
| Decisions emitted | 3, one per accepted record |
| Historical cases | 0 |
| Authorization tokens / broker invocations / operational effects | 0 / 0 / 0 |

The test suite and committed `P2-CE-002` evidence package observed deterministic accounting and fail-closed qualification behavior under the named fixture. They do not estimate historical acceptance, data quality, model efficacy, operational error rates, agentic alignment, or readiness for a live shadow connection. Qualification changes the evaluated population, so any future result over accepted records must report the full intake and quarantine distribution to avoid survivorship bias.

The fixed Phase 2.3 Gate B campaign reports the following separate CE-2 result:

| `P2-CE-003` measure | Included result |
|---|---:|
| Complete repetitions | 2 |
| Fixed scenarios per repetition | 16 |
| Observations matching project-controlled expectations | 32 / 32; no exclusions |
| Test-only validate-only passes | 2 |
| Structural pre-payload blocks | 28 |
| Structural-block attempts with governed payload-role open/read observed by declared hooks during harness invocation | 0 / 28 |
| Post-qualification, pre-engine threshold blocks | 2 |
| Engine / authorization / broker / target-effect boundary reaches | 0 / 0 / 0 / 0 |
| Completed run manifests / decision artifacts / audit artifacts | 0 / 0 / 0 |
| Sanitized result ledgers | Byte-identical across the two repetitions |
| Historical cases | 0 |

The exact [`evidence record`](contracts/v0.2.0/examples/phase2-gate-b-ce2-evidence-record.json) binds the [`campaign profile and result bundle`](evidence/phase2_gate_b_ce2/README.md), fixed plan, schema, implementation commit, generator, validator, fixtures, model, and policy. It does not represent a real approval, actual historical data, a live feed or action, OS-level nonaccess or non-egress, target-side proof, exhaustive coverage, an operational failure-rate estimate, efficacy, or an alignment/misalignment evaluation.

The fixed Phase 2.4 feature-assurance campaign reports the following separate CE-2 result:

| `P2-CE-004` measure | Included result |
|---|---:|
| Complete repetitions | 2 |
| Fixed scenarios per repetition | 16 |
| Observations matching project-controlled expectations | 32 / 32; no exclusions |
| Clean qualification and reference-projection matches | 16 |
| Qualification quarantines | 8: 2 `INVALID_BOOLEAN`, 2 `INVALID_TYPE`, 4 `UNAUTHORIZED_MODELED_SIGNAL` |
| Reference-projection mismatch blocks | 8 |
| Model / policy / verifier / decision-engine calls | 0 / 0 / 0 / 0 |
| Authorization / broker / target-effect / operational-effect calls | 0 / 0 / 0 / 0 |
| Retries / exclusions / failures / deviations | 0 / 0 / 0 / 0 |
| Sanitized result ledgers | Byte-identical across the two repetitions |
| Historical cases | 0 |

The exact [`feature-assurance evidence record`](contracts/v0.2.0/examples/phase2-feature-assurance-ce2-evidence-record.json) binds the [`campaign bundle`](evidence/phase2_feature_assurance_ce2/README.md), fixed plan, schema, A2 implementation commit, generator, corrected validator, project sources, dependency declarations, runtime fingerprint, seed, order, expected outcomes, and budget. It does not establish source truth, full decision correctness, independent assurance, historical/live behavior, efficacy, production readiness, or alignment/misalignment behavior.

The planned Phase 2.5 campaign has no observed-result table. Its plan specifies ten clean/mutant pairs per run and two deterministic same-process runs, with ten expected clean matches and two expected blocks at each of `EVIDENCE`, `MODEL`, `POLICY`, `VERIFIER`, and `FINAL_SURFACE` per run. Each pair shares one directly instrumented production baseline, so the planned accounting is ten baseline executions and ten calls to each production component per run, 20 of each across both runs, plus 20 reference-path calls per run and 40 total. The contract keeps directly instrumented authorization-gate/broker/target-effect/scoped-write calls separate from decision-derived authorization-token, action-result, and operational-effect fields. Every planned value, including zero, is a predeclared expectation only. No governed exact-Commit-A execution, eligible result ledger, evidence record, supported claim, pass rate, or CE-2 status is asserted here.

The worked [`starter evidence record`](contracts/v0.2.0/examples/phase2-starter-evidence-record.json), [`qualification evidence record`](contracts/v0.2.0/examples/phase2-qualification-evidence-record.json), [`Gate B campaign evidence record`](contracts/v0.2.0/examples/phase2-gate-b-ce2-evidence-record.json), and [`feature-assurance campaign evidence record`](contracts/v0.2.0/examples/phase2-feature-assurance-ce2-evidence-record.json) state the exact narrow claims these results support, identify the systems and artifacts, and carry forward limitations and prohibited inferences. The broader [`claim-evidence standard`](docs/phase2/CLAIM_EVIDENCE_STANDARD.md) defines what additional validity, adversarial, statistical, and independent-review evidence is required before stronger language is permitted. The current POC uses a logistic model and deterministic controls; it does not contain an autonomous generative-language-model agent.

The committed `P2-CE-001` and `P2-CE-002` replay bundles predate alpha.5 and do not contain either current reference-assurance artifact. Their original version-bound narrow claims remain validated as recorded; they were not retroactively upgraded. A newly generated alpha.6 replay is incomplete unless it produces and binds both `reference_feature_assurance.jsonl` and `source_to_decision_assurance.jsonl` and the harness completes every final revalidation.

## Phase 3: published simulation-only operational MVP

Phase 3 adds an external raw-request-to-synthetic-effect path without adding a
live connector. The caller supplies an opaque invocation credential outside the
request JSON; a firewall-owned resolver maps it to a signed
`ResolvedPrincipal`. The firewall validates runtime HMAC attestations over
synthetic evidence, including the evidence subject target; loads trusted
source/action/target facts from a closed policy; enforces code-owned evidence,
consequence, rule-order, and Tier-0 safety floors; and returns `ALLOW`, `DENY`,
`ESCALATE`, or `ALLOW_CONSTRAINED` with structured reasons.

An allowed decision must pass a functionally separate deterministic verifier
before a short-lived authorization is issued. The token binds the exact request,
decision, agent, action, target, canonical permitted parameters, expiration,
policy digest, decision context, and target-state precondition. The mandatory
broker consumes it once and can change only the in-memory simulation. A separate
read-only observer—not the broker return value—drives final verification.

The two published-boundary demonstrations show:

- a Tier-0 domain-controller isolation request with AI confidence `0.96`, stale
  and conflicting evidence, cascading consequence, and insufficient authority
  returns `ESCALATE`, creates a bound approval requirement, and produces no
  authorization or target effect; and
- a properly authorized low-criticality workstation request returns `ALLOW`,
  executes one simulated isolation, and is observed through the functionally
  separate same-project readback path as `VERIFIED`.

Published exact Commit `423685d` passed 57/57 focused Phase 3 tests, both
demonstration acceptance checks, the 46/46 deterministic adversarial corpus,
and the then-current 288/288 repository suite locally and in exact-commit CI.
Prepublication review found and closed
release-blocking defects across consequence/evidence binding, opaque identity
and key-domain separation, exact-type/deep-immutable security objects, machine
policy floors, replay and receipt atomicity, dependency-failure closure, and
executed-path/post-effect audit semantics.

These controls are application-level Python boundaries, not OS/process
security. The authorization ledger is in memory and is not durable or
distributed. Runtime HMAC fixture keys do not create enterprise provenance.
Human approval resolves a separate opaque human credential and permits only an
exact-scope signed reevaluation receipt; it cannot execute or itself cause
reevaluation. Both verifiers are same-project/functionally separate, not
externally independent.

Start with [`docs/phase3/README.md`](docs/phase3/README.md) for reproduction,
architecture, test status, traceability, and explicit nonclaims.

Phase 3.1 now adds a separate synthetic-only evaluation path for the advisory
model. It recombines the 1,200 committed synthetic cases as source pools,
creates disjoint temporal training/calibration/evaluation partitions, compares
an interpretable logistic baseline with a Platt calibration challenger, and
reports aggregate discrimination, calibration, Wilson-interval, selective-risk
and subgroup diagnostics. The observed synthetic calibration deltas demonstrate
the mechanism only. Model promotion remains `NOT_AUTHORIZED`; no historical
payload may be opened without a separately authenticated Gate B package. See
[`docs/phase31/README.md`](docs/phase31/README.md).

## Architecture

The following transaction is the **Phase 1 v0.1 synthetic-simulation compatibility path**. It is retained for bounded simulator testing; it is not constructed or reachable in either Phase 2 read-only mode.

```text
Synthetic evidence
      |
      v
Schema and evidence-quality assessment -----> Traceable evidence record
      |
      v
Allow-listed features -----> Advisory risk model
      |                            |
      +-------------+--------------+
                    v
          Deterministic policy engine
                    |
                    v
 Functionally separate deterministic verifier
                    |
          approved reversible action?
              /                 \
            no                   yes
            |                     |
   abstain or escalate     scoped authorization token
                                  |
                                  v
                         simulated action broker
                                  |
                                  v
                         post-action verification
                                  |
                                  v
                          hash-chained audit log
```

The current Phase 2 read-only architecture is:

![AI Decision Firewall logical architecture](docs/architecture/02_logical_architecture.png)

In the Phase 1 compatibility path, the model has no signing key, target credentials, action-broker reference, or direct execution path. Only an independently verified, policy-compliant proposal can cause the authorization gate to mint a token, and the in-memory broker validates that token. Phase 2 structurally omits the authorization gate, broker, and target.

Phase 2 places a read-only ingestion boundary in front of the same decision path:

```text
Manifest control bytes + optional Gate B package
                    |
                    v
 historical origin? require current approvals and bindings
                    |
                    v
 only after Gate B: open and verify declared payloads
                    |
                    v
 frozen inputs + descriptor-bound run snapshot
                    |
                    v
 fail-dataset validation OR cases-only qualification
          |                         |
          |                 metadata-only ledger
          |                 + quarantined subset
          +------------+------------+
                       v
 accepted cases only, passed in memory
                    |
                    v
 deterministic normalization and temporal ordering
                    |
                    v
 typed/source-authorized feature contract
                    |
                    v
 evidence -> model -> policy -> functionally separate deterministic verifier
                    |
                    v
       mandatory execution suppression
                    |
                    v
 counterfactual decision + exact eight-stage audit
                    |
                    v
 separate reference feature projection
          | mismatch: stop; publish neither receipt
          v
 separate source-to-decision reference recomputation
          | mismatch: stop; publish neither receipt
          v
 write and bind both metadata-only assurance receipts
                    |
                    v
 deferred evaluator + metrics + completed manifest
```

In the built-in runner and canonical adapter, replay and shadow suppression is enforced by construction rather than by a downstream “do not execute” flag. The v0.1 authorization and simulator path exists only under `synthetic_simulation` for compatibility testing. The starter is an in-process Python harness, not an OS-enforced sandbox against arbitrary imported code; the no-effect claim is limited to the tested, repository-controlled path.

Additional diagrams are available in [`docs/architecture/`](docs/architecture/), including the system context, decision state machine, and trust boundaries.

## Safety and authority model

The executable safety invariants are:

- free text is treated as untrusted content and never as action authority;
- ground truth is evaluator-only and never enters a runtime decision;
- only exactly typed, source-authorized modeled fields enter the risk model; unrecognized opaque attributes cannot become features, while the network-only Boolean `source_conflict` is separately governed as an evidence-quality input (`QUARANTINE_RECORD` uses `SEMANTICS / UNAUTHORIZED_DECISION_SIGNAL` for wrong source and `SEMANTICS / INVALID_BOOLEAN` for wrong type);
- every JSON numeric value in an accepted case is finite before engine invocation, including values inside opaque attributes;
- every asset-inventory assertion exactly matches the canonical asset, privilege, break-glass, and criticality context;
- missing, stale, conflicted, poisoned, or low-integrity evidence forces abstention;
- canonical cases marked as break-glass or above the configured asset-criticality threshold require human authority;
- human-only actions cannot appear in an autonomous authorization token;
- no token is issued without independent-verifier approval;
- tokens are signed, short-lived, case-bound, and action-scoped;
- no action is declared successful solely because a command returned success;
- material decision and execution events are recorded in a tamper-evident audit chain;
- the separately implemented in-process reference projector must reproduce each serialized feature value and trace before evaluation metrics or a completed run manifest can exist;
- a historical payload cannot be touched until a current, exact Gate B package passes; manifest attestations alone are insufficient;
- Gate B control bytes are frozen before payload processing, historical outputs use owner-only descriptor-bound writes, the runner receives no filesystem paths, and evaluator labels are withheld until decisions close; and
- Gate B validates structure and byte bindings, not the external truth of authority, identity, signatures, privacy controls, or custody assertions.

The three POC action types—revoke active sessions, require step-up authentication, and increase monitoring—operate only against the in-memory simulator. The `CONTAIN_REVERSIBLE` label means bounded and operationally recoverable in this POC; it does not imply exact transactional reversal. For example, a revoked session is recovered through reauthentication rather than restoration of the original session. Account disablement, endpoint isolation, network blocking, and persistent policy changes remain human-only in policy and are not implemented as live actions.

See [`docs/SECURITY_AND_SAFETY_CASE.md`](docs/SECURITY_AND_SAFETY_CASE.md) for the argument structure and residual risks.

## Frozen synthetic baseline

The included baseline uses seed `20260814`, 800 synthetic training cases, and 400 synthetic evaluation cases. The evaluation set contains 187 compromised and 213 benign cases.

| Measure | Included result |
|---|---:|
| `NO_ACTION` | 161 cases |
| `INVESTIGATE` | 64 cases |
| `CONTAIN_REVERSIBLE` | 112 cases |
| `ESCALATE_HUMAN` | 63 cases |
| Expected-disposition agreement | 98.75% |
| False autonomous containment | 0 cases |
| Unsafe automation under encoded test rules | 0 cases |
| Autonomous actions involving poisoned evidence | 0 cases |
| Evidence-ID trace coverage | 100% |
| Authorization without independent-verifier approval | 0 cases |
| Simulated command-execution success | 97.6% |
| Complete post-action verification | 92.9% |
| Audit-chain verification | Valid |
| Automated tests | 7 of 7 passed |

The lower execution and post-action verification rates are intentional: deterministic downstream failures test whether the system distinguishes an accepted command from a verified state change.

The trace-coverage metric confirms that every cited and feature-linked event ID resolves to an input event. It does not validate the semantic truth, cryptographic provenance, or completeness of that evidence.

The v0.1 verifier evaluates the state returned by the in-memory simulator. It is not an independent readback from a production target. Independent target observation is a requirement for later controlled-action phases.

These results establish that the encoded control and safety invariants executed repeatably for the supplied frozen artifacts in the recorded runtime. The seed deterministically regenerates the synthetic dataset in that boundary; byte-identical model retraining across permitted Python, NumPy, BLAS, processor, or operating-system combinations is not established. The results **do not** establish operational detection accuracy, real-world false-positive rates, production safety, or suitability for live containment. The model and evaluation data share the same synthetic scenario family, so model-performance metrics are intentionally optimistic.

The complete results are in [`outputs/baseline/metrics.json`](outputs/baseline/metrics.json) and the self-contained [`baseline_report.html`](outputs/baseline/baseline_report.html).

## Run the POC

Requirements: Python 3.11 or later and NumPy.

```bash
git clone https://github.com/redxking/ai-decision-firewall.git
cd ai-decision-firewall

python -m venv .venv
# Linux/macOS
source .venv/bin/activate
# Windows PowerShell
# .venv\Scripts\Activate.ps1

python -m pip install --upgrade pip
python -m pip install -r requirements.txt
python run_poc.py
```

The default run regenerates the dataset, trains the synthetic advisory model, processes 400 cases, verifies the audit chain, and writes ignored local artifacts under `data/local/synthetic-baseline/` and `outputs/local/synthetic-baseline/`. It does not replace the checked-in, campaign-bound baseline model.

Use temporary or separate directories when you want an isolated run:

```bash
python run_poc.py \
  --data-dir /tmp/adf-data \
  --output-dir /tmp/adf-output
```

Inside the repository, an ordinary run may write only under `data/local/**` and `outputs/local/**`; explicitly selected external data and output directories are also permitted. `--allow-tracked-artifact-overwrite` expands the repository scope only to `data/**` and `outputs/baseline/**` and is reserved for an explicitly reviewed model-freeze workflow. Other repository paths, symlink redirects, and overlapping data/output destinations fail before generation. Existing generated leaves—including `run_manifest.json`—must be regular, nonsymlinked, singly linked files, and the manifest binds the seven other output artifacts by SHA-256. These checks reduce operator-error clobber risk; they are not an OS or mount boundary, adversarial TOCTOU/race or comprehensive hard-link protection, or confinement of direct library writers. A successful local retraining run does not authorize replacement of the frozen model: NumPy reductions and full-precision coefficient serialization can produce different bytes across otherwise permitted runtimes even when stored decision probabilities remain unchanged.

Run the safety and pipeline tests:

```bash
PYTHONPATH=src python -m unittest discover -s tests -v
```

Run the Phase 3 simulation-only demonstrations and 46-case adversarial corpus
into fresh temporary directories:

```bash
demo_dir="$(mktemp -d /tmp/adf-phase3-demo.XXXXXX)"
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src python3 run_phase3.py \
  --output-dir "$demo_dir"

corpus_dir="$(mktemp -d /tmp/adf-phase3-corpus.XXXXXX)"
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src python3 run_phase3_corpus.py \
  --output-dir "$corpus_dir"
```

Both commands use only synthetic state and refuse to clobber a nonempty output
directory. Their local JSON/JSONL artifacts are diagnostics, not a release or
evidence package.

Validate the Phase 2 configuration, governed manifest, file integrity, and canonical cases without invoking the engine:

```bash
python run_phase2.py --validate-only
```

Validate the seven-record Phase 2.1 qualification campaign without invoking the engine:

```bash
python run_phase2.py \
  --config config/phase2_qualification.json \
  --validate-only
```

Verify that the committed fixture still matches deterministic generation from the reviewed three-case controls:

```bash
python scripts/generate_phase2_qualification_fixture.py --check
```

Validate the commit-frozen Phase 2.3 campaign plan, optionally re-execute the two 16-attempt ledgers for a byte comparison without rewriting the published artifacts, and validate the committed `P2-CE-003` evidence record:

```bash
python scripts/generate_gate_b_ce2_campaign.py --validate-plan
python scripts/generate_gate_b_ce2_campaign.py \
  --implementation-commit e8aa8b0efc7d54efdf74f49fb3d10ee067f2b49b \
  --evaluated-at 2026-08-15T03:12:44Z \
  --check
python -m scripts.validate_claim_evidence \
  --record contracts/v0.2.0/examples/phase2-gate-b-ce2-evidence-record.json \
  --profile P2-CE-003
```

The `--check` command performs a new verification execution; it is not part of the published 32-observation denominator. The static claim-evidence command validates the committed record and artifacts. The campaign generator intentionally requires an already committed implementation SHA. A new evaluation time or any change to a bound source, plan, schema, fixture, model, policy, generator, validator, seed, or budget requires a new evidence record; do not overwrite the published result and retain its claim-lifecycle history.

Validate the frozen `P2-CE-004` plan and the committed A2 campaign evidence:

```bash
python scripts/generate_feature_assurance_ce2_campaign.py --validate-plan
python -m scripts.validate_claim_evidence \
  --record contracts/v0.2.0/examples/phase2-feature-assurance-ce2-evidence-record.json \
  --profile P2-CE-004
```

The claim validator checks the committed artifacts and performs a fresh frozen-evaluator re-execution without rewriting them. That verification is not added to the published 32-attempt denominator. The plan-only command still validates structure and bindings only.

Validate only the planned `P2-CE-005` structure and bindings after its generator is frozen:

```bash
python scripts/generate_source_to_decision_ce2_campaign.py --validate-plan
```

This does not execute the campaign or create evidence. `P2-CE-005` remains CE-0 `NOT_EVALUATED` until the exact Commit-A run and evidence-only Commit B are complete.

Run the synthetic starter through the historical-replay code path:

```bash
python run_phase2.py
```

Run the qualification campaign through the same offline, read-only historical-replay path:

```bash
python run_phase2.py --config config/phase2_qualification.json
```

The Phase 2 run writes local, ignored artifacts under `outputs/replay/phase2_starter/` and refuses to overwrite a nonempty output directory. A complete alpha.6 run includes both closed `reference_feature_assurance.jsonl` and `source_to_decision_assurance.jsonl` artifacts. A source-to-decision mismatch stops before either is published, before evaluator loading, metrics, and completed-run finalization. A later failure can leave additional files, including a manifest written before final revalidation; only successful harness return establishes completion. Under the built-in tested path the run issues no authorization token, constructs no action broker or target, and produces no operational effect. Use a reviewed configuration with a new repository-confined `output_dir` for each additional run.

Run with different synthetic counts, seed, or output location:

```bash
python run_poc.py \
  --train-count 800 \
  --test-count 400 \
  --seed 20260814 \
  --output-dir outputs/local/custom-baseline
```

Rebuild the **historical v0.1** editable engineering baseline after changing its v0.1 source inputs. This command does not create the current Phase 2 status package:

```bash
python -m pip install -r requirements-docs.txt
python docs/build_engineering_doc.py
```

Verify a package only against the manifest committed with those exact bytes. The
`MANIFEST.sha256` in published Commit `854b15c` covers that Phase 2.5 package.
The manifest in published Phase 3 exact Commit `423685d` covers that exact
tree, and the Phase 3.1 manifest applies only to exact Commit `bb6b8f28`. The
307-entry manifest in published Stage A implementation Commit `8818d5d2`
verified 307/307 and applies only to that implementation tree. It does not cover
the later [`ADF-STAGE-A-ER-002`](docs/production/STAGE_A_RECEIPT_RESULT_EVIDENCE_RECORD.md)
or its evidence-carrier tree. The carrier therefore uses its own separately
regenerated 308-entry manifest covering that record; carrier qualification
verified it 308/308. Its exact SHA is reported in the completion handoff. The tracked data, model,
and baseline outputs remain at their published bytes. Reverify a manifest only
after checking out its matching commit:

```bash
shasum -a 256 -c MANIFEST.sha256
```

## Repository layout

```text
.
├── config/
│   ├── policy.json                 # Decision, evidence, authority, and safety policy
│   ├── phase2_replay.json          # Whole-dataset, read-only replay configuration
│   ├── phase2_qualification.json   # Cases-only synthetic qualification campaign
│   ├── gate_b_ce2_campaign_plan.json # Fixed P2-CE-003 expected outcomes and budget
│   ├── feature_assurance_ce2_campaign_plan.json # Fixed P2-CE-004 expected outcomes and budget
│   ├── source_to_decision_ce2_campaign_plan.json # CE-0 P2-CE-005 plan; not an observed result
│   ├── phase3_policy.json            # Closed synthetic source/action/target/consequence policy
│   └── production_readiness_requirements.json # Strict 18-domain BLOCKED production gate
├── contracts/v0.2.0/               # Replay, Gate B, campaign, and claim-evidence contracts
├── contracts/v0.3.0/               # Strict Phase 3 request and policy contracts
├── data/
│   ├── phase2_starter/             # Three-case synthetic replay fixture; no historical data
│   └── phase2_qualification/       # Seven-record mixed-quality synthetic fixture and expectations
├── docs/
│   ├── adr/                        # Architecture decision records
│   ├── architecture/               # Source and rendered current/historical diagrams
│   ├── phase2/                     # Replay architecture, feature/source-to-decision assurance, safety, V&V, traceability
│   ├── phase3/                     # Operational-MVP architecture, safety case, T&E, gap analysis, and traceability
│   ├── production/                 # Production RTM narrative, threat register, and failure/recovery matrix
│   ├── operations/                 # Stage A inspection/recovery runbook; not operationally validated
│   ├── ENGINEERING_STATUS_AND_FORWARD_PLAN.md # Current living status and forward plan
│   ├── AI_Decision_Firewall_Engineering_Status_v0.3.0-alpha.1-candidate.docx # Published Phase 3 archived render; inspected
│   ├── AI_Decision_Firewall_Engineering_Status_v0.3.0-alpha.1-candidate.pdf  # Paired published Phase 3 archive; 7 pages inspected
│   ├── AI_Decision_Firewall_Engineering_Status_v0.3.1-alpha.1-candidate.docx # Published Phase 3.1 archived render; 9 pages inspected
│   ├── AI_Decision_Firewall_Engineering_Status_v0.3.1-alpha.1-candidate.pdf  # Paired published Phase 3.1 archive; 9 pages inspected
│   ├── AI_Decision_Firewall_Engineering_Status_v0.2.0-alpha.6-candidate.docx # Archived Phase 2.5 package render
│   ├── AI_Decision_Firewall_Engineering_Status_v0.2.0-alpha.6-candidate.pdf  # Archived Phase 2.5 paired render; 15 pages
│   ├── build_engineering_status.py # Rebuilds the current status DOCX/PDF package
│   ├── CONCEPT_OF_OPERATIONS.md
│   ├── REQUIREMENTS_TRACEABILITY_MATRIX.csv
│   ├── SECURITY_AND_SAFETY_CASE.md
│   ├── SYNTHETIC_DATA_CARD.md
│   └── TEST_AND_EVALUATION_PLAN.md
├── evidence/phase2_starter/         # Sanitized evidence supporting the narrow CE-2 starter claim
├── evidence/phase2_qualification/   # Sanitized 7=3+4 qualification evidence and exact run artifacts
├── evidence/phase2_gate_b_ce2/      # Sanitized two-repetition P2-CE-003 bundle; no stored approval or historical data
├── evidence/phase2_feature_assurance_ce2/ # Sanitized two-repetition P2-CE-004 bundle; synthetic and SELF-reviewed
├── local/gate_b/                    # Ignored restricted package location; never commit real controls
├── outputs/baseline/               # Restored committed Phase 1 decisions, metrics, audit, and report
├── scripts/                        # Confined fixture generation/checks and claim-evidence validation
├── src/adf_poc/
│   ├── replay/                     # Contracts, Gate B, qualification, path-free harness, secure output, metrics
│   ├── phase3/                     # Raw request, evidence, decision, authorization, simulation, readback, audit, corpus
│   └── stage_a.py                  # Optional authority ledger, durable synthetic adapter, receipts, and sanitized lookup
├── tests/                          # Safety and end-to-end tests
├── run_poc.py                      # End-to-end synthetic baseline entry point
├── run_phase2.py                   # Offline replay/shadow starter entry point
├── run_phase3.py                   # Two simulation-only raw-request demonstrations
├── run_phase3_corpus.py            # Deterministic 46-scenario adversarial corpus
├── pyproject.toml
└── requirements.txt
```

## Limitations and non-claims

The current baseline has not established:

- behavior on any historical organizational case (the Phase 2 starter reports `historical_case_count = 0`);
- approval of a real Gate B package or authority to acquire, stage, or process organizational historical data;
- authenticated approver identity or authority, signature validation, external custody truth, or effective de-identification from the Gate B structural preflight;
- historical acceptance or quarantine rates, source completeness, or performance over records that did not survive qualification;
- production vendor-adapter behavior or semantic equivalence between source telemetry and the canonical contract;
- performance against historical or live identity, endpoint, network, or cloud telemetry;
- generalization to unseen attack or benign-administration patterns;
- operational false-positive or false-negative rates;
- analyst agreement, workflow fit, or mission/business consequences;
- behavior under vendor API semantics, race conditions, eventual consistency, or production-scale load;
- cryptographic provenance rooted in enterprise trust infrastructure;
- production key management, distributed token replay protection, or
  independently custodied target-side command receipts; the Stage A candidate
  provides only opt-in single-host authority state plus a separate local
  synthetic-adapter state/receipt database and authority-free result lookup;
- an externally anchored or independently signed audit trail (a process able to rewrite the log can recompute the v0.1 hash chain);
- organizationally or externally independent source-to-decision assurance. Phase 2.5 separately recomputes the evidence, model, policy, verifier, and read-only final surfaces from the same normalized case, model, and policy bytes in the same process and project; agreement is calculation consistency, not source truth, outcome correctness, policy fitness, efficacy, or independent custody;
- externally trusted audit timestamps, OS-level nonaccess/non-egress, or independent evidence custody;
- external or operational target-state readback or executable rollback orchestration; Phase 3 performs functionally separate observation over the same in-memory simulator, while Stage A reads the separate durable synthetic-adapter store through a same-project observer that is still not independent evidence;
- reconciliation of conflicting break-glass or asset-criticality values in the v0.1 direct-run interface (the Phase 2 canonical adapter instead rejects such disagreement before engine invocation);
- suitability for safety-critical, operational-technology, or critical-infrastructure control environments;
- agentic alignment, scheming, sabotage resistance, or monitor effectiveness; the evaluated path is deterministic and contains no autonomous generative agent.
- OS/process isolation for the Phase 3 private-capability boundary, distributed
  request/token ledgers, enterprise source attestation/key custody, production
  human-approval workflow, or external/organizationally independent
  verification.

The typed contract does not prove that an authorized source assertion is truthful, authentic, complete, or semantically equivalent to a vendor record. Both reference implementations are separately implemented but not externally or organizationally independent, and their metadata hashes do not create independent custody. `P2-CE-004` supplies only the exact SELF-reviewed synthetic CE-2 result above. `P2-CE-005` remains CE-0 `NOT_EVALUATED`; its plan supplies no observed behavior. Neither provides historical/live evaluation, independent replication, external custody, exhaustive coverage, or a failure-rate estimate.

`P2-CE-003` adds no exception to these limitations. Its 32/32 observations are two repetitions of the same 16 project-selected synthetic scenarios under SELF automated project-controlled review. They do not establish a complete mutation space, a bounded failure rate, independent replication, real Gate B authority, effective de-identification, historical efficacy, live-shadow readiness, target-side effect absence, or zero risk.

The policy engine and verifier also share configuration and may share design defects. The POC signing key has a documented non-production fallback. These limitations are deliberate release constraints, not deferred permission to connect the software to a live environment.

## Roadmap

The **Phase 2 starter, Phase 2.1 qualification increment, Phase 2.2 Gate B machine preflight, Phase 2.3 audit/campaign increment, Phase 2.4 typed-feature/reference-projection controls, and Phase 2.5 source-to-decision implementation are present**, with live actions remaining disabled. `P2-CE-005` is planned but not evaluated; no Phase 2.5 CE-2 result exists.

The exact Phase 2.5 package commit is now published and its CI is green, but the
separate `P2-CE-005` two-commit campaign protocol was not entered. Any future
execution still requires an explicit governed designation of Commit A, a clean
detached no-retry run, and a distinct validated evidence-only Commit B.

The ADR-015 Stage A two-database synthetic receipt and sanitized terminal-result
implementation is published on `main` at exact Commit `8818d5d2` while retaining
the Phase 3.1 no-promotion boundary. Its exact local, manifest, CI, and Dependency
Graph observations are bound in
[`ADF-STAGE-A-ER-002`](docs/production/STAGE_A_RECEIPT_RESULT_EVIDENCE_RECORD.md).
The next safe technical gate is a separately
controlled campaign for broader power-loss, filesystem/disk, restore,
retention, load, and cross-store divergence conditions at every authority,
adapter, observation, audit, and result boundary, followed by distributed
execution ownership and process isolation. Current tests cover selected real
process termination, concurrent first creation, response loss, recovery
prefixes, audit-write ambiguity, and cross-store corruption; they do not make
those broader operational claims.

The next data-bearing step remains external: accountable owners must
assemble and authenticate the restricted Gate B authority, custody, privacy,
mapping, adjudication, and pilot package before a small de-identified historical
corpus can be processed. No Gate B approval, historical run, live feed, or
shadow-feed progression has occurred.

Later phases, each requiring separate evidence and authorization, are:

1. authenticated offline historical replay, then live read-only shadow
   evaluation in an approved environment;
2. reversible actions against non-production test targets under change control,
   managed keys, durable idempotency, independent vendor readback, and rollback;
3. a limited operational pilot with human approval for all actions; and
4. action-class-specific autonomy only if statistically and operationally
   defensible gates are met and an authorizing official accepts the residual
   risk.

See [`docs/ROADMAP.md`](docs/ROADMAP.md) for the full sequence and exit conditions.

## Documentation

- [`docs/REPRODUCIBILITY_BOUNDARY.md`](docs/REPRODUCIBILITY_BOUNDARY.md) — frozen-artifact versus retraining claim boundary and required future builder controls
- [`DELIVERY_NOTES.md`](DELIVERY_NOTES.md) — v0.1 scope, results, and handoff
- [`docs/AI_Decision_Firewall_POC_Engineering_Baseline_v0.1.pdf`](docs/AI_Decision_Firewall_POC_Engineering_Baseline_v0.1.pdf) — engineering baseline
- [`docs/ENGINEERING_STATUS_AND_FORWARD_PLAN.md`](docs/ENGINEERING_STATUS_AND_FORWARD_PLAN.md) — current living status and forward plan
- [`docs/adr/015_durable_synthetic_adapter_receipt_and_result_lookup.md`](docs/adr/015_durable_synthetic_adapter_receipt_and_result_lookup.md) — bounded two-database Stage A receipt, lookup, and reconciliation decision; production authorization not granted
- [`docs/AI_Decision_Firewall_Engineering_Status_v0.3.0-alpha.1-candidate.docx`](docs/AI_Decision_Firewall_Engineering_Status_v0.3.0-alpha.1-candidate.docx) — inspected artifact for the now-published Phase 3 simulation-only baseline
- [`docs/AI_Decision_Firewall_Engineering_Status_v0.3.0-alpha.1-candidate.pdf`](docs/AI_Decision_Firewall_Engineering_Status_v0.3.0-alpha.1-candidate.pdf) — paired 7-page Phase 3 artifact; all rendered pages inspected at that boundary
- [`docs/AI_Decision_Firewall_Engineering_Status_v0.3.1-alpha.1-candidate.docx`](docs/AI_Decision_Firewall_Engineering_Status_v0.3.1-alpha.1-candidate.docx) — current Phase 3.1 status package built from the reviewed Markdown and diagrams
- [`docs/AI_Decision_Firewall_Engineering_Status_v0.3.1-alpha.1-candidate.pdf`](docs/AI_Decision_Firewall_Engineering_Status_v0.3.1-alpha.1-candidate.pdf) — paired Phase 3.1 status render; all 9 pages inspected
- [`docs/AI_Decision_Firewall_Engineering_Status_v0.2.0-alpha.6-candidate.docx`](docs/AI_Decision_Firewall_Engineering_Status_v0.2.0-alpha.6-candidate.docx) — inspected historical Phase 2.5 package-bound status artifact
- [`docs/AI_Decision_Firewall_Engineering_Status_v0.2.0-alpha.6-candidate.pdf`](docs/AI_Decision_Firewall_Engineering_Status_v0.2.0-alpha.6-candidate.pdf) — paired 15-page historical Phase 2.5 artifact
- [`docs/build_engineering_status.py`](docs/build_engineering_status.py) — reproducible builder for the current Phase 3 status DOCX/PDF package
- [`docs/CONCEPT_OF_OPERATIONS.md`](docs/CONCEPT_OF_OPERATIONS.md) — actors, modes, decisions, and off-nominal behavior
- [`docs/REQUIREMENTS_TRACEABILITY_MATRIX.csv`](docs/REQUIREMENTS_TRACEABILITY_MATRIX.csv) — requirement-to-design-and-test traceability
- [`docs/MODEL_CARD.md`](docs/MODEL_CARD.md) — advisory model purpose, performance, and limits
- [`docs/SYNTHETIC_DATA_CARD.md`](docs/SYNTHETIC_DATA_CARD.md) — dataset design and appropriate use
- [`docs/TEST_AND_EVALUATION_PLAN.md`](docs/TEST_AND_EVALUATION_PLAN.md) — acceptance criteria and required next-phase tests
- [`docs/phase2/README.md`](docs/phase2/README.md) — Phase 2 scope and documentation map
- [`docs/phase3/README.md`](docs/phase3/README.md) — published Phase 3 scope, reproduction, evidence status, and documentation map
- [`docs/phase3/ARCHITECTURE.md`](docs/phase3/ARCHITECTURE.md) — Phase 3 request-to-effect architecture and trust boundaries
- [`docs/phase3/SECURITY_AND_SAFETY_CASE.md`](docs/phase3/SECURITY_AND_SAFETY_CASE.md) — Phase 3 safety argument, supporting observations, residual risks, and nonclaims
- [`docs/phase3/TEST_AND_EVALUATION_PLAN.md`](docs/phase3/TEST_AND_EVALUATION_PLAN.md) — planned acceptance requirements separated from local observations
- [`docs/phase3/REQUIREMENTS_TRACEABILITY.csv`](docs/phase3/REQUIREMENTS_TRACEABILITY.csv) — Phase 3 requirement-to-code/test traceability and evidence boundaries
- [`docs/phase31/README.md`](docs/phase31/README.md) — Phase 3.1 synthetic-only model-evaluation scope, reproduction, result boundary, and next authority gate
- [`docs/phase31/MODEL_EVALUATION_PLAN.md`](docs/phase31/MODEL_EVALUATION_PLAN.md) — temporal split, metrics, candidate strategy, and owner-threshold requirements
- [`docs/phase31/DATA_GOVERNANCE_GATE.md`](docs/phase31/DATA_GOVERNANCE_GATE.md) — approvals and frozen controls required before historical payload access
- [`docs/phase31/REQUIREMENTS_TRACEABILITY.csv`](docs/phase31/REQUIREMENTS_TRACEABILITY.csv) — Phase 3.1 requirement-to-code/test traceability
- [`docs/phase2/CLAIM_EVIDENCE_STANDARD.md`](docs/phase2/CLAIM_EVIDENCE_STANDARD.md) — claim classes, proof requirements, statistical rules, and adversarial evaluations
- [`docs/phase2/FEATURE_ASSURANCE.md`](docs/phase2/FEATURE_ASSURANCE.md) — typed/source-authorized signals, exact inventory binding, reference projection, controlled campaign evidence, and nonclaims
- [`docs/phase2/SOURCE_TO_DECISION_ASSURANCE.md`](docs/phase2/SOURCE_TO_DECISION_ASSURANCE.md) — Phase 2.5 stage scope, numeric rule, artifact ordering, failure semantics, CE-0 campaign plan, and nonclaims
- [`docs/phase2/RESEARCH_INFORMED_VALIDATION.md`](docs/phase2/RESEARCH_INFORMED_VALIDATION.md) — dated research lessons mapped to the bounded Phase 2.4/2.5 designs; research is not project evidence
- [`docs/phase2/RESEARCH_COVERAGE_REGISTER.md`](docs/phase2/RESEARCH_COVERAGE_REGISTER.md) — dated Anthropic and OpenAI research screen, dispositions, gaps, and refresh triggers
- [`docs/phase2/RECORD_QUALIFICATION.md`](docs/phase2/RECORD_QUALIFICATION.md) — fatal/quarantine taxonomy, metadata contract, accounting invariants, privacy rules, synthetic gate, and historical-pilot prerequisites
- [`docs/phase2/GATE_B_HISTORICAL_PILOT.md`](docs/phase2/GATE_B_HISTORICAL_PILOT.md) — restricted-package contents, approval roles, pre-payload ordering, stop conditions, and nonclaims
- [`docs/adr/006_gate_b_machine_readable_preflight.md`](docs/adr/006_gate_b_machine_readable_preflight.md) — decision to require Gate B before historical payload access
- [`docs/adr/007_separate_reference_feature_projection.md`](docs/adr/007_separate_reference_feature_projection.md) — accepted Phase 2.4 decision for a separately implemented feature projector
- [`docs/adr/008_source_to_decision_reference_candidate.md`](docs/adr/008_source_to_decision_reference_candidate.md) — Phase 2.5 decision accepted at predecessor design-freeze Commit `08ce203c`, with release/evidence conditions and independence limits
- [`docs/architecture/README.md`](docs/architecture/README.md) — current diagram scope, legacy-chart boundary, and reproducible visual-generation commands
- [`docs/phase2/REQUIREMENTS_TRACEABILITY.csv`](docs/phase2/REQUIREMENTS_TRACEABILITY.csv) — Phase 2 requirement status and verification evidence
- [`contracts/v0.2.0/gate-b-authorization.schema.json`](contracts/v0.2.0/gate-b-authorization.schema.json) — closed Gate B authorization-package contract
- [`contracts/v0.2.0/gate-b-ce2-campaign.schema.json`](contracts/v0.2.0/gate-b-ce2-campaign.schema.json) — closed profile, result-row, and summary contract for `P2-CE-003`
- [`contracts/v0.2.0/reference-feature-assurance.schema.json`](contracts/v0.2.0/reference-feature-assurance.schema.json) — closed metadata-only matched-projection record
- [`contracts/v0.2.0/feature-assurance-ce2-campaign.schema.json`](contracts/v0.2.0/feature-assurance-ce2-campaign.schema.json) — closed profile/result contract for the observed `P2-CE-004` campaign
- [`contracts/v0.2.0/source-to-decision-assurance.schema.json`](contracts/v0.2.0/source-to-decision-assurance.schema.json) — closed metadata-only Phase 2.5 matched-path receipt
- [`contracts/v0.2.0/source-to-decision-ce2-campaign.schema.json`](contracts/v0.2.0/source-to-decision-ce2-campaign.schema.json) — closed `P2-CE-005` plan/profile/result contract; CE-0 until executed and published
- [`contracts/v0.2.0/examples/gate-b-authorization-draft.json`](contracts/v0.2.0/examples/gate-b-authorization-draft.json) — schema-valid but explicitly non-authorizing public example
- [`contracts/v0.2.0/replay-qualification.schema.json`](contracts/v0.2.0/replay-qualification.schema.json) — closed per-source-record qualification ledger contract
- [`contracts/v0.2.0/qualification-expectations.schema.json`](contracts/v0.2.0/qualification-expectations.schema.json) — closed predeclared synthetic-campaign expectation contract
- [`contracts/v0.2.0/evaluation-evidence.schema.json`](contracts/v0.2.0/evaluation-evidence.schema.json) — machine-readable claim-evidence contract
- [`contracts/v0.2.0/examples/phase2-starter-evidence-record.json`](contracts/v0.2.0/examples/phase2-starter-evidence-record.json) — validated, narrowly bounded starter result
- [`contracts/v0.2.0/examples/phase2-qualification-evidence-record.json`](contracts/v0.2.0/examples/phase2-qualification-evidence-record.json) — validated, narrowly bounded seven-record qualification result
- [`contracts/v0.2.0/examples/phase2-gate-b-ce2-evidence-record.json`](contracts/v0.2.0/examples/phase2-gate-b-ce2-evidence-record.json) — validated, narrowly bounded Gate B controlled-behavior record
- [`contracts/v0.2.0/examples/phase2-feature-assurance-ce2-evidence-record.json`](contracts/v0.2.0/examples/phase2-feature-assurance-ce2-evidence-record.json) — validated, narrowly bounded feature-assurance controlled-behavior record
- [`evidence/phase2_starter/README.md`](evidence/phase2_starter/README.md) — sanitized inputs, outputs, hashes, and custody limits for that result
- [`evidence/phase2_qualification/README.md`](evidence/phase2_qualification/README.md) — exact qualification run, accounting artifacts, hashes, and custody limits
- [`evidence/phase2_gate_b_ce2/README.md`](evidence/phase2_gate_b_ce2/README.md) — exact two-repetition Gate B campaign bundle, raw denominators, and limits
- [`evidence/phase2_feature_assurance_ce2/README.md`](evidence/phase2_feature_assurance_ce2/README.md) — exact two-repetition feature-assurance campaign bundle, raw denominator, and limits
- [`SECURITY.md`](SECURITY.md) — vulnerability reporting and non-production security boundaries
- [`docs/SOURCE_PROVENANCE.md`](docs/SOURCE_PROVENANCE.md) — imported-package provenance and archive-integrity limitation

### Rebuild the current status package

Install the documentation dependencies, then run the paired DOCX/PDF builder:

```bash
python -m pip install -r requirements-docs.txt
python docs/build_engineering_status.py
```

`requirements-docs.txt` supplies the Python document and plotting dependencies,
including `python-docx` and `matplotlib`. LibreOffice/`soffice` is additionally
required to produce the paired PDF. The builder creates the current status pair
from the Markdown source and linked architecture figures; the separately named
15-page Phase 2.5 pair remains an immutable package-bound archive. A rebuilt
pair must be rendered and inspected before its integrity manifest is frozen.

## Licensing

No open-source license is included in this repository. Public availability does not itself grant permission to use, modify, or redistribute the work.
