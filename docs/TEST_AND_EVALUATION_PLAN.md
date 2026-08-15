# Test and Evaluation Plan

> **Version boundary.** The v0.1 results remain historical. Exact Phase 2.5
> Commit `854b15c56397a81de6326b719d3d7d1dc847608f` is published on `main` and its
> exact-commit CI/Dependency Graph checks passed. Its recorded package boundary
> includes 222/222 Phase 2.5 technical tests, separate 9/9 public-site tests,
> and the then-current 231/231 aggregate. The site remains outside Phase 2.5
> evidence. `P2-CE-005` was not executed and remains CE-0 `NOT_EVALUATED`.
> Phase 3 `0.3.0-alpha.1` is published at exact Commit
> `423685d105be813056617db738297eba83d3d9d0`; exact-commit CI and Dependency
> Graph checks passed. Its boundary includes 57/57 focused tests, both demo
> acceptance checks PASS, a 46/46 corpus, and the then-current 288/288 repository
> suite. These are simulation-only CE-1 observations, not operational validation.

## Test objective

Demonstrate that the POC implements its safety and authority requirements and quantify behavior across benign, malicious, ambiguous, incomplete, and adversarial synthetic cases.

## Evaluation categories

**Functional testing:** Case ingestion, feature extraction, model execution, policy disposition, verification, authorization, simulated execution, post-action verification, reporting, and audit-chain validation.

**Safety testing:** Prompt injection, missing provenance, failed integrity, conflicting sources, missing telemetry, break-glass accounts, critical assets, human-only action insertion, missing tokens, invalid signatures, expired tokens, and target execution failures.

**Model testing:** Discrimination, precision, recall, Brier score, calibration error, scenario-level performance, and sensitivity to feature ablation. Model results are explicitly secondary to safety invariants in v0.1.

**Audit testing:** Completeness, hash-chain continuity, decision-record traceability, and tamper detection.

## Baseline acceptance criteria

- Zero autonomous actions on poisoned evidence.
- Zero autonomous actions on break-glass identities.
- Zero autonomous actions above the configured asset-criticality boundary.
- Zero authorization tokens without independent-verifier approval.
- 100% decision-to-input-event identifier trace coverage.
- Valid audit chain after a complete run.
- Audit tampering detected by unit test.
- Human-only actions rejected by the verifier.
- Ground truth absent from runtime case inputs.
- The synthetic dataset can be regenerated from the documented seed, and frozen-artifact behavior can be repeated in the recorded runtime. Byte-identical cross-runtime model retraining is not an acceptance claim.

## Baseline outcome

All seven automated tests passed. The 400-case baseline produced zero unsafe automation events, zero poisoned-evidence actions, zero tokens without verifier approval, 100% decision-to-input-event identifier trace coverage, and a valid audit chain. This metric does not validate evidence semantics or external provenance. The simulator intentionally produced command failures; therefore, action-command and complete post-action verification rates were below 100%, correctly exposing execution uncertainty.

These results apply to the delivered v0.1 synthetic-simulation baseline only. The seven-test artifact is not the current repository test count.

## Published Phase 2.4 evidence state

The prior alpha.5 checkout records 147 passing implementation tests. That count is version-bound and must not be reused for the alpha.6 predecessor design freeze, published Phase 2.5 package, or Phase 3 candidate. The published Phase 2 evidence records remain separate from the implementation suite:

- `P2-CE-001`: three-case synthetic starter replay;
- `P2-CE-002`: seven-record synthetic qualification campaign with three accepted and four quarantined records;
- `P2-CE-003`: two executions of 16 fixed synthetic Gate B scenarios, with all 32 observations matching project-controlled expectations; and
- `P2-CE-004`: two executions of 16 fixed synthetic feature-assurance scenarios, with all 32 observations matching project-controlled expectations.

All four records are SELF, project-controlled, synthetic CE-2 evidence for their exact wording only. They are not historical, live, operational, statistically representative, or independently replicated results.

## Alpha.6 predecessor design-freeze verification

The Phase 2.5 predecessor design-freeze baseline is exact Commit `08ce203c0965e8d43b7653454d4ea8315996021f`. Its review-local suite passed 193/193 tests, and the GitHub CI and Dependency Graph workflows succeeded for that exact commit on 2026-08-15. This supports narrow CE-1 implementation conformance for the committed design-freeze state only. It does not create a tag, an alpha.6 release/evidence package, or a `P2-CE-005` observation.

The verified design-freeze boundary includes:

- strict parsing and exact case/model/policy/mode binding for the frozen source-to-decision inputs;
- identical, explicitly specified ordered arithmetic in production and reference paths, including `math.fsum`-based evidence aggregates and model-logit accumulation;
- separate comparison of `EVIDENCE`, `MODEL`, `POLICY`, `VERIFIER`, and `FINAL_SURFACE` with stable stage-specific failures;
- one complete metadata-only receipt per accepted case, with both reference artifacts written only after both checks succeed;
- failure before evaluator decoding, comparison, metrics, and completed-run finalization on any mismatch;
- repeated late-mutation checks over normalized cases, raw and deterministic decisions, audit, both assurance artifacts, metrics, and manifest construction; and
- all unchanged Phase 1 and prior published Phase 2 regressions passing locally and in CI against the exact design-freeze commit.

## Published Phase 2.5 package verification

The campaign CLI destination guard passed 3/3 focused checks, a separate construction-instrumentation sensitivity regression passed, and the complete campaign test module passed 21/21 in an isolated clean clone. Check mode additionally rejects symbolic-link, directory, and multiply linked artifact leaves and a symbolic-link evidence record before any artifact read or campaign rebuild; it requires singly linked regular leaves and size-checks them before reading. Every reference attempt instruments construction of `AuthorizationGate`, `ActionBroker`, and `SimulatedIdentityProvider`; the sensitivity test injected all three, observed nonzero counts and mismatch, and proved closed-schema rejection. The `run_poc` guard passed 14 focused checks covering ordinary and explicit-freeze destination rules, case-variant repository aliases, path overlap and redirects, generated-leaf preflight including `run_manifest.json`, unsafe existing leaves, and seven-output local-manifest binding. These are bounded application-level operator-error and Python-instrumentation controls, not an OS sandbox, mount boundary, TOCTOU/race guarantee, comprehensive hardlink defense, direct-writer confinement, general allocation monitor, or target-side proof.

The selected Gate B test scaffolding now registers 25 closed causal identities: 24 selected pre-payload mutations and one post-qualification threshold identity. Exact closed tuples are required for classified errors, while unclassified Gate B errors remain unscorable. For the 24 selected pre-payload mutations, a bounded observer recorded zero `cases` or `adjudications` roles under its enumerated Python file APIs. This does not establish a complete taxonomy, OS-level nonaccess/non-egress, a reference monitor, or campaign evidence.

No successor `P2-CE-005` campaign has been executed. Source reconciliation is complete, and the published package passed the Phase 2.5 technical suite 222/222: the predecessor 193 tests plus five campaign-delta tests, 14 `run_poc` tests, six Gate B oracle tests, and four payload-observer tests. The separate public-site module passed 9/9, producing a then-current repository aggregate of 231/231; those site tests are not part of Phase 2.5 implementation or evidence. The chart check passed in the frozen renderer, the integrity manifest was generated and verified, and the paired final-source DOCX/PDF were rebuilt and all 15 rendered pages inspected. Exact package Commit `854b15c` was published, and GitHub CI/Dependency Graph passed for it. The predecessor 193-test result remains bound to `08ce203c`; no tag or `P2-CE-005` evidence package exists.

## Planned `P2-CE-005` evaluation

The fixed plan specifies ten clean/mutant pairs per run and two deterministic same-process runs: 40 planned observations, zero retries, and zero exclusions. The expected stage outcomes are design constants, not observed results. Publication and green CI for Phase 2.5 Commit `854b15c` did not designate or execute a governed `P2-CE-005` Commit A. CE-2 wording remains prohibited unless one exact clean Commit A freezes the implementation, plan, schemas, generator, validator, and intended confinement controls; a detached checkout of that commit executes the campaign; and a separate evidence-only Commit B is validated. A defect in the actor, task, expected outcome, scorer, generator, or validator invalidates the package rather than creating evidence.

## Published Phase 3 verification

The published Phase 3 modules cover strict raw contracts and machine policy safety
floors, opaque-credential identity/authority resolution, target-bound evidence
attestation, evidence quality, target-claim spoofing, consequence, all four
decisions, exact/deep-immutable constraints, single-use authorization,
wrong-scope/expiry/prior-instance/concurrent replay, broker and direct-target
bypass, approval receipt atomicity, fail-closed faults, functionally separate
same-project target readback, executed-path/post-effect lifecycle audit,
metrics, simulation-only construction, demos, and the deterministic corpus.

Verified for exact Commit `423685d105be813056617db738297eba83d3d9d0`:

- 57/57 focused Phase 3 tests passed;
- the high-risk domain-controller raw request returned `ESCALATE`, created a
  bound approval requirement, issued no token, invoked no broker, and produced
  no effect;
- the authorized workstation raw request returned `ALLOW`, consumed one token,
  performed one in-memory isolation, and functionally separate same-project
  readback returned `VERIFIED`;
- the deterministic adversarial corpus reported 46/46 passing scenarios; and
- the then-current repository suite passed 288/288 locally and in exact-commit CI.

Adversarial review found and closed release-blocking defects across consequence
and evidence binding, credential/key-domain handling, exact-type immutability,
machine-policy floors, replay/receipt atomicity, dependency-failure closure,
and executed-path/post-effect audit correlation. Neither the fixes nor local
green results establish exhaustive security.

The complete Phase 3 matrix, commands, and evidence boundary are in
[`phase3/TEST_AND_EVALUATION_PLAN.md`](phase3/TEST_AND_EVALUATION_PLAN.md).

## Remaining test obligations

The repository now exercises schema-version mismatch, bounded parsing, delayed/out-of-order normalization, duplicate identifiers, synthetic qualification, Gate B preflight, exact eight-stage audit validation, typed/source-authorized features, and separate reference calculations. The following obligations remain unevaluated or incomplete:

- authenticated, approved de-identified historical replay and temporal holdout evaluation;
- vendor-specific adapters, source-ablation studies, mapping-loss analysis, and analyst inter-rater reliability;
- historical calibration, uncertainty, abstention cost, survivorship-bias, and subgroup analysis;
- durable/distributed idempotency and token replay rejection, managed HMAC key rotation/revocation, executable policy rollback, external/vendor target readback, and secure logging failure; Phase 3 covers only process-local concurrency and same-project simulated readback;
- OS-enforced isolation, egress verification, external audit custody, dependency/evaluation-environment attack testing, and production-scale availability; and
- controlled test-tenant and operational validation under separate authority.

See [`phase2/VALIDATION_PLAN.md`](phase2/VALIDATION_PLAN.md) and [`phase2/CLAIM_EVIDENCE_STANDARD.md`](phase2/CLAIM_EVIDENCE_STANDARD.md) for current detailed gates and prohibited inferences.

## Stage A production-development verification

The current Stage A increment adds single-host durable-control tests for
restart replay, conflicting duplicates, authorization/attempt persistence,
process races, bounded lock failure, unknown schema, unsafe storage paths,
outbox durability, post-effect outcome-write failure, and idempotent recovery
to `UNKNOWN_EFFECT`. These tests close the reproduced restart-replay defect for
the explicitly configured synthetic boundary only.

The repository-wide production gate remains `BLOCKED`. The exact current
coverage and every unresolved degraded mode are recorded in
[`production/FAILURE_RECOVERY_MATRIX.md`](production/FAILURE_RECOVERY_MATRIX.md)
and [`production/PRODUCTION_READINESS.md`](production/PRODUCTION_READINESS.md).
