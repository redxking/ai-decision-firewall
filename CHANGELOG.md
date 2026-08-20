# Changelog

## Unreleased — `0.4.0-alpha.2` Stage A production-development candidate

Exact implementation Commit
[`8818d5d2d40faebced66a254d58b1f0d04c9f8b4`](https://github.com/redxking/ai-decision-firewall/commit/8818d5d2d40faebced66a254d58b1f0d04c9f8b4)
was published to `main` on 2026-08-16. The version remains unreleased: no tag or
GitHub Release was created, no deployment occurred, and no exact-SHA Pages run
was observed. Exact evidence and limitations are recorded in
[`ADF-STAGE-A-ER-002`](docs/production/STAGE_A_RECEIPT_RESULT_EVIDENCE_RECORD.md).

- Pinned every external GitHub Action in CI and Pages to a full commit SHA and
  added a regression that rejects tags, branches, and short SHAs.
- Advanced the official CI and Pages actions to immutable Node.js 24 releases
  after GitHub reported that the earlier Node.js 20 actions were deprecated and
  being force-run on Node.js 24.
- Added a fail-closed cold backup/restore command for the correlated Stage A
  audit, control, and synthetic-adapter artifacts. Backup uses the cooperative
  durable/audit lock and atomic directory publication; restore requires the
  exact configuration, policy, secret binding, store identities, file digests,
  and empty state path before regenerating the audit-inode-bound service marker.
  This is local self-custodied recoverability mechanics, not approved DR,
  rollback resistance, trusted time, continuous backup, RPO, or RTO evidence.
- Added a layered Stage A storage-fault campaign with uncatchable process loss
  at T1, observation, T2, audit closure, and T3; ambiguous audit-`fsync` and
  persistent `ENOSPC` controls; and a real Linux tmpfs-exhaustion container
  case. A complete audit row with failed `fsync` now raises a distinct
  durability error and cannot reach T3. A partial row caused by actual
  exhaustion is preserved and forces quarantine. The container package now
  includes both required Phase 3 schemas, and CI constructs the packaged policy
  and runs the bounded fault layer under non-root, network-disabled,
  read-only restrictions.
- Extended the campaign through two additional system boundaries. A Docker
  controller now terminates the whole non-root Stage A container from outside
  at T1, observation, T2, audit closure, and T3, then verifies the persisted
  volumes from a fresh container. A separate explicitly authorized privileged
  lab derives from an inspected local image ID and switches an ext4 loopback
  device to `dm-error` at the same five boundaries. Recovery preserved zero
  receipts before effect, one receipt after effect, conservative nonterminal
  disposition, and the durable T3 result without a duplicate effect. The lab
  records raw pre/post-`e2fsck` image hashes and application-file changes;
  filesystem repair is never treated as evidence authenticity. Physical power,
  torn writes, lost flushes, intended CSI behavior, and operational acceptance
  remain open.
- Added exact-version, SHA-256 hash-locked runtime and documentation dependency
  graphs, a reproducible CycloneDX 1.6 runtime SBOM, closed lock/SBOM
  validation, and `--require-hashes` CI installation. A clean temporary runtime
  environment installed the lock successfully and passed 23 representative
  contract tests. This is project-controlled dependency integrity evidence,
  not trusted-builder provenance, vulnerability disposition, or a signed
  release.
- Corrected the runtime lock after CI proved the original graph was not closed
  across the supported interpreter matrix: NumPy `2.5.2` had no Python 3.11
  wheel and `referencing` required conditional `typing-extensions` on Python
  3.11/3.12. The runtime range now resolves to NumPy `2.4.6`, the conditional
  package is hash locked, and the SBOM validator requires every reviewed
  transitive edge rather than only root edges. Clean binary-only hash installs
  and import smoke checks passed locally on Python 3.11 and 3.12.
- Removed reliance on jsonschema's process-global optional date-time format
  registry. Installing SBOM tooling registered an optional validator and
  changed malformed timestamp classification from the code-owned stable reason
  code to a generic schema error. Timestamp semantics now remain in the
  offset-aware code-owned validation path regardless of unrelated installed
  format extras.
- Reproduced a critical restart replay on the published Phase 3.1 baseline:
  two newly constructed firewall instances sharing the same valid audit path
  accepted the same authenticated request and each reported one synthetic
  operational effect. The hash-linked audit remained valid because it was not
  the authority-state ledger.
- Added an opt-in single-host SQLite transaction ledger for immutable request
  claims, unique verified-decision issuance, atomic authorization consumption
  plus attempt reservation, monotonic outcomes, digest-only audit outbox, and
  conservative `UNKNOWN_EFFECT` reconciliation. WAL, `synchronous=FULL`, strict
  schema/version checks, foreign keys, bounded lock waits, and unsafe-path
  refusal fail closed.
- Adopted the ADR-015 two-database offline boundary. A separate SQLite
  synthetic-adapter store transactionally updates only synthetic target state
  and inserts one immutable exact-bound receipt before returning. The authority
  ledger stores a closed, sanitized terminal `RequestLookupResult` through a
  separate authenticated read-only seam; `process_json` remains fail closed on
  duplicates and never returns the lookup envelope as a fresh decision.
- Added query-only existing-store preflight, exact closed schema and semantic
  validation, path/link/type/mode refusal, and cross-store correlation over
  overlapping principal, request, decision/context, authority, policy,
  receipt, and terminal-target facts. All three authoritative artifact paths
  are preflighted before a missing artifact is created. Bounded cooperative
  same-host fencing serializes direct store initialization and durable request,
  approval, lookup, and recovery operations without adding a lock sidecar.
- Added explicit `ISSUED` / `CONSUMED` / `REVOKED` authority semantics,
  receipt-scoped attempt states, and quiesced recovery rules. Exact `NO_EFFECT`
  receipts may close as `FAILED_NO_EFFECT`; `APPLIED`, `PARTIAL`, `AMBIGUOUS`,
  or absent receipt evidence without separately durable verification closes as
  `UNKNOWN_EFFECT` with `recovery_required=true`. Receipt absence never proves
  no effect or permits retry. Recovery never reissues a command, reopens
  authority, or fabricates verification or rollback.
- Required a valid read-back normal JSONL lifecycle closure before T3. Recovery
  writes and reads back the exact contiguous `RECOVERY_STARTED`,
  `RECOVERY_EVIDENCE_ASSESSED`, and `RECOVERY_FINALIZED` prefix before T3,
  truthfully records the original lifecycle as `COMPLETE`, `INCOMPLETE`, or
  `UNRESOLVED`, and resumes idempotently at any prefix. A pending recovery
  commit fences request and approval writers; append/readback failure
  suppresses T3; a post-T3 repeat returns the identical audit-inert result.
- Added restart, conflict, multiprocess initialization/exact-once,
  storage-lock, schema/path/sidecar, durable-outbox, cross-store substitution,
  response-loss, recovery-prefix, audit-failure, chronology, and post-effect
  outcome-write regressions. At exact implementation Commit `8818d5d2`, local
  verification passed 43/43 focused Stage A tests in 8.248 seconds, 18/18
  production-gate tests, the warning-fatal 360/360 repository suite in 48.995
  seconds, 57/57 focused Phase 3 tests, and the deterministic 46/46 corpus; the
  corpus reported `live_actions_possible=false`. The integrated exact-once race
  passed 5/5 parallel repetitions. The 307-entry implementation manifest
  verified 307/307. Exact-SHA CI run
  [31953570779](https://github.com/redxking/ai-decision-firewall/actions/runs/31953570779)
  succeeded on Python 3.11 and 3.12, and Dependency Graph run
  [31953572482](https://github.com/redxking/ai-decision-firewall/actions/runs/31953572482)
  succeeded. These are project-controlled mechanism observations, not independent
  verification, production authorization, or operational effectiveness.
  The boundary remains synthetic/offline and single-host, not cross-store
  atomic, distributed, highly available, process isolated, or operationally
  validated.
- Added a strict 18-domain production-readiness matrix and validator whose
  derived production gate remains `BLOCKED`, plus threat, failure/recovery,
  operations, architecture, and evidence-boundary records.
- Added successor evidence record `ADF-STAGE-A-ER-002` in a separate carrier
  with a regenerated 308-entry manifest that verified 308/308. The carrier SHA
  is necessarily reported after creation rather than self-claimed here.
- No historical or live data, connector, operational credential, external
  target, or model promotion was introduced. No deployment, tag, or GitHub
  Release occurred; no exact-SHA Pages run was observed.

## `0.3.1-alpha.1` — published Phase 3.1 governed model-evaluation baseline

Exact Commit `bb6b8f28afba0961bb97b24e6050fccaa94d5702` was published to
`main` on 2026-08-15. Exact-commit CI passed on Python 3.11 and 3.12, and the
Dependency Graph workflow passed. No Phase 3.1 GitHub tag or Release was
created; the commit is a published code baseline, not a packaged release.

- Added closed v0.3.1 plan/result schemas and fixed plan `P3-1-MEV-001` for a
  synthetic-only model-evaluation mechanism. The plan binds the four committed
  source pools by SHA-256 and record count, prohibits historical/live access and
  live action, and contains no owner-approved promotion thresholds.
- Added a disjoint temporal 60/20/20 training/calibration/evaluation split that
  moves equal timestamps forward so one timestamp cannot cross a boundary.
- Added an interpretable logistic baseline and a deterministic Platt calibration
  challenger. Both are evaluated once on the final temporal partition; the
  challenger does not add authority or change the Phase 3 decision path.
- Added ROC AUC, average precision, Brier score, log loss, expected calibration
  error, threshold metrics, Wilson intervals, selective-risk curves, and
  scenario/criticality/privilege strata. Results are aggregate only.
- The fixed synthetic run used 720 training, 240 calibration and 240 evaluation
  rows. The challenger preserved ranking and the threshold confusion matrix
  while reducing synthetic Brier score by `0.00098425`, log loss by
  `0.01113884`, and ten-bin expected calibration error by `0.00309615`. These
  are mechanism observations, not practical-significance, superiority or
  operational-performance claims.
- Added 10 focused regressions for plan safety, source binding, temporal
  separation, deterministic execution, metrics, calibration inputs, no-clobber
  output, no action/historical imports, and structural refusal of promotion.
  The focused module passed 11/11 and the then-current repository suite passed
  299/299 locally and in exact-commit CI.
- Added the Phase 3.1 architecture diagram, data-governance gate, model
  evaluation plan, contracts, ADR 013, and traceability matrix. No historical
  payload was accessed and no action credential, authorization, broker, target,
  operational effect, model promotion or `P2-CE-005` execution occurred.

## `0.3.0-alpha.1` — published Phase 3 simulation-only operational MVP baseline

Exact Commit `423685d105be813056617db738297eba83d3d9d0` was published to `main`
on 2026-08-15. Exact-commit CI passed on Python 3.11 and 3.12, and the Dependency
Graph workflow passed. The release boundary retains 57/57 focused Phase 3 tests,
both demonstration checks PASS, the 46/46 deterministic corpus, the then-current
288/288 repository aggregate, a verified 269-entry manifest, and inspected
seven-page DOCX/PDF artifacts. It remains simulation-only CE-1 implementation
evidence, not operational validation.

- Added a strict closed v0.3.0 raw decision-request contract and validated
  external policy contract. Duplicate members, non-finite numbers, unsupported
  versions, invalid time, unsafe bounds, and unknown/missing fields fail closed.
- Added opaque invocation credentials, firewall-owned signed-principal/authority
  resolution, and trust-material domain separation; policy-owned source, action,
  and target registries; runtime HMAC source attestations with content,
  semantics, time, provenance, and subject-target binding; evidence freshness,
  corroboration, relevance, conflict, missing-source, and poisoning assessment;
  and deterministic consequence evaluation.
- Added exact `ALLOW`, `DENY`, `ESCALATE`, and `ALLOW_CONSTRAINED` outcomes with
  stable reason codes, policy/context digests, deep-immutable records, canonical
  constraints, and a functionally separate deterministic decision verifier.
  Code-owned policy invariants preserve unique closed rule precedence,
  conservative evidence/zero-conflict thresholds, severe-consequence approval
  floors, and Tier-0 treatment for every domain controller. AI recommendation
  and confidence remain non-authoritative.
- Added short-lived HMAC authorizations binding issuer, request, decision,
  agent, action, target, canonical parameters, time, policy, decision context,
  target precondition, and nonce. The in-memory ledger enforces single use,
  including sequential/concurrent replay, prior-instance replay, and failed
  simulated attempts.
- Added a mandatory simulation broker, a private-capability in-memory target,
  state-precondition enforcement, and separate read-only target observation
  with `VERIFIED`, `FAILED`, `PARTIAL`, `UNEXPECTED_EFFECT`, and
  `ROLLBACK_REQUIRED` classifications. No live or generic target adapter exists.
- Added exact-scope, expiring, single-use human approval through a separately
  resolved opaque human credential. Receipt creation and audit registration are
  atomic and retryable on precommit failure; the signed receipt permits
  reevaluation only and cannot mint an action token or invoke the broker.
- Added correlated lifecycle audit, runtime metrics, two raw-request SOC
  demonstrations, and a deterministic 46-scenario adversarial corpus. The
  published boundary passed 57/57 focused tests, both demonstration acceptance
  checks reported PASS, the corpus reported 46/46, and the complete repository
  suite passed 288/288 locally and in exact-commit CI.
- Reconciled the living engineering, safety, test, traceability, and architecture
  documentation; added the current Phase 3 DOT/PNG/SVG architecture view; and
  generated an inspected paired 7-page Phase 3 candidate DOCX/PDF status
  package. The separately named Phase 2.5 and v0.1 packages remain immutable
  historical artifacts.
- Regenerated and locally verified the candidate integrity manifest across all
  269 other tracked files. This binds the local package bytes but does not
  constitute publication, exact-commit CI, or Phase 2/Phase 3 evaluation
  evidence.
- Candidate review found and closed release blockers across cascading
  consequence, evidence subject-target binding, identity/key-domain handling,
  polymorphic and late-mutable security values, machine-policy safety floors,
  request/token/verifier/approval replay and atomicity, dependency-failure
  closure, and executed-path/post-effect audit correlation. Dedicated negative
  regressions cover these classes; this is not exhaustive assurance.
- Phase 3 remains synthetic and CE-1. Its private-capability controls are not
  OS/process security; ledgers are not durable/distributed; fixture HMAC keys
  are not enterprise provenance; and same-project verifiers are not external
  independence. No live action, operational efficacy, production safety, or
  external assurance is claimed.

## 0.2.0-alpha.6 — published code/package baseline; no P2-CE-005 result

Predecessor design-freeze Commit `08ce203c0965e8d43b7653454d4ea8315996021f` was published on 2026-08-15 and its GitHub CI/Dependency Graph passed. The complete Phase 2.5 package was subsequently published on `main` at exact Commit `854b15c56397a81de6326b719d3d7d1dc847608f`; exact-commit CI and Dependency Graph also passed. Its Phase 2.5 technical suite passed 222/222, the separate public-site module passed 9/9, and the then-current repository aggregate passed 231/231. The site and its tests are not Phase 2.5 or `P2-CE-005` evidence. The package adds bounded campaign/local-run guards, selected Gate B CE-1 scaffolding, documentation, visuals, and status artifacts; its campaign module passed 21/21; its chart check passed in the frozen renderer; and it includes a generated-and-verified integrity manifest plus paired final-source DOCX/PDF renders whose 15 pages were inspected. No tag or release/evidence package was created. The tracked data, model, and `outputs/baseline/` bytes remain at their committed baselines. `P2-CE-005` was not executed or published and remains CE-0 `NOT_EVALUATED`.

- Added a separately implemented, standard-library-only source-to-decision reference path that recomputes the ordered `EVIDENCE`, `MODEL`, `POLICY`, `VERIFIER`, and read-only `FINAL_SURFACE` calculation surfaces from frozen normalized-case, model, and policy bytes.
- Standardized provenance, integrity, freshness, and source-trust aggregation on ordered `math.fsum(values) / event_count`, and model-logit accumulation on ordered `math.fsum` before the intercept and clamped sigmoid, in both production and reference paths.
- Added the closed, metadata-only `source_to_decision_assurance.jsonl` receipt and its schema. Successful rows bind the normalized case, exact model and policy bytes, read-only mode, five expected/observed stage digest pairs, and the ordered path digest; they contain no raw case or decision values.
- Positioned Phase 2.5 after read-only decision validation, deterministic projection, complete eight-stage audit validation, and Phase 2.4 feature recomputation, but before qualification/rejection publication, adjudication decoding, comparison, metrics, and completed-run finalization. A source-to-decision mismatch leaves prior decision/audit files as incomplete diagnostic material and publishes neither reference-assurance artifact.
- Extended exact-digest construction and late-mutation checks across normalized cases, normalization diagnostics, raw and deterministic decisions, audit, both reference receipts, adjudication comparison, replay metrics, and qualification/rejection artifacts when enabled. The complete set is revalidated before manifest construction, after construction, and after the manifest write; presence of an intermediate artifact or manifest file after an exception does not establish a completed run.
- Added Phase 2.5 positive, stage-mutation, duplicate/non-finite input, numeric-summation, case-set, artifact-mutation, and harness-ordering tests. The predecessor design-freeze implementation passed **193/193 tests in a review-local run**, and CI succeeded for exact Commit `08ce203c` on 2026-08-15. The complete package subsequently passed the Phase 2.5 technical suite **222/222**. The separately inherited public-site module passed 9/9, producing a then-current repository aggregate of 231/231 without expanding the Phase 2.5 evidence boundary. Exact package Commit `854b15c` was published and its CI passed. These are narrow CE-1 implementation-conformance observations within their stated boundaries only; they are not `P2-CE-005` campaign evidence, a tagged release, or an alpha.6 evidence package.
- Added a post-design-freeze campaign CLI destination preflight that rejects repository-root/outside/`.git` paths, existing symlink traversal, output/record overlap, nonempty output reuse, and existing record targets before ordinary CLI generation/check operations. Three focused CLI regressions passed 3/3. Check mode additionally rejects symbolic-link, directory, and multiply linked artifact leaves and a symbolic-link record before any artifact read or campaign rebuild. Added a separate negative sensitivity regression for reference-scope construction instrumentation; the campaign module passed 21/21 in an isolated clean clone, and all five campaign-delta tests are included in the 222/222 Phase 2.5 technical suite. Exact package Commit `854b15c` was published and its CI passed. These are operator-error and bounded Python-instrumentation controls, not an OS sandbox, TOCTOU/race guarantee, direct `generate_artifacts` confinement, or campaign evidence.
- Instrumented every campaign reference attempt for construction of `AuthorizationGate`, `ActionBroker`, and `SimulatedIdentityProvider`. The sensitivity regression injects all three, observes nonzero counters, forces an expected-row mismatch, and confirms closed-schema rejection. This is not a general allocation monitor, target-side proof, or an observed `P2-CE-005` result.
- Added a `run_poc.py` write interlock. Ordinary repository writes are limited to `data/local/**` and `outputs/local/**`; explicit external paths remain permitted; and the freeze flag expands scope only to `data/**` and `outputs/baseline/**`. Other repository paths, case-variant repository aliases, symlink redirects, data/output overlap, and existing symlink, nonregular, or multiply linked generated leaves—including `run_manifest.json`—are rejected before generation. The local run manifest SHA-256-binds its seven non-self-referential outputs. Fourteen focused tests passed. This is an operator interlock, not OS/mount containment, adversarial TOCTOU/race or comprehensive hard-link protection, or direct-writer confinement.
- Added CE-1 Gate B causal/observation scaffolding: a validator-owned closed registry of 25 selected `(stage, control_id, reason_code)` identities, exact-match scoring that rejects unclassified failures, and bounded observation over six enumerated Python file APIs. Tests cover 24 selected pre-payload mutations with zero observed `cases` or `adjudications` roles through those APIs and one postqualification threshold identity. This is not a complete failure taxonomy, reference monitor, sandbox, OS-level nonaccess proof, or successor campaign result; no successor campaign has executed.
- Added the fixed `P2-CE-005-SOURCE-TO-DECISION-SYNTHETIC` plan and closed campaign contract: ten clean/mutant pairs per run, two planned deterministic same-process repetitions, 40 planned attempt observations, zero retries/exclusions, and two expected blocks at each recomputation stage per run. Each run generates ten directly instrumented production baselines shared by the clean/mutant twins—ten calls to each of the engine, evidence, model, policy, and verifier components per run, 20 calls to each component across both runs—while the reference path is called once for each of 20 attempts per run, 40 total.
- Separated the campaign's planned directly instrumented boundary counters from derived decision-output accounting. Authorization-gate, broker, target-effect, and scoped artifact-write calls are direct observations if the campaign runs; authorization tokens, action results, and operational effects are derived from serialized decisions. Their required zero values remain predeclared expectations, not observations, while `P2-CE-005` is CE-0.
- `P2-CE-005` remains CE-0 `NOT_EVALUATED`. The plan, expected outcomes, predecessor design-freeze commit and CI result, 222/222 Phase 2.5 technical suite, separate 9/9 public-site module, 231/231 then-current repository aggregate, manifest, inspected renders, publication of exact Commit `854b15c`, and its green CI are not campaign observations. That commit was not executed or published as `P2-CE-005` evidence. CE-2 wording remains prohibited unless a governed Commit A is designated under the frozen protocol, its clean detached campaign runs without repair/retry, and a separate evidence-only Commit B is published and validated.
- Preserved the read-only boundary: no live execution mode, authorization token, broker, target, action credential, or operational effect was added. This increment makes no historical/live performance, source-truth, outcome-correctness, policy-fitness, efficacy, calibration, privacy/authority, OS-isolation, organizational-independence, production-readiness, statistical-failure-bound, alignment, misalignment, sandbagging, or sabotage-robustness claim.

## 0.2.0-alpha.5 — 2026-08-15

- Added a typed, source-authorized contract for all modeled event attributes. JSON Booleans are no longer interpreted through generic truthiness, `failed_logins` accepts only finite integral JSON numbers in the code-owned `0..1,000,000` range, and modeled keys asserted by an unauthorized source fail closed.
- Required every `asset_inventory` event to contain `asset_id`, `privilege_level`, `break_glass`, and `asset_criticality` and to match the canonical case context exactly before the case can reach feature extraction.
- Added a separately implemented in-process reference projector that reconstructs the 20 model feature values and event traces from normalized cases without importing the production extractor, feature-contract implementation, engine, model, policy, verifier, harness, or metrics modules.
- Added the closed, metadata-only `reference_feature_assurance.jsonl` artifact. Each successful case row contains only the case identifier, normalized-case digest, expected and observed projection digests, and `matched=true`; the run manifest hash/count-binds the artifact and metrics report checked, matched, mismatched, and completeness counts.
- Positioned the reference check after read-only decision validation, deterministic decision serialization, and complete eight-stage audit validation, but before qualification/rejection publication, adjudication loading, comparisons, metrics, or completed run-manifest finalization. A mismatch emits no reference-assurance artifact, metrics, or completed manifest; earlier decision and audit files may remain as explicitly incomplete evidence.
- Added schema/runtime differential, positive-fixture, opaque-attribute feature-invariance, event-order metamorphic, exact-inventory-binding, non-finite-number, typed network-only `source_conflict` (including `UNAUTHORIZED_DECISION_SIGNAL` wrong-source classification), duplicate-aware artifact, coherent decision/audit-rehash, strict evidence-number, and validator-entry-point tests. The full local suite now contains 147 passing tests.
- Hardened campaign evidence parsing and serialization to reject duplicate members, `NaN`, positive or negative infinity, and exponent overflow at every JSON and JSONL boundary. Direct-file and module-form claim validation now share the same import-safe execution path.
- Preserved the version boundary for the pre-alpha.5 `P2-CE-001` and `P2-CE-002` bundles: their original narrow claims remain validated against their recorded artifacts, but they contain no reference-feature-assurance artifact and were not retroactively upgraded. New alpha.5 replays require that artifact for completion.
- Froze the corrected `P2-CE-004` implementation and campaign design in Commit `53e409d6ffa4af98ea892bc1a81302bf30870693`, then executed two complete deterministic same-process repetitions of 16 fixed synthetic attempts. All 32 observations matched the commit-frozen, project-controlled expectations with zero retries, exclusions, failures, or deviations: 16 clean matches, eight qualification quarantines, and eight reference-projector blocks. The two sanitized ledgers were byte-identical, and scoped model, policy, verifier, engine, authorization, broker, target-effect, operational-effect, and result-artifact write counters remained zero.
- Published the exact `P2-CE-004` profile, two ledgers, summary, evidence record, and bundle documentation as CE-2 controlled-behavior evidence under `SELF` automated project-controlled review. An initial unpublished package against Commit `1945ff283794c42f8eb649e320ba6adf91a6b982` was withheld after its frozen validator accepted non-finite JSON; it is invalidated, excluded from every claim denominator, and is not evidence. The current package is one new execution against the corrected freeze, not a retry within its denominator.
- Research from Anthropic and OpenAI informs the evaluation design and prohibited inferences; it does not validate this implementation. This increment establishes no historical or live performance, approval, authentication, privacy or custody result, OS-level isolation/non-egress, target-side proof, exhaustive coverage, bounded failure rate, efficacy, production readiness, independent replication, or alignment/misalignment/sabotage-robustness claim.

## 0.2.0-alpha.4 — 2026-08-14

- Strengthened the read-only audit boundary to require exactly one canonical, correctly ordered eight-stage trace per accepted case: `CASE_RECEIVED`, `EVIDENCE_ASSESSED`, `MODEL_ASSESSED`, `POLICY_PROPOSED`, `INDEPENDENTLY_VERIFIED`, `EXECUTION_SUPPRESSED`, `AUTHORIZATION_EVALUATED`, and `DECISION_FINALIZED`.
- Added rejection tests for missing, duplicated, reordered, malformed, extra-field, time/sequence-invalid, suppression-forged, policy-action-forged, decision/hash-mismatched, and duplicate-member audit records.
- Added a fixed, closed-schema `P2-CE-003` Gate B controlled-behavior campaign frozen in implementation Commit `e8aa8b0efc7d54efdf74f49fb3d10ee067f2b49b`.
- Executed two complete repetitions of 16 fixed synthetic scenarios. All 32 observations matched the project-controlled expectations with no exclusions: two validate-only passes, 28 structural pre-payload blocks, and two post-qualification/pre-engine threshold blocks. The two sanitized result ledgers were byte-identical.
- During the 28 structural-block harness invocations, no governed payload-role open/read attempt was observed by the declared `Path`/`os.open` hooks. Across all 32 attempts, no engine, authorization, broker, or target-effect boundary was reached, and no completed run manifest, decision artifact, or audit artifact was observed.
- Added a commit-bound campaign profile, two result ledgers, summary, evidence record, campaign contract, generator/checker, claim-evidence validation profile, negative tests, and documentation. The full local suite now contains 101 passing tests.
- The audit result is CE-1 implementation-conformance evidence; `P2-CE-003` is CE-2 controlled-behavior evidence under SELF automated project-controlled review. Neither establishes a real approval, actual historical-data handling, a live feed or action, OS-level nonaccess/non-egress, target-side proof, exhaustive coverage, an operational failure rate, efficacy, independent assurance, or alignment/misalignment behavior. The two repetitions are not independent statistical trials, and the Commit A freeze is not external preregistration.

## 0.2.0-alpha.3 — 2026-08-14

- Added a closed Gate B authorization-package contract, non-authorizing DRAFT example, ADR, operator guide, and blank pilot, mapping, and adjudication templates.
- Required historical, de-identified input to pass a current five-role approval, independent-review, custody, purpose/scope, time, contract, adapter, model, policy, and protocol-binding preflight before any case or adjudication payload access.
- Added frozen sampling, complete-intake, accepted-case time-window, overall/category quarantine, fatal/unknown-failure, and claim-revalidation controls before engine invocation.
- Confined restricted Gate B inputs to ignored `local/gate_b/` paths and historical outputs to new ignored owner-only `outputs/replay/<run>/` directories; retained directory descriptors for every snapshot and artifact operation so bound replay-ancestor relocation or run-directory substitution fails without redirecting writes.
- Added a path-free historical runner interface using only in-memory accepted cases, model bytes, policy bytes, read-only decisions, and audit rows; no output, snapshot, source, or adjudication path crosses that boundary.
- Deferred adjudication snapshot publication until decisions and boundary-audit checks close, while retaining the exact predecision bytes in a harness-owned frozen buffer so source mutation cannot alter evaluation inputs.
- Rejected duplicate JSON object members in governed control and JSONL records, restricted replay audit rows to the exact code-owned record-type vocabulary, and rechecked authorization validity at payload, runner, post-run, and evidence-finalization boundaries.
- Sanitized missing-path, schema, source-integrity, and post-decision adjudication failures so restricted paths, identifiers, digests, values, and operating-system text are not returned through historical validation or run surfaces.
- Added schema/runtime differential, path/symlink/TOCTOU, parser-resource, binding, privacy/error-surface, pre-payload access, stop-condition, label-separation, snapshot, and zero-effect tests.
- This increment establishes CE-1 implementation existence only. It does not approve a Gate B package, process organizational historical data, validate external authority or de-identification, or establish historical efficacy, operational readiness, live-shadow safety, or action safety.

## 0.2.0-alpha.2 — 2026-08-14

Phase 2.1 bounded record qualification and quarantine increment.

- Added the code-owned `FAIL_DATASET` and offline-historical-only `QUARANTINE_RECORD` failure policies; shadow-read-only input remains fail-dataset.
- Added bounded binary JSONL qualification with deterministic run identity, physical/nonblank line accounting, exact raw-line SHA-256 traceability, and sanitized typed outcomes.
- Added closed metadata-only qualification and rejection schemas that cannot carry source payloads, identifiers extracted from payloads, exception text, or free-form rejection messages.
- Added fatal whole-file handling for source-read, integrity, encoding, line-size, JSON-nesting, contract-version, label-contamination, duplicate-identifier, record-count, and unmapped-validator failures.
- Added deterministic `qualification_accounting.jsonl` and `rejections.jsonl` artifacts, run-manifest bindings, reason counts, and the invariant `input = accepted + quarantined` with one decision per accepted case.
- Added a predeclared seven-record synthetic campaign: three accepted controls and four quarantined records covering invalid JSON, a missing field, an invalid timestamp, and canonical-context disagreement.
- Added a deterministic fixture generator/checker with reviewed-source digests, confined target sets, single-read source hashing, and symlink/hard-link write protections.
- Added qualification unit, integration, tamper, determinism, privacy, parser-resource, source-fault, fatal-boundary, and regression tests while retaining zero authorization tokens, zero broker invocations, and zero operational effects.
- Hardened validate-only processing so adapter substitution and an empty accepted set fail before a `VALID` result is returned.
- Hardened claim-evidence validation by recomputing the shared read-only decision and audit invariants and cross-binding raw decisions, deterministic projections, adjudication comparisons, metrics, model, policy, and execution scope.
- Added qualification architecture, data-contract, validation, privacy, survivorship-bias, research-evidence, and historical-pilot-gate documentation.
- Added the validated `P2-CE-002` evidence record and exact 17-artifact run bundle for the fixed seven-record synthetic campaign.

This increment uses synthetic records only, reports `historical_case_count: 0`, and does not establish historical efficacy, agentic alignment, live-shadow readiness, or authority to connect to an operational environment.

## 0.2.0-alpha.1 — 2026-08-14

Phase 2 historical-replay and shadow-mode starter.

- Added code-owned `synthetic_simulation`, `historical_replay`, and `shadow_read_only` execution modes; no live mode exists.
- Removed authorization-gate, broker, and target construction from read-only modes and retained proposed actions only as counterfactual records.
- Added versioned replay-contract, adapter, normalization, integrity-manifest, metrics, and harness scaffolding.
- Added fail-closed governance, label-separation, path-confinement, digest, record-count, timestamp, uniqueness, range, and canonical-context consistency checks.
- Added frozen run-input snapshots and before/after digest checks to bind the exact configuration, manifest, model, policy, cases, and adjudications used.
- Added strict read-only decision validation, decision-record hash recomputation, and one-to-one suppression, authorization, and finalization audit binding.
- Added a clearly synthetic Phase 2 starter fixture; no historical organizational data is included.
- Added Phase 2 requirements traceability, architecture, safety, data-contract, validation, and research-informed claim-evidence documentation.
- Added an evaluation-evidence schema, worked synthetic evidence record, and adversarial-evaluation matrix; these constrain public claims rather than establishing operational efficacy.
- Added regression tests and public-repository continuous integration while keeping live actions disabled.

## 0.1.0 — 2026-08-14

Initial working engineering baseline.

- Added deterministic synthetic scenarios for privileged-identity containment decisions.
- Added separate runtime case and evaluator-only label datasets.
- Added evidence trust, provenance, freshness, conflict, and poisoning assessment.
- Added interpretable advisory logistic model and allow-listed structured features.
- Added deterministic four-disposition policy and independent verifier.
- Added scoped short-lived authorization tokens and simulated reversible actions.
- Added post-action verification, deliberate downstream failure injection, and hash-chained audit logging.
- Added automated safety tests, evaluation outputs, architecture diagrams, requirements traceability, and engineering documentation.
- Restricted the release to synthetic data and simulated actions; production integration is explicitly prohibited.
