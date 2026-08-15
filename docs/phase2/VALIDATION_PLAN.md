# Phase 2 Validation Plan

> **Release boundary.** Exact Phase 2.5 Commit
> `854b15c56397a81de6326b719d3d7d1dc847608f` is published on `main`; its
> exact-commit CI and Dependency Graph checks passed. The package boundary
> records 222/222 Phase 2.5 technical tests, separate 9/9 public-site tests, and
> a then-current 231/231 aggregate. Site tests are outside Phase 2.5 validation
> and evidence. These observations support narrow CE-1 conformance wording
> only. `P2-CE-005` was not executed or published and remains CE-0
> `NOT_EVALUATED` until its separate frozen two-commit campaign completes.

## Validation objective

Validation must establish whether the built-in Phase 2 path can reject untrusted or ungoverned replay inputs, produce traceable counterfactual decisions from accepted records, account for every input, and maintain zero authorization-token issuance, zero broker invocation, and zero operational effects under the exact tested configuration.

The current evidence base contains only synthetic fixtures with `historical_case_count=0`: the three-case starter, the seven-record Phase 2.1 qualification campaign, the ephemeral test-only inputs used by the fixed Phase 2.3 Gate B campaign, and the generated inputs used by the fixed Phase 2.4 feature-assurance campaign. Phase 2.4 has CE-1 implementation tests plus a separate CE-2 `P2-CE-004` controlled-behavior result against corrected Commit `53e409d6ffa4af98ea892bc1a81302bf30870693`. Phase 2.5 adds CE-1 source-to-decision implementation tests; its planned `P2-CE-005` campaign remains CE-0 `NOT_EVALUATED`. Historical efficacy, historical calibration, historical acceptance rates, and analyst-agreement claims remain unavailable.

## Evidence hierarchy

Phase 2 uses six complementary evidence types:

1. **Static architecture inspection** confirms that no live mode, production connector, action credential, or action-enable parameter exists.
2. **Execution-guard unit tests** prove that read-only modes do not construct or call the authorization gate, broker, or target.
3. **Contract and qualification unit tests** exercise structure, semantics, governance, path confinement, digest verification, label separation, bounded parsing, code-owned fatal/quarantine classification, metadata privacy, and deterministic accounting.
4. **Replay integration tests** verify frozen-input integrity, qualification/rejection artifacts, record accounting, normalization, counterfactual output, decision/audit binding, metrics, and failure behavior.
5. **Claim-evidence records** bind the exact public wording to the system, harness, data origin, raw counts, artifacts, validity checks, limitations, review state, and prohibited inferences.
6. **Governance review evidence** authorizes any future historical or live read-only use; software tests cannot substitute for data-owner, privacy/legal, security, or mission approval.

## Test levels

### Execution-boundary tests

`tests/test_execution_modes.py` must cover both `historical_replay` and `shadow_read_only` with an automation-eligible high-risk case. Tests patch the authorization gate, simulator, and broker constructors to raise if reached. Required assertions include:

- a counterfactual containment recommendation is preserved;
- `proposal.executable_actions` is empty;
- `authorization.issued` is false;
- `action_results` is empty;
- post-action verification is explicitly `NOT_APPLICABLE`, with `passed: null`;
- `execution_control.status` is `SUPPRESSED_READ_ONLY`;
- `authorization_attempted` is false;
- `broker_invocations` and `operational_effects` are zero;
- `EXECUTION_SUPPRESSED` is present in the audit;
- `ACTION_EXECUTED` is absent;
- no live mode or live-enablement parameter exists;
- the original v0.1 synthetic-simulation behavior remains available only through its explicit mode.

### Contract and governance tests

The contract-validation plan covers the following cases. Implemented versus remaining coverage is recorded in the requirements traceability matrix:

- a valid synthetic starter manifest and case;
- unsupported or missing contract versions;
- malformed JSON and missing required fields;
- duplicate record, case, and event identifiers;
- event-to-parent case-ID mismatch;
- nonfinite or out-of-range trust and criticality values;
- timezone-naive, malformed, and policy-invalid timestamps;
- missing historical approval or de-identification attestation;
- embedded labels, expected dispositions, ground truth, or adjudication;
- canonical break-glass and asset-criticality disagreement;
- missing or mismatched canonical asset ID, privilege level, break-glass state, or asset criticality in any asset-inventory event;
- wrong-type, non-finite, fractional, negative, or over-bound modeled values and modeled keys asserted by unauthorized sources;
- unrecognized opaque attributes that must not change the 20-feature values or traces;
- Boolean/network-only `source_conflict` handling as an explicit evidence-quality input outside reference feature recomputation;
- non-finite JSON numbers at any nesting depth, including otherwise opaque attributes;
- valid out-of-order events that normalize with a retained warning;
- absolute, traversal, symlink-escape, and otherwise out-of-scope paths;
- case or adjudication digest and record-count mismatch.

### Record-qualification tests

`tests/test_replay_qualification_unit.py` and `tests/test_replay_qualification.py` cover:

- exact classification of reviewed ordinary record-local defects into sanitized category/code pairs;
- fatal whole-call behavior for source-read faults, invalid UTF-8, record-count overflow, a full physical line over the encoded limit, excessive JSON nesting, unsupported record version, runtime-label contamination, duplicate case/event identifiers, source-digest mismatch, and unmapped validator failure;
- the distinction between a line-size bound that includes LF/CRLF and a raw-line digest that excludes only that delimiter;
- deterministic qualification identity and byte-stable ledger/rejection output;
- absence of rejected payload, payload identifiers, exception text, and free-form messages from result and error representations;
- schema validation for accepted and quarantined metadata records;
- exact source physical-line, nonblank-ordinal, file-digest, and raw-line-digest correspondence;
- rejection artifact equality with the ordered quarantined ledger projection;
- forged, incomplete, or internally inconsistent accounting rejected before engine invocation; and
- the predeclared campaign result `7 input = 3 accepted + 4 quarantined`, with three decisions and zero tokens, brokers, or effects.

`tests/test_qualification_fixture_generator.py` separately verifies that the reviewed fixture source is hashed from the single byte string that is parsed, and that symbolic-link directory redirection and hard-linked target overwrite attempts fail closed.

### Gate B preflight tests

`tests/test_gate_b.py` verifies the Phase 2.2 implementation boundary with test-only control packages and no organizational historical data:

- missing, DRAFT, expired, malformed, mismatched, nonhistorical, and unsafe packages abort before any case or adjudication open, hash, count, decode, or parse in both validation and run paths;
- exactly one `APPROVED` assertion is required for each of `DATA_OWNER`, `MISSION_OWNER`, `SECURITY`, `PRIVACY_LEGAL`, and `RECORDS_MANAGEMENT`, together with an `APPROVED` review whose asserted reviewer identifier differs from all asserted approver identifiers;
- every critical Boolean, manifest/model/policy/contract/adapter binding, protocol digest, count, time relation (including `window_end <= custody.frozen_at <= valid_from`), status, and review state fails closed when mutated;
- schema and runtime agree on integral JSON numbers, whitespace, path syntax and length, and declared bounds;
- control JSON nesting, mapping/protocol size, model/policy size, confined-path, nonsymlink, no-hardlink, and output-custody limits are enforced;
- resolved artifacts are opened without following a swapped final-component symlink, and frozen controls are revalidated before and after the runner;
- injected paths, digests, operating-system errors, unexpected member names, and values are absent from public error surfaces;
- missing private configuration paths, missing qualification schemas, and post-preflight integrity failures are converted to bounded historical errors in both validate-only and run paths;
- historical output is restricted to an ignored `outputs/replay/<run>/` directory with owner-only directory and file permissions; descriptor-bound writes reject ancestor relocation, run-directory substitution, symlink targets, and hard-linked artifacts rather than following a changed display path;
- after authorized qualification, accepted-case windows and exact-decimal overall/category quarantine thresholds stop the run before normalization or engine invocation; and
- duplicate JSON object members are rejected in governed control and JSONL inputs, and authorization expiry at a staged runner boundary prevents a completed run manifest;
- the historical runner receives only in-memory accepted cases, model bytes, policy bytes, and the read-only execution mode; label bytes and all filesystem/output paths are excluded until decision/audit closure, while the completed test path retains zero authorization attempts/tokens, broker invocations, action results, and operational effects.

These tests support the CE-1 statement that the preflight controls exist in the identified commit. They do not establish real approver authority, signature validity, de-identification effectiveness, custody truth, organizational authorization, or historical performance. The separate fixed campaign below supports a narrower CE-2 controlled-behavior statement; it does not elevate these external or operational nonclaims.

The published Phase 2.5 package additionally exercises a closed registry of 25 selected causal identities: 24 selected pre-payload mutations and one post-qualification threshold identity. Classified failures must match exact closed tuples; unclassified Gate B errors remain unscorable. A bounded observer recorded zero `cases` or `adjudications` roles for the 24 selected pre-payload mutations under `builtins.open`, `io.open`, `os.open`, `Path.open`, `Path.read_bytes`, and `Path.read_text`. Hard-link aliases to governed files are explicitly outside the monitor boundary. This is CE-1 instrumentation scaffolding only. It is not a complete failure taxonomy, OS-level nonaccess/non-egress proof, sandbox, reference monitor, or campaign result.

### Phase 2.3 Gate B controlled-behavior campaign

[`P2-CE-003`](../../contracts/v0.2.0/examples/phase2-gate-b-ce2-evidence-record.json) binds the exact generator, plan, schema, validator, Gate B implementation, contracts, harness, fixtures, model, policy, runtime fingerprint, seed, budget, scenario order, expected outcomes, and implementation Commit [`e8aa8b0`](https://github.com/redxking/ai-decision-firewall/commit/e8aa8b0efc7d54efdf74f49fb3d10ee067f2b49b). The fixed design executes two complete repetitions of the same 16 project-selected synthetic scenarios:

- one test-only validate-only positive control per repetition;
- 14 single-mutation structural negative controls per repetition that are expected to block before governed payload access;
- one quarantine-threshold control per repetition that is expected to open both governed payload roles, qualify the cases, and stop before normalization or engine invocation; and
- zero permitted decision-engine, authorization, broker, or target-effect boundary calls.

The published campaign observed 32/32 matches with no exclusions: two validate-only passes, 28 structural pre-payload blocks with no governed payload-role open/read attempt observed by the declared `Path.open`, `Path.read_text`, `Path.read_bytes`, and `os.open` hooks during the harness invocation, and two post-qualification/pre-engine threshold blocks. The two sanitized 16-row result ledgers were byte-identical. No engine, authorization, broker, or target-effect boundary was reached, and no completed run manifest, decision artifact, or audit artifact was observed. The exact artifacts and their custody limits are listed in the [`campaign bundle`](../../evidence/phase2_gate_b_ce2/README.md).

This is a CE-2 `CONTROLLED_BEHAVIOR` result under `SELF` automated project-controlled review. It uses no real approval or actual historical data and authorizes no live feed or action. The two executions are repetitions, not independent or statistically representative trials; Commit A is a public project-controlled freeze, not external preregistration; the mutation set is not exhaustive; the open/read hooks do not establish OS-level nonaccess or non-egress; boundary counters do not provide target-side proof; and 32/32 does not estimate an operational failure probability, demonstrate efficacy, or establish alignment/misalignment behavior.

### Phase 2.4 feature-assurance tests and controlled campaign

`tests/test_feature_contract.py`, `tests/test_reference_features.py`, and the replay-harness tests establish the following CE-1 implementation-conformance boundary in the current checkout:

- every modeled Boolean requires an exact JSON Boolean and a code-authorized source role;
- `failed_logins` requires a finite integral JSON number in `0..1,000,000`, accepting integral representations such as `10.0` while rejecting Boolean, string, fractional, non-finite, negative, and over-bound values;
- every asset-inventory event contains and exactly matches canonical `asset_id`, `privilege_level`, `break_glass`, and `asset_criticality`;
- bounded opaque attributes do not alter the 20-feature values or traces;
- `source_conflict` is accepted only as a network Boolean and remains explicitly outside the projector's evidence-quality scope; `QUARANTINE_RECORD` assigns `SEMANTICS / UNAUTHORIZED_DECISION_SIGNAL` to a wrong-source assertion and `SEMANTICS / INVALID_BOOLEAN` to a non-Boolean network assertion;
- valid event permutations normalize to the same projection and canonical trace;
- the separately implemented in-process projector reconstructs all 20 feature values and traces without importing the production feature/contract/engine/model/policy/verifier/harness/metrics calculation path;
- exact/unique case sets and normalized-case bindings are required; and
- coherent feature-value, feature-trace, source-context, decision-hash, and fully rechained audit mutations that pass the legacy read-only/audit validators are rejected before evaluation completion.

The reference check runs only after read-only decision validation, deterministic decision serialization, and complete eight-stage audit validation. On mismatch, no `reference_feature_assurance.jsonl`, qualification/rejection publication, adjudication comparison, metrics, or completed run manifest is emitted. Earlier raw/normalized/deterministic decisions and audit may remain and must be classified as incomplete evidence. On success, a closed metadata-only row is emitted per case and the run manifest hash/count-binds it and its checked/matched counts.

Each assurance row binds the normalized case with SHA-256 over the UTF-8 bytes of `json.dumps(normalized_case, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False)` and no trailing newline. Accepted cases have already passed the all-number finiteness gate.

The fixed [`P2-CE-004`](../../contracts/v0.2.0/examples/phase2-feature-assurance-ce2-evidence-record.json) plan specified two deterministic same-process 16-attempt repetitions, each containing eight clean matches, four qualification quarantines (`INVALID_BOOLEAN`, `INVALID_TYPE`, and two `UNAUTHORIZED_MODELED_SIGNAL` cases), and four `REFERENCE_FEATURE_PROJECTION_MISMATCH` blocks covering feature-value, feature-trace, input-event-order, and cross-case named-feature-value rehashes. Against corrected Commit `53e409d6ffa4af98ea892bc1a81302bf30870693`, all 32 observations matched those expectations with zero retries, exclusions, failures, or deviations, and the two sanitized ledgers were byte-identical. The exact [`campaign bundle`](../../evidence/phase2_feature_assurance_ce2/README.md) is CE-2 under SELF automated project-controlled review. The repetitions are neither independent nor fresh statistical trials.

An earlier unpublished package against Commit `1945ff283794c42f8eb649e320ba6adf91a6b982` was withheld after its frozen validator accepted non-finite JSON. It is invalidated, excluded from every claim denominator, and is not evidence. The current result is one new execution against the corrected freeze, not a retry within its denominator.

The committed `P2-CE-001` and `P2-CE-002` bundles predate alpha.5 and omit both current reference-assurance artifacts. Their original narrow claims remain version-bound and validated as recorded; they are not later-phase evidence. Any new alpha.6 replay must emit and bind both receipts and complete all final revalidation before the replay is complete.

### Phase 2.5 source-to-decision tests and planned campaign

The source-to-decision reference path must be tested independently of any campaign claim. CE-1 coverage requires:

- exact frozen-byte, duplicate-member, non-finite-number, closed-shape, range, identifier, timestamp, and equal-case-set validation;
- code-owned ceilings of 64 MiB per model/policy document, 512 MiB per JSONL input, one MiB per line, 100,000 records, depth 128, 10,000 events/case, 16,384 untrusted-text characters, 256 KiB per attributes/training-metadata object, and 256 limitations entries/64 KiB total;
- successful reconstruction of the ordered `EVIDENCE`, `MODEL`, `POLICY`, `VERIFIER`, and `FINAL_SURFACE` stages;
- deterministic ordered `math.fsum(values) / event_count` evidence-aggregate controls, including a rounding-sensitive ten-event trust-score case;
- deterministic ordered `math.fsum` model-logit controls, including cancellation-heavy valid parameters;
- coherent stage-specific mutations that rehash the decision and rechain the audit while first passing the legacy read-only decision validator, exact eight-stage audit check, and Phase 2.4 feature projector;
- receipt completeness, uniqueness, sort order, normalized-case/model/policy/mode binding, stage/path digest equality, schema closure, and metadata-only shape;
- mismatch behavior before either receipt, qualification/rejection publication, adjudication decoding, comparison, metrics, or completed-run finalization; and
- exact-digest and late-mutation checks for normalized cases, normalization diagnostics, raw and deterministic decisions, audit, both reference receipts, adjudication comparison, replay metrics, and qualification/rejection artifacts when enabled, including revalidation before manifest construction, after construction, and after manifest write.

The semantic receipt deliberately excludes volatile `decision_id`, `created_at`, `latency_ms`, and `decision_record_hash`. The completed run manifest separately co-binds the raw decision and eight-stage audit. Tests must not treat a receipt alone, or a manifest file left by a failed late check, as a complete run or custody proof.

The published Phase 2.5 package also requires a bounded campaign CLI destination preflight. Exact regressions verify acceptance of absent or empty repository-confined output and absent record destinations; rejection of repository-root, outside-repository, `.git`, symlink-traversing, and overlapping destinations; preservation of an existing nonempty output or record; and rejection of an outside destination before campaign execution. Check mode additionally requires singly linked regular artifact and optional record leaves, rejects symbolic-link, directory, and multiply linked artifact leaves before any artifact read or campaign rebuild, and size-checks before reading. The three focused CLI regressions passed 3/3, and `test_check_rejects_unsafe_leaf_aliases_before_read_or_rebuild` covers the check-mode leaf control. A separate sensitivity regression injected construction of `AuthorizationGate`, `ActionBroker`, and `SimulatedIdentityProvider` during a reference attempt, observed nonzero counts and an expected-row mismatch, and proved the closed schema rejects the row. The full campaign module passed 21/21; these five campaign-delta tests are included in the 222/222 Phase 2.5 technical suite. The separate public-site tests are outside these validation claims. Exact Commit `854b15c` and its CI passed. These claims cover CLI operator-error handling and the named Python constructor sensors only; they do not establish OS/mount containment, adversarial TOCTOU or race resistance, same-user process isolation, direct `generate_artifacts` confinement, general allocation monitoring, target-side proof, or campaign evidence.

The same published Phase 2.5 boundary includes the `run_poc` entry-point interlock. Ordinary repository writes are limited to `data/local/**` and `outputs/local/**`; the explicit freeze flag expands only to `data/**` and `outputs/baseline/**`. Preflight covers every generated leaf, including `run_manifest.json`, rejects redirects and unsafe existing leaves, and the local manifest SHA-256-binds its seven non-self-referential outputs. Fourteen focused methods passed within the 222/222 Phase 2.5 technical suite and exact `854b15c` CI passed. Ordinary singly linked regular leaves under an allowed destination may be replaced. This is a bounded operator-error guard, not OS/mount containment, TOCTOU/race resistance, comprehensive hardlink defense, direct-writer confinement, or a general no-clobber control.

The fixed `P2-CE-005-SOURCE-TO-DECISION-SYNTHETIC` plan specifies ten clean/mutant pairs per run and two deterministic same-process runs: 40 planned attempt observations, zero retries, and zero exclusions. Each run expects ten clean matches and exactly two reference blocks at each ordered stage. One directly instrumented production baseline is generated per pair and shared by its clean/mutant twins, yielding ten baseline executions and ten calls to each production component per run, 20 of each across the campaign. The reference path is called for every attempt, yielding 20 calls per run and 40 total. Direct authorization-gate/broker/target-effect/scoped-write counters are distinct from derived serialized-decision fields for authorization tokens, action results, and operational effects. The plan requires both groups to be zero, but these are expectations, not observations.

The campaign may advance from CE-0 only through the two-commit protocol: final Commit A freezes implementation, plan, schema, generator, validator, and CLI destination-confinement controls; a clean detached checkout of that exact commit runs with no retries; any actor/task/scorer/validator defect invalidates the package; and a separate Commit B publishes evidence only. Published package Commit `854b15c` contains the intended controls and green CI, but it was not designated or executed as governed `P2-CE-005` Commit A. The claim validator must bind any future final Commit A and freshly rerun the frozen evaluator. Until then, no pass rate, result ledger, CE-2 claim, or broader inference is permitted.

### Replay-harness tests

`tests/test_replay_harness.py` is the required starter evidence for:

- complete success against the synthetic fixture;
- `historical_case_count=0` retained in the run evidence;
- a manifest-integrity failure aborts before any decision is emitted;
- the exact configuration, manifest, model, policy, cases, and adjudications are frozen in a run snapshot and reverified after execution;
- historical adjudication bytes may be integrity-frozen inside the harness, but their path and contents are withheld from the runner and they are decoded and semantically loaded only after decisions and boundary-audit checks close;
- every accepted case retains evidence-ID traceability;
- semantically equivalent runs produce equivalent decisions after excluding time, latency, UUID, and run-ID fields;
- the output audit chain verifies and every accepted case has exactly one canonical eight-stage trace in the required order; exact row/payload shapes, global sequence and aware/nondecreasing timestamps, code-owned suppression content, frozen-policy action bindings, decision identifiers, and decision hashes are cross-checked; missing, duplicate, reordered, forged, malformed, and duplicate-member records fail closed; and
- token/decision-hash residue and any non-applicable post-action success claim are rejected;
- authorization, broker, and operational-effect counters remain zero.

The following remain planned, not current evidence:

- source-completeness, collection-delay, and quarantine-distribution measures against an approved historical mapping;
- independent reconstruction of normalized cases from accepted source occurrences in the standalone claim-evidence validator;
- missingness and survivorship-bias analysis by authorized source, time, population, and consequence strata;
- explicit historical-unavailability reason objects in a future origin-stratified metrics contract; and
- independent review and a claim-evidence record specific to any historical qualification result.

The default `FAIL_DATASET` policy still treats all runtime cases as one validation unit. The cases-only `QUARANTINE_RECORD` policy is implemented only for offline `HISTORICAL_REPLAY`: reviewed record-local defects can be quarantined, but source-read, integrity, encoding, line-size, JSON-nesting, version, label-contamination, duplicate-identifier, record-count, and unmapped-validator failures abort the complete qualification call. Adjudications remain a separate post-decision validation unit; any invalid adjudication aborts comparisons and metrics after preserving decision and audit evidence.

## Starter release criteria

The Phase 2 starter is acceptable for public release only when the implemented gates below pass and deferred requirements remain explicitly labeled as planned:

| Gate | Acceptance criterion | Starter disposition |
|---|---|---|
| Data boundary | Repository fixture is synthetic and input manifest reports `historical_case_count=0` | Required |
| Execution boundary | Both read-only modes issue zero tokens, invoke zero brokers, and attempt zero effects | Required |
| No live capability | No live mode, write-capable connector, action credential, or enablement override exists | Required |
| Integrity | Referenced file digests/counts verify, exact inputs are snapshotted, and snapshot integrity verifies before and after engine execution; mismatch aborts | Required |
| Path safety | Manifest-relative paths cannot escape the manifest directory | Required |
| Contract safety | Governance, integrity, label-contamination, version, duplicate, bound, and unmapped failures abort; only reviewed record-local defects may be quarantined under the explicit offline policy | Required |
| Whole-dataset accounting | Every declared file count and accepted case-to-decision count reconciles | Required |
| Qualification accounting | Under `QUARANTINE_RECORD`, `input_records = accepted_records + quarantined_records`, the rejection artifact is the exact quarantined projection, and accepted cases equal decisions | Required for Phase 2.1; observed as 7 = 3 + 4 in the synthetic campaign |
| Qualification privacy | Ledger, rejection, expectation, and fatal-error surfaces contain metadata only and do not echo source payload or raw validator text | Required for Phase 2.1 |
| Historical preflight | Historical origin requires a current, exact Gate B package and owner-only ignored paths before payload access; observed window/rate gates pass after qualification but before the engine | Required for Phase 2.2 implementation; no real package or pilot is approved |
| Selected Gate B causal identity and observation | Exact closed tuples for 25 selected identities; 24 selected pre-payload mutations observe zero governed payload roles under enumerated Python APIs; one post-qualification threshold identity | CE-1 scaffolding only; unclassified errors unscorable; not complete taxonomy, OS nonaccess, or campaign evidence |
| Historical label boundary | Adjudication bytes may be frozen within the harness, but are neither passed nor made path-discoverable to the built-in runner and are decoded only after decisions close | Required for Phase 2.2; same-process isolation limitation retained |
| Traceability | Every accepted decision's cited and feature-linked event IDs resolve to accepted input events | Required |
| Audit | Exactly one canonical, ordered eight-stage trace exists per accepted case; decision/policy bindings and the presented hash chain verify | Required CE-1 implementation conformance, with independent-recomputation, time, and custody limitations |
| Typed structured-input boundary | Exact type/range and source authority for modeled attributes; all case numbers finite; network-only Boolean `source_conflict`; exact four-field inventory binding; unrecognized opaque attributes remain feature-inert | Required CE-1 implementation conformance for Phase 2.4 |
| Reference feature projection | One separate 20-feature value/trace match per accepted case; mismatch stops before evaluator, metrics, and completed manifest; matched artifact is closed and bound | Required CE-1 implementation conformance for Phase 2.4; not full source-to-decision validation |
| Feature-assurance controlled behavior | Fixed, commit-bound 16-attempt x two-repetition campaign with raw artifacts, repeatability, and claim record | `P2-CE-004`: 32/32 project-controlled expected-outcome matches, zero retries/exclusions, byte-identical ledgers; SELF-reviewed CE-2 only |
| Source-to-decision recomputation | One separate match per accepted case across evidence, model, policy, verifier, and read-only final semantic surfaces; receipt and exact raw/audit instances co-bound by the completed manifest | Required CE-1 implementation conformance for Phase 2.5; same-process/project, not independent assurance |
| Source-to-decision controlled behavior | Fixed exact-commit 20-attempt x two-run campaign, full denominator, stage outcomes, repeatability, and evidence-only publication | CE-0 `NOT_EVALUATED`; planned values are not observations and no CE-2 claim exists |
| Gate B controlled behavior | Fixed, commit-bound synthetic positive/negative campaign reports raw denominators, boundary observations, repeatability, and nonclaims | `P2-CE-003`: 32/32 project-controlled expected-outcome matches across two repetitions; CE-2 only |
| Compatibility | All Phase 1 tests continue to pass | Required |
| Claim discipline | A schema-valid evidence record states the exact supported wording, data origin, validity status, limitations, and prohibited inferences | Required |
| Nonclaims | Synthetic evaluation is not described as historical or operational performance | Required |

An audit-validity result alone does not satisfy the integrity gate because the current chain is not independently anchored.

## Metrics and diagnostics

The implemented `replay_metrics.json` reports:

- cases evaluated, adjudicated-case count, and adjudication coverage;
- qualification input, accepted, rejected, and decision counts; complete-accounting status; rejection-reason counts; historical-availability flag; and denominator note when qualification is enabled;
- declared `data_origin` and `historical_case_count` carried from the validated manifest;
- disposition counts and counterfactual-action count;
- adjudicated-disposition match count and rate when adjudications are present;
- threshold-0.5 confusion counts, accuracy, and Brier score when adjudications are present;
- authorization-token issuance count;
- broker-invocation count;
- operational-effect count;
- action-result count and the two label-separation assertions recorded by the harness;
- enforced audit validation, presented-chain validity, total audit records, execution-suppression, authorization-evaluation, and decision-finalization record counts, and `ACTION_EXECUTED` record count.
- reference-feature cases checked, matched, mismatched, and completeness status, with a narrow statement that the boundary covers only serialized feature values and traces.
- source-to-decision cases checked, matched, mismatched, and completeness status, with the exact `EVIDENCE_MODEL_POLICY_VERIFIER_READ_ONLY_FINAL` scope and same-process/project limitation.

The implemented `normalization_diagnostics.json` reports case and event counts, source-mapping warning count, temporal-reordering warning count, total warning count, and case-specific warning records. The run manifest records digests for every snapshotted input and deterministic artifact and binds the current run's volatile raw decisions and audit log with separate digests and counts. Those volatile digests vary across runs because their records contain timestamps, UUIDs, latency, and chain values. Audit-chain verification is separate evidence and retains the custody limitation below.

The following metrics remain planned for an approved historical-replay evaluation:

- historical acceptance/quarantine rates and rejection-reason distribution by approved source and time strata;
- required-field completeness, unmapped-field counts, and missing expected-source rate;
- collection-delay p50 and p95;
- evidence decision-grade and evidence-ID traceability rates;
- calibration error and reliability bins;
- counterfactual containment precision;
- false-containment rate among adjudicated benign cases;
- analyst/system agreement;
- raw analyst agreement and Cohen's kappa;
- Wilson confidence bounds for proportions.

Future results must be stratified by synthetic versus historical origin and must not be combined into a single efficacy figure. The current files evaluate synthetic adjudications and synthetic qualification behavior only. Because both manifests declare `historical_case_count=0`, those values are not historical-performance or historical-quality evidence. When no adjudications are present, the implemented rate, accuracy, and Brier fields are `null`; zero confusion counts do not establish measured historical performance. Decision metrics over accepted records must retain the complete intake and quarantine counts next to them.

## Claim and adversarial-evaluation rules

Passing tests support only the claim those tests were designed to evaluate. Every release result must use the claim class, evidence-record fields, statistical rules, and prohibited wording in [`CLAIM_EVIDENCE_STANDARD.md`](CLAIM_EVIDENCE_STANDARD.md). The machine-readable contract is `contracts/v0.2.0/evaluation-evidence.schema.json`. `P2-CE-001` covers the three-case synthetic starter, `P2-CE-002` covers only the fixed seven-record qualification campaign and its accepted subset's read-only invariants, `P2-CE-003` covers only the fixed two-repetition synthetic Gate B registry and declared instrumentation, and `P2-CE-004` covers only the fixed two-repetition synthetic typed-feature/reference-projection registry. Those four are CE-2 controlled-behavior records under SELF review; none is historical, operational, alignment, or production evidence. `P2-CE-005` is a CE-0 plan with no observed result. The Phase 2.5 reference path is CE-1 same-process/project calculation-consistency evidence only and provides no source-truth, policy-fitness, efficacy, external time/custody, or independence evidence.

The adversarial matrix in that standard derives future test families from Anthropic and OpenAI research: goal conflict, evaluation awareness, instruction/evidence poisoning, reward and test hacking, code sabotage, oversight undermining, sandbagging, hidden-objective audit, long-horizon state manipulation, human-decision sabotage, monitor effectiveness, and independent operational-effect proof. The current deterministic POC implements only a subset. It contains no autonomous generative-language-model agent, so it makes no claim about alignment, scheming, sabotage resistance, or monitor recall.

For any later repeated behavioral evaluation, report raw numerators and denominators, exclusions, representative failures, configuration-specific results, and uncertainty only where sampling assumptions are justified. A `0/n` observation is not zero risk. Synthetic, historical, and live-shadow results must remain separate.

## Release gates

### Gate A: Public starter

Required evidence:

- all Phase 1, Phase 2 starter, Phase 2.1 qualification, Phase 2.2 Gate B, Phase 2.3 audit/campaign, Phase 2.4 feature-assurance, and Phase 2.5 source-to-decision tests pass; the final frozen count is recorded only after Commit-A verification and CI;
- no credential or production endpoint is present;
- fixture provenance and synthetic status are documented;
- public files contain no historical or direct-identifier data;
- requirement statuses match the committed implementation;
- each supported public result has a schema-valid evidence record and its deterministic artifact hashes match a clean run;
- security and integrity limitations remain adjacent to relevant results.

Passing Gate A authorizes only publication of the starter code and synthetic fixture.

### Gate B: Approved historical replay

Before any historical record is processed, the structural Gate B preflight requires:

- top-level `APPROVED` status, an `APPROVED` independent review, and exactly one approved assertion from each of `DATA_OWNER`, `MISSION_OWNER`, `SECURITY`, `PRIVACY_LEGAL`, and `RECORDS_MANAGEMENT`;
- documented external de-identification, access, retention, deletion, incident-response, isolation, egress, kill-switch, and custody evidence;
- exact manifest, dataset, model, policy, contract, adapter, source-mapping, adjudication-protocol, and pilot-protocol byte bindings;
- a temporal holdout, frozen sampling method, complete-intake and sample counts, separated adjudication, indeterminate-outcome rule, and predeclared stop conditions;
- confined nonsymlink restricted inputs under ignored `local/gate_b/`, owner-only output under ignored `outputs/replay/<run>/`, and restricted handling for source and raw-line hashes; and
- complete negative-control evidence that any missing, stale, malformed, mismatched, unsafe, or unknown structural condition stops before payload access.

After that structural preflight permits qualification, but before normalization or engine invocation, the runtime must require every accepted case to fall inside the approved half-open window and every observed overall/category quarantine rate to remain at or below its predeclared threshold. An unknown observed category fails closed. Complete-intake, quarantined, fatal, excluded, adjudicated, indeterminate, and missing-label counts remain visible alongside accepted-case measures.

Gate B does not authorize a live feed, shadow-feed deployment, operational recommendation workflow, or operational action.

### Gate C: Live read-only shadow evaluation

Phase 2.3 did not enter Gate C. Before a Phase 3 live shadow service, require:

- a separately approved deployment architecture;
- read-only service identities with no action permission;
- tenant, network, secrets, monitoring, and logging boundaries;
- ingestion stop conditions and data-collection kill switch;
- retention, deletion, and incident-response procedures;
- schema-drift and source-outage handling;
- assurance testing that no action credential or write-capable client is present.

Gate C still does not authorize operational action.

### Gate D: Phase 2 completion decision

Phase 2 may recommend whether the privileged-identity use case warrants further read-only evaluation. It may not recommend autonomous action based solely on replay model performance. Any later controlled-action phase requires a new threat model, action-specific test plan, non-production environment, rollback and independent readback, statistical release criteria, and authorizing-official decision.

## Exit conditions and nonclaims

The current increment exits implementation validation when all implemented requirements have passing evidence, planned requirements are not mislabeled as complete, every unavailable metric is explicit, and each public claim is no broader than its evidence record. Published exact Commit `854b15c` passed the Phase 2.5 technical suite 222/222 and completed its manifest, chart, rendered-status, publication, and exact-commit CI gates. The separate public-site module passed 9/9, yielding a then-current 231/231 aggregate; it is outside Phase 2.5 implementation conformance and evidence. Those observations support only narrow CE-1 implementation conformance within their stated boundaries; they are not a tagged release, a `P2-CE-005` evidence package, or a campaign result. `P2-CE-005` stays CE-0 until its separate two-commit campaign protocol completes. Neither establishes historical efficacy, historical data quality, source truth, outcome correctness, policy fitness, safe future autonomy, privacy compliance, production readiness, live-shadow readiness, agentic alignment/misalignment or sabotage robustness, monitor effectiveness, OS-level isolation/non-egress, target-side proof, exhaustive coverage, bounded operational failure rate, external independence, or independent audit custody.
