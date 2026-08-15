# Phase 2 Validation Plan

## Validation objective

Validation must establish whether the built-in Phase 2 path can reject untrusted or ungoverned replay inputs, produce traceable counterfactual decisions from accepted records, account for every input, and maintain zero authorization-token issuance, zero broker invocation, and zero operational effects under the exact tested configuration.

The current evidence base contains only synthetic fixtures with `historical_case_count=0`: the three-case starter, the seven-record Phase 2.1 qualification campaign, and the ephemeral test-only inputs used by the fixed Phase 2.3 Gate B campaign. Historical efficacy, historical calibration, historical acceptance rates, and analyst-agreement claims are therefore unavailable.

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

### Phase 2.3 Gate B controlled-behavior campaign

[`P2-CE-003`](../../contracts/v0.2.0/examples/phase2-gate-b-ce2-evidence-record.json) binds the exact generator, plan, schema, validator, Gate B implementation, contracts, harness, fixtures, model, policy, runtime fingerprint, seed, budget, scenario order, expected outcomes, and implementation Commit [`e8aa8b0`](https://github.com/redxking/ai-decision-firewall/commit/e8aa8b0efc7d54efdf74f49fb3d10ee067f2b49b). The fixed design executes two complete repetitions of the same 16 project-selected synthetic scenarios:

- one test-only validate-only positive control per repetition;
- 14 single-mutation structural negative controls per repetition that are expected to block before governed payload access;
- one quarantine-threshold control per repetition that is expected to open both governed payload roles, qualify the cases, and stop before normalization or engine invocation; and
- zero permitted decision-engine, authorization, broker, or target-effect boundary calls.

The published campaign observed 32/32 matches with no exclusions: two validate-only passes, 28 structural pre-payload blocks with no governed payload-role open/read attempt observed by the declared `Path.open`, `Path.read_text`, `Path.read_bytes`, and `os.open` hooks during the harness invocation, and two post-qualification/pre-engine threshold blocks. The two sanitized 16-row result ledgers were byte-identical. No engine, authorization, broker, or target-effect boundary was reached, and no completed run manifest, decision artifact, or audit artifact was observed. The exact artifacts and their custody limits are listed in the [`campaign bundle`](../../evidence/phase2_gate_b_ce2/README.md).

This is a CE-2 `CONTROLLED_BEHAVIOR` result under `SELF` automated project-controlled review. It uses no real approval or actual historical data and authorizes no live feed or action. The two executions are repetitions, not independent or statistically representative trials; Commit A is a public project-controlled freeze, not external preregistration; the mutation set is not exhaustive; the open/read hooks do not establish OS-level nonaccess or non-egress; boundary counters do not provide target-side proof; and 32/32 does not estimate an operational failure probability, demonstrate efficacy, or establish alignment/misalignment behavior.

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
| Historical label boundary | Adjudication bytes may be frozen within the harness, but are neither passed nor made path-discoverable to the built-in runner and are decoded only after decisions close | Required for Phase 2.2; same-process isolation limitation retained |
| Traceability | Every accepted decision's cited and feature-linked event IDs resolve to accepted input events | Required |
| Audit | Exactly one canonical, ordered eight-stage trace exists per accepted case; decision/policy bindings and the presented hash chain verify | Required CE-1 implementation conformance, with independent-recomputation, time, and custody limitations |
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

Passing tests support only the claim those tests were designed to evaluate. Every release result must use the claim class, evidence-record fields, statistical rules, and prohibited wording in [`CLAIM_EVIDENCE_STANDARD.md`](CLAIM_EVIDENCE_STANDARD.md). The machine-readable contract is `contracts/v0.2.0/evaluation-evidence.schema.json`. `P2-CE-001` covers the three-case synthetic starter, `P2-CE-002` covers only the fixed seven-record qualification campaign and its accepted subset's read-only invariants, and `P2-CE-003` covers only the fixed two-repetition synthetic Gate B registry and declared instrumentation. All three are CE-2 controlled-behavior records; none is historical, operational, alignment, or production evidence. The separate eight-stage audit hardening remains a CE-1 implementation-conformance claim because it cross-checks presented decisions and policy actions but does not independently recompute the full decision path or provide external time/custody evidence.

The adversarial matrix in that standard derives future test families from Anthropic and OpenAI research: goal conflict, evaluation awareness, instruction/evidence poisoning, reward and test hacking, code sabotage, oversight undermining, sandbagging, hidden-objective audit, long-horizon state manipulation, human-decision sabotage, monitor effectiveness, and independent operational-effect proof. The current deterministic POC implements only a subset. It contains no autonomous generative-language-model agent, so it makes no claim about alignment, scheming, sabotage resistance, or monitor recall.

For any later repeated behavioral evaluation, report raw numerators and denominators, exclusions, representative failures, configuration-specific results, and uncertainty only where sampling assumptions are justified. A `0/n` observation is not zero risk. Synthetic, historical, and live-shadow results must remain separate.

## Release gates

### Gate A: Public starter

Required evidence:

- all Phase 1, Phase 2 starter, Phase 2.1 qualification, Phase 2.2 Gate B, and Phase 2.3 audit/campaign tests pass;
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

The current increment exits validation when all implemented requirements have passing evidence, planned requirements are not mislabeled as complete, every unavailable metric is explicit, and each public claim is no broader than its evidence record. Success establishes narrow controlled synthetic results for the built-in test-harness path, not historical efficacy, historical data quality, safe future autonomy, privacy compliance, production readiness, live-shadow readiness, agentic alignment/misalignment behavior, monitor effectiveness, OS-level nonaccess/non-egress, target-side proof, exhaustive coverage, an operational failure rate, or independent audit custody.
