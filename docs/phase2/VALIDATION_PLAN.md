# Phase 2 Validation Plan

## Validation objective

Validation must establish whether the built-in Phase 2 path can reject untrusted or ungoverned replay inputs, produce traceable counterfactual decisions from accepted records, account for every input, and maintain zero authorization-token issuance, zero broker invocation, and zero operational effects under the exact tested configuration.

The current evidence base contains only synthetic fixtures with `historical_case_count=0`: the three-case starter and the seven-record Phase 2.1 qualification campaign. Historical efficacy, historical calibration, historical acceptance rates, and analyst-agreement claims are therefore unavailable.

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

### Replay-harness tests

`tests/test_replay_harness.py` is the required starter evidence for:

- complete success against the synthetic fixture;
- `historical_case_count=0` retained in the run evidence;
- a manifest-integrity failure aborts before any decision is emitted;
- the exact configuration, manifest, model, policy, cases, and adjudications are frozen in a run snapshot and reverified after execution;
- decisions are closed before adjudications are loaded;
- every accepted case retains evidence-ID traceability;
- semantically equivalent runs produce equivalent decisions after excluding time, latency, UUID, and run-ID fields;
- the output audit chain verifies, every final decision hash is recomputed and bound to exactly one finalization record, and ordinary record tampering is detected;
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
| Traceability | Every accepted decision's cited and feature-linked event IDs resolve to accepted input events | Required |
| Audit | One suppression, no-authorization, and hash-bound finalization record exists per case and the presented hash chain verifies | Required, with custody limitation |
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

Passing tests support only the claim those tests were designed to evaluate. Every release result must use the claim class, evidence-record fields, statistical rules, and prohibited wording in [`CLAIM_EVIDENCE_STANDARD.md`](CLAIM_EVIDENCE_STANDARD.md). The machine-readable contract is `contracts/v0.2.0/evaluation-evidence.schema.json`. `P2-CE-001` covers the three-case synthetic starter, and `P2-CE-002` covers only the fixed seven-record qualification campaign and its accepted subset's read-only invariants. Both are CE-2 controlled-behavior records; neither is historical, operational, alignment, or production evidence.

The adversarial matrix in that standard derives future test families from Anthropic and OpenAI research: goal conflict, evaluation awareness, instruction/evidence poisoning, reward and test hacking, code sabotage, oversight undermining, sandbagging, hidden-objective audit, long-horizon state manipulation, human-decision sabotage, monitor effectiveness, and independent operational-effect proof. The current deterministic POC implements only a subset. It contains no autonomous generative-language-model agent, so it makes no claim about alignment, scheming, sabotage resistance, or monitor recall.

For any later repeated behavioral evaluation, report raw numerators and denominators, exclusions, representative failures, configuration-specific results, and uncertainty only where sampling assumptions are justified. A `0/n` observation is not zero risk. Synthetic, historical, and live-shadow results must remain separate.

## Release gates

### Gate A: Public starter

Required evidence:

- all Phase 1, Phase 2 starter, and Phase 2.1 qualification tests pass;
- no credential or production endpoint is present;
- fixture provenance and synthetic status are documented;
- public files contain no historical or direct-identifier data;
- requirement statuses match the committed implementation;
- each supported public result has a schema-valid evidence record and its deterministic artifact hashes match a clean run;
- security and integrity limitations remain adjacent to relevant results.

Passing Gate A authorizes only publication of the starter code and synthetic fixture.

### Gate B: Approved historical replay

Before any historical record is processed, require:

- data-owner authorization and approved use;
- privacy/legal, security, and mission-owner review;
- documented de-identification, access, retention, deletion, and incident-response procedures;
- source-field mapping and provenance review;
- a frozen model, policy, contract, and adapter baseline;
- manifest and dataset custody outside the mutable replay directory;
- temporal holdout design and safeguards against hindsight, selection, and adjudication bias;
- an approved plan for handling disagreement and indeterminate outcomes.
- predeclared overall and category-specific quarantine thresholds, fatal stop conditions, escalation ownership, complete-intake reporting, and survivorship-bias analysis;
- restricted handling for source and raw-line hashes, which remain linkable even though the ledger is metadata-only.

Gate B does not authorize a live feed, shadow-feed deployment, operational recommendation workflow, or operational action.

### Gate C: Live read-only shadow evaluation

Phase 2.1 did not enter Gate C. Before a Phase 3 live shadow service, require:

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

The current increment exits validation when all implemented requirements have passing evidence, planned requirements are not mislabeled as complete, every unavailable metric is explicit, and each public claim is no broader than its evidence record. Success establishes a controlled synthetic result for the built-in test-harness path, not historical efficacy, historical data quality, safe future autonomy, privacy compliance, production readiness, live-shadow readiness, agentic alignment, monitor effectiveness, or independent audit custody.
