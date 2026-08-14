# Phase 2 Validation Plan

## Validation objective

Validation must establish whether the built-in Phase 2 path can reject untrusted or ungoverned replay inputs, produce traceable counterfactual decisions from accepted records, account for every input, and maintain zero authorization-token issuance, zero broker invocation, and zero operational effects under the exact tested configuration.

The current evidence base is a synthetic fixture with `historical_case_count=0`. Historical efficacy, historical calibration, and analyst-agreement claims are therefore unavailable.

## Evidence hierarchy

Phase 2 uses six complementary evidence types:

1. **Static architecture inspection** confirms that no live mode, production connector, action credential, or action-enable parameter exists.
2. **Execution-guard unit tests** prove that read-only modes do not construct or call the authorization gate, broker, or target.
3. **Contract tests** exercise structure, semantics, governance, path confinement, digest verification, and label separation.
4. **Replay integration tests** verify frozen-input integrity, record accounting, normalization, counterfactual output, decision/audit binding, metrics, and failure behavior.
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

The following are planned follow-on tests, not starter evidence:

- safe per-record reject-and-continue behavior;
- a `rejections.jsonl` artifact with record-specific reasons;
- `input_records = accepted_records + rejected_records` accounting for a partially accepted file;
- source-completeness and collection-delay metrics against an approved historical mapping;
- explicit historical-unavailability reason objects in a future origin-stratified metrics contract.

The implemented starter treats all runtime cases as one validation unit: any invalid case aborts before engine invocation. Adjudications are a separate post-decision validation unit; any invalid adjudication aborts comparisons and metrics after preserving the already-written decision and audit evidence. This fail-closed choice prevents silent partial-set evaluation while the partial-acceptance policy remains undefined.

## Starter release criteria

The Phase 2 starter is acceptable for public release only when the implemented gates below pass and deferred requirements remain explicitly labeled as planned:

| Gate | Acceptance criterion | Starter disposition |
|---|---|---|
| Data boundary | Repository fixture is synthetic and input manifest reports `historical_case_count=0` | Required |
| Execution boundary | Both read-only modes issue zero tokens, invoke zero brokers, and attempt zero effects | Required |
| No live capability | No live mode, write-capable connector, action credential, or enablement override exists | Required |
| Integrity | Referenced file digests/counts verify, exact inputs are snapshotted, and snapshot integrity verifies before and after engine execution; mismatch aborts | Required |
| Path safety | Manifest-relative paths cannot escape the manifest directory | Required |
| Contract safety | Invalid critical fields, labels, governance failures, and context disagreements abort before engine invocation | Required |
| Whole-dataset accounting | Every declared file count and accepted case-to-decision count reconciles | Required |
| Partial-file accounting | `input_records = accepted_records + rejected_records` with a rejection artifact | Planned; not a release claim |
| Traceability | Every accepted decision's cited and feature-linked event IDs resolve to accepted input events | Required |
| Audit | One suppression, no-authorization, and hash-bound finalization record exists per case and the presented hash chain verifies | Required, with custody limitation |
| Compatibility | All Phase 1 tests continue to pass | Required |
| Claim discipline | A schema-valid evidence record states the exact supported wording, data origin, validity status, limitations, and prohibited inferences | Required |
| Nonclaims | Synthetic evaluation is not described as historical or operational performance | Required |

An audit-validity result alone does not satisfy the integrity gate because the current chain is not independently anchored.

## Metrics and diagnostics

The implemented `replay_metrics.json` reports:

- cases evaluated, adjudicated-case count, and adjudication coverage;
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

- accepted/rejected record accounting and rejection-reason distribution;
- required-field completeness, unmapped-field counts, and missing expected-source rate;
- collection-delay p50 and p95;
- evidence decision-grade and evidence-ID traceability rates;
- calibration error and reliability bins;
- counterfactual containment precision;
- false-containment rate among adjudicated benign cases;
- analyst/system agreement;
- raw analyst agreement and Cohen's kappa;
- Wilson confidence bounds for proportions.

Future results must be stratified by synthetic versus historical origin and must not be combined into a single efficacy figure. The current metrics file evaluates the included synthetic adjudications only. Because the input manifest declares `historical_case_count=0`, those values are not historical-performance evidence. When no adjudications are present, the implemented rate, accuracy, and Brier fields are `null`; zero confusion counts do not establish measured historical performance.

## Claim and adversarial-evaluation rules

Passing tests support only the claim those tests were designed to evaluate. Every release result must use the claim class, evidence-record fields, statistical rules, and prohibited wording in [`CLAIM_EVIDENCE_STANDARD.md`](CLAIM_EVIDENCE_STANDARD.md). The machine-readable contract is `contracts/v0.2.0/evaluation-evidence.schema.json`, and the starter record is explicitly a CE-2 controlled-behavior result over three synthetic cases.

The adversarial matrix in that standard derives future test families from Anthropic and OpenAI research: goal conflict, evaluation awareness, instruction/evidence poisoning, reward and test hacking, code sabotage, oversight undermining, sandbagging, hidden-objective audit, long-horizon state manipulation, human-decision sabotage, monitor effectiveness, and independent operational-effect proof. The current deterministic POC implements only a subset. It contains no autonomous generative-language-model agent, so it makes no claim about alignment, scheming, sabotage resistance, or monitor recall.

For any later repeated behavioral evaluation, report raw numerators and denominators, exclusions, representative failures, configuration-specific results, and uncertainty only where sampling assumptions are justified. A `0/n` observation is not zero risk. Synthetic, historical, and live-shadow results must remain separate.

## Release gates

### Gate A: Public starter

Required evidence:

- all Phase 1 and Phase 2 starter tests pass;
- no credential or production endpoint is present;
- fixture provenance and synthetic status are documented;
- public files contain no historical or direct-identifier data;
- requirement statuses match the committed implementation;
- the supported public result has a schema-valid evidence record and its deterministic artifact hashes match a clean run;
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

Gate B does not authorize a live feed or operational action.

### Gate C: Live read-only shadow evaluation

Before a Phase 3 live shadow service, require:

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

The starter exits validation when all implemented requirements have passing evidence, planned requirements are not mislabeled as complete, every unavailable metric is explicit, and the public claim is no broader than its evidence record. Success establishes a controlled result for the built-in test-harness path, not operational efficacy, safe future autonomy, privacy compliance, production readiness, agentic alignment, monitor effectiveness, or independent audit custody.
