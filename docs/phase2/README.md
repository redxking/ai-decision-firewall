# Phase 2: Historical Replay and Shadow-Mode Starter

Phase 2 introduces the read-only evaluation boundary needed to test the AI Decision Firewall against more realistic evidence without creating a path to operational action. The starter is deliberately narrow: it defines versioned replay contracts, local snapshot ingestion, semantic validation, decision-only execution, counterfactual evaluation, and validation gates.

## Current status

| Attribute | Phase 2 starter state |
|---|---|
| Implementation maturity | Starter scaffolding; not an operational capability |
| Included data | Synthetic fixture data only |
| `historical_case_count` | `0` |
| Historical-data approval | Not requested or implied |
| Live data feeds | Not implemented |
| Authorization-token issuance | Prohibited in replay and shadow modes |
| Action-broker invocation | Prohibited in replay and shadow modes |
| Operational-effect attempts | Prohibited in replay and shadow modes |
| Production connectors or credentials | None |

The words *historical replay* and *shadow mode* describe execution semantics, not the data maturity of this starter. The repository does not contain historical cases, production telemetry, direct identifiers, vendor connectors, or a live-feed integration. The starter fixture must report `historical_case_count: 0` and identify its origin as synthetic.

## Objective

The Phase 2 objective is to determine whether the v0.1 decision-control architecture can accept a governed, versioned evidence snapshot; detect contract and context failures; produce a traceable counterfactual disposition; and suppress every authorization and execution path.

Phase 2 is meant to expose assumptions before operational integration. It should quantify data availability, mapping loss, timing behavior, evidence conflicts, abstention, and analyst disagreement. It is not intended to improve apparent model scores by tuning against a replay corpus.

## Starter scope

The starter allocates responsibilities to the following repository areas:

| Area | Responsibility |
|---|---|
| `contracts/v0.2.0/` | Versioned replay-manifest, replay-case, adjudication, and evaluation-evidence schemas plus a worked evidence record |
| `config/phase2_replay.json` | Fail-closed replay configuration with no live-action option |
| `data/phase2_starter/` | Synthetic-only fixture and manifest; no historical records |
| `src/adf_poc/execution.py` | Execution-mode definitions and the read-only suppression boundary |
| `src/adf_poc/replay/` | Contract validation, local adapter, normalization, harness, and replay metrics |
| `run_phase2.py` | Offline Phase 2 entry point |
| `tests/test_execution_modes.py` | Read-only execution-guard verification |
| `tests/test_replay_contracts.py` | Structural, semantic, governance, and path-validation tests |
| `tests/test_replay_harness.py` | End-to-end replay and artifact-accounting tests |
| `scripts/validate_claim_evidence.py` | JSON Schema, artifact-hash/count, replay-manifest, audit, decision, and claim-boundary validator |
| `tests/test_claim_evidence.py` | Positive and negative tests for the complete claim-evidence validation gate |
| `docs/phase2/` | Architecture, contracts, safety case, validation plan, claim-evidence standard, and traceability |

An artifact listed here may be a starter implementation rather than an operational capability. [`REQUIREMENTS_TRACEABILITY.csv`](REQUIREMENTS_TRACEABILITY.csv) is the authoritative statement of implemented, scaffolded, and planned status.

## Required processing sequence

1. Load a local replay manifest.
2. Confine all referenced paths beneath the manifest directory.
3. Verify every declared file digest and record count before decision processing.
4. Copy the exact configuration, manifest, model, policy, case, and adjudication bytes into a new run-input snapshot and verify the copied digests and counts.
5. Validate contract version and governance fields, then decode and validate the complete snapshotted case record set.
6. Apply case semantics, including canonical-context consistency and timestamp rules; fail the case set closed on any error.
7. Normalize valid event ordering while retaining mapping warnings.
8. Run the snapshotted model and policy through evidence assessment, deterministic policy, and independent verification in decision-only mode.
9. Preserve any proposed containment as a counterfactual recommendation.
10. Issue no authorization token, invoke no action broker, and attempt no operational effect; represent post-action verification as not applicable.
11. Require one suppression, authorization-evaluation, and hash-bound decision-finalization audit record per case before decoding the snapshotted adjudications.
12. Reverify the complete input snapshot and produce record-accounting, data-quality, safety, audit, and run-manifest artifacts.

Manifest-integrity or case-level contract failure aborts the declared case set before engine invocation. Adjudication syntax and semantics are checked only after decisions close; an adjudication failure aborts comparison and metrics generation while preserving the decision and audit evidence already written. Exceptions retain specific reasons, and invalid input is never silently repaired or dropped. Per-record reject-and-continue processing and a `rejections.jsonl` artifact are planned requirements, not starter behavior.

## Safety rules

- The Phase 2 command surface accepts only read-only modes.
- There is no `LIVE` execution mode, production executor, action credential, connector, or `--enable-live-actions` option.
- Unknown or contradictory execution configuration fails closed.
- Counterfactual actions are data for evaluation, not commands for an operator or system.
- The no-effect result applies to the built-in runner and canonical adapter under the tested configuration; the single Python process is not a security sandbox for arbitrary imported code.
- Historical records require documented data-owner approval and de-identification attestation before ingestion. Those statements are governance evidence, not proof that de-identification is effective.
- Labels and adjudications remain physically and logically separate from runtime evidence.
- Raw, historical, or locally adjudicated data must not be committed to the public repository.

## Starter invocation

The offline interface is:

```bash
python3 run_phase2.py --config config/phase2_replay.json
```

Use `--validate-only` to verify configuration, manifest integrity, attestations, and case contracts without invoking the engine. The starter output directory is code-owned through the validated configuration and includes a frozen input snapshot, normalized cases, raw and deterministic decision records, an audit log, normalization diagnostics, adjudication comparisons, replay metrics, and a run manifest. Generated replay and shadow outputs are local artifacts and should remain untracked. Record-level rejection/continue behavior is a traced Phase 2 requirement; consult the traceability matrix for its implementation status rather than assuming the starter already provides partial-file recovery.

## Documentation map

- [`ARCHITECTURE.md`](ARCHITECTURE.md) defines component allocation, data flow, trust boundaries, and failure behavior.
- [`DATA_CONTRACTS.md`](DATA_CONTRACTS.md) defines manifest, case, adjudication, governance, integrity, and semantic-validation requirements.
- [`SHADOW_MODE_SAFETY.md`](SHADOW_MODE_SAFETY.md) states the no-effect safety case and residual risks.
- [`VALIDATION_PLAN.md`](VALIDATION_PLAN.md) defines tests, metrics, acceptance criteria, and release gates.
- [`CLAIM_EVIDENCE_STANDARD.md`](CLAIM_EVIDENCE_STANDARD.md) defines claim classes, required evidence, validity hazards, statistical rules, adversarial tests, and prohibited inferences.
- [`RESEARCH_COVERAGE_REGISTER.md`](RESEARCH_COVERAGE_REGISTER.md) records the dated OpenAI Research Index and Anthropic source screen, applicability decisions, exclusions, unresolved obligations, and refresh triggers.
- [`REQUIREMENTS_TRACEABILITY.csv`](REQUIREMENTS_TRACEABILITY.csv) traces every Phase 2 requirement to artifacts and evidence.

## Nonclaims

The Phase 2 starter does not establish operational detection accuracy, historical replay performance, analyst agreement, calibration against real telemetry, privacy compliance, production scalability, vendor compatibility, or authorization to connect to a live environment. With `historical_case_count=0`, the synthetic adjudication metrics must not be represented as historical performance. A future origin-stratified metrics contract must represent unavailable historical values as `null` with an explicit reason, not as measured zeros.
