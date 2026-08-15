# Phase 2: Historical Replay and Shadow-Mode Starter

Phase 2 introduces the read-only evaluation boundary needed to test the AI Decision Firewall against more realistic evidence without creating a path to operational action. The current code defines versioned replay contracts, a Gate B historical-pilot preflight, local snapshot ingestion, semantic validation, bounded record qualification, decision-only execution, counterfactual evaluation, and validation gates.

## Current status

| Attribute | Phase 2 starter state |
|---|---|
| Implementation maturity | Phase 2 starter, Phase 2.1 qualification, and Phase 2.2 Gate B preflight; not an operational capability |
| Included data | Synthetic fixture data only: three-case starter and seven-record qualification campaign |
| `historical_case_count` | `0` |
| Qualification campaign | 7 nonblank inputs = 3 accepted + 4 quarantined |
| Qualification scope | Cases only; offline `HISTORICAL_REPLAY` only |
| Historical-data approval | Not requested or implied |
| Gate B package | Public DRAFT/templates only; no real package is approved or stored |
| Live data feeds | Not implemented |
| Authorization-token issuance | Prohibited in replay and shadow modes |
| Action-broker invocation | Prohibited in replay and shadow modes |
| Operational-effect attempts | Prohibited in replay and shadow modes |
| Production connectors or credentials | None |

The words *historical replay* and *shadow mode* describe execution semantics, not the data maturity of this code. The repository does not contain historical cases, production telemetry, direct identifiers, vendor connectors, or a live-feed integration. Both fixtures report `historical_case_count: 0` and identify their origin as synthetic. Phase 2.2 did not advance the project to historical processing, live testing, or shadow-feed testing.

## Objective

The Phase 2 objective is to determine whether the v0.1 decision-control architecture can accept a governed, versioned evidence snapshot; detect contract and context failures; produce a traceable counterfactual disposition; and suppress every authorization and execution path.

Phase 2 is meant to expose assumptions before operational integration. It should quantify data availability, mapping loss, timing behavior, evidence conflicts, abstention, and analyst disagreement. It is not intended to improve apparent model scores by tuning against a replay corpus.

## Starter scope

The starter allocates responsibilities to the following repository areas:

| Area | Responsibility |
|---|---|
| `contracts/v0.2.0/` | Versioned replay-manifest, replay-case, adjudication, qualification, rejection, synthetic-expectation, and evaluation-evidence schemas plus validated starter and qualification evidence records |
| `contracts/v0.2.0/gate-b-authorization.schema.json` | Closed Gate B structure for approvals, bindings, controls, custody, sampling, adjudication, review, and claim lifecycle |
| `contracts/v0.2.0/examples/gate-b-authorization-draft.json` | Schema-valid, deliberately non-authorizing public DRAFT |
| `config/phase2_replay.json` | Fail-closed replay configuration with no live-action option |
| `config/phase2_qualification.json` | Synthetic, offline historical-replay configuration with `record_failure_policy: QUARANTINE_RECORD` |
| `data/phase2_starter/` | Synthetic-only fixture and manifest; no historical records |
| `data/phase2_qualification/` | Seven-record synthetic mixed-quality fixture, separate adjudications, and predeclared metadata-only expectations |
| `evidence/phase2_qualification/` | Exact sanitized run artifacts supporting the narrow `P2-CE-002` qualification claim |
| `src/adf_poc/execution.py` | Execution-mode definitions and the read-only suppression boundary |
| `src/adf_poc/replay/` | Contract validation, record qualification, local adapter, normalization, harness, and replay metrics |
| `src/adf_poc/replay/gate_b.py` | Bounded control parsing, role/binding checks, scope and quarantine gates, and sanitized preflight summary |
| `run_phase2.py` | Offline Phase 2 entry point |
| `tests/test_execution_modes.py` | Read-only execution-guard verification |
| `tests/test_replay_contracts.py` | Structural, semantic, governance, and path-validation tests |
| `tests/test_replay_harness.py` | End-to-end replay and artifact-accounting tests |
| `tests/test_replay_qualification_unit.py` | Fatal/quarantine taxonomy, bounds, privacy, digest, and deterministic qualification tests |
| `tests/test_replay_qualification.py` | Seven-record campaign, ledger/rejection integrity, tamper, and end-to-end accounting tests |
| `scripts/generate_phase2_qualification_fixture.py` | Deterministically generate or check only the reviewed qualification fixture targets |
| `tests/test_qualification_fixture_generator.py` | Source-read consistency and symlink/hard-link target-safety tests |
| `scripts/validate_claim_evidence.py` | JSON Schema, artifact-hash/count, replay-manifest, audit, decision, and claim-boundary validator |
| `tests/test_claim_evidence.py` | Positive and negative tests for the complete claim-evidence validation gate |
| `tests/test_gate_b.py` | Schema/runtime, authority, binding, path, privacy, ordering, stop-condition, label-separation, snapshot, and read-only tests |
| `docs/phase2/` | Architecture, contracts, safety case, validation plan, claim-evidence standard, and traceability |

An artifact listed here may be a starter implementation rather than an operational capability. [`REQUIREMENTS_TRACEABILITY.csv`](REQUIREMENTS_TRACEABILITY.csv) is the authoritative statement of implemented, scaffolded, and planned status.

## Required processing sequence

1. Load configuration and only the replay-manifest control bytes.
2. For `HISTORICAL_DEIDENTIFIED`, require an `APPROVED` Gate B package under ignored `local/gate_b/`; validate current roles, independent review, scope-field presence, time, controls, counts, and exact manifest/model/policy/contract/adapter/protocol bindings before any case or adjudication payload is opened.
3. Confine historical output to an ignored owner-only `outputs/replay/<run>/` directory. Freeze the exact Gate B, model, policy, manifest, mapping, adjudication-protocol, and pilot-protocol bytes and revalidate them.
4. Only after Gate B passes, confine and verify the cases. Freeze evaluator-only adjudication bytes in harness-owned memory, but do not place their file beside or pass it to the decision runner.
5. Validate contract version and select the code-owned record policy. `FAIL_DATASET` is the default; Gate B historical work requires `QUARANTINE_RECORD`.
6. Under `FAIL_DATASET`, validate the complete case set as one unit. Under `QUARANTINE_RECORD`, bind every nonblank occurrence to a deterministic metadata-only ledger and separate accepted from quarantined records.
7. Abort the complete qualification call on integrity, encoding, line-size, contract-version, label-contamination, duplicate-identifier, record-count, or unmapped-validator failures. Do not return a partial accepted subset after a fatal condition.
8. Independently verify `input = accepted + quarantined`, source line/digest correspondence, exact rejection projection, and one deterministic qualification run ID.
9. For Gate B, evaluate accepted-case `opened_at` values and observed overall/category quarantine rates against the frozen window and thresholds. This is a post-qualification, pre-engine gate—not a pre-payload check.
10. Normalize accepted event ordering while retaining mapping and qualification diagnostics.
11. Recheck authorization validity, then run only accepted cases through the snapshotted model and policy, evidence assessment, deterministic policy, and independent verification in decision-only mode. Recheck validity again after the runner returns.
12. Preserve proposed containment only as a counterfactual recommendation; issue no token, invoke no broker, and attempt no effect.
13. Require the exact code-owned read-only audit vocabulary plus one suppression, authorization-evaluation, and hash-bound decision-finalization record per accepted case. Only then materialize and decode the frozen adjudications for comparison; ambiguous duplicate JSON members fail rather than using last-member-wins semantics.
14. Reverify the complete snapshot and current authorization, then produce qualification, rejection, diagnostics, decisions, audit, metrics, and a run manifest containing only a bounded Gate B summary.

Manifest-integrity and code-owned fatal qualification failures abort before engine invocation. Reviewed ordinary record-local defects may be quarantined only under `QUARANTINE_RECORD`; each remains visible through sanitized category/code metadata and exact source hashes, while its raw payload is excluded from rejection artifacts. Adjudication syntax and semantics are still checked only after decisions close. An adjudication failure aborts comparison and metrics generation while preserving decision and audit evidence already written.

The committed synthetic qualification campaign contains seven nonblank records. Three predeclared valid controls are accepted and four records are quarantined—one each for invalid JSON, a missing required field, an invalid timestamp, and canonical-context disagreement. Three decisions are produced, and authorization-token, broker-invocation, and operational-effect counts remain zero. These are controlled wiring and accounting results, not historical-quality or efficacy evidence.

## Safety rules

- The Phase 2 command surface accepts only read-only modes.
- There is no `LIVE` execution mode, production executor, action credential, connector, or `--enable-live-actions` option.
- Unknown or contradictory execution configuration fails closed.
- Counterfactual actions are data for evaluation, not commands for an operator or system.
- The no-effect result applies to the built-in runner and canonical adapter under the tested configuration; the single Python process is not a security sandbox for arbitrary imported code.
- Historical records require documented data-owner approval and de-identification attestation before ingestion. Those statements are governance evidence, not proof that de-identification is effective.
- Labels and adjudications remain physically and logically separate from runtime evidence.
- Raw, historical, or locally adjudicated data must not be committed to the public repository.
- Real Gate B authorization, protocol, mapping, custody, and data files belong only under ignored, access-controlled local paths; historical run outputs are owner-only.

## Starter invocation

The offline interface is:

```bash
python3 run_phase2.py --config config/phase2_replay.json
```

Run or validate the Phase 2.1 campaign with:

```bash
python3 run_phase2.py --config config/phase2_qualification.json --validate-only
python3 run_phase2.py --config config/phase2_qualification.json
python3 scripts/generate_phase2_qualification_fixture.py --check
```

Use `--validate-only` to verify configuration, manifest integrity, attestations, record qualification, and case contracts without invoking the engine. A qualification run adds deterministic `qualification_accounting.jsonl` and `rejections.jsonl` artifacts to the frozen snapshot, normalized cases, decisions, audit, diagnostics, comparisons, metrics, and run manifest. Generated replay outputs are local artifacts and should remain untracked. The harness refuses to overwrite a nonempty output directory.

No runnable historical configuration is committed. A future restricted configuration must point `gate_b_authorization` into `local/gate_b/` and use a run-specific `outputs/replay/` directory. The public DRAFT cannot pass runtime preflight.

## Documentation map

- [`ARCHITECTURE.md`](ARCHITECTURE.md) defines component allocation, data flow, trust boundaries, and failure behavior.
- [`DATA_CONTRACTS.md`](DATA_CONTRACTS.md) defines manifest, case, adjudication, governance, integrity, and semantic-validation requirements.
- [`SHADOW_MODE_SAFETY.md`](SHADOW_MODE_SAFETY.md) states the no-effect safety case and residual risks.
- [`VALIDATION_PLAN.md`](VALIDATION_PLAN.md) defines tests, metrics, acceptance criteria, and release gates.
- [`CLAIM_EVIDENCE_STANDARD.md`](CLAIM_EVIDENCE_STANDARD.md) defines claim classes, required evidence, validity hazards, statistical rules, adversarial tests, and prohibited inferences.
- [`RESEARCH_COVERAGE_REGISTER.md`](RESEARCH_COVERAGE_REGISTER.md) records the dated OpenAI Research Index and Anthropic source screen, applicability decisions, exclusions, unresolved obligations, and refresh triggers.
- [`RECORD_QUALIFICATION.md`](RECORD_QUALIFICATION.md) defines the fatal/quarantine taxonomy, closed metadata contract, accounting invariants, privacy and survivorship-bias rules, synthetic acceptance criteria, and Gate B extension.
- [`GATE_B_HISTORICAL_PILOT.md`](GATE_B_HISTORICAL_PILOT.md) defines the restricted package, exact authority roles, two-stage preflight/qualification gates, custody rules, templates, and nonclaims.
- [`../adr/006_gate_b_machine_readable_preflight.md`](../adr/006_gate_b_machine_readable_preflight.md) records the architectural decision and its limits.
- [`REQUIREMENTS_TRACEABILITY.csv`](REQUIREMENTS_TRACEABILITY.csv) traces every Phase 2 requirement to artifacts and evidence.

## Nonclaims

The Phase 2 code does not establish operational detection accuracy, historical replay performance, historical record-acceptance rates, analyst agreement, calibration against real telemetry, privacy compliance, production scalability, vendor compatibility, agentic alignment, or authorization to process real data or connect to a live environment. Gate B machine conformance does not authenticate authority, verify signatures, prove de-identification or custody, or authorize a pilot. With `historical_case_count=0`, synthetic measures must not be represented as historical performance or data quality. Results over accepted records are conditional on qualification and must never conceal complete intake and quarantine denominators. No historical, live, or shadow-feed progression is claimed.
