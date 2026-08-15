# AI Decision Firewall

- **Current code:** v0.2.0-alpha.5 Phase 2.4 typed-feature and reference-projection assurance increment
- **Validated baseline:** v0.1.0 synthetic proof of concept
- **Decision domain:** privileged-identity containment
- **Operational status:** offline synthetic replay, record qualification, and historical-pilot preflight; no organizational historical data, approved Gate B package, live feed, or operational connector is included
- **Safety boundary:** not approved for production integration, operational decision-making, or live containment

AI systems can rank alerts and recommend actions, but consequential operations require a stronger control boundary: the system must determine whether the available evidence is trustworthy and sufficient, whether an action is within delegated authority, and whether the intended effect actually occurred.

This repository implements an **AI Decision Firewall**—a model-agnostic control plane between AI-assisted analysis and operational execution. The first bounded decision is:

> Based on the available evidence, should suspicious privileged-identity activity result in no action, further investigation, reversible low-impact containment, or escalation to a human authority?

The model is advisory. Deterministic policy, independent verification, scoped authorization, and post-action verification control the action boundary.

## Why this problem matters

An alert score or model confidence is not action authority. Real telemetry can be stale, incomplete, contradictory, duplicated, or adversarially manipulated. The operational cost of a false containment can also differ radically by identity, asset, mission, and timing.

The POC therefore treats the decision as an evidence-and-authority problem, not merely a classification problem. It is designed to make five questions explicit and testable:

1. What evidence supports the decision, and where did it come from?
2. Is that evidence fresh, intact, corroborated, and sufficient for the proposed consequence?
3. Is the proposed action permitted for this case, identity, asset, and risk level?
4. Did an independent control agree before authorization was issued?
5. Did the target reach the intended state, or did execution fail or remain uncertain?

## POC scope

Version 0.1 implements a complete synthetic decision transaction for privileged identities:

- deterministic generation of benign, malicious, ambiguous, degraded-telemetry, break-glass, sensor-conflict, and evidence-poisoning scenarios;
- separate runtime evidence and evaluator-only ground-truth files;
- structured evidence from simulated identity, endpoint, network, threat-intelligence, CMDB, change-management, workforce, travel, and ticketing sources;
- evidence-quality assessment for provenance, integrity, freshness, source diversity, corroboration, missing telemetry, conflicts, and adversarial instructions;
- an interpretable logistic risk model used only as an advisory component;
- deterministic selection of `NO_ACTION`, `INVESTIGATE`, `CONTAIN_REVERSIBLE`, or `ESCALATE_HUMAN`;
- independent, non-model verification of the decision and action boundary;
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

The fixed [`P2-CE-004`](contracts/v0.2.0/examples/phase2-feature-assurance-ce2-evidence-record.json) campaign is now a narrow CE-2 `CONTROLLED_BEHAVIOR` result against corrected implementation Commit [`53e409d6`](https://github.com/redxking/ai-decision-firewall/commit/53e409d6ffa4af98ea892bc1a81302bf30870693). Two deterministic same-process repetitions of 16 synthetic attempts produced 32/32 matches to commit-frozen, project-controlled expectations with zero retries, exclusions, failures, or deviations: 16 clean qualification/reference matches, eight qualification quarantines, and eight reference-projection blocks. The two sanitized ledgers were byte-identical. No model, policy, verifier, decision engine, authorization, broker, target-effect, or operational-effect boundary was reached. This is SELF automated project-controlled evidence only; the 147-test implementation suite remains separate CE-1 conformance evidence.

An earlier unpublished package against Commit `1945ff283794c42f8eb649e320ba6adf91a6b982` was withheld after review found that its frozen validator accepted non-finite JSON. That package is invalidated, excluded from every claim denominator, and is not evidence. The published package is one new execution against the corrected A2 freeze, not a retry within its 32-attempt denominator.

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
| Full automated suite | 147 of 147 passed locally in this checkout |

The 147-test count is local implementation-conformance evidence for this checkout. It is not a `P2-CE-004` campaign result, GitHub CI evidence, or evidence that an organizational safeguard is effective.

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

The worked [`starter evidence record`](contracts/v0.2.0/examples/phase2-starter-evidence-record.json), [`qualification evidence record`](contracts/v0.2.0/examples/phase2-qualification-evidence-record.json), [`Gate B campaign evidence record`](contracts/v0.2.0/examples/phase2-gate-b-ce2-evidence-record.json), and [`feature-assurance campaign evidence record`](contracts/v0.2.0/examples/phase2-feature-assurance-ce2-evidence-record.json) state the exact narrow claims these results support, identify the systems and artifacts, and carry forward limitations and prohibited inferences. The broader [`claim-evidence standard`](docs/phase2/CLAIM_EVIDENCE_STANDARD.md) defines what additional validity, adversarial, statistical, and independent-review evidence is required before stronger language is permitted. The current POC uses a logistic model and deterministic controls; it does not contain an autonomous generative-language-model agent.

The committed `P2-CE-001` and `P2-CE-002` replay bundles predate alpha.5 and do not contain `reference_feature_assurance.jsonl`. Their original version-bound narrow claims remain validated as recorded; they were not retroactively upgraded to Phase 2.4 assurance. A newly generated alpha.5 replay is incomplete unless it produces and binds the new artifact.

## Architecture

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
           Independent verifier
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

![AI Decision Firewall logical architecture](docs/architecture/02_logical_architecture.png)

The model has no signing key, target credentials, action-broker reference, or direct execution path. Only an independently verified, policy-compliant proposal can cause the authorization gate to mint a token. The broker validates that token before changing simulated state.

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
 evidence -> model -> policy -> independent verifier
                    |
                    v
       mandatory execution suppression
                    |
                    v
 counterfactual decision + exact eight-stage audit
                    |
                    v
 separate reference feature projection
          | mismatch: stop before completion
          v
 metadata-only assurance + evaluator + metrics + manifest
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

## Reproducible synthetic baseline

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

These results establish that the encoded control and safety invariants are executable and reproducible against the supplied generator. They **do not** establish operational detection accuracy, real-world false-positive rates, production safety, or suitability for live containment. The model and evaluation data share the same synthetic scenario family, so model-performance metrics are intentionally optimistic.

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

The default run regenerates the dataset, trains the synthetic advisory model, processes 400 cases, verifies the audit chain, and writes artifacts to `outputs/baseline/`.

The default paths are tracked baseline artifacts, so this command rewrites `data/` and `outputs/baseline/`. Use temporary or separate directories when you want to preserve the checked-in baseline:

```bash
python run_poc.py \
  --data-dir /tmp/adf-data \
  --output-dir /tmp/adf-output
```

Run the safety and pipeline tests:

```bash
PYTHONPATH=src python -m unittest discover -s tests -v
```

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

Run the synthetic starter through the historical-replay code path:

```bash
python run_phase2.py
```

Run the qualification campaign through the same offline, read-only historical-replay path:

```bash
python run_phase2.py --config config/phase2_qualification.json
```

The Phase 2 run writes local, ignored artifacts under `outputs/replay/phase2_starter/` and refuses to overwrite a nonempty output directory. A complete alpha.5 run includes the closed `reference_feature_assurance.jsonl` artifact; a reference mismatch stops before metrics and a completed manifest. Under the built-in tested path it issues no authorization token, constructs no action broker or target, and produces no operational effect. Use a reviewed configuration with a new repository-confined `output_dir` for each additional run.

Run with different synthetic counts, seed, or output location:

```bash
python run_poc.py \
  --train-count 800 \
  --test-count 400 \
  --seed 20260814 \
  --output-dir outputs/baseline
```

Rebuild the editable engineering baseline after changing its source inputs:

```bash
python -m pip install -r requirements-docs.txt
python docs/build_engineering_doc.py
```

Verify the current release files against the integrity manifest:

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
│   └── feature_assurance_ce2_campaign_plan.json # Fixed P2-CE-004 expected outcomes and budget
├── contracts/v0.2.0/               # Replay, Gate B, campaign, and claim-evidence contracts
├── data/
│   ├── phase2_starter/             # Three-case synthetic replay fixture; no historical data
│   └── phase2_qualification/       # Seven-record mixed-quality synthetic fixture and expectations
├── docs/
│   ├── adr/                        # Architecture decision records
│   ├── architecture/               # Source and rendered diagrams
│   ├── phase2/                     # Replay architecture, feature assurance, safety, V&V, traceability
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
├── outputs/baseline/               # Reproducible decisions, metrics, audit, and report
├── scripts/                        # Confined fixture generation/checks and claim-evidence validation
├── src/adf_poc/
│   └── replay/                     # Contracts, Gate B, qualification, path-free harness, secure output, metrics
├── tests/                          # Safety and end-to-end tests
├── run_poc.py                      # End-to-end synthetic baseline entry point
├── run_phase2.py                   # Offline replay/shadow starter entry point
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
- production key management, token replay protection, or durable broker idempotency;
- an externally anchored or independently signed audit trail (a process able to rewrite the log can recompute the v0.1 hash chain);
- independently recomputed full source-to-decision, evidence-quality (including `source_conflict`), model-probability, policy, verifier, or disposition correctness. Phase 2.4 separately recomputes only the 20-feature values and traces from the same normalized cases, in the same process and project;
- externally trusted audit timestamps, OS-level nonaccess/non-egress, or independent evidence custody;
- independent target-state readback or executable rollback orchestration;
- reconciliation of conflicting break-glass or asset-criticality values in the v0.1 direct-run interface (the Phase 2 canonical adapter instead rejects such disagreement before engine invocation);
- suitability for safety-critical, operational-technology, or critical-infrastructure control environments;
- agentic alignment, scheming, sabotage resistance, or monitor effectiveness; the evaluated path is deterministic and contains no autonomous generative agent.

The typed contract does not prove that an authorized source assertion is truthful, authentic, complete, or semantically equivalent to a vendor record. The reference projector is separately implemented but not externally or organizationally independent, and its metadata hashes do not create independent custody. `P2-CE-004` supplies only the exact SELF-reviewed synthetic CE-2 result above. It provides no historical/live evaluation, independent replication, external custody, exhaustive coverage, or feature-assurance failure-rate estimate.

`P2-CE-003` adds no exception to these limitations. Its 32/32 observations are two repetitions of the same 16 project-selected synthetic scenarios under SELF automated project-controlled review. They do not establish a complete mutation space, a bounded failure rate, independent replication, real Gate B authority, effective de-identification, historical efficacy, live-shadow readiness, target-side effect absence, or zero risk.

The policy engine and verifier also share configuration and may share design defects. The POC signing key has a documented non-production fallback. These limitations are deliberate release constraints, not deferred permission to connect the software to a live environment.

## Roadmap

The **Phase 2 starter, Phase 2.1 qualification increment, Phase 2.2 Gate B machine preflight, Phase 2.3 audit/campaign increment, and Phase 2.4 typed-feature/reference-projection implementation and controlled campaign are now present**, with live actions remaining disabled. Phase 2.4 closes one bounded implementation gap and records one narrow synthetic CE-2 campaign result. It does not close the broader independent source-to-decision, evidence-custody, model, policy, verifier, or operational-validity gaps.

The next internal evidence work is broader independent reconstruction of the evidence-quality, model, policy, verifier, and source-to-decision path plus stronger custody and evaluation-environment controls. The next data-bearing step is external: accountable owners must assemble and authenticate a restricted Gate B approval, custody, privacy, mapping, adjudication, and pilot package for a small de-identified historical corpus. Only then may an isolated offline pilot measure source availability, schema gaps, temporal fidelity, analyst disagreement, contextual assumptions, and calibration while keeping the complete intake denominator visible. No Gate B approval, historical run, live feed, or shadow-feed progression has occurred; `shadow_read_only` remains unconnected until a separately approved Phase 3 architecture and safety case exist.

Later phases, each requiring separate evidence and authorization, are:

1. live read-only shadow evaluation in an approved environment;
2. reversible actions against non-production test identities under change control;
3. a limited operational pilot with human approval for all actions;
4. action-class-specific autonomy only if statistically and operationally defensible gates are met and an authorizing official accepts the residual risk.

See [`docs/ROADMAP.md`](docs/ROADMAP.md) for the full sequence and exit conditions.

## Documentation

- [`DELIVERY_NOTES.md`](DELIVERY_NOTES.md) — v0.1 scope, results, and handoff
- [`docs/AI_Decision_Firewall_POC_Engineering_Baseline_v0.1.pdf`](docs/AI_Decision_Firewall_POC_Engineering_Baseline_v0.1.pdf) — engineering baseline
- [`docs/CONCEPT_OF_OPERATIONS.md`](docs/CONCEPT_OF_OPERATIONS.md) — actors, modes, decisions, and off-nominal behavior
- [`docs/REQUIREMENTS_TRACEABILITY_MATRIX.csv`](docs/REQUIREMENTS_TRACEABILITY_MATRIX.csv) — requirement-to-design-and-test traceability
- [`docs/MODEL_CARD.md`](docs/MODEL_CARD.md) — advisory model purpose, performance, and limits
- [`docs/SYNTHETIC_DATA_CARD.md`](docs/SYNTHETIC_DATA_CARD.md) — dataset design and appropriate use
- [`docs/TEST_AND_EVALUATION_PLAN.md`](docs/TEST_AND_EVALUATION_PLAN.md) — acceptance criteria and required next-phase tests
- [`docs/phase2/README.md`](docs/phase2/README.md) — Phase 2 scope and documentation map
- [`docs/phase2/CLAIM_EVIDENCE_STANDARD.md`](docs/phase2/CLAIM_EVIDENCE_STANDARD.md) — claim classes, proof requirements, statistical rules, and adversarial evaluations
- [`docs/phase2/FEATURE_ASSURANCE.md`](docs/phase2/FEATURE_ASSURANCE.md) — typed/source-authorized signals, exact inventory binding, reference projection, controlled campaign evidence, and nonclaims
- [`docs/phase2/RESEARCH_INFORMED_VALIDATION.md`](docs/phase2/RESEARCH_INFORMED_VALIDATION.md) — dated research lessons mapped to the bounded Phase 2.4 design; research is not project evidence
- [`docs/phase2/RESEARCH_COVERAGE_REGISTER.md`](docs/phase2/RESEARCH_COVERAGE_REGISTER.md) — dated Anthropic and OpenAI research screen, dispositions, gaps, and refresh triggers
- [`docs/phase2/RECORD_QUALIFICATION.md`](docs/phase2/RECORD_QUALIFICATION.md) — fatal/quarantine taxonomy, metadata contract, accounting invariants, privacy rules, synthetic gate, and historical-pilot prerequisites
- [`docs/phase2/GATE_B_HISTORICAL_PILOT.md`](docs/phase2/GATE_B_HISTORICAL_PILOT.md) — restricted-package contents, approval roles, pre-payload ordering, stop conditions, and nonclaims
- [`docs/adr/006_gate_b_machine_readable_preflight.md`](docs/adr/006_gate_b_machine_readable_preflight.md) — decision to require Gate B before historical payload access
- [`docs/phase2/REQUIREMENTS_TRACEABILITY.csv`](docs/phase2/REQUIREMENTS_TRACEABILITY.csv) — Phase 2 requirement status and verification evidence
- [`contracts/v0.2.0/gate-b-authorization.schema.json`](contracts/v0.2.0/gate-b-authorization.schema.json) — closed Gate B authorization-package contract
- [`contracts/v0.2.0/gate-b-ce2-campaign.schema.json`](contracts/v0.2.0/gate-b-ce2-campaign.schema.json) — closed profile, result-row, and summary contract for `P2-CE-003`
- [`contracts/v0.2.0/reference-feature-assurance.schema.json`](contracts/v0.2.0/reference-feature-assurance.schema.json) — closed metadata-only matched-projection record
- [`contracts/v0.2.0/feature-assurance-ce2-campaign.schema.json`](contracts/v0.2.0/feature-assurance-ce2-campaign.schema.json) — closed profile/result contract for the observed `P2-CE-004` campaign
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

## Licensing

No open-source license is included in this repository. Public availability does not itself grant permission to use, modify, or redistribute the work.
