# POC Test Suite

Run from the repository root:

```bash
PYTHONPATH=src python -m unittest discover -s tests -v
```

The suite focuses on safety and evidence invariants rather than synthetic classifier accuracy. Exact Phase 2.5 Commit `854b15c56397a81de6326b719d3d7d1dc847608f` passed the **222/222** technical suite and exact-commit CI/Dependency Graph after publication. The separate public-site module passed **9/9**, yielding a then-current aggregate of **231/231**. Site tests are not Phase 2.5 or `P2-CE-005` evidence, and `P2-CE-005` remains CE-0 `NOT_EVALUATED`. Published Phase 3 `0.3.0-alpha.1` at exact Commit `423685d105be813056617db738297eba83d3d9d0` passed **57/57** focused tests and the then-current **288/288** repository suite in exact-commit CI. Published Phase 3.1 `0.3.1-alpha.1` at exact Commit `bb6b8f28afba0961bb97b24e6050fccaa94d5702` passed **11/11** focused tests and the then-current **299/299** repository suite in exact-commit CI. The predecessor Stage A authority-ledger checkpoint passed **16/16** durable-ledger tests, **18/18** production-gate tests, and the then-current **333/333** local repository suite. The unreleased `0.4.0-alpha.2` Stage A implementation is published on `main` at exact Commit [`8818d5d2d40faebced66a254d58b1f0d04c9f8b4`](https://github.com/redxking/ai-decision-firewall/commit/8818d5d2d40faebced66a254d58b1f0d04c9f8b4). Against that exact commit, the two Stage A modules passed **43/43 in 8.248 seconds**, the production-gate module passed **18/18**, the warning-fatal complete suite passed **360/360 in 48.995 seconds**, the focused Phase 3 suite passed **57/57**, and the deterministic corpus passed **46/46** with `live_actions_possible=false`. Its 307-entry manifest verified **307/307**; exact-SHA [CI run 31953570779](https://github.com/redxking/ai-decision-firewall/actions/runs/31953570779) succeeded on Python 3.11 and 3.12, and [Dependency Graph run 31953572482](https://github.com/redxking/ai-decision-firewall/actions/runs/31953572482) succeeded. These remain project-controlled implementation observations; no tag or GitHub Release exists, no deployment occurred, no exact-SHA Pages run was observed, and no owner acceptance or production authorization exists. See [`ADF-STAGE-A-ER-002`](../docs/production/STAGE_A_RECEIPT_RESULT_EVIDENCE_RECORD.md).

## Stage A focused suites

```bash
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src:. PYTHONWARNINGS=error \
  python3 -m unittest \
    tests.test_stage_a_receipt_recovery \
    tests.test_stage_a_durable_control_ledger -v

PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src:. PYTHONWARNINGS=error \
  python3 -m unittest tests.test_production_readiness_gate -v
```

The Stage A modules exercise the separate control and offline synthetic-adapter
SQLite stores, strict schema and cross-store correlation, restart-safe claims,
single-use authorization and attempt reservation, atomic synthetic
state-plus-receipt writes, sanitized terminal lookup, exact duplicate handling,
recovery-audit fencing, process termination, direct and integrated multiprocess
concurrency, path/sidecar safety, corruption, chronology, and conservative
reconciliation. The production-gate module separately verifies strict
derivation of the 18-domain, 36-requirement `BLOCKED` gate. These tests do not
establish cross-store atomicity, independently custodied target observation,
distributed linearizability or fencing, process isolation, HA/DR, production
deployment, owner acceptance, or operational effectiveness.

## Phase 3 focused suite

```bash
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src python3 -m unittest \
  tests.test_phase3_contracts \
  tests.test_phase3_decision_path \
  tests.test_phase3_authorization_boundary \
  tests.test_phase3_adversarial \
  tests.test_phase3_end_to_end \
  tests.test_phase3_corpus \
  tests.test_phase3_release_blockers -v
```

Coverage includes:

- closed raw request/policy contracts, duplicate/non-finite/time/resource
  rejection, and stable fail-closed codes;
- opaque-credential resolution to a signed principal, trusted target facts,
  evidence HMAC/content/semantic/time/subject binding, key-domain separation,
  freshness, corroboration, conflict, missing source, poisoning, and
  confidence/recommendation invariance;
- all four decisions, canonical constraints, cascading consequence, Tier-0
  escalation, and zero effect for non-allow outcomes;
- exact token bindings, expiration boundary, sequential/concurrent/prior-instance
  replay, failed-attempt consumption, missing/wrong token, broker scope, direct
  target bypass, and target precondition drift;
- exact-scope single-use human approval through a separate opaque credential,
  with failure-atomic receipt/audit recording and reevaluation only;
- functionally separate same-project state-based `VERIFIED`, `FAILED`,
  `PARTIAL`, `UNEXPECTED_EFFECT`, and `ROLLBACK_REQUIRED` behavior under
  injected faults;
- exact-type/deep-immutable security objects, machine-enforced policy safety
  floors, principal-namespaced requests, fail-closed injected clock/identifier/
  dependency failures, exact executed-path/post-effect audit correlation, and
  one honest `POST_EFFECT_ACCOUNTING_FAILURE` / `ROLLBACK_REQUIRED` recovery
  record with exactly-once decision/failure metrics after a post-effect prewrite
  append failure;
- correlated secret-free audit lifecycle, metrics reconciliation, demo output,
  no-clobber writers, simulation-only environment rejection; and
- a deterministic 46-case declarative corpus whose project-controlled
  expectations passed 46/46 locally.

The Phase 3 review found and closed release-blocking defects across the
consequence, evidence, identity, policy, replay/receipt, dependency-failure, and
audit boundaries. The **57/57** result includes the dedicated release-blocker
regressions. The then-current repository result was **288/288** at exact Commit
`423685d`; exact-commit CI passed. These tests do not establish
OS/process isolation, durable/distributed replay control, enterprise source
provenance, external verifier independence, live action safety, efficacy, or a
statistical failure bound.

Phase 2.1 qualification coverage includes:

- the predeclared seven-record campaign with three accepted and four quarantined records;
- exact reasons for invalid JSON, a missing field, an invalid timestamp, and canonical-context mismatch;
- `input = accepted + quarantined`, exact rejection projection, and one decision per accepted case;
- source-file, physical-line, nonblank-ordinal, and raw-line-digest binding;
- byte-deterministic qualification and rejection artifacts;
- closed-schema and representation tests that prevent rejected payload and raw validator-text disclosure;
- fatal whole-call behavior for source-read faults, encoding, line-size, record-count, JSON-nesting, version, label, duplicate-ID, source-integrity, and unmapped-validator failures;
- forged, substituted, empty-acceptance, or incomplete qualification results rejected in validate-only and run paths before engine invocation;
- deterministic fixture-generation checks against pinned reviewed-source digests; and
- fail-closed protection against symlinked target directories, hard-linked target files, and source read/hash inconsistency.

These are synthetic control tests with `historical_case_count=0`. They do not measure historical acceptance, historical efficacy, operational performance, agentic alignment, or live-shadow readiness.

Phase 2.2 Gate B coverage includes:

- closed-schema and runtime agreement for approval states, exact roles, controls, review, counts, bindings, path syntax, and resource ceilings;
- rejection of missing, DRAFT, expired, malformed, mismatched, nonhistorical, or unsafe packages before any case or adjudication open, hash, count, decode, or parse;
- confined nonsymlink Gate B inputs under ignored `local/gate_b/` and descriptor-bound, owner-only historical outputs under ignored `outputs/replay/<run>/`, including ancestor-relocation and run-directory-substitution negative controls;
- frozen manifest, model, policy, mapping, and protocol bytes with mutation and symlink-swap detection;
- sanitized failures that do not echo private paths, digests, operating-system errors, unexpected field names, or injected values;
- missing private paths and qualification schemas fail through bounded validate-only and run errors, while duplicate JSON object members are rejected rather than accepted with last-member-wins behavior;
- post-qualification window and exact-decimal quarantine thresholds that stop before normalization or engine invocation;
- staged authorization expiry prevents completion, and unrecognized audit record types fail the replay evidence boundary;
- a path-free historical runner interface containing only in-memory accepted cases, model bytes, policy bytes, and the read-only execution mode, with adjudication bytes withheld until decision and audit closure; and
- zero authorization attempts, tokens, broker calls, action results, or operational effects for the fixed test-only package.

These tests establish implementation and negative-control coverage in the current checkout. No real Gate B approval or historical evidence bundle exists, so they do not establish organizational authority, privacy effectiveness, custody validity, or historical performance.

Published Phase 2.5 Commit `854b15c` adds a validator-owned closed registry and exact-match oracle for 25 selected Gate B identities: 24 selected pre-payload mutations plus one post-qualification threshold identity. Six oracle methods and four bounded observer methods passed. The observer recorded zero `cases` or `adjudications` roles for the 24 selected pre-payload mutations under `builtins.open`, `io.open`, `os.open`, `Path.open`, `Path.read_bytes`, and `Path.read_text`; hard-link aliases to governed files are explicitly outside its boundary. Unclassified Gate B errors remain unscorable. This is CE-1 scaffolding, not a complete taxonomy, OS-level nonaccess/non-egress proof, reference monitor, or campaign result.

Phase 2.3 audit-conformance coverage additionally rejects:

- any missing, duplicate, or reordered stage from the exact per-case sequence `CASE_RECEIVED`, `EVIDENCE_ASSESSED`, `MODEL_ASSESSED`, `POLICY_PROPOSED`, `INDEPENDENTLY_VERIFIED`, `EXECUTION_SUPPRESSED`, `AUTHORIZATION_EVALUATED`, and `DECISION_FINALIZED`;
- extra row or payload fields, noninteger or discontinuous sequence values, and malformed, timezone-naive, or decreasing timestamps;
- forged code-owned suppression values and counterfactual action lists that differ from the exact frozen policy; and
- mismatched decision identifiers or hashes, unknown record types, and duplicate JSON object members.

That coverage is CE-1 implementation-conformance evidence only. It cross-checks the presented audit, decisions, and policy actions; it does not independently recompute source-to-decision/model/policy correctness, establish externally trusted time or custody, or prevent wholesale replacement of the self-custodied chain.

The `P2-CE-003` controlled-behavior tests validate the closed campaign plan, schema, profile, result rows, summary, and exact evidence record. The published result contains two complete repetitions of 16 fixed synthetic scenarios (32/32 project-controlled expected-outcome matches), including two validate-only passes, 28 structural pre-payload blocks, and two post-qualification/pre-engine threshold blocks. The two sanitized result ledgers are byte-identical. During the 28 structural-block harness invocations, no governed payload-role open/read attempt was observed by the declared `Path`/`os.open` hooks; across all 32 attempts, no engine, authorization, broker, or target-effect boundary was reached and no completed run manifest, decision artifact, or audit artifact was observed.

Negative claim-evidence tests reject extra or reordered results, missing attempts, outcome drift, nonzero boundary counters, source-binding changes, duplicate JSON members, and authorization-canary disclosure. The result remains a SELF automated project-controlled synthetic check. It includes no real approval or actual historical data, and it does not establish independent/statistical trials, external preregistration, OS-level nonaccess/non-egress, target-side proof, exhaustive coverage, a bounded failure rate, efficacy, live safety, or alignment/misalignment behavior.

Phase 2.4 feature-assurance coverage additionally verifies:

- exact JSON Boolean handling and source authorization for all modeled Boolean attributes;
- finite integral `failed_logins` values in `0..1,000,000`, including accepted `10.0` and rejected Boolean, string, fractional, non-finite, negative, and over-bound forms;
- mandatory exact equality of `asset_id`, `privilege_level`, `break_glass`, and `asset_criticality` across the case and every asset-inventory event;
- opaque-attribute feature-projection invariance and event-order metamorphic behavior;
- rejection of non-finite JSON numbers anywhere in an accepted case and exact Boolean/network-only handling of decision-driving `source_conflict`, which is outside reference feature recomputation; under `QUARANTINE_RECORD`, wrong source is `SEMANTICS / UNAUTHORIZED_DECISION_SIGNAL` and wrong type is `SEMANTICS / INVALID_BOOLEAN`;
- exact normalized-case digest binding: SHA-256 over UTF-8 canonical JSON generated with sorted keys, compact separators, `ensure_ascii=True`, `allow_nan=False`, and no trailing newline;
- a separately implemented standard-library-only projector for all 20 feature values and feature-to-event traces;
- exact/unique case-set and normalized-case hash binding;
- closed metadata-only assurance rows, duplicate-member-aware persisted JSONL validation, and run-manifest/metrics count and digest bindings;
- failure before evaluator loading, qualification/rejection publication, comparisons, metrics, or completed run-manifest finalization; and
- coherent feature-value, feature-trace, source-context, decision-hash, and fully rechained-audit forgeries that pass the legacy validators but are rejected by the reference projector.

On a reference mismatch, earlier raw/normalized/deterministic decisions and audit artifacts may remain and are intentionally incomplete; no `reference_feature_assurance.jsonl`, metrics, or completed run manifest exists. These tests are CE-1 implementation-conformance evidence for the current checkout. They do not prove source truth, evidence quality, model probability, policy/disposition or verifier correctness, external custody, external independence, exhaustive coverage, a bounded failure rate, production readiness, or alignment/misalignment/sabotage robustness.

The committed `P2-CE-001` and `P2-CE-002` bundles were generated before alpha.5 and contain neither current reference-assurance artifact. Their original version-bound claims remain validated as recorded and were not retroactively upgraded; newly generated alpha.6 replay evidence must include both receipt artifacts and complete final revalidation.

The fixed `P2-CE-004` campaign against corrected Commit `53e409d6ffa4af98ea892bc1a81302bf30870693` contains two complete 16-attempt synthetic repetitions. All 32 observations matched project-controlled expectations: 16 clean matches, eight qualification quarantines, and eight reference-projector blocks, with zero retries, exclusions, failures, or deviations and byte-identical ledgers. The evidence record is CE-2 under SELF automated project-controlled review only. The implementation suite remains separate CE-1 evidence and does not itself create the campaign result. A prior unpublished package against Commit `1945ff283794c42f8eb649e320ba6adf91a6b982` was invalidated after its frozen validator accepted non-finite JSON and is excluded from every claim denominator.

Phase 2.5 source-to-decision coverage additionally verifies:

- strict duplicate-aware and non-finite-aware parsing of frozen normalized-case, decision, model, and policy bytes;
- exact, unique case sets and decision-record-hash validation before stage comparison;
- separately implemented reconstruction of `EVIDENCE`, `MODEL`, `POLICY`, `VERIFIER`, and `FINAL_SURFACE`, checked in that order with stable stage-specific errors;
- ordered `math.fsum(values) / event_count` evidence-aggregate agreement, including a rounding-sensitive ten-event trust-score control;
- ordered `math.fsum` model-logit agreement, including cancellation-heavy valid model controls;
- exact feature order, top-factor ordering, policy branches, verifier blockers, fail-safe downgrade, counterfactual action, read-only suppression, and traceability surfaces;
- receipt-schema, model/policy/case, execution-mode, stage-digest, path-digest, count, uniqueness, and deterministic-order binding;
- failure before either receipt, qualification/rejection publication, adjudication decoding, comparison, metrics, or completed-run finalization on a source-to-decision mismatch;
- exact-digest and late-mutation detection for normalized cases, normalization diagnostics, raw and deterministic decisions, audit, both reference receipts, adjudication comparison, replay metrics, and qualification/rejection artifacts when enabled, before manifest construction, after construction, and after manifest write; and
- the distinction between deterministic semantic receipts and volatile raw decision/audit instances, which are separately co-bound by the completed run manifest.

These tests are CE-1 implementation-conformance evidence only. The reference path is same-process, same-project, project-controlled, and not an external oracle or independent custody boundary. It does not establish source truth, outcome correctness, policy fitness, efficacy, historical/live performance, privacy authority, OS isolation, exhaustive coverage, or a statistical failure bound.

`P2-CE-005-SOURCE-TO-DECISION-SYNTHETIC` remains CE-0 `NOT_EVALUATED`. Its planned ten clean/mutant pairs per run share ten directly instrumented production baselines, so two runs budget 20 baseline executions, 20 calls to each production component, and 40 reference-path calls across the 40-attempt denominator. Direct authorization-gate/broker/target-effect/scoped-write counters and decision-derived token/result/effect fields are separately checked. These counts, zeros, and stage outcomes are expected values only. Unit or integration tests do not create the campaign result; CE-2 requires the documented exact-commit execution and evidence-only publication protocol.

Published Phase 2.5 Commit `854b15c` adds three campaign CLI destination regressions: `test_cli_destination_preflight_accepts_only_repo_confined_fresh_paths`, `test_cli_destination_preflight_rejects_escape_symlink_and_overlap`, and `test_cli_rejects_outside_destination_before_campaign_execution`. They passed 3/3. `test_check_rejects_unsafe_leaf_aliases_before_read_or_rebuild` verifies that check mode rejects symbolic-link, directory, and multiply linked artifact leaves and a symbolic-link record before any artifact read or campaign rebuild. `test_reference_scope_constructor_instrumentation_is_sensitive` separately injected construction of `AuthorizationGate`, `ActionBroker`, and `SimulatedIdentityProvider` during a reference attempt, observed nonzero counters and mismatch, and proved closed-schema rejection. The full campaign module passed 21/21. Fourteen `run_poc` safety methods separately passed for ordinary versus explicit-freeze destinations, repository aliases, redirects/overlap, unsafe existing generated leaves, and seven-output local-manifest binding. All are included in the 222/222 Phase 2.5 technical suite; the separate public-site module contributes nine tests only to the then-current 231/231 aggregate. Exact-commit CI passed. These are bounded operator-error and Python-instrumentation controls only; they do not establish OS/mount isolation, adversarial race or TOCTOU resistance, comprehensive hard-link defense, direct writer confinement, general allocation monitoring, target-side proof, or a campaign result.
