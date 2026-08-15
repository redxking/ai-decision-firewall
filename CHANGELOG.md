# Changelog

## 0.2.0-alpha.5 — 2026-08-15

- Added a typed, source-authorized contract for all modeled event attributes. JSON Booleans are no longer interpreted through generic truthiness, `failed_logins` accepts only finite integral JSON numbers in the code-owned `0..1,000,000` range, and modeled keys asserted by an unauthorized source fail closed.
- Required every `asset_inventory` event to contain `asset_id`, `privilege_level`, `break_glass`, and `asset_criticality` and to match the canonical case context exactly before the case can reach feature extraction.
- Added a separately implemented in-process reference projector that reconstructs the 20 model feature values and event traces from normalized cases without importing the production extractor, feature-contract implementation, engine, model, policy, verifier, harness, or metrics modules.
- Added the closed, metadata-only `reference_feature_assurance.jsonl` artifact. Each successful case row contains only the case identifier, normalized-case digest, expected and observed projection digests, and `matched=true`; the run manifest hash/count-binds the artifact and metrics report checked, matched, mismatched, and completeness counts.
- Positioned the reference check after read-only decision validation, deterministic decision serialization, and complete eight-stage audit validation, but before qualification/rejection publication, adjudication loading, comparisons, metrics, or completed run-manifest finalization. A mismatch emits no reference-assurance artifact, metrics, or completed manifest; earlier decision and audit files may remain as explicitly incomplete evidence.
- Added schema/runtime differential, positive-fixture, opaque-attribute feature-invariance, event-order metamorphic, exact-inventory-binding, non-finite-number, typed network-only `source_conflict` (including `UNAUTHORIZED_DECISION_SIGNAL` wrong-source classification), duplicate-aware artifact, and coherent decision/audit-rehash tests. The full local suite now contains 143 passing tests.
- Preserved the version boundary for the pre-alpha.5 `P2-CE-001` and `P2-CE-002` bundles: their original narrow claims remain validated against their recorded artifacts, but they contain no reference-feature-assurance artifact and were not retroactively upgraded. New alpha.5 replays require that artifact for completion.
- Added and froze the planned `P2-CE-004` synthetic campaign scaffold: two intended repetitions of 16 fixed attempts each, comprising eight clean projection matches, four qualification quarantines, and four reference-projector blocks per repetition, with zero retries or exclusions permitted. **No campaign execution, result ledger, evidence record, or CE-2 result exists yet; `P2-CE-004` remains CE-0 / not evaluated.**
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
