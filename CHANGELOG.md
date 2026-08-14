# Changelog

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
