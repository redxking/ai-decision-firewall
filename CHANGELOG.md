# Changelog

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
