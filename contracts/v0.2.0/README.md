# Phase 2 Canonical Replay Contract v0.2.0

These initial contracts define the boundary between de-identified replay or read-only shadow data and the AI Decision Firewall decision engine. They are integration stubs, not a claim that vendor-specific mappings or operational data have been validated.

## Files

- `replay-case.schema.json` defines runtime case metadata and nested evidence events.
- `replay-adjudication.schema.json` defines evaluator-only labels stored in a separate JSONL file.
- `replay-manifest.schema.json` defines dataset provenance, approval and de-identification attestations, file roles, record counts, adapters, and SHA-256 digests.
- `evaluation-evidence.schema.json` defines the claim, exact system and harness, evaluation scope, validity checks, raw counts, evidence artifacts, review state, limitations, and prohibited inferences required before reporting a result.
- `examples/phase2-starter-evidence-record.json` is a worked CE-2 controlled-behavior record for the three-case synthetic fixture. It is not historical or operational evidence.

For replay manifests, cases, and adjudications, the Python validator in `src/adf_poc/replay/contracts.py` is the executable POC authority. It enforces constraints that JSON Schema cannot express cleanly, including repository-path confinement, file digest and record-count verification, globally unique case and event identifiers, timezone-aware timestamp ordering, runtime-label exclusion, and equality between canonical `break_glass` / `asset_criticality` values and the corresponding asset-inventory attributes.

Claim-evidence records are validated against `evaluation-evidence.schema.json` and cross-checked against their committed artifacts by `scripts/validate_claim_evidence.py`. That validator checks schema and format conformance, path confinement, artifact hashes and counts, run-manifest consistency, audit-chain integrity, per-case suppression/finalization records, empty authorization state, and the exact synthetic-only claim boundary.

## Runtime/evaluator separation

Case input must not contain `compromised`, `expected_disposition`, `scenario`, adjudication, ground-truth, or equivalent label fields. The replay harness passes only normalized cases to the engine. It loads the separate adjudication file only after decisions have been written and the read-only execution invariants have been validated.

## Governance boundary

Only `HISTORICAL_REPLAY` and `SHADOW_READ_ONLY` are valid Phase 2 modes. `live_actions_enabled` is fixed to `false` outside this data contract. Both modes require explicit approved-use, de-identification, and no-direct-identifier attestations. The starter dataset is synthetic by construction and declares `historical_case_count: 0`; it is not historical evidence.

## Deterministic normalization

Evidence is sorted by normalized UTC `observed_at`, `collected_at`, `source_type`, `source_instance`, and `event_id`. Reordered cases are reported in `normalization_diagnostics.json`. Volatile engine artifacts retain timestamps, UUIDs, latency, and audit hashes, while the replay harness emits a separate deterministic decision projection, comparison file, metrics file, and artifact manifest. The run manifest records current-run digests and counts for raw decisions and audit records as well as digests for deterministic outputs; volatile hashes are not expected to match across runs.

The executable validator also applies bounded-input controls: at most 100,000 records per declared JSONL file, one MiB per JSONL line, 10,000 events per case, 16,384 characters of untrusted text per event, 256 KiB of structured attributes per event, and 512 MiB per declared file. The harness refuses to use a non-empty output directory so prior replay evidence is never silently overwritten.
