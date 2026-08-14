# Phase 2 Starter Evidence Bundle

This directory preserves the complete output of one built-in `historical_replay` run over the three-case synthetic starter fixture on 2026-08-14. It exists so the narrow CE-2 result can be independently inspected rather than inferred from a summary table.

The bundle includes:

- exact snapshotted configuration, manifest, model, policy, cases, and adjudications;
- normalized cases and diagnostics;
- raw engine decisions and the deterministic decision projection;
- the complete presented audit chain;
- adjudication comparisons and replay metrics; and
- the run manifest that binds every input and output digest and record count.

The controlling evidence record is [`contracts/v0.2.0/examples/phase2-starter-evidence-record.json`](../../contracts/v0.2.0/examples/phase2-starter-evidence-record.json). Run `python scripts/validate_claim_evidence.py` from the repository root to validate its schema, artifact hashes and counts, run-manifest cross-checks, audit chain, and narrow result totals.

## Evidence boundary

- All records are synthetic. `historical_case_count` is zero.
- The three adjudications are project-authored test expectations, not historical or operational ground truth.
- Raw decisions, audit records, and the run manifest include run-specific timestamps, UUIDs, latency, and chain hashes; repeated runs will not reproduce those bytes.
- The deterministic artifacts are expected to reproduce byte for byte with the same committed inputs and implementation.
- Git and `MANIFEST.sha256` provide repository integrity. They are not an external signature, WORM store, or independent chain of custody.
- This bundle supports only the wording in the controlling evidence record. It does not establish historical performance, operational efficacy, agentic alignment, monitor effectiveness, production safety, or authorization for live action.
