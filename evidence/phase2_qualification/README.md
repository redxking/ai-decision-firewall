# Phase 2.1 Qualification Evidence Bundle

This directory contains the sanitized artifacts from one read-only run of the fixed seven-record synthetic qualification campaign. The run was generated from Git commit `499a5f63eb2cd82024adbfcbac3cd6602ce4101e` and is evaluated by claim profile `P2-CE-002`.

The observed result is deliberately narrow:

- 7 governed nonblank source records;
- 3 accepted records and 4 quarantined records;
- one quarantine each for invalid JSON, a missing required field, an invalid timestamp, and canonical-context mismatch;
- 3 read-only decisions, one for each accepted record;
- 0 authorization attempts or tokens, broker invocations, action results, or operational effects; and
- 24 audit records with one suppression, authorization-evaluation, and hash-bound finalization record per decision.

`expected_qualification.json` fixes all seven expected source-occurrence outcomes. `qualification_accounting.jsonl` binds every governed record by file digest, physical line, nonblank ordinal, and raw-line digest. `rejections.jsonl` is the exact ordered projection of quarantined ledger rows and contains no raw rejected payload.

Validate the complete bundle and its public wording boundary from the repository root:

```bash
python -m scripts.validate_claim_evidence \
  --record contracts/v0.2.0/examples/phase2-qualification-evidence-record.json \
  --profile P2-CE-002
```

The bundle is project-controlled and self-custodied. Git, the root `MANIFEST.sha256`, the run manifest, and the hash chain provide internal integrity checks; they do not provide an external signature, independent custody, WORM retention, or independent replication. The result does not establish historical data quality, operational performance, representativeness, alignment, sabotage resistance, live-shadow readiness, production safety, or zero risk.
