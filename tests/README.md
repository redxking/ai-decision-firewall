# POC Test Suite

Run from the repository root:

```bash
PYTHONPATH=src python -m unittest discover -s tests -v
```

The 67-test suite focuses on safety and evidence invariants rather than synthetic classifier accuracy. It covers the original abstention, break-glass, human-authority, authorization, label-separation, and audit-tamper controls plus the Phase 2 read-only execution boundary, replay contracts, path confinement, canonical-context consistency, frozen input snapshots, temporal normalization, post-decision adjudication loading, deterministic artifacts, decision/audit binding, exact authorization-state rejection, zero token/broker/effect assertions, and the narrow starter claim-evidence record.

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
