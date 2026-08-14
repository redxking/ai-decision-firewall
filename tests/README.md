# POC Test Suite

Run from the repository root:

```bash
PYTHONPATH=src python -m unittest discover -s tests -v
```

The 33-test suite focuses on safety invariants rather than synthetic classifier accuracy. It covers the original abstention, break-glass, human-authority, authorization, label-separation, and audit-tamper controls plus the Phase 2 read-only execution boundary, replay contracts, canonical-context consistency, frozen input snapshots, temporal normalization, post-decision adjudication loading, deterministic artifacts, decision/audit binding, exact authorization-state rejection, zero token/broker/effect assertions, and the narrow claim-evidence record.
