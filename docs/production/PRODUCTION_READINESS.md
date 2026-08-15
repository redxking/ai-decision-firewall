# Production-readiness control record

**Candidate label:** `PRODUCTION_DEVELOPMENT_CANDIDATE`
**Production gate:** `BLOCKED`
**Stage authority:** bounded Stage A engineering only; Stage B and Stage C are not authorized
**Baseline:** `bb6b8f28afba0961bb97b24e6050fccaa94d5702` (`0.3.1-alpha.1`)

## Decision

The repository is not production-ready. The verified Phase 3.1 baseline is a
published, synthetic-only evaluation mechanism with model promotion fixed at
`NOT_AUTHORIZED`. Phase 3 effects remain confined to in-memory synthetic target
state. The present Stage A increment adds a single-host durable authority-state
mechanism and an enforceable production-readiness gate; it does not establish
an operational service, a production trust boundary, or authorization to use
historical data or external systems.

The machine-readable source of truth is
[`config/production_readiness_requirements.json`](../../config/production_readiness_requirements.json).
It contains mandatory requirements for all 18 production-readiness domains,
including acceptance criteria, accountable role, recorded owner acceptance,
evidence state, exact artifacts, remaining gate, release gate, and prohibited
inference. [`scripts/validate_production_readiness.py`](../../scripts/validate_production_readiness.py)
derives the gate from those rows. A declared ready state is invalid unless
every mandatory row has objective evidence, recorded owner acceptance, and a
recorded `OPERATIONALLY_EFFECTIVE` state.

## Verified starting point

The following observations were independently reproduced or verified before
the Stage A code was changed:

| Item | Verified state | Evidence boundary |
|---|---|---|
| Remote baseline | `origin/main` and GitHub `main` resolved to exact commit `bb6b8f28afba0961bb97b24e6050fccaa94d5702` | Publication to `main` is not a tag, signed artifact, or GitHub Release. |
| Package/version | PEP 440 `0.3.1a1`; project label `0.3.1-alpha.1` | Baseline identity only. |
| Exact-commit CI | GitHub Actions unit-test jobs succeeded on Python 3.11 and 3.12; Dependency Graph job succeeded | Green CI is implementation evidence, not operational effectiveness. |
| Local regression | 299/299 tests passed on the clean exact baseline | Local runtime observation, separately reproduced; no production environment was exercised. |
| Phase 3.1 focused | 11/11 passed | Synthetic evaluation-mechanism conformance only. |
| Phase 3 corpus | 46/46 matched project-controlled expectations | Declared synthetic corpus coverage, not exhaustive security assurance. |
| Integrity inventory | 290/290 entries passed before modification | SHA-256 inventory is neither signature nor external custody. |
| Execution boundary | Phase 2 read-only; Phase 3 synthetic and in-memory | No external connector, credential, broker endpoint, or live target. |
| Model promotion | `NOT_AUTHORIZED` | No approved threshold, representative data, historical validation, or owner acceptance. |
| P2-CE-005 | CE-0 `NOT_EVALUATED` | A plan is not an observed campaign result. |

No Phase 3 or Phase 3.1 tag or GitHub Release was found. The published Phase
3.1 commit was reported unsigned. Those facts remain release and provenance
gaps, not test failures.

## Defect discovered

On the exact baseline, a completed request could execute again after process
restart. The same authenticated principal, request identifier, and canonical
request were submitted to two newly constructed firewall instances sharing the
same persisted audit file. Both returned `ALLOW`; both synthetic lifecycles
reported one operational effect; and the resulting 26-row hash chain still
validated.

The defect existed because request claims, verified-decision issuance, token
consumption, attempt bindings, and target state were process-local dictionaries.
The persisted audit was evidence of a lifecycle but was not consulted as the
authority-state ledger. A valid hash chain therefore did not prevent replay.

## Stage A increment implemented

The additive [`src/adf_poc/stage_a.py`](../../src/adf_poc/stage_a.py)
provides a development-grade SQLite transaction spine. When an explicit
control-ledger path is configured, it provides:

- one immutable request claim per authenticated principal and request ID, with
  an exact canonical request digest and conflict detection;
- durable uniqueness for verified-decision authorization issuance;
- atomic authorization consumption and attempt reservation before synthetic
  target invocation;
- exact attempt-scope digest binding and monotonic attempt outcomes;
- transactional digest-only audit-outbox events for each authority-state
  transition;
- WAL mode, `synchronous=FULL`, foreign keys, strict tables, a bounded busy
  timeout, an explicit schema version, owner-only database-file permissions,
  and refusal of symlink, nonregular, multiply linked, corrupt, locked, or
  unsupported-schema storage; and
- explicit, idempotent reconciliation of incomplete `RESERVED` attempts to
  `UNKNOWN_EFFECT` without reopening the consumed authorization or
  automatically reissuing the command.

The default Phase 3 simulation remains process-local for published-baseline
compatibility. Durability is opt-in through an explicit Stage A ledger path.
The correction is tested across newly constructed service objects and
independent operating-system processes. A post-effect ledger failure produces
`ROLLBACK_REQUIRED`; restart reconciliation preserves `UNKNOWN_EFFECT` instead
of fabricating success, no effect, or successful rollback.

## Evidence-state interpretation

The controlled vocabulary is intentionally ordinal only as an evidence
discipline, not as an automatic maturity promotion:

1. `IMPLEMENTED`
2. `UNIT_TESTED`
3. `INTEGRATION_TESTED`
4. `SYNTHETIC_MECHANISM_EVALUATED`
5. `HISTORICALLY_EVALUATED`
6. `NON_PRODUCTION_VALIDATED`
7. `PILOT_ACCEPTED`
8. `PRODUCTION_AUTHORIZED`
9. `OPERATIONALLY_EFFECTIVE`

`NOT_IMPLEMENTED` and `EXTERNAL_APPROVAL_REQUIRED` are blocking states. A
higher technical test state does not imply any later state. In particular,
synthetic mechanism evaluation does not imply historical evaluation, and owner
acceptance cannot be inferred from repository authorship or CI.

## Current authority and execution boundary

Permitted in this increment:

- repository-local code, documentation, schemas, and tests;
- synthetic fixtures and in-memory targets already present in the repository;
- temporary local SQLite databases created only by tests; and
- a local commit and exact-commit verification.

Not authorized or performed:

- historical organizational data or representative operational datasets;
- production or test-tenant connectors;
- operational credentials, enterprise IAM, KMS/HSM keys, or external secrets;
- a live or designated external target, broker, source, audit sink, or queue;
- infrastructure deployment, network access, Stage B integration, or Stage C
  pilot activity;
- model promotion, threshold approval, policy approval, or target-owner
  acceptance; and
- push, merge, tag, GitHub Release, repository-setting change, or external
  message.

## Remaining release blockers

The machine matrix is authoritative; the following are the most consequential
open gates:

- request duplicates are safely blocked, but durable terminal-result retrieval
  and a durable adapter receipt/reconciliation seam are not yet implemented;
- SQLite establishes single-host durability and interprocess serialization,
  not distributed linearizability, fencing, failover, partition tolerance, HA,
  or disaster recovery;
- the broker, observer, target, and key material remain same-process and
  project-custodied; there is no OS isolation, mutually authenticated IPC,
  vendor adapter, managed key lifecycle, or independently controlled audit;
- no representative or historical validation is authorized; label independence,
  owner thresholds, operational error costs, OOD/shift gates, signed promotion,
  rollback, and revocation remain open;
- deployment architecture, IaC, secrets procedures, SLOs, monitoring, incident
  response, backup/restore exercises, capacity/load evidence, and intended-
  environment rollback are not operational;
- SBOM, hash-locked dependencies, signed artifacts, reproducible-build evidence,
  and provenance attestations are absent; and
- mission, security, data, model, policy, operations, target-system, and
  authorizing-official acceptances are not recorded.

The next safe engineering increment is a durable synthetic adapter receipt and
terminal request-result seam with crash injection at every pre- and post-effect
boundary. Process isolation should follow that transaction contract. Any move
to representative data, external identity, a connector, or a designated target
requires a separate, exact authorization package.
