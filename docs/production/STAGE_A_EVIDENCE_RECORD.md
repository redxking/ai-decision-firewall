# Stage A exact-commit evidence record

**Record ID:** `ADF-STAGE-A-ER-001`

**Recorded:** 2026-08-15

**Implementation commit:** `71d5e1000a268a061f16211364f78712f57fb51a`

**Baseline commit:** `bb6b8f28afba0961bb97b24e6050fccaa94d5702`

**Candidate:** `0.4.0-alpha.1` / PEP 440 `0.4.0a1`

**Derived production gate:** `BLOCKED`

**Review state:** project-controlled SELF verification; no independent review,
accountable-owner acceptance, authorizing-official approval, or exact-commit
remote CI exists for this unpushed branch.

## Decision and claim boundary

Commit `71d5e1000a268a061f16211364f78712f57fb51a` is the exact
implementation boundary for the Stage A increment. It adds a development-grade,
single-host SQLite authority-state ledger and a strict production-readiness
gate. It does not establish production readiness, operational effectiveness,
historical validation, pilot acceptance, distributed idempotency, process
isolation, external audit custody, HA/DR, a deployed service, or authority to
connect to any external system.

The evidence-record carrier commit necessarily follows the implementation
commit and is not self-referential. `MANIFEST.sha256` in the carrier commit
binds this file and the other repository artifacts; the carrier commit is
reported in the completion handoff and must be reverified before any later use.

## Execution environment

| Property | Recorded value | Boundary |
|---|---|---|
| Host/runtime | Darwin 25.6.0 arm64; CPython 3.13.0 | Local development host, not an intended production environment |
| Runtime libraries | NumPy 2.3.4; jsonschema 4.25.1; SQLite 3.45.3 | Observed local versions; not a deployment lock or approved bill of materials |
| Wheel builder | Bundled CPython 3.12.13; setuptools 83.0.0; wheel 0.47.0 | Local, non-isolated builder; no signed provenance or reproducible-build claim |
| Repository state | Clean exact implementation commit `71d5e1000a268a061f16211364f78712f57fb51a` | Local branch `codex/production-stage-a-bb6`; no push, merge, tag, or release |
| Data and target | Committed synthetic fixtures and in-memory synthetic target only | Zero historical/live payload access and no external target or credential |

## Claim-to-evidence trace

All Stage A implementation claims below bind to exact Commit
`71d5e1000a268a061f16211364f78712f57fb51a` unless another commit is
explicitly stated.

| ID | Requirement or bounded claim | Implementation and exact artifact | Test or evaluation method | Result | Limitations and prohibited inference | Reviewer / remaining gate |
|---|---|---|---|---|---|---|
| SA-ER-001 | Preserve the published starting point and its evidence boundaries. | Published baseline `bb6b8f28afba0961bb97b24e6050fccaa94d5702`; [`PRODUCTION_READINESS.md`](PRODUCTION_READINESS.md) | Verified exact local baseline, 290-entry manifest, 299-test suite, Phase 3 corpus, Phase 3.1 focused suite, and public GitHub status before modification. | Baseline reproduced; Phase 3.1 remained synthetic-only and promotion remained `NOT_AUTHORIZED`. | Publication and green CI do not imply a tag, signed artifact, operational validation, or production acceptance. | SELF verified; external provenance and release gates remain open. |
| SA-ER-002 | Prevent a completed request from executing again after every service object is reconstructed. | [`src/adf_poc/stage_a.py`](../../src/adf_poc/stage_a.py); [`phase3/engine.py`](../../src/adf_poc/phase3/engine.py) | `test_restart_replay_is_denied_before_a_second_broker_or_effect` destroys and reconstructs the firewall over one ledger and replays the same authenticated request. | PASS; one first broker invocation/effect and no second invocation/effect. | Duplicate requests return a safe duplicate disposition, not a durable copy of the original full result. This is one-host SQLite serialization, not distributed replay protection. | SELF verified; terminal-result retrieval and distributed consistency remain open. |
| SA-ER-003 | Bind a request identifier immutably to the authenticated principal and canonical request digest. | `requests` table and `claim_request` in [`stage_a.py`](../../src/adf_poc/stage_a.py) | `test_restart_request_identifier_conflict_fails_closed`; `test_process_concurrency_yields_one_request_claim` uses independent OS processes. | PASS; exact duplicates are blocked, digest conflicts fail closed, and one concurrent claim wins. | A crash after claim but before completion sacrifices availability; no lease or automatic replay exists. | SELF verified; service-level recovery and owner-approved retry policy remain open. |
| SA-ER-004 | Consume an issued authorization and reserve one bound attempt atomically before target invocation. | `authorizations`, `attempts`, and outbox transitions in [`stage_a.py`](../../src/adf_poc/stage_a.py); integration in [`authorization.py`](../../src/adf_poc/phase3/authorization.py) and [`simulation.py`](../../src/adf_poc/phase3/simulation.py) | `test_process_concurrency_reserves_one_attempt_and_consumes_once`; `test_verified_decision_can_issue_only_once_across_restart`; `test_attempt_idempotency_binding_is_independent_of_attempt_id`. | PASS; one token consumption and attempt reservation, stable exact binding, and conflict rollback. | The synthetic adapter has no separate durable command receipt. Missing post-effect persistence therefore remains indeterminate. | SELF verified; durable adapter receipt and reconciliation contract are the next safety gate. |
| SA-ER-005 | Fail closed on unavailable, unsafe, corrupt, locked, or unknown-schema authority storage. | Path, schema, integrity, transaction, WAL, `synchronous=FULL`, foreign-key, and busy-timeout controls in [`stage_a.py`](../../src/adf_poc/stage_a.py) | Storage/schema, lock-timeout, preexisting-unversioned DB, symlink-file, symlink-parent, and audit/control alias tests in [`test_stage_a_durable_control_ledger.py`](../../tests/test_stage_a_durable_control_ledger.py). | 16/16 focused Stage A tests PASS with `ResourceWarning` treated as failure. | Filesystem safety checks are application controls, not protection from a privileged same-host actor or adversarial filesystem replacement. | SELF verified; hardened runtime, managed volume, and independent security review remain open. |
| SA-ER-006 | Preserve uncertainty after a possible effect and never reopen a consumed authorization. | Monotonic `RESERVED`, `COMPLETED`, `FAILED_NO_EFFECT`, and `UNKNOWN_EFFECT` attempt states; conservative engine handling | `test_post_effect_ledger_failure_is_honest_and_recovers_unknown`; `test_incomplete_attempt_recovers_to_unknown_and_never_reopens_token`; `test_no_effect_broker_failure_is_not_recorded_as_completed`. | PASS; possible-effect persistence failure reports `ROLLBACK_REQUIRED`, reconciliation records `UNKNOWN_EFFECT`, and the token remains consumed. | Reconciliation is an explicit, quiesced single-owner operation. It cannot determine target truth without an authoritative adapter receipt and never proves rollback. | SELF verified; independent observation and operational recovery acceptance remain open. |
| SA-ER-007 | Make every authority-state transition durable with the state transaction. | Digest-only `audit_outbox` in [`stage_a.py`](../../src/adf_poc/stage_a.py) | Successful reopen, failure rollback, and recovery tests inspect durable ordered pending rows. | PASS for the exercised local transitions. | No exporter, external custody, trusted time, WORM store, signature, anchor, retention implementation, or verified restoration exists. | SELF verified; external-audit architecture and records-owner approval remain open. |
| SA-ER-008 | Enforce a closed, non-self-promoting production-readiness decision across all prompt domains. | [`production_readiness_requirements.json`](../../config/production_readiness_requirements.json); [`validate_production_readiness.py`](../../scripts/validate_production_readiness.py) | 18 mutation/positive tests plus direct CLI derivation. | 18/18 PASS; structurally valid 18 domains and 36 mandatory requirements; CLI intentionally returned exit 2 and `BLOCKED`; all 36 IDs remain blockers. | Structural validity does not close any requirement. `PRODUCTION_AUTHORIZED` alone is insufficient; every row would require recorded `OPERATIONALLY_EFFECTIVE` evidence and owner acceptance. | SELF verified; all accountable-owner and authorizing-official decisions remain open. |
| SA-ER-009 | Preserve all repository behavior while adding Stage A. | Complete source and test tree at the implementation commit | `PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src:. PYTHONWARNINGS=error::ResourceWarning python3 -m unittest discover -s tests -p 'test_*.py'` | 333/333 PASS in 38.571 seconds on the exact implementation commit. | Test passage is bounded to the implemented cases and local runtime. No Stage A exact-commit CI, coverage threshold, formal proof, red-team result, or operational reliability bound exists. | SELF verified; independent V&V and remote CI require separate authorization/publication. |
| SA-ER-010 | Preserve Phase 3 synthetic decision and adversarial behavior. | [`run_phase3.py`](../../run_phase3.py); [`run_phase3_corpus.py`](../../run_phase3_corpus.py) | Executed both demonstrations and the fixed 46-case corpus into fresh temporary directories. | Demonstration acceptance PASS; audit chain valid; corpus 46/46 PASS; `live_actions_possible=false`. | Project-controlled synthetic expectations are not efficacy, exhaustiveness, or live-action safety evidence. | SELF verified; target-owner and operational T&E acceptance remain open. |
| SA-ER-011 | Preserve Phase 3.1 data and authority separation. | [`phase31`](../../src/adf_poc/phase31); fixed evaluation plan | 11 focused tests and fresh benchmark execution. | 11/11 PASS; 240 evaluation records; `COMPLETE_SYNTHETIC_ONLY`; promotion `NOT_AUTHORIZED`; broker and target not constructed; zero historical/live access and operational effects. | No representative data, independent labels, approved thresholds, OOD/shift acceptance, historical efficacy, or promotion authority exists. `P2-CE-005` remains `NOT_EVALUATED`. | SELF verified; data, model-risk, mission, and owner approvals remain open. |
| SA-ER-012 | Bind the repository snapshot and confirm package construction. | [`MANIFEST.sha256`](../../MANIFEST.sha256); [`pyproject.toml`](../../pyproject.toml) | `shasum -a 256 -c MANIFEST.sha256`; local PEP 517 wheel build with no dependency resolution or network access. | 300/300 manifest entries PASS; `ai_decision_firewall_poc-0.4.0a1-py3-none-any.whl` built successfully, observed SHA-256 `480347fdfbdf080a93e962e5cdf73e9d709a858db7861c769952a1f07d2f43fb`. | The wheel was a temporary local observation, not a committed, signed, reproducible, scanned, published, or approved release artifact. The manifest is self-custodied and unsigned. | SELF verified; SBOM, dependency lock, provenance, signing, scanning, and release approval remain open. |
| SA-ER-013 | Keep architecture and operating guidance aligned with the actual boundary. | [`ADR 014`](../adr/014_stage_a_durable_transaction_spine.md); [`THREAT_CONTROL_REGISTER.md`](THREAT_CONTROL_REGISTER.md); [`FAILURE_RECOVERY_MATRIX.md`](FAILURE_RECOVERY_MATRIX.md); [`STAGE_A_DURABLE_LEDGER_RUNBOOK.md`](../operations/STAGE_A_DURABLE_LEDGER_RUNBOOK.md); [`09_phase31_model_evaluation.png`](../architecture/09_phase31_model_evaluation.png) | Link/path checks through the production validator; cited test-name resolution; manual image inspection. | Required paths and cited tests resolved; the rendered diagram was visually inspected with no crop or overlap observed. | The runbook is a bounded development procedure. Backup/restore, incident response, SLOs, deployment, rollback, HA, and disaster recovery are not operationally exercised. | SELF verified; operations, security, data, target-system, and authorizing-official acceptance remain open. |

## Negative execution statement

This Stage A activity did not use or create:

- historical organizational data, representative operational data, or an
  approved Gate B data package;
- a production/test-tenant connector, live feed, broker endpoint, external
  target, operational credential, enterprise identity, or managed key;
- model promotion, an approved decision threshold, policy-owner authorization,
  a pilot, deployment, network integration, or live action; or
- a push, merge, tag, GitHub Release, repository-setting change, deployment,
  or external communication.

## Release decision

The only supportable disposition is **BLOCKED / NOT PRODUCTION-READY**.
The highest-priority next safe increment is a durable synthetic adapter receipt
and terminal request-result seam with crash injection before and after every
effect boundary. That increment must continue to use offline synthetic data and
must not introduce a live connector or operational credential without a new,
explicit authorization package.
