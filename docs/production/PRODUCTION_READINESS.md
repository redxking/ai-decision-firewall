# Production-readiness control record

**Candidate label:** `PRODUCTION_DEVELOPMENT_CANDIDATE`
**Candidate version:** `0.4.0-alpha.2` (`0.4.0a2`)
**Production gate:** `BLOCKED`
**Stage authority:** bounded Stage A engineering only; Stage B and Stage C are not authorized
**Baseline:** `bb6b8f28afba0961bb97b24e6050fccaa94d5702` (`0.3.1-alpha.1`)

## Decision

The repository is not production-ready. The verified Phase 3.1 baseline is a
published, synthetic-only evaluation mechanism with model promotion fixed at
`NOT_AUTHORIZED`. The present opt-in Stage A candidate adds a single-host
durable authority database and a separate durable offline synthetic-adapter
database, plus an enforceable production-readiness gate. The adapter remains
same-process, same-host, same-project, and synthetic-only. Its receipt is not
independent evidence, and the increment does not establish an operational
service, production trust boundary, or authority to use historical data,
external systems, credentials, connectors, or targets.

The bounded implementation is frozen at exact Commit
[`8818d5d2d40faebced66a254d58b1f0d04c9f8b4`](https://github.com/redxking/ai-decision-firewall/commit/8818d5d2d40faebced66a254d58b1f0d04c9f8b4).
Exact-SHA GitHub Actions [run 31953570779](https://github.com/redxking/ai-decision-firewall/actions/runs/31953570779)
succeeded on Python 3.11 and 3.12, and [Dependency Graph run
31953572482](https://github.com/redxking/ai-decision-firewall/actions/runs/31953572482)
succeeded. The exact-SHA Pages query returned no runs. These observations are
exact implementation evidence only; they do not establish a release,
deployment, owner acceptance, production authorization, or operational
effectiveness. The successor evidence record is carried separately from the
implementation by this evidence-only change. Its exact carrier SHA is
necessarily reported after creation and is not self-claimed in these contents.

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

The following project-controlled observations were reproduced or verified
before the Stage A code was changed:

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
provides a development-grade two-database SQLite transaction spine. When
explicit, pairwise-distinct `control_ledger_path`, `synthetic_adapter_path`,
and JSONL `audit_path` values are configured, it provides:

- one immutable request claim per authenticated principal and request ID, with
  an exact canonical request digest and conflict detection;
- durable uniqueness for verified-decision authorization issuance;
- atomic authorization consumption and attempt reservation before invoking the
  offline `SQLiteSyntheticAdapterStore`;
- exact attempt-scope digest binding and monotonic attempt outcomes;
- an adapter schema-v1 transaction that validates the trusted precondition,
  changes durable synthetic target state, and commits one immutable,
  exact-bound `SyntheticAdapterReceipt`; an exact repeat returns the same
  receipt without a second state change, while a changed binding conflicts;
- a separate read-only observation of durable adapter state. It is distinct
  from command acknowledgement but remains same-store/project custody and is
  not independent verification;
- a closed, versioned, sanitized `RequestLookupResult`, atomically committed
  with its control terminal transition and metadata-only outbox event. It is
  not a serialized `Phase3Result` and recursively excludes authorization,
  token, nonce, signature, credential, key, raw-audit, and executable-authority
  material;
- an authenticated, read-only `lookup_request_result` seam keyed by exact
  principal, request ID, and canonical request digest. An exact duplicate can
  retrieve the stored projection with explicit replay/no-new-work flags;
  changed digest or principal fails closed without result disclosure, and
  `process_json` remains duplicate-denying and returns only `Phase3Result`;
- transactional digest-only audit-outbox events for each authority-state
  transition;
- bounded cooperative POSIX directory locking for public-store first creation,
  combined three-artifact startup, and each durable firewall operation, plus
  exclusive audit-file ownership for a complete JSONL lifecycle. Contention
  fails within the configured startup bound for cooperating processes;
- WAL mode, `synchronous=FULL`, foreign keys, strict tables, a bounded busy
  timeout, an explicit schema version, owner-only database-file permissions,
  owner-private active sidecars, and refusal of symlink, nonregular, multiply
  linked, corrupt, locked, or unsupported-schema storage;
- a single firewall-clock creation timestamp for both new stores; closed
  schema fingerprints and full control relationship, provenance, lifecycle,
  result, and chronology scans; continuous adapter target/receipt state-time
  chain validation; and startup/runtime correlation that rejects orphan,
  missing, substituted, disposition-inconsistent, or target-inconsistent
  cross-store histories before authoritative use; and
- explicit `reconcile_request(operator_asserted_quiesced=True)` recovery that
  never invokes the command, mints replacement authority, reopens a consumed
  token, fabricates verification, or claims rollback.

The control database uses schema version 2 and the adapter database uses schema
version 1. The control-ledger constructor refuses and preserves a schema-v1
control file; no migrator exists. The supported successor procedure is to
preserve the v1 artifact and create a new reviewed v2 ledger at a distinct safe
path. A future migrator would require a separate quiesced, transactional design
and test package.

T1 control reservation, T2 adapter mutation plus receipt, JSONL lifecycle
audit, read-only observation, and T3 terminal control result are deliberately
separate boundaries. No cross-store transaction or crash-consistent recovery
point is claimed. Reconciliation is conservative: an exact affirmative
`NO_EFFECT` receipt may close `FAILED_NO_EFFECT`; `APPLIED`, `PARTIAL`, or
`AMBIGUOUS` without separately durable verification closes `UNKNOWN_EFFECT`;
no receipt also closes `UNKNOWN_EFFECT`; corrupt, mismatched, or unavailable
adapter evidence halts with no state change. `UNKNOWN_EFFECT` remains terminal
and never authorizes automatic retry.

Recovery writes the exact JSONL sequence `RECOVERY_STARTED`,
`RECOVERY_EVIDENCE_ASSESSED`, and `RECOVERY_FINALIZED` before T3. Each record
binds the recovery identity and exact request; the lifecycle records whether
the original execution audit was `COMPLETE`, `INCOMPLETE`, or `UNRESOLVED`
without rewriting that history. Prefixes resume idempotently. A complete trio
whose T3 control commit is still pending fences request and approval audit
writers with `RECOVERY_AUDIT_PENDING`; the exact recovery retry may commit T3
without changing the trio.

The cooperative locks and correlation checks are detection and serialization
controls for supported processes on one POSIX host. They do not create
cross-store atomicity, independent custody, a distributed lease or fencing
epoch, protection from a noncooperating same-user writer, failover, HA, or DR.

The default Phase 3 simulation remains process-local for published-baseline
compatibility. The two-database successor path is opt-in and offline. Its
implementation evidence is repository-controlled synthetic conformance only.
The exact implementation commit, local focused/full verification, manifest,
and exact-SHA CI are now recorded below. Broader real power-loss, filesystem and
storage-failure, hostile-writer, capacity, independent-assessment, and
operational campaigns remain separate release steps.

The current successor source tree also carries exact-version SHA-256 runtime
and documentation dependency locks, an unsigned CycloneDX 1.6 runtime SBOM,
strict lock/SBOM validation, exact Git-tracked manifest coverage validation,
full-commit Action pins, nonpersistent checkout credentials, binary-only
hash-enforced workflow installation, warning-fatal tests, and job-scoped Pages
write/OIDC authority. These are repository-controlled mechanisms. Until a
clean candidate commit, regenerated complete manifest, exact-commit CI, build
artifact, provenance, vulnerability disposition, and independent review exist,
they are not release evidence or production authorization.

### Exact implementation evidence

On 2026-08-16, the frozen implementation and exact-SHA automation produced the
following bounded evidence. Local results are project-controlled observations;
CI and Dependency Graph success are exact-SHA implementation checks. None is
production authorization, operational effectiveness, or owner acceptance:

| Check | Observed result | Evidence boundary |
|---|---|---|
| Implementation identity | Commit `8818d5d2d40faebced66a254d58b1f0d04c9f8b4`; candidate `0.4.0-alpha.2` / `0.4.0a2`; baseline remains `bb6b8f28afba0961bb97b24e6050fccaa94d5702` | Exact source identity; not the later ER-002 evidence-carrier identity. |
| Focused Stage A receipt/recovery and durable-ledger suite | 43/43 passed in 8.248 seconds with bytecode writes disabled and warnings treated as errors | Exact implementation mechanism coverage; synthetic and project controlled. |
| Multiprocess exact-once repeat | 5/5 passed | Bounded same-host cooperative-process evidence, not distributed linearizability, HA, or a capacity result. |
| Production-readiness validator | Structurally valid; 18 domains, 36 mandatory requirements, 36 blocking requirements; derived `BLOCKED`; expected exit 2 | Every `owner_acceptance` remains `NOT_RECORDED`; structural validity is not readiness. |
| Complete repository regression | 360/360 passed in 48.995 seconds with `PYTHONWARNINGS=error` | Local exact-implementation observation; no intended production environment was exercised. |
| Phase 3 inherited boundary | 57/57 focused; both demonstrations PASS; deterministic corpus 46/46 with `live_actions_possible=false` | Preserves simulation-only behavior; no live action or operational-effect claim. |
| Phase 3.1 inherited boundary | 11/11 focused; promotion remains `NOT_AUTHORIZED` | Synthetic model-evaluation mechanism only. |
| Integrity inventory | 307/307 entries verified | SHA-256 inventory is not a signature, SBOM, reproducible build, or external custody. |
| Exact-SHA CI | Run `31953570779` succeeded for Commit `8818d5d2...` on Python 3.11 and 3.12 | The workflow unit-test step did not promote `ResourceWarning` to an error; green CI remains implementation evidence only. |
| Dependency Graph | Run `31953572482` succeeded | Dependency ingestion success is not an SBOM, signature, provenance attestation, release, or deployment. |
| Pages | Exact-SHA query returned `[]` | Pages did not run; no publication or deployment claim follows. |

The successor requirement-to-implementation map is
[`STAGE_A_RECEIPT_RESULT_TRACEABILITY.csv`](STAGE_A_RECEIPT_RESULT_TRACEABILITY.csv).
It binds exact implemented seams to named tests and the exact implementation
evidence above. Successor evidence record
[`STAGE_A_RECEIPT_RESULT_EVIDENCE_RECORD.md`](STAGE_A_RECEIPT_RESULT_EVIDENCE_RECORD.md)
(`ADF-STAGE-A-ER-002`) binds the implementation commit, local observations,
manifest, exact-SHA CI, evidence status, and non-inferences. ER-002 is not owner
acceptance, production authorization, operational effectiveness, or a release;
its evidence carrier is necessarily unnamed within its own contents and its
separate 308-entry manifest verified 308/308 during carrier qualification. Its
exact SHA is reported in the completion handoff. The historical
[`STAGE_A_EVIDENCE_RECORD.md`](STAGE_A_EVIDENCE_RECORD.md) remains unchanged and
must not be used as evidence for this successor.

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
- synthetic fixtures, the compatibility in-memory target, and the offline
  durable synthetic target state used by the opt-in Stage A harness;
- temporary local schema-v2 control and schema-v1 adapter SQLite databases
  created by repository-controlled tests; and
- a local commit and exact-commit verification.

Not authorized or performed:

- historical organizational data or representative operational datasets;
- production or test-tenant connectors;
- operational credentials, enterprise IAM, KMS/HSM keys, or external secrets;
- a live or designated external target, broker, source, audit sink, or queue;
- infrastructure deployment, network access, Stage B integration, or Stage C
  pilot activity;
- model promotion, threshold approval, policy approval, or target-owner
  acceptance.

This control record confirms the exact implementation commit and exact-SHA CI
only. The ER-002 evidence carrier is necessarily unnamed within its own
contents; its exact SHA is reported after creation in the completion handoff.
No claim is made that the successor was tagged, released, deployed,
operationally accepted, or authorized for production. Publication of source and successful CI do not
establish any of those states.

## Remaining release blockers

The machine matrix is authoritative; the following are the most consequential
open gates:

- the durable receipt/result seam is deliberately split across control,
  adapter, audit, and observation boundaries; there is no cross-store
  transaction, shared recovery-point marker, verified backup/restore, or proof
  against all real crash, disk, corruption, and divergence cases;
- SQLite establishes single-host durability and interprocess serialization,
  not distributed linearizability, a lease/fencing epoch, failover, partition
  tolerance, HA, or disaster recovery; the directory/audit locks are
  cooperative and local;
- the broker, synthetic adapter, observer, target state, result projection, and
  key material remain same-process and project-custodied; there is no OS
  isolation, mutually authenticated IPC, vendor adapter, managed key lifecycle,
  independently custodied observation, or independently controlled audit;
- no representative or historical validation is authorized; label independence,
  owner thresholds, operational error costs, OOD/shift gates, signed promotion,
  rollback, and revocation remain open;
- deployment architecture, IaC, secrets procedures, SLOs, monitoring, incident
  response, backup/restore exercises, capacity/load evidence, and intended-
  environment rollback are not operational;
- signed SBOM and release artifacts, hermetic and independently reproduced
  build evidence, trusted-builder provenance attestations, transparency-log
  records, and completed vulnerability disposition are absent; and
- mission, security, data, model, policy, operations, target-system, and
  authorizing-official acceptances are not recorded.

The next safe engineering gate is broader real power-loss, kill/fsync,
filesystem and storage-failure injection at every T1, T2, observation, audit,
and T3 boundary, including receipt/result corruption, hostile writers, mixed
backups, and cross-store divergence, plus resource and soak evidence. Process
isolation should follow the verified transaction contract. ER-002 must be
published in a later evidence-only carrier whose exact SHA and manifest are
recorded only after that commit exists. Any move to representative data,
external identity, a connector, or a designated target requires a separate,
exact authorization package.
