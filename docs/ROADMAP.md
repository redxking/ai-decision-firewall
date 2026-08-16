# Engineering roadmap

## Current boundary — 2026-08-16

- Exact Phase 2.5 Commit
  `854b15c56397a81de6326b719d3d7d1dc847608f` is published on `main`; its
  exact-commit CI and Dependency Graph checks passed.
- `P2-CE-001` through `P2-CE-004` retain their version-bound evidence claims.
  `P2-CE-005` was not executed or published and remains CE-0
  `NOT_EVALUATED`.
- Exact Phase 3 Commit
  `423685d105be813056617db738297eba83d3d9d0` is published on `main`; exact-commit
  CI and Dependency Graph checks passed. Its simulation-only boundary includes
  57/57 focused tests, two demonstration checks PASS, a 46/46 corpus and the
  then-current 288/288 repository aggregate.
- Phase 3.1 `0.3.1-alpha.1` is published at exact Commit `bb6b8f28`; its
  focused module passed 11/11 and the then-current repository suite passed
  299/299 locally and in exact-commit CI. No historical/live adapter, owner
  promotion threshold or action path exists.
- The unreleased `0.4.0-alpha.2` Stage A production-development implementation
  is published on `main` at exact Commit
  [`8818d5d2d40faebced66a254d58b1f0d04c9f8b4`](https://github.com/redxking/ai-decision-firewall/commit/8818d5d2d40faebced66a254d58b1f0d04c9f8b4).
  It adds
  single-host durable request, authorization, attempt, and audit-outbox state
  plus a separate durable offline synthetic-adapter state/receipt database and
  an authority-free terminal-result lookup. Bounded cooperative same-host
  fencing, strict store/cross-store validation, and recovery-audit closure are
  implemented, but the store-local transactions and JSONL audit are not
  cross-store atomic. Exact local verification passed 43/43 focused Stage A in
  8.248 seconds, 18/18 readiness-gate, the warning-fatal 360/360 repository suite
  in 48.995 seconds, 57/57 focused Phase 3, and 46/46 corpus checks with
  `live_actions_possible=false`; the 307-entry implementation manifest verified
  307/307. Exact-SHA CI run 31953570779 succeeded on Python 3.11/3.12 and
  Dependency Graph run 31953572482 succeeded. These are project-controlled
  mechanism observations; no tag, GitHub Release, deployment, or exact-SHA Pages
  run was created. Its machine-derived production gate is `BLOCKED`; no Stage B
  or C activity is authorized. See
  [`ADF-STAGE-A-ER-002`](production/STAGE_A_RECEIPT_RESULT_EVIDENCE_RECORD.md).
- No historical organizational data, approved Gate B package, live feed,
  test-tenant/production connector, operational credential, or live action is
  authorized or present.

## Phase 0 — Concept convergence

Completed. The program narrowed broad autonomous-SOC concerns to an
evidence-and-authority decision boundary for privileged-identity containment.

## Phase 1 — Synthetic executable baseline (v0.1)

Completed at its historical boundary. The package contains deterministic
synthetic scenarios, an advisory logistic model, evidence-quality controls,
bounded policy, a verifier, legacy scoped simulator tokens/actions, post-action
checks, hash-linked audit, metrics, diagrams, and tests.

**Evidence boundary:** generator-consistent software/safety controls only; no
operational efficacy, production safety, or portable retraining claim.

## Phase 2 — Read-only replay and assurance (v0.2)

Implementation increments 2.0 through 2.5 are present. Phase 2 has strict
read-only `historical_replay` and `shadow_read_only` semantics, record
qualification, Gate B preflight, exact audit checks, typed/source-authorized
features, reference feature projection, and same-project source-to-decision
recomputation. Authorization, broker, target construction, and effects remain
structurally absent in both modes.

Published synthetic CE-2 records `P2-CE-001` through `P2-CE-004` remain narrow,
SELF, project-controlled results. Phase 2.5 Commit `854b15c` and its green CI
support package/implementation status only. They do not create an observed
`P2-CE-005` campaign result.

### Separate Phase 2 workstreams still open

1. **Optional `P2-CE-005` campaign:** if still programmatically useful,
   explicitly designate a governed Commit A, run the clean detached frozen
   campaign without repair/retry, and publish a separate validated evidence-only
   Commit B. Do not relabel the already-published Phase 2.5 commit as evidence.
2. **External Gate B pilot:** accountable owners must authenticate authority,
   privacy/de-identification, custody, source mapping, sample selection,
   adjudication, stop conditions, and complete-intake reporting before any
   historical payload is accessed.

## Phase 3 — Simulation-only operational decision control (`0.3.0-alpha.1` published)

### Published baseline

- strict external v0.3.0 raw request and policy contracts;
- opaque invocation credentials resolved to signed principals, plus trusted
  source, action, target, policy, and time context;
- runtime HMAC evidence attestation with content, semantic, time, provenance,
  and subject-target binding;
- deterministic authority/evidence/consequence evaluation and `ALLOW`, `DENY`,
  `ESCALATE`, `ALLOW_CONSTRAINED` decisions;
- functionally separate deterministic decision verification and code-owned
  policy safety floors for evidence, consequence, rule precedence, and Tier-0
  domain controllers;
- exact-scope, signed, short-lived, single-use process-local authorization;
- mandatory broker and private-capability in-memory target mutation;
- functionally separate same-project read-only target observation and five-way
  verification status;
- separate opaque-human-credential approval that emits an exact-scope signed
  reevaluation-only receipt;
- correlated lifecycle audit, in-process metrics, two required demos, and a
  deterministic 46-scenario adversarial corpus.

Adversarial review found and closed release-blocking defects across consequence
and evidence binding, credential/key-domain handling, immutable exact-type
security values, machine-policy safety floors, replay/receipt atomicity,
dependency-failure closure, and executed-path/post-effect audit semantics. The
baseline remains synthetic and CE-1 only. Its application boundaries are
not OS/process security; request/token ledgers are not durable/distributed;
runtime HMAC fixture keys and self-custodied audit are not enterprise trust; and
same-project verification is not external independence.

**Exit condition:** met for the published simulation-only code baseline at
`423685d`. This exit does not authorize live data or action.

## Phase 3.1A — Governed model-validation groundwork (`0.3.1-alpha.1` published baseline)

The published baseline adds closed plan/result contracts, SHA-256-bound synthetic
source pools, a disjoint temporal training/calibration/evaluation split, one
logistic baseline, one Platt calibration challenger, aggregate discrimination,
calibration, threshold, Wilson-interval, selective-risk and subgroup metrics,
and an unconditional `NOT_AUTHORIZED` promotion state.

The current mechanism observation uses 720 training, 240 calibration and 240
evaluation rows. It demonstrates reproducible comparison mechanics only. It
does not establish source realism, operational calibration, practical
significance, model superiority or promotion eligibility.

### Remaining gates

1. Before any historical payload access, obtain an authenticated external Gate
   B package covering data authority, custody, privacy, source mapping,
   adjudication, temporal split, owner thresholds and stop conditions.
2. Keep the final temporal holdout evaluator-controlled and prohibit repeated
   candidate selection against it.

**Exit condition:** published synthetic evaluation mechanism with green
exact-commit CI and no model-promotion claim. Historical evaluation remains a
separate authority state.

## Stage A — Two-store offline synthetic durability (`0.4.0-alpha.2` implementation)

The first bounded increment corrected the verified process-restart replay path
with an explicitly configured SQLite/WAL authority ledger. ADR-015 extends the
candidate with a second SQLite database owned by the offline synthetic adapter.
The adapter transaction validates the exact idempotency binding, updates only
durable synthetic target state, and inserts one immutable receipt. After
same-project read-only observation, the authority ledger can atomically close
the attempt/request and persist one sanitized `RequestLookupResult` that
contains no token, nonce, signature, credential, raw audit rows, or executable
authority.

The normal path has three distinct database transactions: T1 authority
reservation, T2 adapter state plus receipt, and T3 terminal authority/result
closure. T3 follows successful readback of the valid normal JSONL lifecycle.
The control database, adapter database, and JSONL audit are three authoritative
artifacts; the audit is an additional commit boundary, not a fourth artifact.
No transaction spans them. Exact receipt or terminal-result repeats are
idempotent; changed bindings conflict. Cross-store correlation binds
overlapping principal, request, decision/context, authority, policy, receipt,
and terminal target facts and rejects missing required or orphan receipts and
recomputed substitutions.

Startup and durable request, lookup, approval, and recovery operations use
bounded cooperative same-host fencing. Explicit quiesced recovery never invokes
the adapter command or reopens/replaces authorization. It writes and reads back
the exact contiguous `RECOVERY_STARTED`, `RECOVERY_EVIDENCE_ASSESSED`, and
`RECOVERY_FINALIZED` trio before T3; audit failure suppresses T3, a partial
prefix resumes exactly, and the pending recovery owner fences other durable
writers until terminal commit. The trio records the original lifecycle as
`COMPLETE`, `INCOMPLETE`, or `UNRESOLVED`. Receipt evidence remains
adapter-reported and never equals independent verification.

**Published implementation evidence for this increment:** exact duplicate lookup
returns only an authority-free replay result and never a second effect;
receipt/result binding, conflict, corruption, recovery, audit ambiguity,
startup concurrency, and independent-process races passed their focused local
checks; the full suite remained green; and the 18-domain production gate
derived `BLOCKED`. Exact implementation Commit `8818d5d2` is on `main`. Its
recorded local observations are 43/43 focused Stage A in 8.248 seconds, 18/18
readiness-gate, warning-fatal 360/360 repository in 48.995 seconds, 57/57 focused
Phase 3, and 46/46 corpus with `live_actions_possible=false`; the integrated
exact-once race passed 5/5 parallel repetitions. The manifest
verified 307/307, and exact-SHA CI plus Dependency Graph succeeded. A version
tag, GitHub Release, deployment, exact-SHA Pages run, owner acceptance, and
operational effectiveness remain absent. This is not exit from Stage A as a
whole.

**Next safe gate:** expand the local campaign beyond the selected process-kill,
audit-failure, corruption, and concurrency cases to cover power loss,
filesystem/disk exhaustion, backup/restore, retention/compaction, bounded load,
and cross-store recovery at every boundary. Then design distributed execution
ownership with leases/epochs/fencing and process-isolated authenticated IPC.
The current cooperative fence is same-host only. The adapter receipt remains
same-project evidence, not independent target verification. External identity,
connectors, targets, representative data, and deployment remain separately
authorized activities.

## Phase 3.1B — Approved read-only evidence realism

After the external Gate B package and an offline historical pilot, evaluate an
approved live read-only shadow service with authenticated sources, independent
custody, analyst adjudication, temporal holdout, calibration, abstention cost,
source ablation, and workflow/consequence analysis.

**Exit condition:** data-handling controls hold; schema/source mapping is stable;
traceability and analyst agreement are measured; false-containment risk and
abstention behavior have defensible origin-stratified bounds. No action
credential is present.

## Phase 4 — Controlled non-production actions

Design a new approved test-tenant architecture with service/process isolation,
managed source/token keys, durable distributed idempotency, vendor-specific
least-privilege broker adapters, independent target-side readback, rollback and
reconciliation, rate/circuit limits, kill switch, externally anchored audit,
change control, and human approval.

**Exit condition:** authorized action classes demonstrate idempotency,
precondition handling, independent verification, rollback/recovery, and stop
conditions under failure injection in a non-production environment.

## Phase 5 — Limited operational pilot

Restrict use to a small approved population and require human approval for every
action. Measure operational false-positive/negative outcomes, workflow effects,
mission consequences, recovery behavior, and control reliability under formal
incident and change authority.

**Exit condition:** the authorizing official accepts residual risk and the
approved action classes meet predeclared statistical and operational gates.

## Phase 6 — Productization

Only after the preceding evidence gates: add multi-tenant policy packs,
vendor-neutral integrations, secure update/supply-chain controls, HA, continuous
calibration, compliance mappings, operator workflows, and sector-specific
mission-consequence models.
