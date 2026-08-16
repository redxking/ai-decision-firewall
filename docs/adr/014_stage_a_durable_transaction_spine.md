# ADR-014: Stage A durable transaction spine

**Status:** Accepted for single-host synthetic Stage A development only
**Date:** 2026-08-15
**Decision owners:** project release owner and service architecture owner
**Production authorization:** not granted

## Context

The published Phase 3 implementation stores request claims, verified-decision
issuance, token-consumption state, attempt bindings, and synthetic target state
in process-local memory. The audit persists a hash-linked lifecycle, but it is
not the authority-state ledger. Exact-baseline testing demonstrated that a
completed request can be accepted and can cause a second synthetic effect after
all service objects are reconstructed.

Creating an isolated broker process before durable ownership would enlarge the
number of crash and message-loss windows without defining which component owns
single use or recovery. The first production-shaped boundary must therefore be
a transaction spine that survives process restart and arbitrates independent
processes.

## Decision drivers

- Prevent a repeated or conflicting request from creating a second effect.
- Consume authorization before any target invocation and never reopen it.
- Preserve an honest indeterminate state after a possible effect.
- Fail closed when authority storage is unavailable or structurally suspect.
- Keep the increment offline, synthetic, dependency-light, and testable without
  external credentials, systems, or operational authority.
- Preserve the published Phase 3 default behavior unless the Stage A store is
  explicitly configured.

## Options considered

### Retain process-local ledgers and infer state from audit

Rejected. The verified restart replay remains possible, and reconstructing
authority from an application audit introduces ambiguity across partial writes.
The audit format also lacks the unique constraints and closed transition rules
required for transactional single use.

### Add SQLite/WAL behind a storage interface

Selected for the bounded increment. SQLite provides atomic local transactions,
unique constraints, crash persistence, and interprocess write serialization
without an external service. It supports deterministic failure injection and
preserves the no-connector/no-credential boundary.

### Adopt a distributed consensus store immediately

Deferred. A distributed store requires a deployment topology, workload
identity, network policy, operational ownership, backup/restore, failover,
partition testing, and secrets that are outside current authority. Selecting a
specific platform without those constraints would manufacture architecture
decisions and still leave the adapter receipt contract undefined.

## Decision

Add a versioned SQLite ledger configured explicitly by path. In one transaction
before target invocation, validate and transition the token from `ISSUED` to
`CONSUMED`, create the uniquely bound attempt in `RESERVED`, and append digest-
only outbox events. Never hold the database transaction across adapter I/O.
After the target call, record a terminal digest in a second transaction. If
that commit cannot be confirmed, return a conservative failure and leave the
attempt reserved. Explicit startup reconciliation moves unresolved reservations
monotonically to `UNKNOWN_EFFECT`; it never retries the command or resets the
token.

Request identity is keyed by authenticated principal plus request ID and bound
to the canonical request digest. An exact duplicate is rejected before new
decision, token, broker, or effect activity. Reuse with different bytes returns
`REQUEST_ID_CONFLICT`.

The schema uses strict tables, primary and unique constraints, foreign keys,
WAL mode, `synchronous=FULL`, an explicit schema version, bounded lock waiting,
and a digest-only audit outbox. Unknown schema, corrupt or locked storage, and
unsafe database paths fail closed.

## Consequences

Positive consequences:

- the reproduced restart replay is prevented for an explicitly configured
  Stage A ledger;
- verified-decision issuance, token consumption, and attempt reservation are
  durable and race safe on one host;
- a consumed token cannot return to `ISSUED` after restart or failure;
- authority transitions have transactionally co-recorded outbox evidence; and
- crash recovery sacrifices availability rather than guessing whether an
  effect occurred.

Costs and limitations:

- SQLite is a single-host mechanism, not consensus, distributed idempotency,
  fencing, HA, or disaster recovery;
- exact duplicates are blocked rather than returning a persisted full terminal
  `Phase3Result`;
- synthetic target state and command receipts are not independently durable,
  so an unresolved post-invocation reservation becomes `UNKNOWN_EFFECT`;
- audit export, external anchoring, WORM retention, trusted time, and durable
  queue behavior remain unimplemented;
- the broker, observer, target, and keys remain in one process; and
- storage availability can deny service. Rate limits, bounded retention,
  request-ledger exhaustion controls, and load evidence remain required.

## Verification

The Stage A tests cover WAL/FULL/schema/permissions, unknown schema and unsafe
path rejection, request replay and conflict across reconstructed services,
durable token and attempt state, idempotent `UNKNOWN_EFFECT` recovery,
post-effect outcome-write failure, bounded lock failure, and independent-process
races for request claims and token/attempt reservation. The existing Phase 3
and repository regressions must remain green.

These tests establish only the named single-host synthetic mechanism. They do
not establish production replay prevention, distributed correctness, vendor
command semantics, independent observation, or operational safety.

## Follow-on decision gates

1. Define a durable synthetic adapter receipt and sanitized terminal-result
   lookup, then inject process termination at every transition boundary. The
   successor decision is recorded in
   [ADR-015](015_durable_synthetic_adapter_receipt_and_result_lookup.md); its
   later evidence does not alter this ADR's original Stage A claim.
2. Define authenticated broker/adapter IPC, process isolation, workload
   identities, and deny-by-default egress.
3. Select a distributed authority store only after topology, consistency,
   recovery-time, data-retention, and operations requirements have approved
   owners.
4. Require target-owner and authorizing-official approval before any external
   adapter or credential is introduced.
