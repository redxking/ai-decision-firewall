# ADR-015: Separate durable synthetic adapter receipts from terminal request lookup

**Status:** Accepted for bounded Stage A implementation

**Date:** 2026-08-16

**Deciders:** project architecture, security, release, and test owners

**Production authorization:** not granted

**Candidate:** `0.4.0-alpha.2`; pre-commit, not an exact-commit evidence claim

## Context

ADR-014 introduced a single-host control ledger that durably claims requests,
issues and consumes authorizations, reserves attempts, and records metadata-only
outbox events. It deliberately left two important failure windows open:

1. synthetic target state and command acknowledgement were process-local, so a
   restart could not determine whether a reserved command changed the target;
2. an exact duplicate could be blocked, but the original caller had no durable,
   authority-free terminal-result lookup after response loss.

Closing those windows requires durable adapter-owned facts without treating an
adapter acknowledgement as independent post-action verification. The design
must also preserve the existing prohibition on production connectors,
operational credentials, external targets, and Stage B or Stage C activity.

## Decision

### Three distinct transaction boundaries

The opt-in Stage A path uses three local artifacts with pairwise-distinct safe
paths:

1. a control SQLite database;
2. a synthetic-adapter SQLite database; and
3. the existing Phase 3 JSONL lifecycle audit.

The control database uses schema version 2. The synthetic-adapter database uses
its own schema version 1. Adapter receipts and request-lookup envelopes each
have independent closed contract versions. A normal constructor refuses and
preserves a schema-v1 control database; it does not silently migrate or rewrite
that evidence. Stage A v1 remains synthetic and disposable, so the supported
successor procedure is to preserve the v1 files and initialize a new reviewed
v2 ledger. A future migrator would require a separate, explicit, quiesced,
transactional decision and test package.

The execution sequence is:

1. **T1 — control reservation.** Validate the signed authorization, then
   atomically consume it, reserve one exact-bound attempt, advance the request
   lifecycle, and add a metadata-only outbox event.
2. **T2 — adapter transaction.** Invoke the offline synthetic adapter with the
   attempt's stable idempotency key. In one adapter-database transaction,
   validate the target precondition, apply the configured synthetic transition,
   update durable synthetic target state, and insert one immutable adapter
   receipt. An exact repeated call returns that receipt without another state
   change. Changed binding under the same key is a hard conflict.
3. **Observation.** Read the durable synthetic target state through a separate
   read-only observer interface. This remains same-project and same-store
   custody; it is not independent target evidence.
4. **T3 — terminal control result.** After verification, atomically advance the
   attempt and request to their legal terminal states, insert one closed
   sanitized `RequestLookupResult`, and add its metadata-only outbox event.

No control-database transaction remains open across T2, observation, or any
other adapter operation. T1, T2, the JSONL audit, and T3 are not one atomic
transaction. Cross-store ambiguity is therefore an explicit recovery state,
not a condition the implementation may conceal.

### Cooperative startup and store correlation

The public control- and adapter-store constructors serialize first creation
through a bounded POSIX directory `flock` without creating a lock-file
artifact. The combined firewall constructor takes the same kind of bounded
cooperative ownership before it preflights any existing artifact, opens or
initializes the three paths, and correlates the stores. One firewall clock
sample supplies the creation timestamp to both new SQLite stores.

The same cooperative directory-root ownership wraps each durable firewall
operation. An exclusive audit-file `flock` then owns the JSONL tail for the
complete operation. These are same-host cooperative-process controls only:
they are not a lease, epoch, distributed fence, protection from a noncooperating
same-user writer, or a high-availability mechanism.

Both SQLite stores reject unsafe main files and active `-wal`/`-shm` sidecars,
including symlinks, nonregular files, multiply linked files, identity changes,
and non-owner-private sidecar modes. Existing stores are opened read-only for
preflight before any missing artifact is initialized. Schema fingerprints,
immutable metadata, row shapes, canonical digests, cardinalities, lifecycle
relations, and timestamp ordering are then validated on open and before
authoritative writes. The adapter additionally proves that each target's
receipt history is a continuous state/time chain ending at the current target
row.

Cross-store correlation is a closed, authority-free projection. It rejects an
orphan adapter receipt, a required-but-missing receipt, overlapping provenance
substitution, receipt-digest mismatch, incompatible terminal disposition, or
terminal target-state mismatch. Correlation runs during startup and before
durable request, approval, reconciliation, and terminal-result lookup use. It
detects divergence; it does not make the stores atomic or independently
custodied.

### Stable adapter binding

The adapter idempotency binding is canonical and covers at least:

- authenticated principal;
- request identifier and canonical request digest;
- decision identifier and decision-context digest;
- authorization token identifier, unsigned-token digest, and issuer domain;
- exact action, target, and canonical parameters;
- trusted target-precondition digest;
- policy identifier, version, and digest;
- fixed adapter identifier, adapter contract version and contract digest; and
- `execution_mode=synthetic_simulation`.

The randomly allocated attempt identifier is correlation metadata and is not
part of the idempotency digest. Neither the binding, receipt, nor result stores a
token signature, token nonce, raw invocation credential, signing key, or bearer
authority.

The adapter receipt is written by the adapter boundary before it returns. It is
adapter-reported evidence only. Its accepted dispositions distinguish explicit
no-effect, applied, partial, and ambiguous outcomes. `reported_success`, an
`APPLIED` receipt, or an adapter state digest never by itself establishes
independent verification, successful rollback, or operational effect.

### Terminal lookup contract

The control ledger stores a closed, versioned `RequestLookupResult`, not a
serialized `Phase3Result`. The projection contains only bounded identifiers,
digests, timestamps, original decision and verification summaries, terminal
disposition, and explicit replay facts. It recursively excludes authorization,
token, nonce, signature, credential, signing material, raw audit rows, and
executable command authority.

An authenticated read-only lookup is keyed by the exact principal, request
identifier, and canonical request digest. A changed request digest returns a
conflict without disclosing the prior result. A different principal cannot
read the prior principal's result. A terminal lookup states:

- `replayed=true`;
- `execution_attempted_this_call=false`;
- `new_decision=false`;
- `new_authorization=false`; and
- `new_effect=false`.

The existing `process_json` contract remains `Phase3Result` and fail closed for
duplicates. It does not return a union type and does not smuggle the lookup
envelope into `Phase3Result`. Callers use the separate authenticated lookup seam
after a duplicate or response loss.

### Monotonic states and recovery

Authorization is monotonic: `ISSUED` may become `CONSUMED` atomically with
attempt reservation or `REVOKED` during explicit quiesced recovery. Neither
`CONSUMED` nor `REVOKED` can become `ISSUED`.

The attempt state separates adapter acknowledgement from verification. A
normal path progresses from `RESERVED` through a receipt-recorded state and
only then to a verification-scoped terminal state such as verified effect,
affirmative failed-no-effect, recovery required, or unknown effect.

Reconciliation is never automatic in a constructor. It requires an explicit
operator assertion that processing is stopped and ownership is quiesced. That
assertion is an administrative interlock, not a lease, epoch, or fencing proof.
The recovery decision is closed:

| Recovered condition | Control disposition |
|---|---|
| Exact affirmative `NO_EFFECT` receipt | `FAILED_NO_EFFECT`; record a sanitized recovered result; do not issue a command |
| `APPLIED`, `PARTIAL`, or `AMBIGUOUS` receipt without separately durable verification | `UNKNOWN_EFFECT` plus recovery-required result; do not issue a command |
| No receipt | `UNKNOWN_EFFECT`; absence does not prove no effect and does not permit retry |
| Receipt or adapter store is corrupt, mismatched, or unavailable | Halt reconciliation with no state transition |
| Existing `UNKNOWN_EFFECT` | Remain terminal and unchanged |

An exact repeated receipt or terminal-result write is idempotent. Any changed
binding or payload under an existing identifier is a conflict and cannot
overwrite history. Reconciliation never invokes the adapter command, mints a
replacement token, reopens authority, fabricates verification, or claims
rollback.

Before T3, reconciliation closes an exact, contiguous JSONL lifecycle of
`RECOVERY_STARTED`, `RECOVERY_EVIDENCE_ASSESSED`, and `RECOVERY_FINALIZED`.
The three records bind the exact recovery identity, request, evidence
assessment, sanitized-result digest, and the observed original execution-audit
status: `COMPLETE`, `INCOMPLETE`, or `UNRESOLVED`. If a crash occurs after any
prefix, exact reconciliation resumes idempotently. If all three records exist
but T3 has not committed, the recovery tail fences other request and approval
audit writers with `RECOVERY_AUDIT_PENDING`; an exact recovery retry may commit
T3 without changing the already closed trio. The trio is not a cross-store
commit record, external anchor, or proof that the original lifecycle was
complete.

## Options considered

### Store target state and receipt in the control database

Rejected. It would collapse authority ownership and adapter reporting into one
store, encourage holding an authority transaction across execution logic, and
make the receipt appear more independent than it is.

### Retain process-local synthetic state and treat every restart as unknown

Rejected as the next increment. It remains safe by sacrificing availability,
but cannot close response-loss idempotency or exercise adapter-owned recovery
semantics.

### Add a live, vendor-specific, or network adapter

Rejected by authority and maturity. No endpoint, credential, target owner,
network boundary, vendor command contract, or Stage B approval exists.

### Add a distributed database, replicated queue, or failover

Deferred. Topology, consistency, tenancy, availability, fencing, RPO/RTO, and
operations ownership are not approved. SQLite remains a single-host
development mechanism.

## Consequences

- Response loss after adapter commit can be reconciled from an immutable
  synthetic receipt without reissuing the command.
- Exact duplicate callers can retrieve a stable authority-free result without
  creating a new decision, authorization, or effect.
- Adapter-state durability allows same-host restart and concurrency tests that
  were not meaningful against process-local target state.
- Bounded cooperative first-open and operation ownership prevents supported
  local processes from racing initialization or interleaving JSONL lifecycles;
  it does not control noncooperating or remote writers.
- Startup and runtime correlation expose a defined set of control/adapter
  substitutions and omissions before a verified terminal result is used.
- The exact recovery audit trio makes a crash between recovery audit closure
  and T3 explicit and retryable without reopening command authority.
- Two databases create deliberate cross-store divergence cases that monitoring,
  recovery, backup, and incident procedures must expose.
- Result persistence creates data-minimization, retention, capacity, and
  records-management obligations even though current content is synthetic.
- Same-process code, same-host storage, same-project custody, local keys, and
  operator-asserted quiescence remain material trust limitations.

## Explicit non-claims

This decision does not establish process isolation, authenticated IPC, vendor
equivalence, target-side or independent observation, external audit custody,
trusted time, distributed linearizability, multi-tenant isolation, fencing,
HA, disaster recovery, coherent cross-store backup/restore, operational
rollback, production readiness, or authority to enter Stage B or Stage C.

## Follow-on gates

1. Complete real process-kill and filesystem/disk-failure campaigns at every
   T1/T2/observation/JSONL/T3 boundary, including recovery-audit prefixes,
   receipt/result corruption, and cross-store divergence.
2. Add tested execution ownership, lease/epoch/fencing, and bounded service
   lifecycle before permitting unattended recovery.
3. Isolate broker and adapter workloads behind mutually authenticated,
   deny-by-default IPC while retaining the offline synthetic target.
4. Require new explicit authorization before adding any representative data,
   external identity, connector, credential, vendor adapter, or designated
   target.
