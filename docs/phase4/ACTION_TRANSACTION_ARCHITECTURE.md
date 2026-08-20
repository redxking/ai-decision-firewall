# Phase 4 controlled-action transaction architecture

**Status:** implementation baseline; real mutation and external authority gates open

**Scope:** one disposable, local, non-production Linux network namespace

**Production authorization:** not granted

## Objective and exit boundary

Phase 4 must prove that an evidence-bound authorization can drive one fixed,
reversible operating-system effect without granting the decision process broad
execution authority. The first action is `NETWORK_ISOLATE` for the code-owned
`LAB_ENDPOINT_001` target. It blocks only the fixed internal lab beacon,
preserves the fixed management listener, and expires within 60–3600 seconds.

This increment is complete only when the real kernel path, independent readback,
rollback, reconciliation, and the full crash matrix pass in a disposable
namespace. It does not authorize an organizational target, external identity,
representative data, vendor connector, Kubernetes API, or production use.

## Requirements

### Functional

- Accept only the closed v0.4.0 command contract and authenticate it before use.
- Bind request, decision, authorization, policy, adapter contract, target boot
  identity, prestate, sequence, expiry, and idempotency key.
- Persist a reservation before crossing the effect boundary.
- Verify target boot identity, exact ruleset prestate, and management
  reachability before invoking the mutation port.
- Apply only the fixed ruleset profile; no command, path, interface, address,
  namespace, or rule is supplied by the caller.
- Persist and replay an exact signed receipt without repeating an effect.
- Obtain a fresh separately keyed observer record that does not trust executor
  output.
- Reconcile an unfinished reservation by observation and an explicit operator
  decision; never automatically retry an ambiguous command.
- Roll back on expiry or an explicit, separately authorized recovery command.

### Safety and reliability

- The firewall remains networkless, unprivileged, and unable to invoke the
  kernel primitive directly.
- Only the executor receives `CAP_NET_ADMIN`, and only inside the disposable
  target namespace. No container-runtime socket or host namespace is mounted.
- An unavailable or mismatched precondition closes as durable `NO_EFFECT`.
- An exception after entering the effect boundary closes as `AMBIGUOUS` with an
  unknown poststate digest when the process remains alive. Process loss leaves
  an open reservation and recovery fence.
- Management loss, partial ruleset state, stale boot identity, observation
  mismatch, or rollback failure is recovery-required and blocks new intake.
- Every lock, IPC exchange, probe, and external controller operation has a
  bounded deadline.

### Evidence and authorization

- Executor receipt, observer record, controller inspection, and audit record
  are separate facts. None alone proves authorized effect.
- Local keys and project-controlled observations are implementation evidence,
  not independent custody.
- External targets, credentials, identities, and pilots require a separate
  authorization package and recorded target-owner acceptance.

## Component and data flow

```text
decision + authorization
          |
          v
networkless control client -- signed command --> executor IPC
                                                    |
                                      durable reservation
                                                    |
                                      precondition read + check
                                                    |
                                      fixed mutation port
                                                    |
                                       signed durable receipt
                                                    |
          +---------------- observation request ----+
          v
independent observer IPC --> fresh target probes --> signed observation
          |
          v
correlation + audit + terminal result / recovery fence
```

The container controller owns lifecycle and inspection but cannot originate an
authorized command. The target process owns only the synthetic management
listener and boot identity. The executor and observer have distinct keys,
state volumes, UIDs, and capabilities.

## Transaction states and recovery rules

| Durable state | Effect knowledge | Permitted next operation |
|---|---|---|
| No reservation | No effect | Validate a new unexpired command |
| Reservation only, pre-effect failure proven | No effect | Persist `NO_EFFECT`; do not mutate |
| Reservation only after effect entry | Unknown | Fence; observe and reconcile explicitly |
| Completion with `APPLIED` | Effect possible | Return exact receipt; request fresh observation |
| Completion with `AMBIGUOUS` or `PARTIAL` | Effect possible | Return exact receipt; fence new action and reconcile |
| Receipt plus matching observation | Observed state known | Close terminal result or initiate authorized rollback |
| Observation mismatch/unavailable | Unknown | Recovery-required; never reissue command |

The executor journal is an idempotency fence, not a distributed lease. A later
multi-host design requires an epoch-bearing lease in a linearizable store and
target-side rejection of stale epochs before any HA or failover claim.

## Mutation-port contract

`LabExecutorService` exposes an internal callable only when both
`effects_enabled=True` and an action implementation are supplied. Existing
nodes do not supply either value, so the shipped harness remains `NO_EFFECT`.
The port receives an already authenticated closed command and validated
prestate, and can return only `APPLIED`, `NO_EFFECT`, `PARTIAL`, or `AMBIGUOUS`
with the exact receipt tuple and a canonical poststate digest.

The kernel driver must be code-owned and fixed-function. It may invoke a
reviewed absolute executable with constant arguments and constant ruleset
bytes, or use a reviewed netlink implementation. It must not invoke a shell,
accept caller-controlled argv or environment, search `PATH`, or mutate any
namespace other than its own.

## Verification gates

1. Unit-contract tests: precondition mismatch, invalid mutation result,
   exception ambiguity, exact replay, conflicting idempotency, and post-effect
   process loss.
2. Namespace integration: beacon blocked, management preserved, exact ruleset
   digest observed, timeout rollback succeeds, and resource inventory is clean.
3. Kill matrix: pre-reservation, post-reservation, post-kernel mutation,
   post-receipt, post-observation, audit closure, terminal result, and rollback.
4. Adversarial boundary: wrong UID/key, socket and journal replacement,
   malformed messages, namespace/capability drift, injected partial rules,
   observer forgery, stale epoch, and controller cleanup failure.
5. Reliability: bounded load/soak, disk exhaustion, response loss, clock skew,
   backup/restore, and intended-filesystem evidence.
6. Independent review: security and target owners approve the exact non-production
   environment before any connector or designated target is introduced.

## Tradeoffs and growth path

The one-host namespace lab is deliberately smaller than Kubernetes or a vendor
broker and can prove real kernel semantics sooner. It cannot prove distributed
linearizability, organizational custody, CNI behavior, or operational efficacy.
Those boundaries are revisited only after the fixed action and recovery matrix
are stable. Productization then replaces local HMAC keys, SQLite journals, and
project-controlled observation with managed identity, KMS/HSM-backed signing,
epoch fencing, independent audit custody, HA, and approved vendor adapters.
