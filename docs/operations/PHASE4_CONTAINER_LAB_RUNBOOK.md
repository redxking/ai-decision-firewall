# Phase 4 Disposable Container Lab Runbook

## Purpose and authority boundary

This runbook exercises the Phase 4 executor and observer contracts in a
project-controlled, disposable Linux Docker topology. It is an explicitly
enabled non-production test. It does not authorize a live connector, external
target, production credential, target mutation, or operational decision.

The accepted result is deliberately `NO_EFFECT`. A successful run proves only
that the inspected local topology exchanged and correlated the bounded command,
receipt, and independent observation messages under the conditions observed.

## Topology

- A fixed beacon and a synthetic target join an internal Docker bridge on
  `172.31.254.0/28`. The bridge has no external route or published port.
- Executor and observer processes share the target network namespace for fixed
  reachability observations. Neither has a mutation capability or container
  runtime socket.
- Executor, observer, and target facts use three distinct named volumes. The
  executor cannot mount the observer key and the observer cannot mount the
  executor key.
- The control client mounts both IPC volumes but runs with `--network none`.
- Application roles use UID/GID `10001:10001`, a read-only root filesystem,
  all capabilities dropped, `no-new-privileges`, bounded PID/CPU/memory limits,
  and a small `noexec,nosuid,nodev` temporary filesystem.
- Five create-once initializers prepare only empty named volumes. The three
  root initializers add only `CHOWN`; application initialization is non-root.

## Preconditions

1. Use a Linux Docker engine. Docker Desktop's Linux VM is acceptable for this
   local engineering campaign.
2. Build the candidate from the exact source under test. Do not use a mutable
   tag as the harness input.
3. Confirm the worktree and intended source identity separately. A local image
   ID is immutable within the engine but is not a registry digest, signature,
   provenance attestation, or reproducibility claim.
4. Confirm no approved or operational credentials are present. The harness
   generates short-lived lab keys only inside disposable named volumes.

## Build and execute

Build the local candidate, then resolve its exact image ID:

```sh
docker build -t adf-phase4-harness:test .
docker image inspect adf-phase4-harness:test --format '{{.Id}}'
```

Pass the resulting `sha256:<64 lowercase hex>` value explicitly:

```sh
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src:. \
python3 scripts/run_phase4_container_lab.py \
  --allow-container-lab \
  --image sha256:<exact-local-image-id>
```

The optional `--lab-id` accepts exactly 12 lowercase hexadecimal characters
for a reproducible test identifier. Omit it for a randomly generated ID.

## Acceptance criteria

The process exits zero and emits one bounded JSON object with all of the
following:

- `status: PASS`
- `receipt_status: NO_EFFECT`
- `effect_possible: false`
- `authorization_integrated: false`
- `live_actions_possible: false`
- `network_internal: true`
- `application_containers_inspected: 5`
- `initializers_inspected: 5`
- `beacon_reachable: true`
- `management_reachable: true`
- `correlation_valid: true`
- `cleanup_complete: true`

Any creation, inspection, transport, correlation, result, exit, or cleanup
failure is a failed campaign. Do not reinterpret partial output as success.

## Cleanup verification

The controller records exact container, network, and volume identifiers and
removes only those identifiers. After either success or failure, inspect Docker
for resources carrying the selected `adf.phase4.lab_id` label. Any residue is a
failed cleanup condition requiring operator review; do not use broad pruning.

## Known limitations and next gate

This campaign does not mutate a namespace, firewall rule, endpoint, service, or
external system. It does not test authorized effects, rollback, post-mutation
recovery, hostile peers, external identity, a registry-published image,
signature verification, independent evidence custody, or production
deployment. The next bounded gate is the ADR-017 adversarial/kill matrix while
retaining the same no-effect authority boundary.

## Container recovery campaign

The recovery controller adds a fourth, control-only volume that stores the
exact signed command before the first exchange. It supports three closed
scenarios:

- `executor-after-reservation`
- `executor-after-completion`
- `observer-after-observation`

Run each scenario explicitly against the exact local image ID:

```sh
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src:. \
python3 scripts/run_phase4_container_recovery.py \
  --allow-container-recovery \
  --image sha256:<exact-local-image-id> \
  --scenario executor-after-reservation
```

The controller waits for a code-owned boundary marker and then kills the exact
recorded container through the host Docker API. No application container can
reach that API. Restart is allowed only after a separate non-root initializer
validates and removes the exact stale owner-private socket.

The reservation scenario passes only when exact replay closes
`RECOVERY_REQUIRED`. The completion and observation scenarios pass only when
the exact persisted command produces a correlated `NO_EFFECT` result after
replacement services start. Every passing result must also state
`container_kill_observed=true`, `exact_command_reused=true`,
`effect_possible=false`, `authorization_integrated=false`,
`live_actions_possible=false`, and `cleanup_complete=true`.
