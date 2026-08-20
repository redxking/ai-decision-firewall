# ADR-017: Process-isolated non-production network-containment lab

**Status:** Proposed; implementation and authority gates open

**Date:** 2026-08-20

**Deciders:** project architecture, security, test, operations, and target owners

**Owner acceptance:** not recorded

**Production authorization:** not granted

## Context

Stage A proves durable, fail-closed decision and recovery mechanics against a
same-project synthetic adapter. It does not prove process isolation,
authenticated IPC, least-privilege execution, target-side observation, or
behavior against a real operating-system network control. The next useful
engineering increment is a disposable non-production lab that crosses those
boundaries without connecting the firewall to an organizational endpoint,
production network, external service, or unrestricted container runtime API.

The lab must preserve the current authority model. A green lab test cannot
authorize live use, establish operational efficacy, or satisfy the independent
mission, security, identity, evidence, platform, or release-owner gates.

## Decision drivers

- The firewall process remains unprivileged and has no IP network interface.
- A compromised request cannot select a shell command, arbitrary namespace,
  host target, Docker socket operation, or external address.
- The executor receives only an exact signed/idempotent containment command.
- Command acknowledgement and target observation have separate process and key
  custody.
- Loss at every request, execution, observation, receipt, audit, and terminal
  boundary remains recoverable without automatic command retry.
- The complete environment is disposable, local, opt-in, and denied external
  ingress and egress.

## Decision

### Topology

The first lab candidate uses four Linux containers on one dedicated internal
container network and one owner-private tmpfs IPC volume:

1. **Firewall.** Runs the durable Stage A control plane as a non-root UID with
   a read-only root filesystem, all capabilities dropped, and no IP network.
2. **Disposable target.** Owns a fresh network namespace and runs only a fixed
   health responder plus bounded synthetic workload. It contains no host,
   enterprise, or reused credential.
3. **Executor sidecar.** Joins only the disposable target network namespace,
   holds `CAP_NET_ADMIN` there, and serves one owner-private Unix-domain IPC
   endpoint. It has no Docker/Podman socket, host namespace, host filesystem,
   package manager, shell-command field, or external route.
4. **Observer sidecar.** Joins the target namespace without capabilities, uses
   a distinct signing key, probes a fixed lab beacon and management channel,
   and publishes a separately signed bounded observation over a second Unix
   endpoint. It cannot invoke the executor.

The lab beacon is an additional fixed-function container on the same internal
network, not an Internet service. The executor may change only the target
namespace rule set needed to block the beacon while preserving the declared
management channel. Container-runtime orchestration is test-controller
authority and is never mounted or delegated into an application container.

### Closed authenticated IPC

Linux Unix-domain `SOCK_SEQPACKET` is preferred so one canonical JSON request
maps to one bounded message. Both services require:

- filesystem ownership/mode checks on the socket directory;
- `SO_PEERCRED` verification against exact configured UIDs;
- HMAC-SHA-256 over a domain-separated, versioned canonical envelope;
- exact request, decision, policy, adapter-contract, target, prestate, action,
  parameter, idempotency, sequence, expiry, and nonce bindings;
- closed message shapes, strict JSON, finite size/depth bounds, and offset-aware
  timestamps; and
- constant-time MAC comparison before semantic use.

The firewall-to-executor key and observer-to-firewall key are distinct. The
executor cannot mint observation evidence; the observer cannot mint or execute
a command. Neither key is an authorization-signing key. Secret rotation and
state migration are outside this first lab contract.

### Execution contract

The only accepted command is a versioned `NETWORK_ISOLATE` operation against
the code-owned target identifier `LAB_ENDPOINT_001`. Parameters have a closed
shape: bounded duration and exact management-channel preservation. There is no
free-form rule, executable, interface, address, hostname, namespace, file path,
or environment selector.

Before mutation the executor reads and hashes the current lab rule set and
validates the firewall-bound prestate. It persists an idempotency reservation
before applying the rule. Exact retry returns the same receipt; changed content
under the same idempotency key conflicts. An error after possible mutation is
`AMBIGUOUS`, never `NO_EFFECT`. The executor never performs automatic rollback
or accepts a new command during unresolved recovery.

### Separate observation

The observer performs code-owned probes before and after execution. Its signed
record binds the command idempotency key, target namespace boot identity,
beacon reachability, management-channel reachability, observation time, and a
canonical observation digest. It does not consume executor output as truth.

The firewall may classify a verified lab effect only when the executor receipt
and observer record independently match the authorized command and expected
state. A missing, stale, invalid, mismatched, or unavailable observation closes
as unknown/recovery-required without reissuing the command.

### Isolation and orchestration

The lab is Linux-only and explicitly opt-in. The controller must verify before
start that no application container has a host namespace, privileged mode,
Docker socket, writable host mount, external network attachment, or unexpected
capability. The target network is created as internal. All images are pinned by
digest for recorded campaigns. CPU, memory, PID, file, and wall-clock limits
are mandatory.

Cleanup removes only resources carrying the exact unique lab label and records
their pre/post inventory. Cleanup success is not test success, and a failed
cleanup is reported as an incident condition. The repository never targets a
pre-existing container, VM, namespace, interface, or address.

## Options considered

### Mount the Docker socket into the adapter

Rejected. The ordinary Docker API is effectively host-level authority and is
far broader than one target-scoped containment action.

### Run executor code inside the firewall container

Rejected. Container capabilities apply at the OS boundary; granting
`CAP_NET_ADMIN` to the firewall would collapse decision and execution custody.

### Use a public VM, Hack The Box target, or free Internet service

Rejected for the first increment. External ownership, terms, identity,
availability, scope, data handling, and safe-stop evidence are unresolved. The
local disposable namespace exercises a real kernel effect without those
authority ambiguities.

### Treat executor acknowledgement as verification

Rejected. Command receipt and post-action observation must remain distinct
facts with separate keys and processes.

### Move directly to Kubernetes NetworkPolicy mutation

Deferred. A Kubernetes API credential, RBAC scope, admission behavior, CNI
semantics, reconciliation, and target-owner approval introduce a larger trust
boundary. The namespace-local container lab is the smaller falsifiable step.

## Consequences

- The project can test a real Linux network-state mutation without giving the
  firewall a network interface or privileged runtime authority.
- Separate executor and observer custody makes forged acknowledgement and
  missing/mismatched observation independently testable.
- Linux namespace and capability semantics become platform dependencies that
  require exact runtime evidence.
- IPC sequence, key lifecycle, liveness, backpressure, crash recovery, and
  receipt/observation retention become new security and operations obligations.
- The design remains one-host and project-controlled; it does not establish
  organizational independence, distributed fencing, or production safety.

## Required verification before implementation acceptance

1. Closed contract/schema tests for every command, receipt, and observation
   field, including duplicate JSON members, oversize/deep input, non-finite
   values, stale/future time, replay, and substitution.
2. Wrong UID, wrong key, socket replacement, symlink, permission, peer death,
   truncation, reordering, duplication, timeout, and backpressure tests.
3. Executor tests proving no arbitrary command/target/interface/address and no
   Docker socket or host namespace access.
4. Observer tests proving it does not trust executor payload and cannot invoke
   execution.
5. Process/container kills at pre-reservation, post-reservation, post-kernel
   mutation, post-receipt, post-observation, audit, and terminal-result
   boundaries with zero automatic retry and zero duplicate effect.
6. External controller inspection of exact capabilities, mounts, namespaces,
   networks, image digests, limits, and cleanup inventory.
7. A separately reviewed threat model and evidence record that retains
   production `BLOCKED` and labels every result as project-controlled
   non-production lab evidence.

## Action items

1. [x] Define versioned command, receipt, and observation JSON schemas.
2. [x] Implement pure validators and canonical HMAC bindings without sockets.
3. [ ] Implement executor and observer Unix-socket services behind an explicit
   opt-in lab flag.
4. [ ] Add the digest-pinned internal-network container harness.
5. [ ] Execute the adversarial and kill matrices.
6. [ ] Seek independent security and target-owner review before any later
   environment or connector decision.

The first two items are implemented in `contracts/v0.4.0/` and
`src/adf_poc/lab_contracts.py`. The implementation closes message shapes,
requires canonical UTC seconds and bounded command lifetime, authenticates
each message under a type-specific domain, rejects shared executor/observer key
material, and correlates the exact signed command with separately authenticated
receipt and observation records. This is contract-level implementation
evidence only. No Unix socket, peer-credential check, executor mutation,
observer probe, container topology, or non-production action has been
implemented or authorized.

The transport foundation is implemented separately in
`src/adf_poc/lab_transport.py`. It is Linux-only, requires an explicit true
opt-in, carries one bounded request and response per `SOCK_SEQPACKET`
connection, checks exact peer UIDs with `SO_PEERCRED`, requires an owner-private
`0700` directory and `0600` socket, revalidates inode identity, and refuses to
replace or clean up an unexpected path. Real Linux tests run without network or
capabilities. Action item 3 remains open because the contract-specific
executor and observer service handlers, durable replay fence, and any target
behavior are not implemented.
