# ADR-016: Offline single-writer Stage A container boundary

**Status:** Accepted for bounded deployment-development packaging only

**Date:** 2026-08-20

**Deciders:** project architecture, security, service, release, and operations owners

**Owner acceptance:** not recorded

**Production authorization:** not granted

## Context

ADR-014 and ADR-015 define an opt-in, single-host Stage A durability path with
one control SQLite database, one offline synthetic-adapter SQLite database, and
one JSONL lifecycle audit. Cooperative POSIX locks, SQLite constraints, closed
receipt/result contracts, audit ownership, semantic validation, and cross-store
correlation narrow local replay and recovery ambiguity. They do not create a
distributed fence, consensus, high availability, disaster recovery, external
audit custody, independent target observation, or a live-action boundary.

The source repository previously had no deployment architecture. A container
and vendor-neutral Kubernetes package are useful for exercising process,
filesystem, configuration, secret, rollout, and resource boundaries without
selecting a cloud provider or adding an external target. Packaging must not
silently weaken the existing single-writer assumptions or imply production
readiness.

The present HTTP implementation is a local reference transport. Its standard-
library server is not accepted as a production network server, and no cluster
network endpoint is exposed by this decision.

## Decision drivers

- Preserve `STAGE_A_SYNTHETIC_ONLY` and `synthetic_simulation` as the only
  executable profile.
- Prevent an update, reschedule, or scale operation from creating concurrent
  writers against the Stage A stores.
- Prevent a missing or incorrectly mounted state volume from being treated as
  authority to initialize a fresh history.
- Run as an unprivileged identity with an immutable application filesystem.
- Keep runtime secrets out of the image, command line, environment, ConfigMap,
  manifest, and logs.
- Deny application network ingress and egress.
- Make bootstrap, rollout, rollback, and evidence limitations explicit and
  machine-testable.
- Remain portable across Kubernetes distributions that support the required
  stable APIs and CSI semantics.

## Decision

### OCI image

The repository carries a multi-stage Dockerfile. Every base image is selected
by an exact SHA-256 digest. Runtime Python distributions are installed from the
existing hash-locked graph with `--require-hashes`, `--only-binary=:all:`,
`--no-deps`, and no source build. The final image contains only the installed
runtime graph, application source, the approved synthetic policy, the runtime
SBOM, and the service entry point.

The final process runs as numeric UID/GID `10001:10001`. Python bytecode writes
are disabled. The Dockerfile declares no exposed port and no image-level health
command. Kubernetes owns the writable mounts and health checks.

The repository Dockerfile is a build input, not a release artifact. A trusted
builder must still produce a registry digest, image-level SBOM and provenance,
vulnerability and license disposition, signature, and independently retained
release evidence.

### Workload and storage ownership

The runtime is one `apps/v1` Deployment with:

- exactly one replica;
- `Recreate` update strategy;
- one `ReadWriteOncePod` filesystem PVC;
- no autoscaler; and
- no Service, Ingress, host port, container port, host network, host PID, or
  host IPC namespace.

`Recreate` stops the prior revision before creating the new revision during a
Deployment update. `ReadWriteOncePod` constrains the PVC to one pod across the
cluster. Both controls are required: ordinary `ReadWriteOnce` may still permit
multiple pods on one node, and neither storage access mode nor a replica count
is a distributed lock or hostile-administrator fence.

The control DB, adapter DB, audit, WAL/SHM companions, and bootstrap binding are
kept in an owner-private `state` child directory under one PVC. The bootstrap
process running as UID 10001 creates that child with mode `0700`; it does not
assume that a CSI-mounted filesystem root is owned by the application UID. This
does not make the artifacts' transactions or backups atomic. It avoids
introducing independent volume-attachment and snapshot timelines for the three
Stage A artifacts.

The selected StorageClass must be validated in the intended environment for
POSIX `fcntl`/`flock`, SQLite WAL, `synchronous=FULL`, `fsync`, atomic rename,
filesystem permissions, persistence, capacity, snapshot, and remount behavior.
Manifest conformance cannot establish those properties.

### Process and filesystem confinement

The pod and every init/application container require:

- `runAsNonRoot=true`, UID/GID 10001;
- `allowPrivilegeEscalation=false`;
- `privileged=false`;
- every Linux capability dropped;
- a read-only root filesystem; and
- the runtime-default seccomp profile.

The pod does not receive a service-account token and has no repository-defined
RBAC binding. `/tmp`, the runtime directory, and staged-secret directory are
bounded `emptyDir` volumes. The application state PVC is the only durable
writable volume.

The pod uses `fsGroupChangePolicy=OnRootMismatch`. This setting is not evidence
that every CSI driver preserves owner-private SQLite sidecars. A recursive
mount-time ownership change could add group permissions to WAL/SHM files that
Stage A intentionally rejects. New-volume bootstrap and remount behavior must
be tested on the selected driver. A privileged recursive `chown` init container
over existing evidence is prohibited.

### Configuration and secrets

The approved policy is baked into the image and therefore bound to the image
digest. An immutable ConfigMap carries a closed, non-secret service
configuration that selects only `STAGE_A_SYNTHETIC_ONLY`, the in-image policy,
the PVC state path, exact secret-file paths, a synthetic principal, and a
bounded SQLite busy timeout.

ConfigMap projections normally expose leaf paths through symlinks, which the
service's safe-file reader rejects. Because the ConfigMap is immutable, each
container mounts only `service.json` as a read-only `subPath` file at the
pre-created `/etc/adf/service.json` image path. Target-cluster validation must
confirm that the resulting mount is a non-writable regular file; no live
ConfigMap update behavior is expected or permitted.

The runtime requires a separately created, versioned Secret containing one
authorization signing key, one evidence key for every policy source, and one
synthetic principal bearer credential. Standard projected Secret leaf paths
are symlinks. The service rejects symlink secret inputs, so a restricted init
container copies only the enumerated files into a bounded memory `emptyDir`,
creates an owner-private child directory rather than trusting the kubelet-owned
volume root, applies owner-private modes, and rejects missing, extra, unsafe, or
invalid values. The application mounts that staged volume read-only.

This staging pattern does not make a Kubernetes Secret a managed KMS/HSM or
prove encryption at rest, rotation, access review, or administrator separation.
Those remain intended-environment gates.

The create-once state marker binds SHA-256 digests of the authorization signing
key, every evidence-source key, and every configured principal credential.
Serve mode checks those bindings before opening either database. A same-path
key or credential change is therefore a state-binding mismatch, not a supported
rotation. Rotation requires a separately designed migration and authorization;
operators must not edit the Secret and retry startup.

### Network and request boundary

The reference transport binds only to `127.0.0.1`, uses one worker, and is not
declared through a Service or container port. A namespace-wide NetworkPolicy
selects every pod and allows no ingress or egress. The target cluster must prove
that its network-policy implementation enforces that policy.

Startup, readiness, and liveness use local exec probes. Startup and liveness
check only the loopback reference process. Readiness performs the deeper policy,
audit, control-store, adapter-store, correlation, and pending-recovery check.
An integrity or recovery condition removes readiness but must not trigger an
automatic state repair or command retry.

Any later remote API, TLS/mTLS endpoint, load balancer, ingress controller,
service mesh, workload identity, metrics exporter, KMS client, audit exporter,
or external adapter is a new trust boundary requiring a separate ADR,
threat-model update, tests, authorization, and owner acceptance.

### Explicit bootstrap

Serving an absent state set is prohibited. Initialization is a separate,
one-shot Kubernetes Job with `backoffLimit=0` and an explicit `--expect-empty`
interlock. The Job uses the same image, policy, secret staging, PVC, and
restricted security context as the Deployment. It is rendered separately and
does not include the Deployment or disruption budget.

The initializer must fail if any authoritative artifact, sidecar, bootstrap
binding, or unexplained file already exists. It creates and validates the new
stores and a binding over the policy/configuration, exact secret-material
digests, store identities, and audit inode. The mount-local device number is
not persisted because it may change across a valid CSI detach/attach; the inode
must remain stable within the same persistent filesystem. Serve mode requires
the complete binding and all three pre-existing artifacts. The bootstrap Job is
never an automatic init container and must not be rerun to repair, replace,
rotate, or migrate state.

Serve mode separately requires `--require-existing`. That lifecycle flag is a
fail-closed operator interlock; the runtime cannot reinterpret a missing state
child as permission to initialize it.

### Rollout and rollback

The committed Kubernetes image reference uses an intentionally impossible
registry and all-zero digest. It prevents the source template from being
mistaken for a deployable release. An environment-specific overlay must replace
both runtime and bootstrap image references with the same approved registry
digest. Tags alone are prohibited.

Rollout requires a recorded exact source revision, image digest, rendered
configuration, Secret revision, store schemas, target StorageClass, static and
server-side validation, signature/provenance verification, vulnerability
disposition, quiesced backup evidence, and rollback decision.

Artifact rollback may use a prior image/configuration/Secret revision only when
that revision is proven compatible with the exact existing control-v2,
adapter-v1, audit, receipt, result, and bootstrap contracts. A schema,
correlation, audit, receipt, or pending-recovery failure is a preservation and
incident condition, not authority for blind rollback. There is no in-place
schema downgrade or automated database repair.

The PodDisruptionBudget sets `minAvailable=1`. It can block an eviction-based
node drain when the single pod is healthy. It does not prevent Deployment
updates, direct pod/controller deletion, involuntary failure, or administrative
bypass and does not create high availability.

## Options considered

### Publish only a Dockerfile

Rejected. It would leave replica ownership, durable storage, network policy,
secrets, probes, and disruption behavior undefined.

### Use a rolling multi-replica Deployment

Rejected. Stage A has no distributed lease, fencing epoch, consensus store, or
multi-node audit owner. Rolling overlap or horizontal scaling could violate the
single-writer assumption.

### Use a StatefulSet

Deferred. Stable ordinal identity does not add consensus or safe failover, and
the current boundary needs one PVC and one process rather than a replicated
stateful topology. A one-replica Recreate Deployment expresses the present
constraint more directly.

### Expose a cluster Service for the reference HTTP transport

Rejected. Bearer authentication over an unaccepted reference server is not an
approved remote trust boundary. No requirement currently authorizes network
clients.

### Mount projected Secrets directly

Rejected. Kubernetes projected leaf paths are symlinks, while the service's
secret-file contract requires singly linked regular files with bounded modes.

### Initialize state from an init container on every pod start

Rejected. A missing/mis-mounted PVC or deleted artifact could be interpreted as
authority to create a fresh history and defeat restart replay controls.

## Consequences

Positive consequences:

- source packaging preserves the synthetic-only, single-writer boundary;
- a pod cannot receive application network traffic through repository-defined
  Kubernetes resources;
- application and init processes run without root, capabilities, writable
  rootfs, or a service-account token;
- state bootstrap is explicit and separately reviewable;
- image and configuration drift are visible in the pod template; and
- focused tests reject floating base images, additional replicas, rolling
  overlap, ordinary RWO, exposed ports, network allow rules, inline Secrets,
  missing probes, or weakened security contexts.

Costs and limitations:

- the service has no authorized remote consumer;
- one pod and one PVC provide no HA or failover;
- the PDB can intentionally block node maintenance;
- Kubernetes Secret custody, CSI filesystem behavior, NetworkPolicy
  enforcement, and Pod Security admission depend on the intended cluster;
- one PVC does not produce a coherent cross-store recovery point;
- the reference HTTP server is not production transport evidence; and
- immutable build, scan, signature, provenance, rollout, rollback, storage,
  capacity, backup/restore, and cluster observations remain external.

## Verification obligations

Repository-controlled validation is limited to Dockerfile/static policy tests,
Kustomize rendering when `kubectl` is available, the existing Stage A and full
regression suites, dependency/SBOM validation, and the source manifest.

An intended environment must additionally demonstrate:

1. exact multi-architecture image construction and registry digest;
2. image SBOM, signed provenance and image identity, and accepted vulnerability
   and license findings;
3. admission under the target restricted Pod Security policy;
4. enforced deny-all ingress/egress;
5. RWOP, mount, lock, WAL, `fsync`, crash, capacity, and remount behavior;
6. no second pod or bootstrap/runtime overlap;
7. secret encryption, access, rotation, revocation, and audit;
8. initialization refusal on any nonempty or inconsistent state;
9. restart with no new decision, authorization, command, effect, result, audit,
   or outbox work;
10. quiesced backup, restore review, artifact rollback, emergency disable, and
    failed-rollback handling; and
11. named owner acceptance.

## Explicit non-claims

This decision and its manifests do not establish a production service,
production transport, managed identity, managed key custody, external audit
custody, independent target observation, representative data validity,
historical authorization, live connector, operational effect, distributed
idempotency, HA, DR, coherent backup, successful rollback, capacity, SLO, RTO,
RPO, signed release, deployment, pilot acceptance, production authorization, or
operational effectiveness. The machine production gate remains `BLOCKED`.
