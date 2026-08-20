# Offline Stage A Kubernetes runbook

**Runbook state:** deployment-development procedure; not operationally accepted

**Runtime profile:** `STAGE_A_SYNTHETIC_ONLY`

**Network boundary:** loopback-only reference transport; no Service, Ingress,
container port, permitted ingress, or permitted egress

**Production authority:** none

## Purpose and hard boundary

This procedure packages and exercises the existing single-host Stage A
synthetic durability path in a vendor-neutral Kubernetes shape. It does not
authorize historical or organizational data, an external caller, production
credential, enterprise identity, live connector, network target, model
promotion, operational action, or Stage B/C activity.

The Kubernetes resources are source candidates. They intentionally reference
`registry.invalid` and an all-zero image digest, and they intentionally omit the
runtime Secret. They cannot become a deployment record until a controlled
environment supplies an exact built image digest, separately created versioned
Secret, rendered overlay, admission evidence, and named approvals.

The reference service binds only to `127.0.0.1`. The current standard-library
HTTP implementation is not accepted as a production network transport. Do not
add a Service, Ingress, port, host network, port-forward workflow, proxy,
sidecar, or network allow rule under this procedure.

Read this procedure together with:

- [ADR-016](../adr/016_offline_stage_a_container_boundary.md);
- [Stage A durable-ledger runbook](STAGE_A_DURABLE_LEDGER_RUNBOOK.md);
- [production readiness](../production/PRODUCTION_READINESS.md); and
- [supply-chain boundary](../production/SUPPLY_CHAIN.md).

## Resource set and lifecycle

The runtime base renders:

- one restricted namespace;
- one tokenless ServiceAccount with no RoleBinding;
- one immutable non-secret ConfigMap;
- one 10 GiB `ReadWriteOncePod` PVC;
- one single-replica, `Recreate` Deployment;
- one namespace-wide deny-all NetworkPolicy; and
- one PodDisruptionBudget with `minAvailable=1`.

The bootstrap package renders the namespace, ServiceAccount, ConfigMap, PVC,
NetworkPolicy, and one bounded Job. It deletes the Deployment and disruption
budget from its rendered set. Bootstrap and runtime are separate operator
actions and must never own the PVC concurrently.

The PVC retains the control-v2 database, adapter-v1 database, JSONL audit,
WAL/SHM companions, and bootstrap binding under the owner-private
`/var/lib/adf-volume/state` child. Bootstrap creates that child as UID 10001
with mode `0700`; the kubelet-owned PVC mount root is not used as the service
state directory. The PVC is not a cross-store transaction or coherent recovery
point.

## Required records and roles

Before any intended-environment action, record:

- release owner, platform owner, security owner, operations owner, and evidence
  custodian;
- exact source commit and clean/dirty state;
- exact Dockerfile base-image digest;
- exact built image registry digest and platforms;
- image SBOM, provenance, signature, scanner versions, vulnerability/license
  disposition, and independent verification;
- exact rendered bootstrap/runtime manifests and digests;
- Kubernetes server, admission, CNI, CSI, StorageClass, node OS/runtime, and
  time-synchronization versions;
- ConfigMap and Secret names, resource versions, and non-secret digests;
- PVC/PV identity, access mode, capacity, filesystem, and reclaim policy;
- Stage A store/audit identities, schemas, counts, correlation result, and
  backup evidence;
- rollout revision, start/end UTC times, probe results, logs, exceptions, and
  final disposition; and
- rollback decision, trigger, result, and preserved evidence.

Do not record raw keys, bearer credentials, signatures, tokens, nonces, Secret
contents, or authorization material.

## Tool and cluster prerequisites

Repository-side minimum checks require Python 3.11 or 3.12, Docker BuildKit,
and `kubectl` with Kustomize support. Intended-environment validation also
requires an approved image registry, scanner, SBOM/provenance generator,
signature verifier, Kubernetes schema validator, policy tester, and target
cluster.

The cluster gate is blocked unless all of the following are verified:

1. Kubernetes and the selected CSI driver support `ReadWriteOncePod`.
2. Restricted Pod Security admission is enforced for the namespace.
3. The CNI implements and enforces both ingress and egress NetworkPolicy.
4. The StorageClass supports filesystem PVCs and the required POSIX lock,
   SQLite WAL, `synchronous=FULL`, `fsync`, atomic rename, ownership, remount,
   persistent inode identity across detach/attach, persistence, and capacity
   behavior. Mount-local device numbers may change and are not persisted in the
   service marker.
5. Kubernetes Secrets are encrypted at rest with approved access/audit policy,
   or a separately approved standard-Secret synchronization boundary exists.
6. No admission mutation adds sidecars, service-account tokens, capabilities,
   writable rootfs, ports, network exceptions, or additional volumes.
7. Backup/snapshot behavior has been reviewed against the non-atomic Stage A
   store set; a volume snapshot alone is not declared coherent DR evidence.
8. Single-file ConfigMap `subPath` mounts appear as non-writable regular files
   at `/etc/adf/service.json`; projected symlink leaves are rejected by the
   service.

If any prerequisite is unknown, stop. Do not substitute a different access
mode, hostPath, network filesystem, privileged init container, floating image
tag, or unreviewed security exception.

## Repository validation

Run from a clean candidate worktree:

```sh
PYTHONDONTWRITEBYTECODE=1 PYTHONWARNINGS=error PYTHONPATH=src \
  python3 -m unittest tests.test_container_deployment -v
PYTHONDONTWRITEBYTECODE=1 PYTHONWARNINGS=error PYTHONPATH=src \
  python3 -m unittest discover -s tests -v
python3 scripts/validate_supply_chain.py
python3 scripts/validate_manifest.py
kubectl kustomize deploy/kubernetes/base
kubectl kustomize deploy/kubernetes/bootstrap
docker build --check .
```

The last command requires a running Docker/BuildKit service. Kustomize rendering
is syntax/composition evidence, not API-server validation or admission.

Run the following through pinned, approved tool distributions:

```text
hadolint Dockerfile
kubeconform -strict -summary <rendered manifests>
conftest test <rendered manifests>
trivy config .
```

Tool success does not replace intended-environment validation.

## Image construction gate

Build the exact commit for each approved Linux platform. Pass the exact commit,
version, and a stable UTC creation timestamp as OCI build metadata. The build
must consume the digest-pinned base and hash-locked binary Python graph without
network-unlocked build dependencies.

Required post-build checks are:

1. inspect the final config and prove numeric user `10001:10001`, no exposed
   port, no inherited health command, and the expected entry point;
2. run with `--user 10001:10001`, `--read-only`, `--network none`, bounded
   tmpfs mounts, an owner-private state directory, staged test secrets, and the
   synthetic config;
3. produce and validate an image-level CycloneDX or SPDX SBOM that covers both
   OS and Python components;
4. scan the exact digest and record every finding and disposition;
5. produce signed provenance and sign the immutable image digest through the
   approved builder/identity;
6. independently verify the signature, provenance subject, SBOM subject, source
   commit, and image digest; and
7. retain the digest and evidence outside the workload namespace.

No source tag, local image ID, repository manifest, package-only SBOM, or green
build is a substitute for the registry digest and external evidence above.

## Environment overlay

Do not edit the repository base to insert an environment image. Create a
controlled overlay whose `images` transformer matches:

```yaml
images:
  - name: registry.invalid/ai-decision-firewall/stage-a
    newName: APPROVED_REGISTRY/APPROVED_REPOSITORY
    digest: sha256:APPROVED_64_HEX_IMAGE_DIGEST
```

Create one overlay over `deploy/kubernetes/bootstrap` and one over
`deploy/kubernetes/base`. Render both and prove that every init/application
container uses the same nonzero digest and no tag-only image remains.

The namespace and object names in the repository are part of the reviewed
single-cell boundary. Do not create a second active copy against the same PVC.

## Runtime Secret contract

Create the immutable `adf-stage-a-runtime-secrets-v1` Secret separately from
individual approved files. The exact required keys are:

- `authorization-signing.key`;
- `CMDB_PRIMARY.key`;
- `CTI_PRIMARY.key`;
- `EDR_PRIMARY.key`;
- `IDP_PRIMARY.key`;
- `NETWORK_PRIMARY.key`; and
- `SOC_AGENT_01.credential`.

Every key must satisfy the service's length, uniqueness, character, and
trust-domain-separation rules. The principal credential is URL-safe bearer
material for this synthetic fixture only. Do not reuse a key or credential from
tests, source, another environment, an operational system, or an earlier store
identity without a reviewed continuity decision.

Create the Secret from files using an approved workstation or secret-delivery
pipeline. Do not use command-line literals. After creation, set or verify
`immutable: true`, record metadata and a non-secret evidence digest through the
approved process, and remove plaintext staging files according to the approved
handling procedure.

The pod does not consume projected symlink leaves directly. The restricted
`stage-runtime-secrets` init container receives only the enumerated keys, copies
them into an owner-private `secrets` child of a 1 MiB memory `emptyDir`, applies
owner-private permissions, and exits. This avoids treating the kubelet-owned
volume root as an owner-private directory. The application receives the staged
volume read-only. A missing, extra, symlinked destination, malformed, reused,
or permission-unsafe value must block the pod.

Kubernetes Secret storage is not automatically managed KMS/HSM custody,
rotation evidence, or administrator separation. Keep those gates explicit.
The bootstrap marker binds a SHA-256 digest projection over the signing key,
every evidence key, and every principal credential. Serve mode verifies that
projection before either database is opened. Any Secret rotation, replacement,
or same-path content change therefore fails closed and requires a separately
designed, reviewed state-binding migration; restarting or rerunning bootstrap is
not a rotation procedure.

## New-state bootstrap

Bootstrap is authorized only for a new, empty PVC with a recorded new lifecycle
decision. It is prohibited for restore, repair, migration, rollback, missing-
mount recovery, or replacement of an existing authoritative set.

1. Confirm that no Deployment, pod, Job, debug container, snapshot process, or
   other workload can mount or access the PVC.
2. Confirm the PVC/PV is the intended new empty object and record its identity.
3. Render the approved bootstrap overlay and run strict schema, policy, and
   server-side dry-run validation.
4. Apply only the bootstrap overlay.
5. Verify the Job uses the exact approved image digest, `backoffLimit=0`, one
   initializer, one secret-staging init container, the tokenless
   ServiceAccount, deny-all network, restricted contexts, and the RWOP PVC.
6. Wait for one successful completion. Do not delete/recreate or rerun a failed
   Job as a retry tactic.
7. Preserve Job status, events, logs, exact rendered manifests, PVC identity,
   and initialization output.
8. Validate the control-v2 DB, adapter-v1 DB, audit, store correlation,
   owner-private modes, policy/config/secret-material binding, persistent audit
   inode, and bootstrap marker read-only.
9. Confirm there are no request, decision, authorization, attempt, receipt,
   result, recovery, or effect rows beyond the exact initialization contract.
10. Mark bootstrap complete in the deployment record. Retain the Job evidence;
    do not treat it as production authorization.

The initializer must fail before mutation if the state directory contains any
authoritative file, sidecar, prior marker, unexpected entry, unsafe ownership,
or unrecognized schema. An unexplained nonempty PVC is an evidence incident.

## Runtime rollout

Before rollout, complete the existing Stage A quiescence, integrity,
correlation, and backup guidance. A live/raw SQLite file copy that ignores WAL
and SHM remains prohibited.

1. Confirm the bootstrap or prior runtime pod is terminated and the PVC has no
   current attachment.
2. Validate the existing store set read-only. Resolve no pending recovery by
   deployment; use only the separate authorized quiesced recovery procedure.
3. Record the current image/config/Secret/store set and the exact rollback
   candidate.
4. Render the approved runtime overlay. Verify one Deployment replica,
   `Recreate`, RWOP, deny-all networking, no Service/Ingress/port, exact digest,
   resources, probes, explicit `--require-existing`, tokenless ServiceAccount,
   immutable single-file configuration mount, and restricted contexts.
5. Run strict schema/policy checks and target-cluster server-side dry run.
6. Review the API-server diff. Any admission-added sidecar, token, network
   resource, volume, capability, writable rootfs, or image mutation blocks the
   rollout.
7. Apply the runtime overlay and wait for Deployment rollout status within the
   recorded deadline.
8. Verify exactly one pod and one PVC attachment. Prove the actual running
   image ID equals the approved digest.
9. Verify the secret-staging init container completed once and did not log
   secret contents.
10. Verify startup and liveness locally, then verify deep readiness.
11. Inspect events and logs for mount, ownership, lock, audit, schema,
    correlation, recovery, probe, resource, or security-policy failures.
12. Confirm the repository defines no EndpointSlice, Service, Ingress,
    LoadBalancer, host port, allowed ingress, or allowed egress.
13. From an approved network-policy test harness, prove both application ingress
    and egress are denied. Do not use an operational endpoint as the test target.
14. Restart/reschedule the pod in the non-production exercise and prove startup
    creates no request, decision, authorization, command, effect, receipt,
    result, recovery, outbox, or audit work.
15. Compare pre/post semantic snapshots and record the bounded outcome.

The pod is not an approved production service even when Ready. Ready means only
that the configured local synthetic policy/audit/store/correlation checks pass.

## Probe interpretation

| Probe | Required meaning | Prohibited inference |
|---|---|---|
| Startup `/livez` | The loopback reference process started within the configured bound. | The state is valid or the service is ready. |
| Liveness `/livez` | The local process responds. | Restart is safe after an integrity or recovery failure. |
| Readiness `/readyz` | Durable mode, policy integrity, audit chain, store integrity/correlation, and no pending recovery pass. | Operational effectiveness, HA, external reachability, or production authorization. |

Readiness failure keeps the pod unavailable. It must not initialize, migrate,
repair, reconcile, retry a request, mint authority, invoke a command, or change
an authoritative artifact. A durable-state readiness failure should not be
turned into an aggressive liveness restart loop.

## Rollback decision and execution

Define rollback triggers before applying a candidate. At minimum:

- image signature/provenance/SBOM subject mismatch;
- unexpected admission mutation or image digest;
- mount, permission, seccomp, capability, Pod Security, or NetworkPolicy
  failure;
- startup/probe regression attributable to the candidate image/config; or
- bounded functional regression with the stores still proven compatible and
  unchanged.

The following are **not** automatic artifact-rollback triggers:

- invalid audit chain;
- unsupported or changed schema;
- `DURABLE_STORE_CORRELATION_INVALID`;
- missing/orphan/mismatched receipt or result;
- pending recovery tail;
- unknown effect;
- evidence of state regression or PVC substitution; or
- unclear storage behavior.

Those conditions require emergency disable, preservation, and investigation.
Starting an older image against uncertain state may reopen authority or conceal
divergence.

Artifact rollback is permitted only when the prior image, ConfigMap, Secret,
policy, bootstrap binding, and exact control-v2/adapter-v1/audit contracts are
proven compatible. Preserve the failed pod, logs, events, rendered manifests,
image identity, and state evidence. Stop the candidate, verify no holder remains,
then apply the prior exact revision. Do not change the PVC, delete sidecars,
down-migrate, edit rows, truncate audit, or restore an older snapshot in place.

After rollback, repeat the complete startup/readiness, semantic no-new-work,
network-denial, resource, and evidence checks. A successful pod start is not a
successful rollback until those checks and the owner disposition are recorded.

## Emergency disable and preservation

Trigger disable on an unexpected connector, route, endpoint, credential,
target, second writer, PVC substitution, code/config/image drift, Secret
compromise, lock anomaly, integrity/correlation failure, pending recovery,
unknown effect, storage exhaustion, or owner direction.

1. Stop the Deployment without deleting it, its ReplicaSets, ConfigMap, Secret,
   PVC, Job evidence, events, or logs.
2. Prove no pod, debug container, backup process, or node process holds the
   stores or sidecars.
3. Preserve exact manifests, API objects, image/provenance evidence, events,
   logs, both databases and companions, audit, marker, configuration, and
   non-secret checksums.
4. Do not run bootstrap, rollout undo, restore, repair, checkpoint, reconciliation,
   or a replacement pod until the applicable owner authorizes the exact action.
5. Classify every possible effect conservatively under the Stage A recovery
   table. Never infer rollback or no effect from pod termination.

Do not delete the PVC or namespace as an emergency-disable shortcut.

## PDB and maintenance boundary

The PDB intentionally allows zero voluntary evictions while the only pod is
available. It may block `kubectl drain`. It does not control Deployment-driven
updates, direct deletion, node failure, storage loss, or administrator bypass.

Planned maintenance requires a recorded outage, clean quiescence, preservation,
and explicit scale-down. Do not relax or delete the PDB merely to make an
unreviewed drain succeed. The present architecture has no alternate replica or
failover site.

## Completion evidence and remaining gates

Repository completion means only that the Dockerfile, Kubernetes source,
Kustomize render, ADR/runbook, focused tests, existing regressions, dependency
locks/SBOM, and repository manifest have been validated against an exact local
commit.

The following remain external and blocking until separately observed and
accepted:

- actual multi-architecture image build and registry digest;
- image-level SBOM, vulnerability/license disposition, signature, provenance,
  trusted-builder custody, and independent verification;
- production-grade transport selection and validation;
- target Kubernetes server-side validation and admission;
- intended CNI/NetworkPolicy and CSI/StorageClass behavior;
- managed secret/KMS custody, rotation, revocation, and audit;
- bootstrap and rollout execution;
- power-loss, capacity, load/soak, resource, disk-full, remount, and denial-of-
  service campaigns;
- coherent backup/restore, artifact rollback, failed rollback, RTO/RPO, HA, and
  DR exercises;
- monitoring, alerting, outbox export, external audit custody, and incident
  response exercises; and
- all accountable-owner acceptances.

None of this procedure changes the machine production gate from `BLOCKED`.
