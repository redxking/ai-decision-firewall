# Runbook: Stage A disposable block-device fault campaign

**Owner:** verification owner and platform owner

**Frequency:** before a production-development candidate that changes Stage A
durability or recovery

**Last updated:** 2026-08-20

**Last repository-controlled run:** 2026-08-20

## Purpose

This procedure injects either full-device `dm-error` or intermittent
`dm-flakey error_writes` failures beneath ext4 at the T1, post-effect
observation, T2, audit-closure, and T3 boundaries. It verifies
restart disposition, exact receipt count, target state, audit integrity, and
the absence of a second synthetic effect.

This is a destructive, privileged, disposable lab. It uses loop devices backed
only by files on a 256 MiB container tmpfs. It must not receive host block
devices, production state, credentials, representative data, or a network
during the fault campaign. The derivative tool image is not a deployable
artifact.

## Prerequisites

- [ ] A named verification owner authorizes privileged local execution.
- [ ] Docker uses a disposable Linux engine with loop and device-mapper support.
- [ ] For `dm-flakey-error-writes`, `dmsetup targets` reports a `flakey`
  target. The runner fails the requested campaign if the target is absent.
- [ ] The exact Stage A candidate image exists locally and its image ID and
  revision label have been recorded.
- [ ] At least 1 GiB memory, two CPUs, and 256 MiB temporary storage are
  available to the lab container.
- [ ] No production or representative data, secrets, sockets, host devices, or
  state volumes are in scope.
- [ ] The operator understands that the derivative-image build uses the Debian
  package repository before the privileged container starts with
  `--network=none`.

## Procedure

### 1. Record the candidate image identity

```bash
docker image inspect --format '{{.Id}} {{index .Config.Labels "org.opencontainers.image.revision"}}' <exact-local-image-tag>
```

**Expected result:** one `sha256:` image ID and the intended candidate revision.

**If it fails:** stop. Build or load the exact candidate through the normal
repository-controlled process; do not substitute a mutable image silently.

### 2. Run the explicitly authorized campaign

From the repository root:

```bash
PYTHONDONTWRITEBYTECODE=1 python3 scripts/run_stage_a_block_device_campaign.py --image <exact-local-image-tag> --fault-mode dm-error --allow-privileged-lab
```

Repeat with `--fault-mode dm-flakey-error-writes` only on a kernel that reports
the required target. Each invocation is a separately identified five-boundary
campaign.

For an ephemeral GitHub-hosted Linux run, merge the reviewed workflow first,
record the exact `main` commit, and dispatch only that commit:

```bash
gh workflow run stage-a-storage-lab.yml --ref main \
  -f candidate_sha=<exact-40-character-main-sha> \
  -f authorization=I_ACKNOWLEDGE_PRIVILEGED_EPHEMERAL_LAB
```

The workflow checks out the supplied SHA, verifies it exactly, validates the
manifest and ordinary suite, requires the host `flakey` target, builds without
publishing, and runs only `dm-flakey-error-writes`. Its least-privilege token is
read-only. The privileged container still has control of the ephemeral runner
kernel, so this workflow is manual and never runs for pull requests or pushes.

The runner binds a unique local alias to the inspected image ID, builds a
temporary lab-only derivative with exact `dmsetup`, ext4, and util-linux package
versions, disconnects the runtime network, and executes five cases. It does
not pass a host device into the container.

**Expected result:** the unit test reports `OK`; the boundary observations show
zero receipts at T1, one receipt at every later boundary, `UNKNOWN_EFFECT` for
the four nonterminal cases, `COMPLETED_VERIFIED` after T3, and `new_effect=false`
for recovery. The runner's final JSON reports `"status": "PASSED"`, the
selected `fault_mode`, and the exact base image ID.

**If it fails:** preserve the complete output. Do not rerun until the failing
boundary, filesystem state, error chain, and cleanup status are understood.

### 3. Verify cleanup

```bash
docker ps --all --filter 'name=adf-stage-a-storage-lab-'
docker image ls 'adf-stage-a-storage-lab'
docker image ls 'adf-stage-a-storage-base'
```

**Expected result:** no campaign container or temporary image tag remains,
unless `--keep-lab-image` was deliberately selected for investigation.

**If it fails:** remove only the exact campaign-created container or tags shown
in that run's output. Do not use broad image, volume, or system-prune commands.

## Verification record

Capture:

- candidate commit, manifest digest, image ID, image revision label, Docker
  Desktop/Engine version, Linux kernel, architecture, and timestamp;
- lab Dockerfile digest and exact `dmsetup`, `e2fsprogs`, and `util-linux`
  versions;
- complete stdout/stderr and per-boundary disposition, receipt count, target
  state, audit-chain result, `e2fsck` return code, raw pre/post-repair image
  hashes, and the exact application paths whose digests changed;
- whether cleanup completed and whether any interruption occurred.
- for GitHub-hosted execution, the run URL, attempt, exact workflow commit, and
  downloaded 30-day evidence-artifact digest before local preservation.

The repository-controlled 2026-08-20 development run used Docker Desktop
4.87.0, LinuxKit kernel 7.0.12 on arm64, and the locally inspected Stage A image
ID `sha256:00b9ed3dab06a3b124c079255851e91877074823093c7a1fa0d37d090f3a45ad`.
All original five `dm-error` boundaries passed. The four nonterminal cases required filesystem
repair and changed WAL/SHM membership or bytes; T2 also changed the visible
audit digest between the pre-repair and remounted views. The post-repair audit
chain and three-store correlation remained valid, with the exact receipt/effect
count. This observation is mutable local development evidence until frozen
through the candidate/carrier process.

The 2026-08-20 capability check against LinuxKit 7.0.12 reported only the
`crypt`, `striped`, `linear`, and `error` device-mapper targets. The explicitly
requested `dm-flakey-error-writes` run therefore failed before creating a test
device with `DM_FLAKEY_ERROR_WRITES requested but the kernel has no
device-mapper flakey target`. That is a verified environment limitation, not a
passing flakey result; the run must be repeated on a capable disposable Linux
kernel.

That repetition completed on the GitHub-hosted Ubuntu 24.04 runner in
[run 32423745805](https://github.com/redxking/ai-decision-firewall/actions/runs/32423745805)
against exact candidate `662cb668f193667af37eddddf2040e666d188d76` and
unpublished image ID
`sha256:09b123a2fcfddd0b2ddbb86805728cb03a438c056646f9bd0fa0fe32062f2215`.
All five `dm-flakey error_writes` boundaries passed: T1 recovered with zero
receipts; observation, T2, and audit closure recovered with one receipt and
`UNKNOWN_EFFECT`; T3 reopened as `COMPLETED_VERIFIED`; every recovery reported
no new effect. The 30-day GitHub artifact
`stage-a-storage-lab-32423745805-1` was recorded as
`sha256:ae56b62e799f7b335e8972b3ad4409aa5b116805a5b001b3280d1de3032bc7b3`.
This remains repository-controlled development evidence, not independent or
intended-environment validation.

## Troubleshooting

| Symptom | Likely cause | Required response |
|---|---|---|
| `/dev/mapper/control` or loop devices are absent | Docker engine does not expose the required Linux kernel interfaces | Stop and use an approved disposable Linux VM; do not pass a host production disk. |
| Requested `dm-flakey` target is absent | The active kernel did not build or load the optional target | Preserve the failed capability result and move the disposable campaign to a capable Linux VM. Do not count the mode as tested or substitute `dm-error`. |
| Exact `dmsetup` package is unavailable | Debian repository state changed | Stop, record repository metadata, and update the lab dependency through review. Do not remove the version pin. |
| `e2fsck` returns greater than 1 | Filesystem damage was not automatically correctable | Preserve output and the lab while it remains isolated; escalate to verification and platform owners. Do not claim a safe restart. |
| Receipt count exceeds one | Idempotency or recovery safety failure | Stop the release, preserve all artifacts, and open a security/reliability defect. |
| Audit is malformed after repair | Partial or lost authoritative evidence | Preserve and quarantine the artifact set. Never truncate or synthesize audit history. |
| The runner is interrupted | The container may still be cleaning loop/device-mapper state | Allow the runner's 20-second stop path to complete. If the Docker VM retains a campaign mapping, preserve diagnostics and restart only the disposable Docker VM; do not manipulate host disks. |

## Rollback and cleanup

There is no rollback of authoritative test evidence. Each case uses a new
loopback image and destroys it after verification. The runner stops and removes
only its uniquely named campaign container and removes only its two
campaign-created image tags. If cleanup cannot be proven, restart the disposable
Docker VM before another campaign.

## Escalation

| Situation | Accountable role | Action |
|---|---|---|
| Duplicate receipt/effect, terminal result without T3, or history mutation | Verification owner and security owner | Block the candidate and preserve the complete lab evidence. |
| Unrecoverable filesystem or device-mapper residue | Platform owner | Isolate and reset the disposable Docker VM; verify host devices were never passed. |
| Proposal to use an intended CSI volume, representative target, or external system | Platform, target-system, data, security, and authorizing owners | Create a separate exact authorization and evidence plan before access. |

## Limitations and prohibited inferences

Passing this procedure does not prove physical power-loss safety, flush/barrier
correctness, torn-write behavior, silent `drop_writes`, device-cache semantics, an intended CSI or
filesystem implementation, hostile-writer resistance, HA/DR, RPO/RTO,
representative-target validity, or production authorization. `e2fsck` repairs
filesystem metadata; it does not authenticate application evidence. Root in the
privileged lab is not the production runtime identity and is accepted only for
loop/device-mapper control in this isolated layer. Pre-repair file digests are
observations through the restored filesystem and are not substitutes for the
raw block-image hash or an independently custodied snapshot. A GitHub-hosted
log or artifact is platform-retained repository-controlled evidence, not
independent custody, trusted-builder provenance, or intended-environment proof.
