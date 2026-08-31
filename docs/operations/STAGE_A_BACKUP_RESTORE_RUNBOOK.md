# Stage A cold backup and restore runbook

**Procedure state:** repository-controlled development mechanism; not
operationally accepted disaster recovery

**Runtime profile:** `STAGE_A_SYNTHETIC_ONLY`

**Live-action authority:** none

## Purpose and boundary

This procedure creates and restores one integrity-bound copy of the Stage A
JSONL audit, control-v2 SQLite database, and adapter-v1 SQLite database. The
service marker is not copied because it binds the audit inode. Restore validates
the copied stores and audit as one correlated set, verifies the original store
identities, and creates a new marker bound to the restored audit inode.

The mechanism acquires the same bounded cooperative durable-state and audit
locks used by Stage A requests. It refuses an incomplete lifecycle, pending
recovery tail, corrupt or divergent stores, unsafe paths, active SQLite
sidecars, an existing destination, a changed configuration/policy/secret
binding, a malformed manifest, or a file digest/size mismatch.

This is not continuous backup, a volume-snapshot claim, cross-store atomicity,
rollback resistance, external custody, WORM retention, trusted time, HA,
failover, or RPO/RTO evidence. A noncooperating process with the same operating
system identity remains outside the lock boundary. The backup manifest is
unsigned and self-custodied. `trusted_time_claimed` is always `false`.

## Preconditions

1. Stop the reference service and prevent a second initializer, request
   processor, recovery operator, backup process, or restore process from using
   the state directory. `--expect-quiesced` is an operator assertion, not a
   distributed fence.
2. Preserve the exact service configuration, policy, and secret set. Their
   digests are part of the backup binding; restore under changed key material or
   a changed absolute state path is rejected.
3. Confirm the source and destination parents are real, owner-private
   directories on storage that supports POSIX ownership, `fsync`, atomic rename,
   advisory `flock`, and SQLite WAL semantics.
4. Preserve suspected-corrupt or failed state separately. Do not overwrite,
   repair, truncate, or delete authoritative artifacts to make restore pass.
5. Record the operator, source commit/image digest, configuration and policy
   digests, source state identity, backup location, start/end time, reason, and
   intended validation. Do not record keys, credentials, signatures, nonces, or
   authorization material.

## Create a cold backup

The destination must be an absolute nonexistent path outside the configured
state directory. The command publishes the directory only after every artifact
and `backup-manifest.json` have been written and synchronized.

```text
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src:. python3 run_service.py backup \
  --config /absolute/path/service.json \
  --destination /absolute/private/backups/stage-a-backup-IDENTIFIER \
  --expect-quiesced
```

Expected status is `BACKUP_CREATED`. The directory contains exactly:

- `audit.jsonl`;
- `control.sqlite3`;
- `synthetic-adapter.sqlite3`; and
- `backup-manifest.json`.

The manifest binds SHA-256 and byte size for each state artifact, exact config,
policy, and secret-binding digests, and the control and adapter store identities.
Retain a separately custodied digest or approved signature over the manifest if
the intended environment requires rollback or replacement detection; this
repository does not provide that custodian.

## Restore

Restore is accepted only at the same absolute configured state path when that
path is absent or empty. Move the failed/original state to a preserved evidence
location through the approved operator procedure; do not destroy it. Ensure the
service remains stopped.

```text
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src:. python3 run_service.py restore \
  --config /absolute/path/service.json \
  --source /absolute/private/backups/stage-a-backup-IDENTIFIER \
  --expect-empty
```

Expected status is `BACKUP_RESTORED`. If copying or validation fails, the
partially restored directory is deliberately retained fail closed for operator
inspection. It has no valid service marker and cannot be served or initialized
as empty state. Do not retry over it.

## Post-restore verification

1. Run existing-state startup and `/readyz`; require `READY`.
2. Confirm the control ledger ID and adapter store ID match the backup manifest.
3. Verify audit continuity, cross-store correlation, terminal-result counts,
   adapter receipt counts, and expected target state.
4. Exercise authenticated result lookup for an exact known request. Do not
   resubmit or reconstruct an unknown/nonterminal action to test the restore.
5. Record the restored marker digest and audit inode, validation results,
   exceptions, and final operator disposition.
6. Keep the service blocked if any result, receipt, audit, chronology, binding,
   or target state is unexpected.

## Required future evidence

Production recovery remains blocked until named owners approve backup scope,
retention, encryption, custody, restore authority, rollback selection, RPO,
RTO, safe-state criteria, compensation, and evidence handling, and the intended
environment demonstrates power-loss, disk-failure, snapshot, restore,
reconciliation, rollback-failure, key-loss/rotation, and hostile-substitution
campaigns with independent verification.
