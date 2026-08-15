# Stage A Durable-Ledger Runbook

**Runbook state:** bounded development procedure; not operationally accepted
**Scope:** one host, one authoritative SQLite ledger, offline synthetic fixtures, and the in-memory synthetic target only
**Baseline:** `bb6b8f28afba0961bb97b24e6050fccaa94d5702` plus the unfrozen local Stage A candidate
**Production authority:** none

## Purpose and hard boundary

This runbook describes how to inspect, stop, reconcile, and preserve the Stage A durable control ledger without turning an uncertain action into a retry. It is deliberately fail closed.

Stage A has no production connector, operational credential, durable target adapter, deployment package, service supervisor, queue, outbox exporter, external audit custodian, high-availability topology, or approved disaster-recovery system. It must not receive historical organizational data or connect to a production or non-production enterprise system. It must not be used to infer production safety, availability, replay resistance, recovery effectiveness, or operational authorization.

The repository's `run_phase3.py` demonstration does **not** pass a `control_ledger_path`; it therefore uses the in-memory compatibility ledger and is not the Stage A durable-ledger launcher. There is currently no supported Stage A CLI or service entry point. Durable behavior is available as a library integration and is exercised by the focused test harness only. Do not create an ad hoc launcher to bypass that gate.

## Safety invariants

1. Only the `synthetic_simulation` execution mode and the repository's in-memory synthetic target are permitted.
2. No request processing begins until ledger integrity, schema, audit integrity, single-writer ownership, and startup reconciliation pass.
3. Reconciliation is an explicit operator action under exclusive, quiesced ownership. It is not run automatically by every constructor because another live process could have a legitimate in-flight reservation.
4. Every `RESERVED` attempt found during authorized restart recovery becomes `UNKNOWN_EFFECT`. The consumed authorization remains consumed.
5. `UNKNOWN_EFFECT` is a terminal quarantine state. It never triggers automatic retry, token reopening, replacement authorization, success reporting, or assumed rollback.
6. Backup availability does not authorize restoration. An older snapshot can omit a consumed token or request claim and thereby re-enable replay.
7. Ledger, audit, WAL, shared-memory, backup, checksum, and incident evidence are preserved. Do not delete, truncate, edit, merge, or repair them in place.
8. Any unknown or inconsistent state keeps processing disabled.

## Durable states and operator meaning

| State | Meaning | Operator action |
|---|---|---|
| `ISSUED` authorization | Token was registered but not durably consumed. | Do not reuse it after an incident or restart without a separately reviewed lifecycle; current Stage A has no approved resume flow. |
| `CONSUMED` authorization | Token was consumed atomically with attempt reservation. | Never reopen it. |
| `RESERVED` attempt | Execution may be active or may have crossed the effect boundary. | During live processing, stop and establish exclusive ownership. During restart recovery, reconcile to `UNKNOWN_EFFECT`. |
| `COMPLETED` attempt | The synthetic path recorded its expected terminal outcome. | Retain as synthetic evidence only; it is not proof of a real effect. |
| `FAILED_NO_EFFECT` attempt | The tested synthetic broker reported no state change and the terminal record committed. | Do not generalize to an external target. Do not automatically retry. |
| `UNKNOWN_EFFECT` attempt | An effect may have occurred or terminal persistence was not supportable. | Quarantine, preserve, investigate read-only, and escalate. No automatic retry. |

## Required roles and records

Use named people in the exercise or incident record before following this runbook. Role labels below are not assignments.

| Role | Required authority |
|---|---|
| `RELEASE_OWNER` | Approves the exact code/worktree and synthetic exercise boundary. |
| `STAGE_A_OPERATOR` | Holds exclusive control of the one local caller and executes this runbook. |
| `SECURITY_OWNER` | Directs response to integrity, replay, bypass, credential, or insider concerns. |
| `EVIDENCE_CUSTODIAN` | Receives checksums and preserves ledger, audit, and incident evidence outside the active directory. |
| `DATA_OWNER` / `MISSION_OWNER` / `AUTHORIZING_OFFICIAL` | No authority is granted by Stage A; explicit approvals remain prerequisites for any later data access, integration, or operational effect. |

The operator record must contain: date/time in UTC, host identifier, operator, branch, exact commit, worktree status, Python and SQLite versions, ledger and audit paths, `ledger_id`, schema version, pre/post state counts, reconciliation count, audit result, outbox count, commands run, checksums, exceptions, and disposition. Do not place secrets or raw credentials in the record.

## Path and host preparation

Use a dedicated owner-only local directory outside the repository and outside any synchronized folder. Replace the example path with an approved absolute path. Do not use symlinks, hard links, removable media, shared network filesystems, or a path inside a Git worktree.

```sh
export ADF_STAGE_A_ROOT="/absolute/approved/local/path/adf-stage-a"
export ADF_STAGE_A_LEDGER="$ADF_STAGE_A_ROOT/control.sqlite3"
export ADF_STAGE_A_AUDIT="$ADF_STAGE_A_ROOT/phase3_audit.jsonl"
export ADF_STAGE_A_BACKUP_DIR="$ADF_STAGE_A_ROOT/backups"
umask 077
mkdir -p "$ADF_STAGE_A_BACKUP_DIR"
chmod 700 "$ADF_STAGE_A_ROOT" "$ADF_STAGE_A_BACKUP_DIR"
```

Fail the procedure if any variable is empty or non-absolute:

```sh
: "${ADF_STAGE_A_ROOT:?Set the approved absolute Stage A root}"
: "${ADF_STAGE_A_LEDGER:?Set the authoritative ledger path}"
: "${ADF_STAGE_A_AUDIT:?Set the authoritative audit path}"
case "$ADF_STAGE_A_ROOT:$ADF_STAGE_A_LEDGER:$ADF_STAGE_A_AUDIT" in
  /*:/*:/*) ;;
  *) echo "FAIL: all Stage A paths must be absolute" >&2; exit 2 ;;
esac
```

Initial creation is owned by the reviewed library integration. Recovery operators must not instantiate `SQLiteControlLedger` against an absent or empty file: its constructor initializes a new ledger. An unexpectedly missing or empty authoritative ledger is an integrity incident, not a clean start.

## Preflight: keep processing disabled

Run these checks before a synthetic exercise and again before recovery. Any failure is a stop condition.

1. Record exact source and runtime state:

   ```sh
   git rev-parse --verify HEAD
   git status --short --branch
   python3 --version
   sqlite3 --version
   ```

2. For restart or recovery, require an existing nonempty ledger and an existing audit file before constructing either object:

   ```sh
   test -s "$ADF_STAGE_A_LEDGER" || { echo "FAIL: ledger missing or empty" >&2; exit 2; }
   test -f "$ADF_STAGE_A_AUDIT" || { echo "FAIL: audit missing" >&2; exit 2; }
   test ! -L "$ADF_STAGE_A_LEDGER" || { echo "FAIL: ledger is a symlink" >&2; exit 2; }
   test ! -L "$ADF_STAGE_A_AUDIT" || { echo "FAIL: audit is a symlink" >&2; exit 2; }
   stat -f 'path=%N mode=%Sp links=%l owner=%Su group=%Sg size=%z' "$ADF_STAGE_A_LEDGER" "$ADF_STAGE_A_AUDIT"
   ```

   Both files must be singly linked regular files owned by the designated local account. The ledger should be mode `0600`; the containing directory should be `0700`. Stop if ownership, link count, type, or path provenance is unexpected.

   Prove that the ledger and audit do not resolve to the same path or existing inode. The library also enforces this before either sink opens:

   ```sh
   python3 -c 'import os, sys; ledger=os.environ["ADF_STAGE_A_LEDGER"]; audit=os.environ["ADF_STAGE_A_AUDIT"]; alias=os.path.realpath(ledger)==os.path.realpath(audit) or (os.path.exists(ledger) and os.path.exists(audit) and os.path.samefile(ledger, audit)); print(f"ledger_audit_alias={alias}"); raise SystemExit(2 if alias else 0)'
   ```

3. Establish exclusive, quiesced ownership. Stop the recorded Stage A caller through its supervisor or recorded PID. Inspect the database and every extant `-wal` and `-shm` companion with `lsof`. Any open handle is a stop condition. Do not reconcile merely because a second process appears idle.

   ```sh
   for candidate in "$ADF_STAGE_A_LEDGER" "${ADF_STAGE_A_LEDGER}-wal" "${ADF_STAGE_A_LEDGER}-shm"; do
     if test -e "$candidate"; then lsof -- "$candidate"; fi
   done
   ```

4. Validate the SQLite file without enabling a caller:

   ```sh
   sqlite3 -readonly -header -column "$ADF_STAGE_A_LEDGER" \
     "PRAGMA integrity_check; SELECT key,value FROM metadata ORDER BY key; SELECT name FROM sqlite_schema WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name; SELECT state,COUNT(*) AS count FROM authorizations GROUP BY state ORDER BY state; SELECT state,COUNT(*) AS count FROM attempts GROUP BY state ORDER BY state;"
   ```

   Required results are `integrity_check = ok`, `schema_version = 1`, one stable nonempty `ledger_id`, and exactly these application tables: `audit_outbox`, `attempts`, `authorizations`, `metadata`, and `requests`. A mismatch is an incident. Do not run schema migration or repair.

5. Validate the JSONL audit chain. This command is allowed only after the audit existence/type checks above:

   ```sh
   PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src python3 -c 'import os; from adf_poc.audit import AuditLogger; from adf_poc.phase3.audit import validate_phase3_audit_chain; rows=AuditLogger(os.environ["ADF_STAGE_A_AUDIT"]).read_all(); ok, errors=validate_phase3_audit_chain(rows); print(f"rows={len(rows)} valid={ok} errors={errors}"); raise SystemExit(0 if ok else 2)'
   ```

   An empty audit may be valid for a newly initialized, never-used fixture, but an absent or unexpectedly empty audit during recovery is not proof that no activity occurred. Stop and escalate.

## Explicit startup reconciliation

Do not put this call in a general constructor or run it while any caller may still be active. Under documented exclusive, quiesced ownership:

1. Record the pre-reconciliation attempts:

   ```sh
   sqlite3 -readonly -header -column "$ADF_STAGE_A_LEDGER" \
     "SELECT attempt_id,token_id,state,reserved_at,completed_at FROM attempts WHERE state IN ('RESERVED','UNKNOWN_EFFECT') ORDER BY reserved_at,attempt_id;"
   ```

2. Reconcile all remaining `RESERVED` rows in one ledger transaction:

   ```sh
   PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src python3 -c 'import os; from adf_poc.stage_a import SQLiteControlLedger; ledger=SQLiteControlLedger(os.environ["ADF_STAGE_A_LEDGER"]); print(f"recovered_to_UNKNOWN_EFFECT={ledger.recover_incomplete_attempts()}"); print(f"pending_outbox={len(ledger.pending_outbox())}")'
   ```

3. Prove there are no remaining reservations and record every uncertain attempt:

   ```sh
   sqlite3 -readonly -header -column "$ADF_STAGE_A_LEDGER" \
     "SELECT state,COUNT(*) AS count FROM attempts GROUP BY state ORDER BY state; SELECT attempt_id,token_id,binding_sha256,reserved_at,completed_at FROM attempts WHERE state='UNKNOWN_EFFECT' ORDER BY reserved_at,attempt_id; SELECT COUNT(*) AS reserved_must_be_zero FROM attempts WHERE state='RESERVED';"
   ```

4. Re-run integrity and audit-chain validation. Inspect the new `ATTEMPT_RECOVERED_UNKNOWN` outbox rows. If any `RESERVED` row remains, any check fails, or ownership is not still exclusive, keep processing disabled.

Reconciliation is monotonic. It does not prove whether an effect happened, reopen a token, repair the JSONL audit, export the outbox, or authorize a retry. Every listed `UNKNOWN_EFFECT` requires case-specific review; because Stage A has no external target, that review is limited to the synthetic evidence and must not assert a production outcome.

## Permitted exercise and normal shutdown

There is no approved long-running service to start. The only presently supported exercise of the durable path is the repository's focused Stage A test suite:

```sh
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src python3 -m unittest tests.test_stage_a_durable_control_ledger -v
```

The tests create isolated temporary ledgers and synthetic in-memory targets. They do not use the operator paths above and do not validate deployment, backup, restoration, live connectors, real credentials, or real target behavior.

For any later reviewed offline caller, the release owner must verify that it passes the same approved absolute `control_ledger_path` and `audit_path`, retains `execution_mode == "synthetic_simulation"`, and has no network or operational adapter. Normal shutdown means: stop intake, wait only for already executing synthetic calls to return, stop the one caller, confirm no open ledger/WAL/SHM handles, inspect attempt states, and reconcile any remaining `RESERVED` row to `UNKNOWN_EFFECT`. Never wait indefinitely and never restart the call as a shutdown tactic.

## Monitoring and alert conditions

Stage A has no dashboard, alert transport, or outbox exporter. The following are manual observations and required future signals, not implemented production monitoring:

| Observation | Safe expectation | Alert / response |
|---|---|---|
| SQLite `integrity_check` | Exactly `ok`. | Disable and preserve on any other result. |
| Schema and `ledger_id` | Version `1`; stable recorded identity. | Disable on absence or change. |
| `RESERVED` attempts | May exist only during a known active synthetic call; zero after quiescence/reconciliation. | Establish exclusive ownership, then reconcile to `UNKNOWN_EFFECT`. |
| `UNKNOWN_EFFECT` attempts | Zero is preferred; any row is unresolved. | Quarantine the request/target context; no retry; security/release review. |
| Authorization state | Only `ISSUED` or `CONSUMED`; consumed never reopens. | Disable on any impossible state or ledger/audit disagreement. |
| Audit-chain validation | Valid, with expected lifecycle records. | Disable; preserve; never rewrite history. |
| Pending outbox | Count and oldest age must be recorded. | There is no exporter, so rows remain pending; this is an open release blocker, not proof of audit delivery. |
| Disk, inode, and WAL growth | Sufficient owner-defined reserve; no approved threshold exists. | Stop intake before exhaustion; do not delete WAL or ledger files. |
| Duplicate/conflict/lock errors | Individually attributable to the synthetic exercise. | Stop on unexplained increase or repeated contention; investigate request poisoning or a second writer. |

Read-only ledger review:

```sh
sqlite3 -readonly -header -column "$ADF_STAGE_A_LEDGER" \
  "SELECT event_id,event_type,subject_id,payload_sha256,created_at,exported_at FROM audit_outbox WHERE exported_at IS NULL ORDER BY event_id;"
```

The outbox stores event digests, not the complete Phase 3 audit record. It is co-committed with ledger transitions, but there is no implemented acknowledgement or external-custody workflow. Never set `exported_at` manually.

## Emergency disable

Trigger emergency disable for any unauthorized path, unexpected connector or credential, loss of exclusive ownership, ledger/audit integrity failure, ambiguous effect, repeated lock/collision anomaly, key compromise, unexplained code/config drift, or safety-owner direction.

1. Stop intake and stop the sole caller through its recorded supervisor or PID. There is no repository-supplied Stage A daemon or remote kill switch.
2. Confirm no process holds the ledger, WAL, or shared-memory files. If a process will not stop, escalate to the host owner; do not reconcile concurrently.
3. Preserve source state, process/supervisor evidence, ledger, WAL/SHM companions, audit, stdout/stderr, and checksums. Do not run cleanup or rerun the request.
4. Under release/security-owner direction, an optional local defense-in-depth interlock is to remove all permission bits from the ledger and any extant WAL/SHM files **after** the caller is stopped:

   ```sh
   chmod 000 "$ADF_STAGE_A_LEDGER"
   test ! -e "${ADF_STAGE_A_LEDGER}-wal" || chmod 000 "${ADF_STAGE_A_LEDGER}-wal"
   test ! -e "${ADF_STAGE_A_LEDGER}-shm" || chmod 000 "${ADF_STAGE_A_LEDGER}-shm"
   ```

   Record the prior modes. This is not a security boundary against the file owner, an administrator, malware, or a modified process. Do not restore permissions or processing until the incident owner authorizes a reviewed recovery.

5. Classify every possible effect as `UNKNOWN_EFFECT`; use read-only observation only where separately authorized. Stage A's declared boundary makes external effects prohibited, but that prohibition is not evidence of a broader operational kill capability.

## Backup guidance — not implemented or validated

No backup job, retention policy, encryption/key-custody process, restore test, RPO, RTO, or failover mechanism is implemented. The following is conservative design guidance for a future controlled exercise; its existence is not disaster-recovery evidence.

Prerequisites: emergency disable or normal quiescence, exclusive ownership, passing integrity/schema/audit checks, an approved owner-only backup destination on the same synthetic host, and an evidence record. Do not copy a live SQLite database file while ignoring its WAL/SHM state.

For a future exercise, prefer SQLite's backup API after quiescence and a successful full checkpoint. Use controlled paths without newline or quote characters:

```sh
export ADF_STAGE_A_BACKUP="$ADF_STAGE_A_BACKUP_DIR/control-$(date -u +%Y%m%dT%H%M%SZ).sqlite3"
sqlite3 "$ADF_STAGE_A_LEDGER" "PRAGMA wal_checkpoint(FULL);"
sqlite3 "$ADF_STAGE_A_LEDGER" ".backup '$ADF_STAGE_A_BACKUP'"
chmod 600 "$ADF_STAGE_A_BACKUP"
sqlite3 -readonly -header -column "$ADF_STAGE_A_BACKUP" \
  "PRAGMA integrity_check; SELECT key,value FROM metadata ORDER BY key; SELECT state,COUNT(*) FROM attempts GROUP BY state ORDER BY state;"
cp -p "$ADF_STAGE_A_AUDIT" "${ADF_STAGE_A_BACKUP}.phase3_audit.jsonl"
shasum -a 256 "$ADF_STAGE_A_BACKUP" "${ADF_STAGE_A_BACKUP}.phase3_audit.jsonl"
```

The first value returned by `wal_checkpoint(FULL)` must be `0` (not busy). Record the database and audit checksums in an independently retained exercise record. Preserve the authoritative `ledger_id`; separately preserve the exact source commit, configuration/policy digests, and deployment signing-key continuity. Stage A has no managed key backup, so this last property is not satisfied.

Do not treat a raw file copy of an active database, a checksum alone, or a successful `.backup` as a validated recovery point. The database and JSONL audit have no cross-store transaction or shared recovery-point marker, so even a quiesced pair requires lifecycle reconciliation and cannot be claimed crash-consistent without a separate exercise. Do not co-mingle ledgers, reuse one `ledger_id` for independent histories, or delete the source after backup.

## Restore guidance — review-only by default

An older ledger can lack newer request claims, consumed tokens, attempts, and outbox events. Making it authoritative without rollback protection can permit replay. Consequently, Stage A restoration stops at an isolated **review-only candidate** unless a future design supplies fencing/epoch control, authoritative rollback approval, key continuity, and accepted replay analysis.

1. Keep the caller disabled and establish exclusive ownership.
2. Verify the backup and paired audit checksums against the independently retained record.
3. Copy the backup to a new, owner-only candidate path. Never overwrite or rename the current authoritative ledger and never merge rows from two ledgers.
4. Validate the candidate with `PRAGMA integrity_check`, the exact table set, `schema_version = 1`, and the recorded `ledger_id`. Validate the paired JSONL audit independently. A valid database with the wrong identity is not the ledger.
5. Compare counts and latest timestamps for requests, authorizations, attempts, and outbox against the incident record and the preserved authoritative files. Any unexplained regression is a stop condition.
6. Under exclusive ownership, explicitly reconcile candidate `RESERVED` attempts to `UNKNOWN_EFFECT`; then prove the reserved count is zero. Never reissue their commands.
7. Preserve both candidate and original as distinct evidence. Mark the candidate `review-only` in the incident/change record.
8. Do not resume effects from the candidate. Promotion to authoritative service state requires a separately implemented and tested rollback/fencing design, owner approvals, RPO/RTO, and a controlled restore exercise in the intended environment.

There is no supported multi-host restore, replication, hot standby, or failover. Copying a ledger to a second active host creates split-brain risk and is prohibited.

## Failure handling and escalation

| Symptom | Immediate disposition | Next action |
|---|---|---|
| Ledger missing, empty, unsafe link, wrong owner/mode, wrong schema, or corrupt | Keep caller disabled; do not initialize or repair. | Preserve filesystem evidence and escalate to `SECURITY_OWNER` and `RELEASE_OWNER`. |
| Audit missing, invalid, truncated, replaced, or inconsistent with ledger | Keep caller disabled; audit closure is unsupported. | Preserve both stores and checksums; external evidence review is required. |
| Database locked or second process detected | Deny/stop; do not increase timeout as a workaround. | Identify and stop the unapproved writer; re-establish quiescence. |
| Reconciliation raises or leaves `RESERVED` | Treat all affected attempts as unresolved without editing rows manually. | Preserve and escalate; no restart. |
| `UNKNOWN_EFFECT` exists | Quarantine; no auto retry or replacement token. | Review synthetic state and lifecycle evidence; record unresolved disposition. |
| `FAILED_NO_EFFECT` exists after broker rejection | Preserve terminal evidence; no auto retry. | New work, if justified, requires a new request and authorization lifecycle. |
| Outbox backlog grows | Do not mark rows exported. | Record backlog; exporter/external custody remain unimplemented release blockers. |
| Disk/WAL growth or I/O error | Stop intake before capacity loss; do not remove ledger/WAL. | Quiesce, preserve, check host storage, then rerun integrity and reconciliation. |
| Unexpected network, credential, adapter, or non-synthetic target | Emergency-disable immediately. | Treat as scope breach and security incident; this runbook does not authorize investigation against that target. |

Escalation order is `STAGE_A_OPERATOR` to `RELEASE_OWNER` and `SECURITY_OWNER`, with `EVIDENCE_CUSTODIAN` preserving artifacts. Any request to use historical data, enterprise identity, external storage, a test tenant, a real adapter, or an operational target stops here and requires the exact approval specified by the production-completion program.

## Verification and runbook exercise record

Before calling a Stage A increment complete, run the focused suite and the complete repository suite from the isolated worktree:

```sh
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src python3 -m unittest tests.test_stage_a_durable_control_ledger -v
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src python3 -m unittest discover -s tests -v
```

An exercised runbook requires a disposable synthetic ledger—not the authoritative candidate—and recorded proof of: safe-path rejection; schema/integrity rejection; one winner under request and authorization races; restart replay denial; durable attempt/outbox reopen; `FAILED_NO_EFFECT`; post-effect terminal-write failure; explicit `RESERVED` to `UNKNOWN_EFFECT` recovery; zero remaining reservations; audit validation; backup-candidate integrity; and restore-candidate review-only disposition.

The current focused tests exercise the ledger behaviors but do **not** exercise the shell procedures, backup, restore, external custody, operator roles, process supervisor, crash-at-every-fsync boundary, storage loss, or deployment environment. Until those are executed and version-bound, record this runbook as `DOCUMENTED / NOT OPERATIONALLY VALIDATED`.

## Evidence limits and prohibited inferences

The Stage A ledger provides development-grade local durability, uniqueness, and transaction boundaries for a synthetic path. It does not establish distributed idempotency, consensus, split-brain prevention, high availability, nonrepudiation, independent audit custody, trusted time, managed secrets, a safe rollback, a recoverable production deployment, or operational effectiveness.

No result from this runbook authorizes Stage B or Stage C, model promotion, historical-data access, external communication, deployment, or an operational effect. Those remain separate owner and authorizing-official decisions.

## Revision history

| Date | Change | Evidence state |
|---|---|---|
| 2026-08-15 | Initial Stage A durable-ledger inspection, reconciliation, emergency-disable, and preservation guidance. | Documented against the unfrozen local Stage A candidate; not operationally validated. |
