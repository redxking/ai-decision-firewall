# Stage A Durable Ledger, Adapter Receipt, and Result Runbook

**Runbook state:** bounded development procedure; not operationally accepted
**Scope:** one host; one schema-v2 control SQLite database; one schema-v1 offline synthetic-adapter SQLite database; one JSONL lifecycle audit
**Baseline:** `bb6b8f28afba0961bb97b24e6050fccaa94d5702`; Stage A implementation Commit `8818d5d2d40faebced66a254d58b1f0d04c9f8b4` on `main`
**Production authority:** none

## Purpose and hard boundary

This runbook describes fail-closed inspection, preservation, exact-duplicate lookup, and explicit request reconciliation for the opt-in Stage A durability path. It is not a deployment or production operating procedure.

Stage A has no production or test-tenant connector, operational credential, vendor adapter, network target, service supervisor, queue, outbox exporter, external audit custodian, independent target observer, high-availability topology, approved backup/restore service, or disaster-recovery system. It must not receive historical organizational data or connect to any enterprise or operational system.

The durable adapter is `SQLiteSyntheticAdapterStore`: a repository-controlled, same-process, offline synthetic component. Its `SyntheticAdapterReceipt` is adapter-reported only. The separate observer reads the same durable adapter state under the same project custody and is not independent verification. A `RequestLookupResult` is a closed, sanitized replay envelope, not a serialized `Phase3Result` and not authority to execute.

The repository demonstration does not constitute a supported Stage A service launcher. The opt-in path is available only through the reviewed library integration configured with pairwise-distinct `control_ledger_path`, `synthetic_adapter_path`, and `audit_path`. Do not create an ad hoc launcher or connect it to a network, credential, connector, or external target.

## Transaction and recovery boundaries

The lifecycle is deliberately split:

1. **T1 — control reservation:** validate authority and atomically consume the token, reserve the exact-bound attempt, advance request state, and write a metadata-only control outbox event.
2. **T2 — adapter transaction:** validate the stable canonical binding and trusted prestate, apply the offline synthetic transition, update durable synthetic state, and insert one immutable `SyntheticAdapterReceipt` in the same adapter-database transaction.
3. **Observation:** read adapter state through the separate read-only observer. This is distinct from acknowledgement but not independently custodied.
4. **T3 — control terminal:** after verification, atomically advance attempt/request state, insert one closed sanitized `RequestLookupResult`, and write a metadata-only control outbox event.
5. **JSONL lifecycle audit:** remains a separate artifact and transaction boundary.

No control transaction remains open across T2 or observation. T1, T2, JSONL audit, observation, and T3 do not form a cross-store transaction. Cross-store divergence is an explicit recovery condition, not an error to conceal.

Supported processes take a bounded exclusive POSIX `flock` on each stable
durable-path root, in deterministic order, before combined startup and before
every durable firewall operation. The public control- and adapter-store
constructors use the same bounded first-open mechanism when invoked directly.
No lock-file artifact is created. A complete JSONL lifecycle additionally owns
an exclusive audit-file `flock`. These are cooperative, one-host controls: they
do not fence a noncooperating same-user process, another host, or modified code.

## Safety invariants

1. Only `execution_mode=synthetic_simulation` and the offline repository-controlled synthetic target are permitted.
2. No processing begins until both databases, the audit, exact code/configuration, path/sidecar separation, safe ownership, semantic/chronological validation, and cross-store correlation pass preflight under cooperative startup ownership.
3. Reconciliation is never run automatically in a constructor. Use `reconcile_request(operator_asserted_quiesced=True)` only after independently establishing exclusive, quiesced ownership.
4. Reconciliation never invokes an adapter command, creates a decision, mints a token, reopens authority, fabricates verification, or claims rollback.
5. An exact affirmative `NO_EFFECT` receipt may close `FAILED_NO_EFFECT`. `APPLIED`, `PARTIAL`, or `AMBIGUOUS` without separately durable verification closes `UNKNOWN_EFFECT`. No receipt also closes `UNKNOWN_EFFECT`. Corrupt, mismatched, or unavailable adapter evidence halts with no state transition.
6. `UNKNOWN_EFFECT` is terminal. It never triggers automatic retry, replacement authorization, success reporting, or assumed rollback.
7. Exact repeated receipt/result writes are idempotent; changed binding or payload under the same key is a hard conflict and cannot overwrite history.
8. `lookup_request_result` is authenticated and read-only. It requires exact principal, request ID, and canonical request digest and performs no new work. `process_json` remains fail closed for duplicates and returns only `Phase3Result`.
9. Backup availability does not authorize restoration. Older or mismatched snapshots can omit consumed authority or committed target state and re-enable unsafe replay.
10. Preserve the control DB, adapter DB, audit, WAL/SHM companions, backups, checksums, and incident evidence. Do not delete, truncate, merge, edit, or repair them in place.
11. Existing artifacts are preflighted read-only before any missing artifact is created. A zero-byte, unsafe, unsupported, corrupt, or semantically impossible existing store is preserved and refused.
12. The control store, adapter store, and audit are correlated at startup and before durable use. An orphan/missing receipt, overlapping provenance substitution, receipt/disposition mismatch, or terminal target-state mismatch fails closed; correlation does not make the artifacts atomic.
13. Recovery audit is exactly `RECOVERY_STARTED`, `RECOVERY_EVIDENCE_ASSESSED`, `RECOVERY_FINALIZED` before T3. A pending exact prefix or completed trio fences other request/approval audit writers with `RECOVERY_AUDIT_PENDING`; only exact recovery may resume it.
14. Any unknown, inconsistent, or unverified state keeps processing disabled.

## Durable objects and operator meaning

| Object / state | Meaning | Operator action |
|---|---|---|
| `ISSUED` authorization | Registered but not consumed. | Do not reuse after an incident/restart without a separately reviewed lifecycle. Explicit quiesced recovery may revoke it. |
| `CONSUMED` authorization | Consumed atomically with attempt reservation. | Never reopen it. |
| `REVOKED` authorization | Permanently nonexecuting. | Preserve; never restore to `ISSUED`. |
| `RESERVED` attempt | T2 may be active or may have committed. | Stop, prove quiescence, inspect exact receipt, and use the closed recovery table. Never rerun the command. |
| `RECEIPT_RECORDED` attempt | Exact receipt reference exists, but verification-scoped terminal closure is incomplete. | Treat as nonterminal; never infer success or replay the command. Reconcile only under proven quiescence. |
| `SyntheticAdapterReceipt` | Immutable adapter-reported record bound to the exact request/decision/token/command/policy/context/prestate/adapter contract. | Validate canonical binding, digest, version, disposition, and state-before/after digests. Do not treat it as independent verification. |
| `VERIFIED_EFFECT` | Repository-controlled observation supported the expected synthetic state. | Retain as bounded same-store synthetic evidence only; it is not an operational-effect claim. |
| `FAILED_NO_EFFECT` | Exact affirmative synthetic no-effect was supportable. | Preserve; no automatic retry. |
| `RECOVERY_REQUIRED` | The terminal synthetic disposition requires separately authorized handling. | Preserve and escalate; do not claim rollback or issue compensation. |
| `UNKNOWN_EFFECT` | Effect may have occurred or terminal proof is unavailable. | Quarantine, preserve, investigate read-only, and escalate. No automatic retry. |
| `RequestLookupResult` | Closed versioned terminal projection with bounded IDs/digests/timestamps, original decision/verification summary, disposition, and replay flags. | Return only through exact authenticated lookup. Never use it as executable authority or claim it is full verification. |
| recovery JSONL prefix/trio | Exact contiguous recovery lifecycle bound to the recovery/request/result and the observed original audit status. | Preserve byte-for-byte. If T3 is pending, keep other audit writers fenced and rerun only the exact recovery. Never append around it or treat it as cross-store commit proof. |

## Required roles and records

Role labels are not assignments. Name each person in the exercise or incident record before using this procedure.

| Role | Required authority |
|---|---|
| `RELEASE_OWNER` | Approves exact code/worktree and the offline synthetic exercise boundary. |
| `STAGE_A_OPERATOR` | Controls the sole local caller and executes inspection/reconciliation. |
| `SECURITY_OWNER` | Directs integrity, replay, bypass, credential, insider, or cross-store-divergence response. |
| `EVIDENCE_CUSTODIAN` | Preserves checksums and copies of both databases, audit, and incident evidence outside the active directory. |
| mission/data/target/authorizing owners | No authority is granted here; their explicit approvals remain prerequisites for later data, integration, or effect. |

Record UTC date/time, host, operator, branch, exact commit, worktree state, Python/SQLite versions, three authoritative paths, database identities and schema versions, pre/post state counts, exact request key, receipt/result digests and dispositions, reconciliation result, audit validation, outbox count, commands, checksums, exceptions, and final disposition. Do not record raw credentials, tokens, nonces, signatures, keys, or bearer material.

## Path and host preparation

Use a dedicated owner-only local directory outside the repository and synchronized folders. Do not use symlinks, hard links, removable media, shared/network filesystems, or a Git worktree path.

```sh
export ADF_STAGE_A_ROOT="/absolute/approved/local/path/adf-stage-a"
export ADF_STAGE_A_CONTROL="$ADF_STAGE_A_ROOT/control-v2.sqlite3"
export ADF_STAGE_A_ADAPTER="$ADF_STAGE_A_ROOT/synthetic-adapter-v1.sqlite3"
export ADF_STAGE_A_AUDIT="$ADF_STAGE_A_ROOT/phase3-audit.jsonl"
export ADF_STAGE_A_BACKUP_DIR="$ADF_STAGE_A_ROOT/backups"
umask 077
mkdir -p "$ADF_STAGE_A_BACKUP_DIR"
chmod 700 "$ADF_STAGE_A_ROOT" "$ADF_STAGE_A_BACKUP_DIR"
```

Fail if any value is empty/nonabsolute, any two resolved paths or existing
inodes alias, or a main path enters another SQLite path's reserved `-wal` or
`-shm` namespace:

```sh
: "${ADF_STAGE_A_ROOT:?Set the approved absolute Stage A root}"
: "${ADF_STAGE_A_CONTROL:?Set the schema-v2 control path}"
: "${ADF_STAGE_A_ADAPTER:?Set the schema-v1 adapter path}"
: "${ADF_STAGE_A_AUDIT:?Set the JSONL audit path}"
case "$ADF_STAGE_A_CONTROL:$ADF_STAGE_A_ADAPTER:$ADF_STAGE_A_AUDIT" in
  /*:/*:/*) ;;
  *) echo "FAIL: all three paths must be absolute" >&2; exit 2 ;;
esac
python3 -c 'import os; p=[os.environ["ADF_STAGE_A_CONTROL"],os.environ["ADF_STAGE_A_ADAPTER"],os.environ["ADF_STAGE_A_AUDIT"]]; r=[os.path.realpath(x) for x in p]; bad=len(set(r))!=3 or any(os.path.exists(p[i]) and os.path.exists(p[j]) and os.path.samefile(p[i],p[j]) for i in range(3) for j in range(i+1,3)); print(f"pairwise_distinct={not bad}"); raise SystemExit(2 if bad else 0)'
```

The reviewed integration enforces the stronger path/sidecar-namespace checks
before opening any sink. Recovery operators must not instantiate a store
against an unexpectedly missing or empty authoritative path: constructors can
initialize new development stores. Missing authoritative state is an integrity
incident, not a clean start.

## Schema-v1 control preservation and new-v2 procedure

The control schema is version 2. The adapter schema is version 1. The v2 control constructor refuses and preserves a schema-v1 control database; there is no migrator.

If a v1 control file exists:

1. Keep processing disabled and establish exclusive ownership.
2. Preserve the v1 database and every extant `-wal`/`-shm` companion, paired audit, exact source/configuration identity, metadata, and checksums as evidence.
3. Do not open it with write tools, alter its schema marker, copy rows, run SQL migration, reuse its `ledger_id`, or replace it in place.
4. Select a new, empty, reviewed absolute path for a v2 control database and a distinct new adapter-v1 path. Re-run all safety and alias checks.
5. Allow only the reviewed library integration to initialize the new empty stores. Initialization creates a new lifecycle; it does not continue, migrate, or prove closure of v1 work.
6. Keep v1 artifacts retained and separately labeled. Any unresolved v1 reservation remains governed by the earlier runbook/evidence and cannot be translated into v2 authority.

A future v1-to-v2 migrator would require a separate architecture decision, explicit quiescence, transactional copy/verification, rollback protection, compatibility tests, owner approval, and exact-commit evidence. None exists now.

## Preflight: keep processing disabled

Run the full procedure before a synthetic exercise and before operator recovery. A normal authenticated `lookup_request_result` call is read-only and does not itself require quiescence; do not run this filesystem/operator procedure concurrently with the caller. If lookup reports missing, corrupt, mismatched, or unavailable state, disable intake, establish quiescence, and then run this preflight. Any failure is a stop condition.

1. Record source/runtime state:

   ```sh
   git rev-parse --verify HEAD
   git status --short --branch
   python3 --version
   sqlite3 --version
   ```

2. For restart/recovery, require all three authoritative artifacts and reject links or empty databases:

   ```sh
   test -s "$ADF_STAGE_A_CONTROL" || { echo "FAIL: control DB missing or empty" >&2; exit 2; }
   test -s "$ADF_STAGE_A_ADAPTER" || { echo "FAIL: adapter DB missing or empty" >&2; exit 2; }
   test -f "$ADF_STAGE_A_AUDIT" || { echo "FAIL: audit missing" >&2; exit 2; }
   test ! -L "$ADF_STAGE_A_CONTROL" || { echo "FAIL: control DB is a symlink" >&2; exit 2; }
   test ! -L "$ADF_STAGE_A_ADAPTER" || { echo "FAIL: adapter DB is a symlink" >&2; exit 2; }
   test ! -L "$ADF_STAGE_A_AUDIT" || { echo "FAIL: audit is a symlink" >&2; exit 2; }
   stat -f 'path=%N mode=%Sp links=%l owner=%Su group=%Sg size=%z' "$ADF_STAGE_A_CONTROL" "$ADF_STAGE_A_ADAPTER" "$ADF_STAGE_A_AUDIT"
   ```

   Each file must be a singly linked regular file owned by the designated local
   account. Database files and every extant `-wal`/`-shm` sidecar must be
   owner-private (`0600` or stricter); the directory should be `0700`. No
   ancestor or sidecar may be a symbolic link. Re-run the pairwise alias and
   sidecar-namespace checks above.

3. Establish exclusive, quiesced ownership. Stop the recorded caller and inspect both databases and all WAL/SHM companions. Any open handle is a stop condition:

   ```sh
   for candidate in "$ADF_STAGE_A_CONTROL" "${ADF_STAGE_A_CONTROL}-wal" "${ADF_STAGE_A_CONTROL}-shm" "$ADF_STAGE_A_ADAPTER" "${ADF_STAGE_A_ADAPTER}-wal" "${ADF_STAGE_A_ADAPTER}-shm"; do
     if test -e "$candidate"; then lsof -- "$candidate"; fi
   done
   ```

4. Validate each SQLite artifact read-only:

   ```sh
   sqlite3 -readonly -header -column "$ADF_STAGE_A_CONTROL" "PRAGMA integrity_check; SELECT key,value FROM metadata ORDER BY key; SELECT name FROM sqlite_schema WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name;"
   sqlite3 -readonly -header -column "$ADF_STAGE_A_ADAPTER" "PRAGMA integrity_check; SELECT key,value FROM metadata ORDER BY key; SELECT name FROM sqlite_schema WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name;"
   ```

   Require exactly `integrity_check = ok`, control `schema_version = 2`, adapter `schema_version = 1`, a stable nonempty control `ledger_id`, a stable nonempty adapter `adapter_store_id`, and these application-table sets:

   - control: `metadata`, `requests`, `request_results`, `authorizations`, `attempts`, and `audit_outbox`;
   - adapter: `metadata`, `target_states`, and `command_receipts`.

   Any unsupported schema, identity change, extra/missing table, or integrity error is an incident. Do not run migration or repair.

   These shell checks are triage only. The reviewed implementation additionally
   verifies code-owned schema fingerprints, immutable metadata, canonical JSON
   digests and shapes, row cardinalities, legal request/authorization/attempt/
   result relations, terminal-result provenance, and monotonic timestamps. The
   adapter must prove a continuous per-target receipt state/time chain from its
   initialized state to the current target row. A foreign-key-clean database can
   still fail these semantic checks.

5. Validate the JSONL chain only after path/type checks:

   ```sh
   PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src python3 -c 'import os; from adf_poc.audit import AuditLogger; from adf_poc.phase3.audit import validate_phase3_audit_chain; rows=AuditLogger(os.environ["ADF_STAGE_A_AUDIT"]).read_all(); ok, errors=validate_phase3_audit_chain(rows); print(f"rows={len(rows)} valid={ok} errors={errors}"); raise SystemExit(0 if ok else 2)'
   ```

6. Under disabled intake, allow the reviewed combined constructor to perform
   its bounded cooperative preflight/open. It preflights every existing store
   before creating a missing one, uses one firewall-clock sample if both stores
   are new, revalidates after open, and correlates the control and adapter
   projections. Require refusal on any orphan adapter receipt, missing required
   receipt, overlapping provenance substitution, receipt digest/disposition
   mismatch, or terminal target-state mismatch. `DURABLE_STARTUP_BUSY` means
   cooperative ownership was not obtained within the configured bound; do not
   increase the timeout as an incident workaround.

An unexpectedly empty audit or missing receipt/result is not proof that no
activity occurred. Stop and escalate. Successful correlation is only a defined
consistency check; it is not a shared recovery point or independent custody.

## Exact-duplicate result lookup after response loss

Use the library's `lookup_request_result` only after authenticating the same principal and recomputing the exact canonical request digest from the original request. It is a read-only seam separate from `process_json`.

The lookup runs under cooperative durable/audit ownership. When it finds a
terminal result, it performs full store validation and runtime cross-store
correlation before returning that result. A recovery prefix/trio does not let
lookup invent a result: before T3 it returns no stored projection; after exact
T3 it may return the correlated terminal projection. Lookup never appends to or
repairs the recovery tail.

Expected exact-duplicate projection flags are:

- `replayed=true`;
- `execution_attempted_this_call=false`;
- `new_decision=false`;
- `new_authorization=false`; and
- `new_effect=false`.

The returned `RequestLookupResult` must retain its original bounded disposition, digests, timestamps, and decision/verification summaries. It must recursively exclude authorization, token, nonce, signature, credential, signing/key material, raw audit rows, executable commands, and bearer authority.

If principal, request ID, or canonical request digest differs, fail closed without disclosing whether or what the prior result was. If the stored projection/version/digest is missing, malformed, or conflicting, stop; do not call `process_json`, recreate the decision, mint authority, execute the adapter, or synthesize a response.

## Explicit startup/request reconciliation

Do not reconcile from a general constructor, while intake is enabled, or while any caller may still be active. `operator_asserted_quiesced=True` is an administrative interlock, not proof of a lease, epoch, fence, or absent second host.

For each request requiring recovery:

1. Preserve pre-reconciliation control request/authorization/attempt/result rows, adapter state/receipt rows, audit status, outbox state, and checksums using read-only inspection.
2. Validate exact principal/request digest, attempt binding, adapter identity/version/digest, receipt contract/digest, and state-before/after digests.
3. Inspect the audit tail. If it contains a recovery record, require the exact
   contiguous prefix `RECOVERY_STARTED`, `RECOVERY_EVIDENCE_ASSESSED`,
   `RECOVERY_FINALIZED` for one recovery ID and exact principal/request/digest.
   Any malformed, interleaved, excess, or differently bound tail is a hard
   conflict. Do not append around it.
4. Invoke only `reconcile_request(operator_asserted_quiesced=True)` through the reviewed library integration for the exact request.
5. Apply and verify the closed outcome:

   | Recovered condition | Required control result |
   |---|---|
   | exact affirmative `NO_EFFECT` receipt | Close `FAILED_NO_EFFECT`; write a recovered sanitized `RequestLookupResult`; do not issue a command. |
   | `APPLIED`, `PARTIAL`, or `AMBIGUOUS` without separately durable verification | Close `UNKNOWN_EFFECT` with recovery-required sanitized result; do not issue a command. |
   | no receipt | Close `UNKNOWN_EFFECT`; absence does not prove no effect or permit retry. |
   | receipt or adapter store corrupt, mismatched, or unavailable | Halt with no control-state transition; processing remains disabled. |
   | existing `UNKNOWN_EFFECT` | Remain terminal and unchanged. |

6. Confirm the recovery audit records the observed original execution-audit
   state exactly as `COMPLETE`, `INCOMPLETE`, or `UNRESOLVED`, then closes the
   exact trio before T3. If the process stops after any prefix, rerun only this
   exact recovery. If the trio is complete but T3 is absent, request and
   approval writers must remain fenced with `RECOVERY_AUDIT_PENDING`; exact
   recovery commits T3 without changing the trio.
7. Re-run both integrity/schema checks, semantic/chronology scans, cross-store
   correlation, and audit validation. Confirm no illegal state transition,
   reopened authorization, new adapter receipt, or new command/effect. Inspect
   metadata-only recovery/result outbox entries without marking them exported.
8. An exact repeat must return the same result without mutation. Any changed binding/payload conflict, remaining unexplained `RESERVED` state, integrity failure, or loss of quiescence keeps processing disabled.

Reconciliation may create a distinct recovered projection from an exact receipt. It must not claim full original verification. In particular, an `APPLIED` receipt alone cannot produce a verified-success result.

## Permitted exercise and normal shutdown

There is no approved long-running service to start. The only supported exercise
is the repository-controlled focused Stage A harness using isolated temporary
control and adapter databases plus synthetic fixtures. Against exact
implementation Commit `8818d5d2`, that focused receipt/recovery and
durable-ledger suite passed 43/43 in 8.248 seconds; the readiness-gate suite
passed 18/18; the warning-fatal full suite passed 360/360 in 48.995 seconds; the
focused Phase 3 suite passed 57/57; and the corpus passed 46/46 with
`live_actions_possible=false`. The 307-entry manifest verified 307/307, and
exact-SHA CI run 31953570779 plus Dependency Graph run 31953572482 succeeded.
This is exact-commit project-controlled implementation evidence, not an
operational runbook exercise, independent verification, owner acceptance, or
production authorization. See
[`ADF-STAGE-A-ER-002`](../production/STAGE_A_RECEIPT_RESULT_EVIDENCE_RECORD.md).

For any later reviewed offline callers, verify the exact approved
`control_ledger_path`, `synthetic_adapter_path`, and `audit_path`, retain
`synthetic_simulation`, and prove no network or operational adapter exists.
Cooperating processes serialize locally; they do not form an HA service.
Normal shutdown means: stop intake; allow only known active synthetic calls a
bounded completion interval; stop every recorded caller; prove no open handles;
inspect both stores and audit; and reconcile any incomplete exact request under
exclusive ownership. Never restart a call as a shutdown tactic.

## Monitoring and alert conditions

Stage A has no dashboard, alert transport, or outbox exporter. These are manual observations and future signal requirements, not implemented production monitoring:

| Observation | Safe expectation | Alert / response |
|---|---|---|
| Control/adapter integrity | Both exactly `ok`; expected identities and schema versions 2/1. | Disable and preserve on any mismatch. |
| Path separation | Three pairwise-distinct safe artifacts. | Disable before opening any store. |
| `RESERVED` attempts | Only during a known active synthetic call; none unexplained after reconciliation. | Prove quiescence; apply exact request recovery. |
| Receipt/result consistency | Exact versions, bindings, digests, legal transitions, and immutable repeats. | Disable on orphan, mismatch, corruption, or overwrite attempt. |
| Store correlation | Control and adapter projections agree on exact provenance, receipt, terminal disposition, and terminal target digest. | Disable on `DURABLE_STORE_CORRELATION_INVALID`; preserve all artifacts; never repair one store to match the other. |
| Receipt disposition | `NO_EFFECT`, `APPLIED`, `PARTIAL`, or `AMBIGUOUS` only. | Never infer verification; apply closed recovery table. |
| `UNKNOWN_EFFECT` | Any row is unresolved and terminal. | Quarantine; no retry; security/release review. |
| Authorization state | Legal monotonic `ISSUED`, `CONSUMED`, or `REVOKED` only. | Disable on impossible/reopened state. |
| Lookup behavior | Exact authenticated lookup only; `replayed=true` and all four activity flags are `false`. | Disable on disclosure, mutation, or new lifecycle work. |
| Audit/outbox | Valid chain; explainable metadata-only events; backlog recorded. | Preserve on loss/gap; never claim export/custody. |
| Recovery tail | No unexplained prefix/trio; if T3 is pending, only the exact recovery may write. | Keep request/approval writers fenced; preserve the tail; rerun exact recovery or escalate on conflict. |
| Disk/inode/WAL/result growth | Within an owner-defined reserve; no approved threshold exists. | Stop before exhaustion; never delete authoritative rows/files ad hoc. |
| Lock/conflict/divergence | Individually attributable to the exercise. | Stop on unexplained contention, conflict, orphan, or second writer. |

## Emergency disable

Trigger disable for an unauthorized path, connector, credential, network route, or target; loss of exclusive ownership; either database or audit failing integrity; receipt/result mismatch; ambiguous possible effect; repeated collision/lock anomaly; key compromise; code/config drift; or owner direction.

1. Stop intake and every recorded caller through its recorded supervisor/PID. There is no repository-supplied daemon or remote kill switch.
2. Confirm no process holds either database or any WAL/SHM file. If a process will not stop, escalate to the host owner; do not reconcile concurrently.
3. Preserve exact source/configuration, process evidence, both databases and companions, audit, logs, and checksums. Do not clean, repair, rerun, or overwrite.
4. Under release/security-owner direction, after the caller stops, permissions may be removed from both database families as a local defense-in-depth interlock. Record prior modes. This is not protection against the file owner, administrator, malware, or modified code.
5. Classify each possible effect conservatively. Use only separately authorized read-only observation; do not infer an operational kill capability from this synthetic procedure.

## Backup guidance — not implemented or validated

No backup job, retention/encryption/key-custody process, coherent three-artifact recovery marker, restore test, RPO, RTO, or failover exists. The following is design guidance for a future controlled synthetic exercise, not DR evidence.

Prerequisites are disable/quiescence, exclusive ownership, passing checks for both databases and audit, an approved owner-only destination, and an evidence record. Do not raw-copy a live SQLite file while ignoring WAL/SHM.

For each database, use SQLite's backup API only after a successful full checkpoint, then separately preserve the audit:

```sh
export ADF_STAGE_A_CONTROL_BACKUP="$ADF_STAGE_A_BACKUP_DIR/control-v2-review.sqlite3"
export ADF_STAGE_A_ADAPTER_BACKUP="$ADF_STAGE_A_BACKUP_DIR/adapter-v1-review.sqlite3"
sqlite3 "$ADF_STAGE_A_CONTROL" "PRAGMA wal_checkpoint(FULL);"
sqlite3 "$ADF_STAGE_A_ADAPTER" "PRAGMA wal_checkpoint(FULL);"
sqlite3 "$ADF_STAGE_A_CONTROL" ".backup '$ADF_STAGE_A_CONTROL_BACKUP'"
sqlite3 "$ADF_STAGE_A_ADAPTER" ".backup '$ADF_STAGE_A_ADAPTER_BACKUP'"
chmod 600 "$ADF_STAGE_A_CONTROL_BACKUP" "$ADF_STAGE_A_ADAPTER_BACKUP"
cp -p "$ADF_STAGE_A_AUDIT" "$ADF_STAGE_A_BACKUP_DIR/phase3-audit-review.jsonl"
shasum -a 256 "$ADF_STAGE_A_CONTROL_BACKUP" "$ADF_STAGE_A_ADAPTER_BACKUP" "$ADF_STAGE_A_BACKUP_DIR/phase3-audit-review.jsonl"
```

Each checkpoint's first returned value must be `0` (not busy). Validate both backups read-only, preserve store identities and exact source/configuration/key continuity, and record lifecycle timestamps/counts and checksums independently. The backups are not one atomic recovery point. Even a quiesced set requires divergence review and cannot be called crash-consistent without a validated protocol.

Never merge independent stores, reuse a store identity for a new lifecycle, delete the sources, or claim an older snapshot is authoritative.

## Restore guidance — review-only

An older control snapshot may omit a consumed token/result; an older adapter snapshot may omit a target change/receipt; a mismatched audit may omit lifecycle evidence. Any combination can re-enable replay or conceal uncertainty.

1. Keep the caller disabled and prove exclusive ownership.
2. Verify checksums against an independently retained record.
3. Copy each artifact to a new owner-only candidate path; never overwrite/rename the current authoritative files or merge rows.
4. Validate both SQLite candidates, identities, schema versions 2/1, table sets, and the paired audit.
5. Compare request/authorization/attempt/result, target/receipt, and audit/outbox chronology. Any regression, orphan, or mismatch stops the procedure.
6. Reconcile exact requests only under quiesced review and the closed table. Never reissue a command.
7. Preserve original and candidate sets as distinct evidence and label the candidate `review-only`.
8. Do not resume effects. Promotion requires a separately implemented rollback/fencing design, coherent backup protocol, RPO/RTO, controlled restore exercise, and owner acceptance.

There is no supported multi-host restore, replication, standby, or failover. Copying either database to another active host creates split-brain risk and is prohibited.

## Failure handling and escalation

| Symptom | Immediate disposition | Next action |
|---|---|---|
| Missing/empty/unsafe/aliased file; wrong ownership/mode/schema/identity; corrupt database | Keep disabled; do not initialize, migrate, or repair the purported authoritative store. | Preserve evidence and escalate to security/release owners. |
| Schema-v1 control DB | Refuse and preserve; no migrator exists. | Create a distinct empty reviewed v2 lifecycle only under the procedure above. |
| Audit missing/invalid or inconsistent | Keep disabled; audit closure unsupported. | Preserve all artifacts; external evidence review required. |
| `DURABLE_STARTUP_BUSY` or unexplained local lock owner | Fail closed; no startup/effect. | Identify every cooperating and noncooperating holder; do not lengthen timeouts as a workaround. |
| `DURABLE_STORE_CORRELATION_INVALID` | Keep disabled; the stores tell incompatible histories. | Preserve both databases, sidecars, audit, and source; do not copy, delete, or edit rows to force agreement. |
| Recovery prefix/trio exists before T3 | Other request and approval audit writes remain fenced. | Resume only the exact quiesced recovery; require byte-stable trio and correlated T3 result. |
| Adapter receipt missing | Not proof of no effect. | Under exact quiesced reconciliation, close `UNKNOWN_EFFECT`; no retry. |
| Exact valid `NO_EFFECT` receipt | May support `FAILED_NO_EFFECT`. | Reconcile without command; store recovered sanitized result. |
| `APPLIED`/`PARTIAL`/`AMBIGUOUS` without separately durable verification | `UNKNOWN_EFFECT` and recovery required. | Reconcile without command; quarantine. |
| Receipt/store corrupt, mismatched, or unavailable | Halt with no state transition. | Preserve and escalate; do not guess or repair. |
| Result missing with exact valid receipt | Recovery may write only the closed recovered projection allowed by the table. | Never fabricate original/full verification. |
| Result or lookup conflict/disclosure anomaly | Keep disabled. | Preserve exact request/binding evidence; security review. |
| Database locked or second process | Deny/stop; do not increase timeout as workaround. | Identify writer; re-establish quiescence. |
| Outbox backlog | Never mark exported manually. | Record backlog; exporter/external custody remain blockers. |
| Disk/WAL/result growth or I/O error | Stop before capacity loss; never delete authoritative files/rows. | Quiesce, preserve, inspect storage, revalidate, reconcile. |
| Unexpected connector/credential/network/target | Emergency-disable. | Treat as scope breach/security incident; this runbook grants no investigative authority against that target. |

Escalation is `STAGE_A_OPERATOR` to `RELEASE_OWNER` and `SECURITY_OWNER`, with `EVIDENCE_CUSTODIAN` preserving artifacts. Historical data, enterprise identity, external storage, a test tenant, real adapter, or designated target requires a separate exact authorization package.

## Verification and runbook exercise record

The successor implementation was frozen and published on `main` at exact Commit
`8818d5d2d40faebced66a254d58b1f0d04c9f8b4`. Its exact local runtimes, tests,
results, limitations, 307/307 manifest state, successful Python 3.11/3.12 CI,
and successful Dependency Graph run are recorded in
[`ADF-STAGE-A-ER-002`](../production/STAGE_A_RECEIPT_RESULT_EVIDENCE_RECORD.md).
No tag or GitHub Release was created, no deployment occurred, and no exact-SHA
Pages run was observed; the runbook remains operationally unexercised. Any later
implementation claim
requires its own exact commit, manifest, verification, and automation record.

The current focused suite names the following implemented controls directly:

- public-store first-open and independent-process execution:
  `test_direct_store_first_creation_is_process_serialized` and
  `test_independent_processes_create_one_effect_receipt_and_terminal_result`;
- exact lookup and nondisclosure:
  `test_restart_lookup_is_sanitized_and_duplicate_does_no_new_work` and
  `test_lookup_conflict_and_wrong_principal_disclose_no_prior_result`;
- semantic/chronology validation:
  `test_fk_clean_impossible_control_history_fails_closed_on_reopen`,
  `test_unlinked_transition_chronology_rejects_past_writes`, and
  `test_synthetic_adapter_rejects_backdated_effect_without_mutation`;
- startup/runtime correlation:
  `test_cross_store_missing_receipt_blocks_reopen_and_live_terminal_lookup`,
  `test_cross_store_orphan_receipt_fails_closed`,
  `test_cross_store_overlapping_provenance_substitution_fails_closed`, and
  `test_cross_store_terminal_target_substitution_fails_closed`; and
- recovery audit ownership: `test_recovery_audit_prefix_is_restart_idempotent_at_every_record`,
  `test_recovery_audit_prewrite_failure_suppresses_t3_until_exact_retry`,
  `test_recovery_audit_readback_failure_leaves_exact_retryable_trio`,
  `test_closed_original_audit_before_lost_t3_recovers_without_reinvocation`,
  and `test_pending_recovery_fences_request_and_approval_audit_writers`.

An exercised procedure additionally requires disposable synthetic stores and
recorded proof of: three-path safety; v1 control refusal/preservation and new-v2
creation; control/adapter schema and integrity rejection; one winner under
request/token/adapter/result races; restart replay denial; exact authenticated
lookup with no-new-work flags; recursive result sanitization; receipt binding/
immutability; every recovery disposition; corruption/mismatch halt without
transition; zero illegal authority reopening; JSONL/outbox validation; backup-
candidate integrity; and restore-candidate review-only disposition.

Repository-controlled tests do not exercise this complete operator procedure, a production supervisor, external custody, independent observation, real power loss at every fsync, storage loss, coherent DR, or a deployment environment. Until the critical runbook is executed and version-bound, its state is `DOCUMENTED / NOT OPERATIONALLY VALIDATED`.

## Evidence limits and prohibited inferences

This Stage A increment provides bounded development evidence for local durability, canonical idempotency, cooperative first-open/operation serialization, semantic/chronology and cross-store consistency checks, separate adapter-reported receipts, sanitized terminal lookup, and conservative same-host reconciliation. It does not establish process isolation, authenticated IPC, independently custodied observation, vendor equivalence, hostile-writer fencing, cross-store atomicity, distributed linearizability, consensus, split-brain prevention, HA, coherent backup/restore, DR, nonrepudiation, trusted time, managed secrets, successful rollback, production safety, or operational effectiveness.

No outcome authorizes Stage B or C, model promotion, historical-data access, external communication, deployment, or operational effect. Every production-readiness owner acceptance remains unrecorded.

## Revision history

| Date | Change | Evidence state |
|---|---|---|
| 2026-08-15 | Initial control-ledger inspection, reconciliation, emergency-disable, and preservation guidance. | Documented against unfrozen local Stage A; not operationally validated. |
| 2026-08-15 | Added separate offline adapter receipt/store, closed terminal lookup, exact recovery table, schema-v1 refusal/preservation and new-v2 procedure, and three-artifact backup boundary. | Documentation candidate only; exact source/test/evidence freeze remains pending. |
| 2026-08-16 | Aligned `0.4.0-alpha.2` with bounded cooperative first-open/operation ownership, preflight-before-create, full semantic/chronology scans, runtime cross-store correlation, and exact recovery-audit trio/writer fence. | 43/43 focused tests observed on mutable worktree; exact commit, full regression, manifest, CI, and operational exercise remain pending. |
| 2026-08-16 | Bound the Stage A implementation to exact Commit `8818d5d2` on `main` and linked `ADF-STAGE-A-ER-002`. | Exact local 43/43 focused, 18/18 gate, warning-fatal 360/360 full, 57/57 Phase 3, 46/46 corpus, manifest 307/307, CI and Dependency Graph succeeded; no tag, GitHub Release, deployment, owner acceptance, or operational exercise; no exact-SHA Pages run observed. |
