# Stage A storage-fault campaign

**Campaign state:** repository-controlled development evidence; operational
storage validation not complete

**Runtime profile:** `STAGE_A_SYNTHETIC_ONLY`

**Live-action authority:** none

## Objective and invariants

This campaign tests whether loss of a process or local audit-storage service can
reopen authority, duplicate an effect, fabricate a terminal result, or corrupt
the correlated audit/control/adapter history. Every case must preserve these
invariants:

1. T1 is the last point before a possible effect; no failure may create a second
   adapter receipt for the same exact request.
2. A receipt or same-store observation is not durable verification.
3. T3 must not commit while audit durability is ambiguous.
4. Restart may return a terminal result only when the exact audit/control/
   adapter history is complete and correlated.
5. Incomplete or ambiguous work requires exact, operator-asserted quiesced
   reconciliation; normal intake and approval writers remain fenced.
6. Corruption or missing evidence halts. Tests may never repair, truncate, or
   synthesize authoritative history to obtain a passing result.

## Layered test strategy

| Layer | Test type | Current coverage | Required next coverage |
|---|---|---|---|
| Audit primitive | Deterministic unit/integration fault injection | Complete-row `fsync` ambiguity raises `AuditDurabilityError`, preserves the observed chain tip, blocks T3, and requires recovery. Persistent post-effect `ENOSPC` prevents alternate closure until the fault is removed. | Short writes, partial-row writes, `EIO` on write/read, directory-sync failure, permission transition, inode replacement during failure handling. |
| Transaction process | Multiprocess integration | Uncatchable `SIGKILL` immediately after T1, post-effect observation, T2, normal audit closure, and T3. | Claim, authorization issuance, each recovery-audit prefix, response-loss, and randomized repeated boundary selection. |
| Container | Container integration/chaos | The non-root, network-disabled, read-only image executes the deterministic SIGKILL/I/O cases. A dedicated 1 MiB tmpfs exhausted after T2 produced a partial audit row; restart preserved it and halted for quarantine with one receipt and one effect. | Container-level termination rather than in-container worker kill, cgroup memory/CPU pressure, read-only remount, repeated tmpfs exhaustion, and an approved disposition for unrecoverable partial audit records. |
| Filesystem/block device | System integration | Not established. | Linux `dm-flakey`/`dm-error` or equivalent disposable virtual block device; ext4 and one intended CSI/filesystem; WAL, main-DB, audit, directory-entry, and flush-loss cases. |
| Host/power | Destructive lab campaign | Not established. | Hypervisor power-off/reset at every boundary, repeated boots, integrity capture before recovery, and independent receipt/state comparison. |
| Soak/resource | Reliability | Not established. | Bounded request/lookup/recovery concurrency, file growth, outbox backlog, disk-watermark stop behavior, latency distribution, and leak checks. |

## Current executable cases

- `tests/test_stage_a_sigkill_campaign.py` verifies the five committed
  transaction boundaries with `SIGKILL`, exact receipt counts, target state,
  terminal/recovery classification, and zero duplicate effect.
- `tests/test_stage_a_storage_failure_campaign.py` verifies ambiguous audit
  `fsync` at both incomplete and complete ordinary lifecycle points, plus
  persistent post-effect `ENOSPC`.
- `tests/container_stage_a_storage_fault.py` is invoked only with an explicit
  container marker and a dedicated tmpfs. It verifies actual kernel `ENOSPC`
  after T2, including the partial-row case that must be preserved and
  quarantined rather than automatically reconciled.
- `tests/test_stage_a_receipt_recovery.py` remains the detailed oracle for
  recovery prefixes, writer fencing, corruption, lookup, and exact replay.

On the mutable successor worktree, the new five-boundary SIGKILL case passed
three consecutive executions; the combined storage/SIGKILL/recovery/release-
blocker selection passed 47/47; and the warning-fatal repository suite passed
439/439. These observations are not exact-commit or independent evidence until
the normal candidate/carrier and CI sequence is completed.

## Exit criteria

Repository completion requires all deterministic cases to pass on Python 3.11
and 3.12, the exact manifest to verify, the candidate container to execute the
container layer, and every failure to produce the declared safe disposition
without a second receipt or effect. Operational storage acceptance additionally
requires named owners, an approved disposable environment, exact filesystem/
CSI versions and mount options, independent evidence capture, destructive
power-loss execution, declared repetition counts, and accepted residual risk.

Green repository or lab results do not establish hostile-writer resistance,
distributed fencing, HA/DR, RPO/RTO, vendor equivalence, production safety, or
operational authorization.
