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
| Audit primitive | Deterministic unit/integration fault injection | Complete-row `fsync` ambiguity raises `AuditDurabilityError`, preserves the observed chain tip, blocks T3, and requires recovery. Persistent post-effect `ENOSPC` prevents alternate closure until the fault is removed. Repeated short writes complete through the bounded append loop, while a partial row followed by write `EIO` is preserved, blocks restart, and cannot duplicate the committed effect. A transient post-effect read `EIO` closes through the alternate accounting lifecycle as durable `RECOVERY_REQUIRED`. | Directory-sync failure, permission transition, and inode replacement during failure handling. |
| Transaction process | Multiprocess integration | Uncatchable `SIGKILL` immediately after request claim, authorization issuance, T1, post-effect observation, T2, normal audit closure, and T3. The T3 case is also response loss after durable terminal commit and proves exact lookup without re-execution. | Each recovery-audit prefix and randomized repeated boundary selection. |
| Container | Container integration/chaos | The non-root, network-disabled, read-only image executes the deterministic SIGKILL/I/O cases. A dedicated 1 MiB tmpfs exhausted after T2 produced a partial audit row; restart preserved it and halted for quarantine with one receipt and one effect. An external Docker controller now kills separate containers at T1, observation, T2, audit closure, and T3, then verifies the persisted volumes from fresh containers. | Cgroup memory/CPU pressure, read-only remount, repeated tmpfs exhaustion, and an approved disposition for unrecoverable partial audit records. |
| Filesystem/block device | System integration | A disposable privileged Linux lab now switches an ext4 loopback device from `linear` to `dm-error` at T1, post-effect observation, T2, audit closure, and T3. After restoring the mapping and running `e2fsck`, fresh Stage A construction preserves the exact receipt/effect boundary and returns conservative recovery or the durable T3 result. | `dm-flakey`, torn/short writes, lost flushes, directory-entry loss, individual WAL/main-DB/audit faults, x86_64 repetition, and one intended CSI/filesystem. |
| Host/power | Destructive lab campaign | Not established. | Hypervisor power-off/reset at every boundary, repeated boots, integrity capture before recovery, and independent receipt/state comparison. |
| Soak/resource | Reliability | Not established. | Bounded request/lookup/recovery concurrency, file growth, outbox backlog, disk-watermark stop behavior, latency distribution, and leak checks. |

## Current executable cases

- `tests/test_stage_a_sigkill_campaign.py` verifies seven committed transaction
  boundaries with `SIGKILL`, exact receipt counts, target state,
  terminal/recovery classification, response-loss lookup, and zero duplicate
  effect.
- `tests/test_stage_a_storage_failure_campaign.py` verifies ambiguous audit
  `fsync` at both incomplete and complete ordinary lifecycle points, plus
  persistent post-effect `ENOSPC`, repeated short audit writes, a transient
  post-effect read `EIO`, and a partial audit row followed by write `EIO` that
  must be preserved and quarantined.
- `tests/container_stage_a_storage_fault.py` is invoked only with an explicit
  container marker and a dedicated tmpfs. It verifies actual kernel `ENOSPC`
  after T2, including the partial-row case that must be preserved and
  quarantined rather than automatically reconciled.
- `tests/test_stage_a_container_external_kill.py` uses the Docker control plane
  to deliver `SIGKILL` from outside the process container at all seven committed
  boundaries. Each case uses fresh named volumes and a fresh verifier container;
  cleanup is restricted to the uniquely named campaign resources.
- `tests/container_stage_a_block_device_fault.py` runs only under the explicit
  privileged-lab marker. `scripts/run_stage_a_block_device_campaign.py` binds a
  temporary derivative to the inspected local image ID, disconnects the runtime
  network, and provides only loopback files on tmpfs to the five-boundary
  `dm-error`/ext4 campaign. The exact operator procedure is in
  `docs/operations/STAGE_A_BLOCK_DEVICE_FAULT_LAB_RUNBOOK.md`.
- `tests/test_stage_a_receipt_recovery.py` remains the detailed oracle for
  recovery prefixes, writer fencing, corruption, lookup, and exact replay.

On the mutable successor worktree, the new five-boundary SIGKILL case passed
three consecutive executions; the combined storage/SIGKILL/recovery/release-
blocker selection passed 47/47; and the warning-fatal repository suite passed
439/439. That increment subsequently passed exact PR and merged-main CI. The
next mutable successor then passed all five external-container-kill boundaries
and all five ext4/`dm-error` boundaries locally. Four nonterminal block-device
cases required `e2fsck`; the campaign recorded raw pre/post-repair image hashes
and WAL/SHM or audit-path transformations before validating the recovered
application history. The successor observations are not exact-commit or
independent evidence until their own candidate/carrier and CI sequence is
completed.

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
