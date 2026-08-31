# Stage A durable receipt and terminal-result exact-commit evidence record

**Record ID:** `ADF-STAGE-A-ER-002`

**Recorded:** 2026-08-16

**Implementation commit:**
[`8818d5d2d40faebced66a254d58b1f0d04c9f8b4`](https://github.com/redxking/ai-decision-firewall/commit/8818d5d2d40faebced66a254d58b1f0d04c9f8b4)

**Baseline commit:**
[`bb6b8f28afba0961bb97b24e6050fccaa94d5702`](https://github.com/redxking/ai-decision-firewall/commit/bb6b8f28afba0961bb97b24e6050fccaa94d5702)

**Predecessor evidence carrier:**
[`509de73b4818e023a480a40d66c676abf660bbcf`](https://github.com/redxking/ai-decision-firewall/commit/509de73b4818e023a480a40d66c676abf660bbcf)

**Candidate:** `0.4.0-alpha.2` / PEP 440 `0.4.0a2`

**Derived production gate:** `BLOCKED`

**Owner acceptance:** 36/36 mandatory requirement rows remain
`NOT_RECORDED`

**Review state:** project-controlled local verification and exact-SHA GitHub
automation; no independent assessment, accountable-owner acceptance,
authorizing-official approval, non-production validation, pilot acceptance, or
operational-effectiveness evidence

## Decision and claim boundary

Commit `8818d5d2d40faebced66a254d58b1f0d04c9f8b4` is the exact
implementation boundary for the Stage A durable synthetic-adapter receipt,
sanitized terminal-result lookup, and conservative recovery increment. It is a
single-host, POSIX-cooperative, offline synthetic development mechanism. The
implementation commit was pushed to `main` and its exact-SHA CI and Dependency
Graph jobs completed successfully. That publication state does not establish a
tag, GitHub Release, deployment, pilot, production authorization, or
operational effectiveness.

The implementation deliberately preserves separate T1 control reservation, T2
adapter state-plus-receipt, read-only observation, JSONL audit, recovery-audit,
and T3 terminal-result boundaries. It does not claim cross-store atomicity.
The adapter receipt and observer remain same-project and same-store custodied;
neither is independently authenticated target evidence. Cooperative directory
and audit-file locking is not a lease, fencing epoch, protection from a
noncooperating same-user writer, or distributed consistency.

This ER-002 file is necessarily added by an evidence-carrier commit after the
implementation commit. The carrier commit therefore cannot be named inside
this file without making the record self-referential. The carrier regenerates
and verifies a separate 308-entry `MANIFEST.sha256` so that this file is
enumerated; carrier qualification observed 308/308 entries passing. The final
handoff records and verifies the exact carrier SHA separately. The 307-entry
implementation manifest reported below cannot cover a file that did not yet
exist.

## Evidence lineage

| Boundary | Exact identity | Meaning |
|---|---|---|
| Published Phase 3.1 baseline | `bb6b8f28afba0961bb97b24e6050fccaa94d5702` | Synthetic-only model-evaluation baseline; promotion remains `NOT_AUTHORIZED`. |
| Predecessor Stage A evidence carrier | `509de73b4818e023a480a40d66c676abf660bbcf` | Carries [`ADF-STAGE-A-ER-001`](STAGE_A_EVIDENCE_RECORD.md) for the schema-v1 authority-ledger checkpoint; it is not evidence for the new adapter receipt/result boundary. |
| ER-002 implementation | `8818d5d2d40faebced66a254d58b1f0d04c9f8b4` | Exact source, tests, documents, Diagram 10, version, and 307-entry implementation manifest evaluated in this record. |
| ER-002 carrier | Follows this record | Non-self-referential commit that adds this file and a separately verified 308-entry carrier manifest; exact SHA must be reported after creation. |

## Exact local verification

All results in this section were observed against a clean checkout of exact
implementation Commit `8818d5d2d40faebced66a254d58b1f0d04c9f8b4`.
They are project-controlled implementation evidence, not independent or
operational validation.

| ID | Check | Exact result | Evidence boundary |
|---|---|---|---|
| LV-01 | Focused `tests.test_stage_a_receipt_recovery` plus `tests.test_stage_a_durable_control_ledger`, with bytecode writes disabled and warnings promoted to errors | 43/43 PASS in 8.248 seconds | Exercises the named local receipt, lookup, restart, process, corruption, chronology, correlation, recovery, and path controls; not power-loss or hostile-writer proof. |
| LV-02 | Repeated integrated shared-audit independent-process exact-once race | 5/5 PASS | Bounded same-host multiprocess repetition; not load, soak, cross-host, partition, or distributed-linearizability evidence. |
| LV-03 | `tests.test_production_readiness_gate` | 18/18 PASS | Validates the closed matrix and mutation controls; does not satisfy any owner gate. |
| LV-04 | Complete `tests/test_*.py` discovery with `PYTHONDONTWRITEBYTECODE=1`, `PYTHONPATH=src:.`, and `PYTHONWARNINGS=error` | 360/360 PASS in 48.995 seconds | Exact local warning-fatal regression; no coverage threshold, formal proof, reliability bound, or independent V&V. |
| LV-05 | Focused Phase 3 contract, decision, authorization, adversarial, end-to-end, corpus-runner, and release-blocker modules | 57/57 PASS | Preserves the simulation-only Phase 3 control surface; same-project conformance only. |
| LV-06 | Fresh Phase 3 demonstration | Acceptance PASS; high-risk domain-controller scenario produced zero effect, and the authorized workstation scenario produced one synthetic effect | Synthetic demonstration only; no live or external operational target, connector, credential, action, or effect. |
| LV-07 | Fresh deterministic Phase 3 adversarial corpus | 46/46 PASS; `live_actions_possible=false` | Project-controlled finite corpus; not exhaustive security assurance or proof of host/network confinement. |
| LV-08 | `tests.test_phase31_model_evaluation` and fresh synthetic model-evaluation execution | 11/11 PASS; promotion `NOT_AUTHORIZED`; no historical/live access, action credential, broker, target, or effect | Mechanism conformance only; no representative data, approved threshold, model-superiority, efficacy, or promotion claim. |
| LV-09 | Production-readiness CLI over [`production_readiness_requirements.json`](../../config/production_readiness_requirements.json) | Expected exit 2; structurally valid; derived `BLOCKED`; 18 domains, 36 mandatory requirements, 36 blockers; all owner acceptances `NOT_RECORDED` | Exit 2 is the intended blocking decision, not a validator failure. Structural validity does not close a gate. |
| LV-10 | `shasum -a 256 -c MANIFEST.sha256` at the implementation commit | 307/307 PASS | Self-custodied unsigned SHA-256 inventory; not a signature, SBOM, provenance attestation, or external anchor. |
| LV-11 | Local `0.4.0a2` wheel build | One wheel observed with SHA-256 `7a75b6a61324fab1773fdcc61652b8b74a62110d1d36a342d6d7d4c7ac127b77` | Observed byte artifact only; not committed, signed, published, scanned, or shown reproducible across rebuilds/environments. |
| LV-12 | Documentation, link, cited-test, and Diagram 10 checks | Tracked Markdown links were inspected with zero missing relative targets; all cited test names resolved; the Stage A receipt/result traceability register had 14 rows and 49 named test references; Diagram 10 hashes matched the implementation manifest; PNG visually inspected with no crop or overlap observed | Parser/path and manual-render checks only; not semantic proof, accessibility certification, or independent document review. |

The exact-commit rerun in LV-01 completed in 8.248 seconds. Earlier mutable-
worktree documents that recorded an 8.854-second pre-commit observation are not
the source for this exact-commit timing. LV-01 and LV-04 are the warning-fatal
local observations; the GitHub workflow described below did not set
`PYTHONWARNINGS=error`.

## Diagram 10 integrity

The following SHA-256 values are both observed at the exact implementation
commit and enumerated in its `MANIFEST.sha256`:

| Artifact | SHA-256 |
|---|---|
| [`10_stage_a_durable_adapter_reconciliation.dot`](../architecture/10_stage_a_durable_adapter_reconciliation.dot) | `4a4f06613aeb1c79f1c633888f18699fb3b04bb4c7d6ebfa15bb089115f8f494` |
| [`10_stage_a_durable_adapter_reconciliation.png`](../architecture/10_stage_a_durable_adapter_reconciliation.png) | `f6a1c7ff43c9d4e8e581ffdde0f95f793df2ccb1b89dc774fca8ed443d74d04a` |
| [`10_stage_a_durable_adapter_reconciliation.svg`](../architecture/10_stage_a_durable_adapter_reconciliation.svg) | `1851cf3e12b0e934ee6f2d5af93038304695eea268fe9048d10fdad62d3eccc9` |

The diagram shows the separate control and adapter databases, T1/T2/T3, the
same-store observation boundary, adapter-reported receipt semantics, terminal
lookup, conservative reconciliation, and explicit no-cross-store-atomicity and
no-retry rules. Presence and hash agreement do not establish production
architecture, external custody, or operational safety.

## Exact remote automation

The following GitHub automation was queried by run identifier and exact head
SHA on 2026-08-16:

| Automation | Exact observation | Boundary |
|---|---|---|
| [CI run 31953570779](https://github.com/redxking/ai-decision-firewall/actions/runs/31953570779) | `SUCCESS`; event `push`; branch `main`; head SHA `8818d5d2d40faebced66a254d58b1f0d04c9f8b4`; `test (3.11)` job `95180658912` SUCCESS; `test (3.12)` job `95180658890` SUCCESS | Both jobs passed their unit-test, Phase 3 demo, corpus, and manifest workflow steps. The workflow used `PYTHONPATH=src python -m unittest discover -s tests -v`; it did **not** promote warnings to errors, so local LV-04 remains the only warning-fatal complete-suite claim. |
| [Dependency Graph run 31953572482](https://github.com/redxking/ai-decision-firewall/actions/runs/31953572482) | `SUCCESS`; branch `main`; head SHA `8818d5d2d40faebced66a254d58b1f0d04c9f8b4`; `update-pip-graph` job `95180664502` SUCCESS | Dependency-graph update is not an SBOM, dependency lock, vulnerability assessment, signed provenance, or supply-chain approval. |
| Exact-SHA Pages query | Returned `[]`; no exact-SHA Pages run was observed | Absence of a Pages run is not a Pages failure and is not deployment evidence. |

Both CI matrix jobs emitted a nonblocking runner-platform warning: the Node 20
targets used by `actions/checkout@v4` and `actions/setup-python@v5` were forced
to Node 24 by the runner. Job and workflow conclusions remained `SUCCESS`.
This warning is retained as provenance context and must not be interpreted as
a test failure or as evidence that action-version/digest pinning is complete.

GitHub-hosted automation improves exact-SHA reproducibility but remains
project-configured evidence. It is not independent assessment, a signed build,
a trusted release ceremony, or intended-environment validation.

## Claim-to-evidence trace

Every implementation claim in this table binds to exact Commit
`8818d5d2d40faebced66a254d58b1f0d04c9f8b4`.

| ID | Bounded claim | Implementation / evidence | Result | Limitation and remaining gate |
|---|---|---|---|---|
| SA2-ER-001 | Supported local processes serialize first creation and durable audit/store work without a lock-file artifact. | Bounded POSIX directory-root ownership in [`stage_a.py`](../../src/adf_poc/stage_a.py) and [`engine.py`](../../src/adf_poc/phase3/engine.py); LV-01/LV-02. | PASS for the exercised same-host processes. | Cooperative lock only; no hostile-writer fence, lease, epoch, multi-node ownership, HA, or DR. |
| SA2-ER-002 | T1 consumes exact authority and reserves one attempt before T2; T2 atomically changes offline synthetic target state and writes one immutable receipt; T3 stores one terminal result and outbox transition. | Control schema v2, adapter schema v1, canonical bindings, receipts, result contract, and focused tests; LV-01. | PASS for exact/repeated/conflicting local paths. | T1, T2, observation, JSONL, and T3 are separate commits. No cross-store transaction or shared recovery point exists. |
| SA2-ER-003 | Store-local semantic and chronological corruption and defined cross-store divergence fail closed before authoritative use. | Code-owned schema fingerprints, relationship/result provenance scans, adapter receipt state/time chain, and startup/runtime correlation; LV-01. | PASS for malformed histories, backdating, orphan/missing receipts, provenance substitution, and terminal-target substitution in the named tests. | Detection covers the implemented closed mismatch set; no Byzantine-store guarantee, trusted time, rollback-resistant counter, or independently custodied anchor. |
| SA2-ER-004 | An exact duplicate can retrieve only a sanitized, authority-free terminal projection and cannot create new decision, authorization, adapter work, effect, or audit lifecycle. | `RequestLookupResult`, `lookup_request_result`, recursive authority-bearing-field rejection, and duplicate-denying `process_json`; LV-01. | PASS across restart, exact duplicate, changed digest, and wrong-principal cases. | Local synthetic identity only; no remote API, enterprise IAM, tenant isolation, rate limiting, approved retention, or operational privacy assessment. |
| SA2-ER-005 | Explicit quiesced recovery never reinvokes the command and uses conservative closed outcomes. | `reconcile_request(operator_asserted_quiesced=True)` and receipt-informed recovery; LV-01. | Exact `NO_EFFECT` may close `FAILED_NO_EFFECT`; positive/partial/ambiguous or absent receipt without durable verification closes `UNKNOWN_EFFECT`; corrupt/mismatched/unavailable evidence halts. | Operator assertion is not a fence. Receipt/readback is not independent verification. No rollback executor, compensation authority, or unattended recovery approval. |
| SA2-ER-006 | Recovery audit survives each prefix and fences unrelated audit writers until T3. | Exact `RECOVERY_STARTED`, `RECOVERY_EVIDENCE_ASSESSED`, `RECOVERY_FINALIZED` tail and `RECOVERY_AUDIT_PENDING` behavior; LV-01. | PASS for prefix crashes, append/readback ambiguity, complete-trio-before-T3, exact retry, and request/approval writer fencing. | Recovery JSONL and T3 remain separate commits; no external anchor, WORM custody, or coherent multi-store recovery point. |
| SA2-ER-007 | Stage A preserves Phase 3 and Phase 3.1 safety boundaries. | LV-04 through LV-08. | 360/360 full, 57/57 Phase 3, demo PASS, corpus 46/46 with `live_actions_possible=false`, and Phase 3.1 11/11 with promotion `NOT_AUTHORIZED`. | Synthetic project-controlled conformance only; no historical evaluation, operational target, efficacy, model promotion, or live-action claim. |
| SA2-ER-008 | The production gate cannot self-promote from implementation evidence. | Machine-readable 18-domain/36-requirement matrix and validator; LV-03/LV-09. | Structurally valid and intentionally `BLOCKED`; all 36 requirements block and all 36 owner acceptances remain `NOT_RECORDED`. | No technical test substitutes for mission, security, data, model, policy, operations, target-system, or authorizing-official acceptance. |
| SA2-ER-009 | The implementation snapshot, package observation, documents, and architecture view are traceable. | LV-10 through LV-12 and Diagram 10 hashes. | Manifest 307/307; wheel built and hashed; links/test references resolved; diagram hashes matched and PNG inspection passed. | Manifest is unsigned/self-custodied; wheel is not reproducibly bound; manual document/image review is not independent assurance. |
| SA2-ER-010 | The published implementation commit executed successfully in the project CI matrix. | Exact-SHA CI and Dependency Graph runs above. | Python 3.11 and 3.12 CI jobs plus Dependency Graph job concluded `SUCCESS`. | CI was not warning-fatal, actions are not digest-pinned, Pages did not run, and automation is not production validation or release authorization. |

## Negative execution statement and prohibited inferences

This Stage A work did not use, create, connect, authorize, or establish:

- historical organizational data, representative operational data, a live
  feed, or an approved Gate B data-access package;
- a production or test-tenant connector, external broker endpoint, vendor
  adapter, operational credential, enterprise identity, managed key, or
  designated external target;
- a live or external operational action/effect, target-side receipt,
  independently custodied observation, executable rollback, compensation, or
  proof of safe recovery;
- model promotion, approved model thresholds, representative model validation,
  policy-owner approval, mission-owner acceptance, target-owner acceptance, or
  authorizing-official approval;
- distributed linearizability, consensus, split-brain prevention, hostile-
  writer fencing, failover, HA, coherent backup/restore, RTO/RPO, or DR;
- Stage B integration, Stage C pilot activity, deployment, a Git tag, GitHub
  Release, signed artifact, SBOM, signed provenance, or operational release;
  or
- a `P2-CE-005` campaign result. `P2-CE-005` remains CE-0
  `NOT_EVALUATED`.

The authorized push of the implementation commit to `main`, the CI run, and
the Dependency Graph run are the only external publication/automation states
claimed here. A repository commit, manifest, wheel hash, green test, green CI
job, or diagram must not be interpreted as deployment, production safety,
source truth, independent verification, owner acceptance, or operational
effectiveness.

## Release decision

The only supportable production disposition remains **BLOCKED / NOT
PRODUCTION-READY**. The implementation and exact-SHA automation close the
bounded Stage A engineering evidence objective; they do not close any of the 36
mandatory production-readiness requirements because every accountable-owner
acceptance remains `NOT_RECORDED` and material operational controls remain
absent.

No later work may add historical or live data, an external identity, connector,
credential, vendor adapter, designated target, model promotion, Stage B
integration, or Stage C pilot authority by inference from ER-002. Each requires
a separate explicit authorization package, intended-environment validation,
and recorded accountable-owner acceptance.
