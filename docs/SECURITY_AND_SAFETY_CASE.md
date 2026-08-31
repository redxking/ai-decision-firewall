# Security and Safety Case

> **Version boundary.** Claims 1–6 preserve the v0.1 safety argument; Claims
> 7–11 preserve Phase 2. Exact Phase 2.5 Commit
> `854b15c56397a81de6326b719d3d7d1dc847608f` is published on `main` and its
> exact-commit CI/Dependency Graph checks passed. `P2-CE-005` was not executed
> and remains CE-0 `NOT_EVALUATED`. Claims 12–18 summarize the published Phase 3
> `0.3.0-alpha.1` simulation-only baseline at exact Commit
> `423685d105be813056617db738297eba83d3d9d0`. Exact-commit CI and Dependency
> Graph checks passed; the release boundary includes 57/57 focused tests, the
> then-current 288/288 repository suite, two demo acceptance checks PASS, and
> 46/46 corpus scenarios. These are simulation-only CE-1 observations; no
> Gate B package, historical dataset, live feed, production/test-tenant
> connector, operational action, production safety, or external assurance is
> approved. The unreleased `0.4.0-alpha.2` Stage A implementation adds a
> bounded two-database offline synthetic receipt/result mechanism under ADR-015.
> It is published on `main` at exact Commit
> `8818d5d2d40faebced66a254d58b1f0d04c9f8b4`. Exact local verification passed
> 43/43 focused Stage A in 8.248 seconds, 18/18 readiness-gate, the warning-fatal
> 360/360 repository suite in 48.995 seconds, 57/57 focused Phase 3, and 46/46
> corpus checks with `live_actions_possible=false`; its 307-entry manifest
> verified 307/307. Exact-SHA CI run 31953570779 and Dependency Graph run
> 31953572482 succeeded. These are project-controlled mechanism observations,
> not independent verification, owner acceptance, operational validation, or
> production authorization. No tag or GitHub Release was created, no deployment
> occurred, and no exact-SHA Pages run was observed. The gate remains `BLOCKED`;
> see
> [`ADF-STAGE-A-ER-002`](production/STAGE_A_RECEIPT_RESULT_EVIDENCE_RECORD.md).

## Top-level claim

In the v0.1 synthetic-simulation path, the POC cannot perform a simulated
reversible identity action unless deterministic policy and a functionally
separate verifier establish that the case, evidence, asset, and action satisfy
the configured boundary. In both Phase 2 read-only modes, the stronger
structural claim applies: the authorization gate, action broker, and target are
not constructed. In the Phase 3 candidate, a synthetic target change requires
trusted identity/evidence/policy/consequence context, an allowed and separately
verified decision, an exact-scope single-use authorization, the mandatory
in-memory broker, and a private target capability. Success requires separate
read-only state observation rather than a broker report.

In the optional Stage A path, the same authorization rule precedes a durable
authority reservation and a separate offline synthetic-adapter transaction.
An adapter-owned receipt may support recovery and a sanitized terminal lookup,
but it cannot establish independent observation, production effect, or
operational success.

## Argument structure

**Claim 1 — The model cannot act directly.** The model module exposes assessment functions only. It has no reference to the authorization gate, action broker, target simulator, signing key, or target state.

**Claim 2 — Evidence is treated as potentially adversarial.** Events carry provenance, integrity, time, trust, and source metadata. Free text is excluded from model features. Instructional content forces abstention.

**Claim 3 — Authority is external to the model.** The policy engine produces a proposal. An independent verifier re-evaluates eligibility. In v0.1 synthetic simulation, the authorization gate signs a case-bound and action-scoped token only after verification. Phase 2 read-only modes do not construct the token gate.

**Claim 4 — The v0.1 simulator action surface is bounded.** Only three reversible POC simulator actions are allow-listed. Account disablement, endpoint isolation, network blocking, and persistent policy changes are human-only and rejected if inserted into the executable action set. Phase 2 has no executable action surface.

**Claim 5 — Action completion is checked in the simulator.** The post-action verifier checks the state returned by the in-memory simulator after each action. Synthetic command failures are intentionally injected so the system demonstrates failed verification rather than assuming success. Independent readback from a target system is not implemented in v0.1.

**Claim 6 — The presented decision history is internally hash-linked.** Each audit record includes the previous record hash and its own SHA-256 hash. The test suite detects modified presented records and Phase 2 cross-checks an exact eight-stage trace against decisions and the frozen policy. This is a self-custodied consistency control, not an externally anchored, independently signed, WORM-protected, or wholesale-replacement-resistant audit trail.

## Phase 2 assurance claims

**Claim 7 — Replay and shadow semantics are structurally read only.** `historical_replay` and `shadow_read_only` do not construct or call an authorization gate, broker, target, or action credential. A containment proposal can be retained only as a counterfactual action.

**Claim 8 — Modeled signals are typed and source authorized.** Published Phase 2.4 requires exact JSON types and code-owned source roles for modeled attributes, finite numbers throughout an accepted case, exact canonical inventory binding, and a separate reference projection of the 20 serialized feature values and traces. This is implementation conformance, not proof that an authorized source assertion is true or complete.

**Claim 9 — Source-to-decision agreement is a calculation-consistency control at the Phase 2.5 boundary.** Predecessor Commit `08ce203c` separately recomputes the ordered evidence, model, policy, verifier, and read-only final semantic surfaces from frozen bytes. Production and reference calculations use explicit ordered arithmetic, including `math.fsum` for evidence aggregates and model contributions. Complete package Commit `854b15c` passed the 222/222 Phase 2.5 technical suite locally and its exact-commit CI/Dependency Graph checks passed after publication. The separate 9/9 public-site result does not extend the safety claim. The path remains same-process, same-project, and project-controlled; it is not an independent oracle, external custody boundary, outcome-validity proof, or `P2-CE-005` result.

**Claim 10 — Local entry points have bounded operator-error path controls.** The campaign CLI rejects destination escape, symlink redirection, source overlap, existing output, and repository-control locations before campaign execution. Check mode requires singly linked regular artifact and optional record leaves, rejects symbolic-link, directory, and multiply linked artifact leaves before any artifact read or campaign rebuild, and applies size bounds before reading. The `run_poc` entry point limits ordinary repository writes to `data/local/**` and `outputs/local/**`; an explicit freeze flag expands only to `data/**` and `outputs/baseline/**`. It preflights every generated leaf, rejects unsafe existing leaves, and binds seven non-self-referential outputs in the local manifest. Focused campaign CLI checks passed 3/3, the campaign module passed 21/21 in an isolated clean clone, and 14 focused `run_poc` checks passed, all within the 222/222 Phase 2.5 technical suite. The separate public-site tests are outside this control claim. These are application-level interlocks, not OS/mount containment, TOCTOU/race resistance, comprehensive hardlink protection, or confinement of direct writer APIs.

The campaign module also instruments construction of `AuthorizationGate`, `ActionBroker`, and `SimulatedIdentityProvider` during every reference attempt. A negative sensitivity regression injected all three constructions, produced nonzero counters and a mismatch, and proved the closed schema rejects the row. This is a bounded Python construction sensor, not a general allocation monitor, OS boundary, or target-side effect proof.

**Claim 11 — Selected Gate B failures have exact causal identities and bounded payload-access observations.** The published Phase 2.5 scaffolding registers 25 selected closed identities: 24 pre-payload mutations and one post-qualification threshold identity. The oracle accepts only exact closed tuples for classified failures, and unclassified Gate B errors remain unscorable. For the 24 selected pre-payload mutations, the bounded observer recorded zero `cases` or `adjudications` roles under its enumerated Python file APIs. This is CE-1 test instrumentation only, not a complete failure taxonomy, OS-level nonaccess/non-egress proof, sandbox, reference monitor, or `P2-CE-005` campaign evidence.

## Published Phase 3 simulation-only claims

**Claim 12 — Request claims cannot create authority.** The v0.3.0 raw request is
untrusted and cannot carry the invocation credential. Agent identity/status/
roles/authority come from an opaque credential resolved by the firewall to a
signed principal; source trust, target facts, action bounds, policy, current
time, and target state come from validated registries and the read-only
observer. AI recommendation and confidence are non-authoritative.

**Claim 13 — Synthetic evidence is integrity and subject bound.** Runtime HMAC
attestation binds source/type, provenance, observation time, canonical content,
support/contradiction semantics, relevance, and subject target. The evaluator
also checks freshness, corroboration, conflicts, missing sources, and poisoned
text. This is synthetic shared-key assurance, not external source truth.

**Claim 14 — Consequence and machine policy can block an apparently confident action.** The
decision path uses trusted criticality, dependencies, cascading effects,
reversibility, blast radius, downtime, mission/safety/availability impact, and
required human authority. The high-risk domain-controller demo therefore
escalates without a token or effect despite AI confidence `0.96`. Code-owned
policy invariants also preserve exact rule precedence, conservative evidence
and zero-conflict automation floors, severe-consequence approval floors, and
Tier-0 treatment for every domain controller.

**Claim 15 — Authorization and broker scope are closed.** Allowed decisions
produce a short-lived HMAC token binding issuer, request, decision, agent,
action, target, canonical parameters, policy/digest, decision context, target
precondition, time, and nonce. The process-local ledger permits one consumption,
including after a failed attempt. The broker rejects missing, altered, expired,
replayed, prior-instance, and wrong-scope tokens.

**Claim 16 — The designed target path is broker mediated.** The exact in-memory
environment creates the broker and retains a private execution capability;
target mutation requires that capability and rechecks the authorized state
precondition under the target lock. This is an application-level Python
boundary, not OS/process isolation or hostile same-process resistance.

**Claim 17 — Verification is observation based.** A functionally separate same-project read-only
interface supplies post-state. The target verifier—not the broker result—returns
`VERIFIED`, `FAILED`, `PARTIAL`, `UNEXPECTED_EFFECT`, or
`ROLLBACK_REQUIRED`. The verifier remains same-project/process and is not an
external target oracle.

**Claim 18 — Approval cannot execute.** `ESCALATE` produces an exact expiring
signed registered approval requirement and no token. A separate opaque
credential must resolve to a trusted human with exact authority before that
requirement can be consumed once and an atomically recorded signed
`APPROVED_FOR_REEVALUATION` receipt returned. The approval gate cannot mint
action authorization, cause reevaluation, or invoke the broker.

## Safety invariants

- No action without a valid token.
- No token without independent-verifier approval.
- No human-only action in an autonomous token.
- No autonomous action for generator-consistent canonical cases marked as break-glass.
- No autonomous action above the asset-criticality threshold.
- No autonomous action with poisoned or conflicting evidence.
- No free-text instruction treated as authority.
- No runtime access to ground-truth labels.
- No success declaration without post-action state verification.
- No silent audit-log mutation.
- No Phase 3 authority from agent recommendation, confidence, self-asserted
  roles/authority, target labels, source trust, or free text.
- No Phase 3 automation with failed evidence attestation/content/subject
  binding, stale/conflicting/insufficient evidence, unsafe cascading
  consequence, or insufficient trusted authority.
- No Phase 3 broker attempt without an exact valid single-use token; no token
  reuse after an attempted failure.
- No direct Phase 3 target mutation through the supported API without the
  broker-held capability.
- No Phase 3 `VERIFIED` status inferred from the broker return value.
- No Phase 3 human approval converted directly into action authorization.
- No Phase 3 policy accepted after weakening the closed rule order, evidence
  floors, zero-conflict automation, severe-consequence floors, or Tier-0
  domain-controller treatment.
- No Phase 3 executed-path audit/result whose request, decision, token, attempt,
  target-state, effect, or verification semantics contradict one another.

## Residual risks

Policy and verifiers share requirements, project governance, runtime, and
configuration and may contain correlated defects. Phase 3 source attestations
use runtime synthetic HMAC keys rather than enterprise device identity,
PKI/HSM custody, or independent provenance. The published Phase 3 request and
authorization ledgers are in memory. Stage A adds local durable authority state
and a separate durable synthetic-adapter database, but it remains single-host,
non-distributed, cooperatively fenced only within the same-host application
boundary, and non-atomic across stores. Private
attributes/capabilities and exact-type construction do not create OS/process
isolation. Human approval is an in-process fixture, not a production
separation-of-duties workflow.

The self-custodied audit lacks an external anchor, WORM storage, trusted time,
and whole-chain replacement/truncation protection. The in-memory simulator does
not represent vendor API semantics, external target-side custody, rate limits,
network partitions, eventual consistency, rollback feasibility, or production
race conditions. A functionally separate observer in the same process is not
organizational independence. No historical, live, privacy-effectiveness,
production-isolation, model-efficacy or calibration, operational-safety, or
bounded-failure-rate claim is available. These residual risks prohibit
operational use.

See [`phase2/SHADOW_MODE_SAFETY.md`](phase2/SHADOW_MODE_SAFETY.md),
[`phase2/CLAIM_EVIDENCE_STANDARD.md`](phase2/CLAIM_EVIDENCE_STANDARD.md), and
[`phase3/SECURITY_AND_SAFETY_CASE.md`](phase3/SECURITY_AND_SAFETY_CASE.md).

## Stage A boundary

The optional Stage A candidate uses two separately pathed SQLite databases. The
control database durably binds request claims, verified-decision issuance,
authorization consumption/revocation, attempt state, sanitized terminal lookup
results, and metadata-only outbox events. The offline synthetic-adapter database
durably holds only synthetic target state and one immutable receipt per stable
idempotency binding. The adapter transaction completes before its result is
returned; an exact repeat returns the same receipt without another state
change, while a changed binding fails closed.

Before any missing artifact is created, all three authoritative paths are
preflighted and existing databases are opened query-only for exact schema,
semantic, path/link/type/mode, sidecar, and integrity checks. Cross-store
validation correlates the overlapping request, authority, decision/context,
policy, receipt, and terminal-target facts and rejects a missing required or
orphan receipt and recomputed substitutions. Bounded cooperative same-host
fencing serializes startup and durable processing, lookup, approval, and
recovery, including direct public-store first creation. It is not a distributed
lease, fencing epoch, consensus mechanism, or OS/process boundary.

The lookup result is a closed authority-free projection, not a serialized
`Phase3Result`. Authenticated retrieval requires the exact principal, request
identifier, and canonical request digest. It explicitly records that the
lookup created no decision, authorization, execution attempt, or effect and
cannot contain a token, nonce, signature, credential, signing material, raw
audit rows, or executable command authority. The existing `process_json` path
continues to fail closed on duplicates and does not turn lookup into a new
decision.

This narrows response-loss and same-host replay risk but does not remove the
residual risks above. Authority reservation, adapter state/receipt, observation,
normal or recovery audit closure, and terminal result are not one atomic
transaction. T3 follows successful readback of the valid normal lifecycle; a
recovery T3 follows the exact read-back three-record recovery closure. The
adapter receipt and read-only observer remain same-project and same-store
custodied, not independently authenticated target evidence. The broker,
adapter, observer, and keys are not process isolated; recovery quiescence is
operator asserted and the fence is cooperative/same-host only; audit remains
self-custodied; and no distributed recovery, HA, failover, vendor system, or
external target has been evaluated.

Explicit quiesced reconciliation may close only an exact affirmative
`NO_EFFECT` receipt as `FAILED_NO_EFFECT`. Applied, partial, ambiguous, or
absent receipts without separately durable verification remain
`UNKNOWN_EFFECT` with `recovery_required=true`; absence proves neither no effect
nor retry safety. Corrupt, unavailable, or mismatched
adapter evidence halts reconciliation with no transition. Recovery never
reissues the command, reopens authority, fabricates verification, or claims
rollback. It must write and read back the contiguous `RECOVERY_STARTED`,
`RECOVERY_EVIDENCE_ASSESSED`, and `RECOVERY_FINALIZED` records, truthfully
classify the original lifecycle as `COMPLETE`, `INCOMPLETE`, or `UNRESOLVED`,
and resume an exact prefix without duplicate records. Append/readback failure
suppresses T3; the pending recovery owner fences request/approval/recovery
writers until T3; a repeat after T3 is an identical audit-inert replay. A
receipt never becomes verification. The machine production gate remains
`BLOCKED`; see
[`adr/015_durable_synthetic_adapter_receipt_and_result_lookup.md`](adr/015_durable_synthetic_adapter_receipt_and_result_lookup.md)
and [`production/PRODUCTION_READINESS.md`](production/PRODUCTION_READINESS.md).
