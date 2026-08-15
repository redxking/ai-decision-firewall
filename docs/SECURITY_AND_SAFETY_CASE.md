# Security and Safety Case

> **Version boundary.** Claims 1–6 preserve the v0.1 synthetic-simulation safety argument. `0.2.0-alpha.5` is the prior published evidence baseline. Exact Commit `08ce203c` is the predecessor untagged `0.2.0-alpha.6` Phase 2.5 design-freeze baseline, with historical CI and Dependency Graph success bound to that commit. This package candidate adds bounded path controls, selected Gate B causal-test scaffolding, documentation, and packaging; its Phase 2.5 technical suite passed 222/222, the separate public-site module passed 9/9, and the combined repository aggregate passed 231/231. The site module is outside Phase 2.5 evidence. The candidate includes a generated-and-verified integrity manifest and inspected final-source status renders. The tracked data, campaign-bound model, and baseline outputs remain at their committed bytes. Package publication and GitHub CI on the exact published package commit remain external gates. No tag, release/evidence package, Gate B package, historical dataset, live feed, production connector, or operational action is approved. `P2-CE-005` is CE-0 `NOT_EVALUATED`.

## Top-level claim

In the v0.1 synthetic-simulation path, the POC cannot perform a simulated reversible identity action unless deterministic policy and an independent verifier establish that the case, evidence, asset, and action satisfy the configured boundary. In both Phase 2 read-only modes, the stronger structural claim applies: the authorization gate, action broker, and target are not constructed, so decisions terminate as counterfactual recommendations with zero authorization or operational effect.

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

**Claim 9 — Source-to-decision agreement is a calculation-consistency control at the design-freeze boundary.** Predecessor Commit `08ce203c` separately recomputes the ordered evidence, model, policy, verifier, and read-only final semantic surfaces from frozen bytes. Production and reference calculations use explicit ordered arithmetic, including `math.fsum` for evidence aggregates and model contributions. Its historical 193-test local run and successful commit-bound CI support narrow CE-1 implementation-conformance wording for that exact commit only. This package candidate's 222/222 Phase 2.5 technical result extends that narrow prepublication check to the candidate boundary; the separate 9/9 public-site result does not extend the safety claim. GitHub CI on the exact published package commit remains required. The path remains same-process, same-project, and project-controlled; it is not an independent oracle, external custody boundary, outcome-validity proof, or `P2-CE-005` result.

**Claim 10 — Local entry points have bounded operator-error path controls.** The campaign CLI rejects destination escape, symlink redirection, source overlap, existing output, and repository-control locations before campaign execution. Check mode requires singly linked regular artifact and optional record leaves, rejects symbolic-link, directory, and multiply linked artifact leaves before any artifact read or campaign rebuild, and applies size bounds before reading. The `run_poc` entry point limits ordinary repository writes to `data/local/**` and `outputs/local/**`; an explicit freeze flag expands only to `data/**` and `outputs/baseline/**`. It preflights every generated leaf, rejects unsafe existing leaves, and binds seven non-self-referential outputs in the local manifest. Focused campaign CLI checks passed 3/3, the campaign module passed 21/21 in an isolated clean clone, and 14 focused `run_poc` checks passed, all within the 222/222 Phase 2.5 technical suite. The separate public-site tests are outside this control claim. These are application-level interlocks, not OS/mount containment, TOCTOU/race resistance, comprehensive hardlink protection, or confinement of direct writer APIs.

The campaign module also instruments construction of `AuthorizationGate`, `ActionBroker`, and `SimulatedIdentityProvider` during every reference attempt. A negative sensitivity regression injected all three constructions, produced nonzero counters and a mismatch, and proved the closed schema rejects the row. This is a bounded Python construction sensor, not a general allocation monitor, OS boundary, or target-side effect proof.

**Claim 11 — Selected Gate B failures have exact causal identities and bounded payload-access observations.** The release-candidate scaffolding registers 25 selected closed identities: 24 pre-payload mutations and one post-qualification threshold identity. The oracle accepts only exact closed tuples for classified failures, and unclassified Gate B errors remain unscorable. For the 24 selected pre-payload mutations, the bounded observer recorded zero `cases` or `adjudications` roles under its enumerated Python file APIs. This is CE-1 test instrumentation only, not a complete failure taxonomy, OS-level nonaccess/non-egress proof, sandbox, reference monitor, or `P2-CE-005` campaign evidence.

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

## Residual risks

The policy and verifier share configuration and may share design defects. The reference implementations share requirements, project governance, process, runtime, and input bytes with production and may contain correlated defects. Provenance identifiers are synthetic and not cryptographically rooted in external trust infrastructure. The v0.1 signing key has a POC fallback and is not protected by a hardware security module. V0.1 trusts top-level canonical break-glass and asset-criticality fields; Phase 2 rejects conflicting canonical inventory assertions but does not prove that the source values are authentic or correct. The audit lacks external custody. The in-memory simulator does not represent vendor API semantics, independent target readback, rate limits, race conditions, or eventual consistency. Local path guards and the Python-API observer are not OS security boundaries and do not rule out same-user access outside the observed process. No historical, live, privacy-effectiveness, production-isolation, model-efficacy, operational-safety, or bounded-failure-rate claim is available. These residual risks prohibit operational use.

See [`phase2/SHADOW_MODE_SAFETY.md`](phase2/SHADOW_MODE_SAFETY.md) and [`phase2/CLAIM_EVIDENCE_STANDARD.md`](phase2/CLAIM_EVIDENCE_STANDARD.md) for the current release boundary.
