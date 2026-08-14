# Security and Safety Case

## Top-level claim

The POC cannot autonomously perform a consequential identity action unless a deterministic policy and independent verifier establish that the case, evidence, asset, and action satisfy the configured reversible-action boundary.

## Argument structure

**Claim 1 — The model cannot act directly.** The model module exposes assessment functions only. It has no reference to the authorization gate, action broker, target simulator, signing key, or target state.

**Claim 2 — Evidence is treated as potentially adversarial.** Events carry provenance, integrity, time, trust, and source metadata. Free text is excluded from model features. Instructional content forces abstention.

**Claim 3 — Authority is external to the model.** The policy engine produces a proposal. An independent verifier re-evaluates eligibility. The authorization gate signs a case-bound and action-scoped token only after verification.

**Claim 4 — The action surface is bounded.** Only three reversible POC actions are allow-listed. Account disablement, endpoint isolation, network blocking, and persistent policy changes are human-only and rejected if inserted into the executable action set.

**Claim 5 — Action completion is checked in the simulator.** The post-action verifier checks the state returned by the in-memory simulator after each action. Synthetic command failures are intentionally injected so the system demonstrates failed verification rather than assuming success. Independent readback from a target system is not implemented in v0.1.

**Claim 6 — The decision history is tamper evident.** Each audit record includes the previous record hash and its own SHA-256 hash. The test suite demonstrates detection of modified records.

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

The policy and verifier share configuration and may share design defects. Provenance identifiers are synthetically generated and not cryptographically rooted in an external trust infrastructure. The signing key has a POC fallback and is not protected by a hardware security module. V0.1 trusts top-level canonical break-glass and asset-criticality fields and does not reconcile conflicting values embedded in evidence events. The in-memory simulator does not represent vendor API semantics, independent target readback, rate limits, race conditions, or eventual consistency. These residual risks prohibit operational use.
