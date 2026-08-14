# ADR 005: Make replay and shadow execution modes structurally read-only

**Status:** Accepted for the Phase 2 starter

## Context

Historical replay and shadow evaluation must exercise the evidence, model, policy, and verification path without acquiring action authority. A configuration flag placed near a live broker would leave a fail-open path and would make the safety claim depend on runtime operator choices.

## Decision

Execution mode is a code-owned enumeration with three values: synthetic simulation, historical replay, and shadow read-only. No live or production execution value exists.

The synthetic-simulation mode preserves the v0.1 in-memory compatibility path. Historical replay and shadow read-only modes do not construct an authorization gate, action broker, or action target. They do not request tokens or execute proposed actions. Proposed executable actions are retained only as counterfactual recommendations, and suppression is recorded in the audit chain.

The Phase 2 replay configuration must state `live_actions_enabled: false`; the harness rejects any other value. Enabling operational action requires a later architecture decision, a different release boundary, and separate authorization evidence.

## Consequences

- Read-only safety can be verified by object construction and call-path tests, not only by observing zero actions in a test dataset.
- Replay and shadow results remain useful for counterfactual analysis without being treated as execution records.
- The v0.1 simulator remains available for synthetic regression tests, but it is not a path to a production connector.
- Later test-tenant execution will require an explicitly different design and cannot be enabled by adding a configuration string.
