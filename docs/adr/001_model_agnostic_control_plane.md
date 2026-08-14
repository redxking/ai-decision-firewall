# ADR-001 — Use a Model-Agnostic Control Plane

**Status:** Accepted

## Decision

The POC treats the risk model as a replaceable recommender with no action authority. Decision policy, verification, authorization, execution, and audit are separate components.

## Rationale

Model behavior, vendors, and capabilities will change. The trusted product boundary must remain stable and testable even when the model is replaced. This also permits deterministic unit testing and comparative evaluation of rules, statistical models, LLMs, and hybrid agents.

## Consequences

Additional integration complexity is accepted in exchange for reduced lock-in, stronger separation of duties, and an explicit safety case.
