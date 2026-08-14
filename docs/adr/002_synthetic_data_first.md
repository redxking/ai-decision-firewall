# ADR-002 — Begin With Synthetic Data

**Status:** Accepted with limitations

## Decision

Use generated data for v0.1 to validate interfaces, authority boundaries, auditability, and failure behavior before acquiring sensitive historical telemetry.

## Rationale

Synthetic data enables repeatability, adversarial edge cases, safe public sharing, and rapid iteration. It prevents early access-control and privacy issues from blocking architecture validation.

## Consequences

No operational performance claim is permitted. Historical replay and shadow-mode data are mandatory before any production decision.
