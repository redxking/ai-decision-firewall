# ADR-003 — Autonomous Actions Must Be Reversible and Low Impact

**Status:** Accepted

## Decision

The v0.1 action allowlist is limited to session revocation, temporary step-up authentication, and enhanced monitoring in an in-memory simulator. Account disablement, endpoint isolation, network blocking, and persistent policy changes remain human-only.

## Rationale

A safe learning path requires bounded blast radius, clear rollback, measurable target state, and simple stop conditions.

## Consequences

The POC cannot demonstrate full incident eradication. It demonstrates whether authority can be constrained and verified.
