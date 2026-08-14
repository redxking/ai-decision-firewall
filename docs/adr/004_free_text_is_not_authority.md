# ADR-004 — Free Text Is Never Action Authority

**Status:** Accepted

## Decision

Free-text tickets, notes, threat reports, and log messages may be retained as evidence but are excluded from model features and cannot satisfy action-policy conditions. Instructional content forces abstention.

## Rationale

Untrusted content can contain prompt injection, social engineering, stale instructions, or ambiguous operational context. Treating it as action authority would collapse the trust boundary.

## Consequences

Useful natural-language context may be underutilized in v0.1. Future LLM-based extraction must produce typed claims with provenance and cannot bypass deterministic policy.
