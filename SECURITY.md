# Security Policy

## Operational-use warning

This repository is a research proof of concept. It uses synthetic fixtures and
in-memory simulators. Phase 2 replay and shadow modes are structurally read
only. The local Phase 3 candidate can apply only a simulated
`NETWORK_ISOLATE` transition to its exact in-memory target type; it has no live
or generic connector. The project is not approved for production integration,
operational decision-making, or live containment.

Do not connect this code to production telemetry, identity providers, action APIs, credentials, or safety-critical systems. Do not submit real incident records, direct identifiers, access tokens, secrets, or proprietary telemetry in a public issue.

## Reporting a vulnerability

Use GitHub's private vulnerability-reporting or Security Advisory channel for this repository when available. If no private channel is visible, open a public issue containing only a minimal, non-sensitive description and request a private coordination path. Do not publish exploit details, secrets, or real organizational data.

Useful reports identify the affected version or commit, the violated safety or security invariant, a minimal synthetic reproduction, expected behavior, and observed behavior.

## Current security boundary

Exact Phase 2.5 Commit `854b15c56397a81de6326b719d3d7d1dc847608f`
is published on `main` and its exact-commit CI/Dependency Graph checks passed.
`P2-CE-005` was not executed and remains CE-0 `NOT_EVALUATED`. Phase 3 is an
uncommitted local `0.3.0-alpha.1` candidate. Its 57/57 focused-test, 288/288
full-suite, two-demo PASS, and 46/46 corpus observations are checkout-local CE-1
evidence, not a published or exact-commit-CI evidence package.

Phase 3 opaque credentials, private capabilities, exact-type construction, and
deep-immutable records are application-level Python boundaries, not OS/process
isolation. Its request and authorization ledgers are in memory, not durable or
distributed. Runtime HMAC keys are domain-separated and bind synthetic source
fixtures, but do not provide enterprise provenance, PKI/HSM custody, or
nonrepudiation. Human approval resolves a synthetic human credential and emits a
reevaluation-only receipt; it cannot execute. Target readback is functionally
separate but remains in the same project/process/simulator and is not externally
independent. Audit is self-custodied and not externally anchored or WORM
protected.

The repository does not claim production-grade key management, durable replay
prevention, vendor API idempotency, executable rollback orchestration,
operational data validation, production safety, live efficacy or calibration,
or a bounded failure rate. These are release gates for later phases, not implied
capabilities. See [`docs/phase3/SECURITY_AND_SAFETY_CASE.md`](docs/phase3/SECURITY_AND_SAFETY_CASE.md).
