# Security Policy

## Operational-use warning

This repository is a research proof of concept. It uses synthetic fixtures and
offline synthetic targets. Phase 2 replay and shadow modes are structurally
read only. The published Phase 3 baseline uses an in-memory target; the opt-in
Stage A development path uses separate local SQLite control and synthetic
adapter stores plus a JSONL audit. Neither path has a live or generic
connector. The project is not approved for production integration, operational
decision-making, or live containment.

Do not connect this code to production telemetry, identity providers, action APIs, credentials, or safety-critical systems. Do not submit real incident records, direct identifiers, access tokens, secrets, or proprietary telemetry in a public issue.

## Reporting a vulnerability

Use GitHub's private vulnerability-reporting or Security Advisory channel for this repository when available. If no private channel is visible, open a public issue containing only a minimal, non-sensitive description and request a private coordination path. Do not publish exploit details, secrets, or real organizational data.

Useful reports identify the affected version or commit, the violated safety or security invariant, a minimal synthetic reproduction, expected behavior, and observed behavior.

## Current security boundary

Exact Phase 2.5 Commit `854b15c56397a81de6326b719d3d7d1dc847608f`
is published on `main` and its exact-commit CI/Dependency Graph checks passed.
`P2-CE-005` was not executed and remains CE-0 `NOT_EVALUATED`. Phase 3
`0.3.0-alpha.1` is published at exact Commit
`423685d105be813056617db738297eba83d3d9d0`; its exact-commit CI and Dependency
Graph checks passed. Its 57/57 focused-test, then-current 288/288 full-suite,
two-demo PASS, and 46/46 corpus observations are simulation-only CE-1 evidence,
not operational validation. The Phase 3.1 working candidate remains
synthetic-only and cannot authorize historical data access or model promotion.

Phase 3 opaque credentials, private capabilities, exact-type construction, and
deep-immutable records are application-level Python boundaries, not OS/process
isolation. The compatibility request and authorization ledgers remain in
memory. Stage A adds opt-in, same-host durable request, authorization, attempt,
receipt, terminal-result, and recovery state for offline synthetic execution;
the current successor tree also includes an explicit-create, loopback-only
reference service and a deny-all Kubernetes source baseline with no Service or
Ingress. These do not provide production transport, distributed fencing, HA/DR,
cross-store atomicity, or an operational service boundary. Runtime HMAC keys are domain-separated and bind
synthetic source fixtures, but do not provide enterprise provenance, PKI/HSM
custody, or nonrepudiation. Human approval resolves a synthetic human credential
and emits a reevaluation-only receipt; it cannot execute. Target readback is
functionally separate but remains under the same project/store custody and is
not externally independent. Audit is self-custodied and not externally anchored
or WORM protected.

The repository carries exact-version, SHA-256-locked runtime and documentation
dependency graphs, an unsigned CycloneDX runtime SBOM, full-commit GitHub Action
references, and an exact tracked-file manifest validator. CI accepts only
hash-locked binary distributions, treats test warnings as failures, and scopes
Pages write/OIDC authority to the deployment job. These are project-controlled
integrity mechanisms, not proof that an upstream artifact, runner, builder, or
published release is trustworthy. No signed artifact, signed provenance,
trusted builder, transparency-log record, independent verification, or
completed vulnerability disposition is claimed.

The repository does not claim production-grade key management, distributed
replay prevention, vendor API idempotency, executable rollback orchestration,
operational data validation, production safety, live efficacy or calibration,
or a bounded failure rate. These are release gates for later phases, not
implied capabilities. Production remains `BLOCKED`. See
[`docs/phase3/SECURITY_AND_SAFETY_CASE.md`](docs/phase3/SECURITY_AND_SAFETY_CASE.md).
