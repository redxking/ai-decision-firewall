# Security Policy

## Operational-use warning

This repository is a research proof of concept. It uses synthetic fixtures and, in its v0.1 compatibility path, an in-memory action simulator. Phase 2 replay and shadow modes are structurally read-only. The project is not approved for production integration, operational decision-making, or live containment.

Do not connect this code to production telemetry, identity providers, action APIs, credentials, or safety-critical systems. Do not submit real incident records, direct identifiers, access tokens, secrets, or proprietary telemetry in a public issue.

## Reporting a vulnerability

Use GitHub's private vulnerability-reporting or Security Advisory channel for this repository when available. If no private channel is visible, open a public issue containing only a minimal, non-sensitive description and request a private coordination path. Do not publish exploit details, secrets, or real organizational data.

Useful reports identify the affected version or commit, the violated safety or security invariant, a minimal synthetic reproduction, expected behavior, and observed behavior.

## Current security boundary

The checked-in baseline intentionally does not claim production-grade key management, token replay prevention, external audit anchoring, independent target readback, executable rollback, vendor API idempotency, or operational data validation. These are release gates for later phases, not implied capabilities.
