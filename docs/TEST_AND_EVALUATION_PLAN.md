# Test and Evaluation Plan

## Test objective

Demonstrate that the POC implements its safety and authority requirements and quantify behavior across benign, malicious, ambiguous, incomplete, and adversarial synthetic cases.

## Evaluation categories

**Functional testing:** Case ingestion, feature extraction, model execution, policy disposition, verification, authorization, simulated execution, post-action verification, reporting, and audit-chain validation.

**Safety testing:** Prompt injection, missing provenance, failed integrity, conflicting sources, missing telemetry, break-glass accounts, critical assets, human-only action insertion, missing tokens, invalid signatures, expired tokens, and target execution failures.

**Model testing:** Discrimination, precision, recall, Brier score, calibration error, scenario-level performance, and sensitivity to feature ablation. Model results are explicitly secondary to safety invariants in v0.1.

**Audit testing:** Completeness, hash-chain continuity, decision-record traceability, and tamper detection.

## Baseline acceptance criteria

- Zero autonomous actions on poisoned evidence.
- Zero autonomous actions on break-glass identities.
- Zero autonomous actions above the configured asset-criticality boundary.
- Zero authorization tokens without independent-verifier approval.
- 100% decision-to-input-event identifier trace coverage.
- Valid audit chain after a complete run.
- Audit tampering detected by unit test.
- Human-only actions rejected by the verifier.
- Ground truth absent from runtime case inputs.
- POC can be reproduced using a documented seed and command.

## Baseline outcome

All seven automated tests passed. The 400-case baseline produced zero unsafe automation events, zero poisoned-evidence actions, zero tokens without verifier approval, 100% decision-to-input-event identifier trace coverage, and a valid audit chain. This metric does not validate evidence semantics or external provenance. The simulator intentionally produced command failures; therefore, action-command and complete post-action verification rates were below 100%, correctly exposing execution uncertainty.

## Required tests for v0.2

Temporal train/test splits, de-identified historical replay, source ablation, delayed and out-of-order evidence, duplicate events, action idempotency, concurrent case execution, HMAC key rotation, token replay rejection, policy rollback, schema version mismatch, denial-of-service limits, secure logging failure, and analyst inter-rater reliability.
