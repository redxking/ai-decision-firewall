# ADR 013: Govern Phase 3.1 model evaluation before adding model complexity

**Status:** Accepted in the published Phase 3.1 baseline

**Date:** 2026-08-15
**Decision owners:** Project architecture, model-risk, data-governance and T&E owners

## Context

The published Phase 3 operational MVP proves a simulation-only decision-control
path. Its advisory model evidence still originates from one synthetic generator
family. Replacing the logistic model with a more complex classifier before an
approved holdout and promotion gate would increase complexity without creating
defensible evidence of improvement.

## Decision

Create a model-agnostic evaluation boundary first. The initial executable slice
uses only committed synthetic fixtures, recombines them as source pools, creates
disjoint temporal training/calibration/evaluation partitions and compares a
logistic baseline with a Platt-calibrated challenger. The output is aggregate
only and promotion is structurally `NOT_AUTHORIZED`.

Historical and live adapters, owner thresholds, operational cost weights and
model promotion remain outside this increment and require an authenticated
Gate B package.

## Options considered

### Train an EBM or gradient-boosted model immediately

Rejected for this increment. It would optimize against generator structure and
could encourage unsupported superiority claims.

### Reuse the historical v0.1 train/test labels as fixed evaluation roles

Rejected. Those partitions come from the same generator and their timestamps
overlap. The Phase 3.1 mechanism recombines them and establishes one temporal
split for evaluation-pipeline testing.

### Build the evaluation contract and calibration challenger first

Accepted. It creates the measurement, leakage-control, governance and
traceability substrate needed to evaluate later candidates without giving the
model authority.

## Consequences

- Model development is slower until data authority and acceptance thresholds
  exist, but resulting claims will be defensible.
- Synthetic metric deltas may be reported only as mechanism observations.
- Future model families can plug into the comparison boundary through frozen
  prediction/model artifacts after separate approval.
- Phase 3 authorization, broker and target code remains unchanged.

## Revisit conditions

Revisit candidate families and promotion thresholds only after the
[Phase 3.1 data-governance gate](../phase31/DATA_GOVERNANCE_GATE.md) is approved
for a specific historical evaluation package.
