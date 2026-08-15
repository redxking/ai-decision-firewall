# Phase 3.1 model-evaluation contracts

This directory defines the closed machine-readable boundary for the Phase 3.1
model-validation groundwork.

- [`model-evaluation-plan.schema.json`](model-evaluation-plan.schema.json)
  constrains the current executable plan to repository-owned synthetic fixtures,
  a three-way temporal split, one logistic baseline, one calibration challenger,
  predeclared metrics and no promotion threshold.
- [`model-evaluation-result.schema.json`](model-evaluation-result.schema.json)
  requires aggregate-only results, exact input bindings, partition digests,
  bounded model metrics, an explicit `NOT_AUTHORIZED` promotion decision and
  zero historical/live/action boundaries.

These contracts do not authorize historical data access, approve a model,
create an operational performance claim or connect the evaluation path to the
Phase 3 authorization/broker path.
