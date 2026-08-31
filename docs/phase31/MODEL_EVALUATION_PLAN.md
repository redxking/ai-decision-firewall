# Phase 3.1 model-evaluation plan

## Decision objective

Determine whether a challenger provides a practically meaningful, calibrated
and operationally safer advisory risk estimate than the frozen baseline on an
approved temporal holdout. The model never receives action authority and cannot
weaken identity, evidence, policy, consequence, approval, authorization,
broker, readback or audit controls.

## Current executable scope

The executable plan
[`P3-1-MEV-001`](../../config/phase31_model_evaluation_plan.json) is deliberately
`DRAFT` and `SYNTHETIC_MECHANISM`. It validates the evaluation machinery using
the committed v0.1 generator outputs only. The plan has no historical-data mode,
no performance threshold and no model-promotion outcome.

## Partition design

For the current mechanism, the four committed case/label files are treated as
two source pools, not as trusted train/test roles. Records are recombined and
ordered by `opened_at`:

- first 60 percent: model fitting;
- next 20 percent: calibration fitting and threshold development only; and
- final 20 percent: one-pass evaluation.

Boundary timestamps cannot appear in two partitions. Case identifiers must be
unique and partition-disjoint. The result records counts, time ranges and
ordered case-ID digests without exporting case content.

An approved historical plan must use a later, separately authorized contract.
It must freeze the population, acquisition interval and temporal cutoff before
labels are decoded by the evaluator.

## Candidate strategy

The current baseline is an interpretable logistic regression using the existing
20 allow-listed features. The only executable challenger is Platt calibration of
that baseline. It tests the calibration path without changing ranking or adding
model complexity.

Future candidates such as an explainable boosting model or monotonic
gradient-boosted tree may be evaluated only after:

1. an approved data and label package exists;
2. monotonic and prohibited-feature constraints are frozen;
3. the training implementation is versioned and reproducible;
4. the same untouched temporal holdout is used; and
5. candidate selection does not repeatedly consume the final holdout.

## Required metrics

| Dimension | Required measure | Interpretation boundary |
|---|---|---|
| Discrimination | ROC AUC and average precision | Ranking only; neither is sufficient for action decisions |
| Calibration | Brier score, log loss and expected calibration error | Must be examined by action class and temporal period |
| Threshold behavior | Precision, recall, false-positive rate and confusion matrix | Must include confidence intervals and denominators |
| Abstention | Coverage-selective-risk curve | Quantifies where escalation/abstention reduces error |
| Strata | Scenario, asset-criticality band and privilege level | Synthetic diagnostics now; approved operational strata later |
| Stability | Temporal slices, source ablation and drift | Required for historical/shadow work; not established now |
| Consequence | False-containment, missed-containment and escalation costs | Weights require accountable owner approval; no defaults are invented |

The current code reports deterministic 95-percent Wilson intervals for
precision, recall and false-positive rate. It does not claim inferential power
from the synthetic sample.

## Promotion gate

The current gate state is `OWNER_THRESHOLDS_REQUIRED`; the threshold list is
empty by design. Before historical evaluation, accountable owners must approve:

- maximum false-containment rate and its confidence bound;
- minimum compromise recall and precision;
- maximum calibration error and Brier score;
- minimum useful coverage at bounded selective risk;
- allowed subgroup and temporal degradation;
- escalation workload and response-time limits;
- source-loss and drift stop conditions; and
- operational consequence and recovery constraints.

Thresholds must be chosen from mission and workflow consequences, not tuned
post hoc to make a candidate pass.

## Acceptance states

- `MECHANISM_VALIDATED`: schemas, bindings, split, metrics and deterministic
  execution work on synthetic fixtures.
- `NOT_AUTHORIZED`: current result; no performance or promotion claim.
- `HISTORICAL_EVALUATED`: future state requiring Gate B authorization and one
  clean frozen execution.
- `SHADOW_VALIDATED`: future read-only state requiring authenticated live
  sources, analyst adjudication and operational monitoring.
- `PROMOTION_APPROVED`: future governance state; never produced solely by this
  repository harness.
