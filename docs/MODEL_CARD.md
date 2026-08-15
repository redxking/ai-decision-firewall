# Model Card — Synthetic Logistic Risk Model

> **Version boundary.** This card describes the v0.1 synthetic model artifact and its version-bound baseline metrics. `0.2.0-alpha.5` is the prior published evidence baseline. Exact Commit `08ce203c` is the predecessor untagged `0.2.0-alpha.6` Phase 2.5 design-freeze baseline, with historical CI and Dependency Graph success bound to that commit. This package candidate's Phase 2.5 technical suite passed 222/222; the separate public-site module passed 9/9; and the combined repository aggregate passed 231/231. The site module is outside Phase 2.5 evidence. The candidate includes a generated-and-verified integrity manifest and inspected final-source status renders. Package publication and GitHub CI on the exact published package commit remain external gates. The tracked model and baseline outputs remain at their committed bytes. Neither increment converts the model into an operational detector. No tag or release/evidence package exists, and `P2-CE-005` is CE-0 `NOT_EVALUATED`.

## Purpose

The model estimates compromise probability from allow-listed structured evidence features. It exists to test the surrounding decision-control architecture. It is not the product and is not authorized for operational use.

## Model type

Interpretable logistic regression trained with batch gradient descent and L2 regularization. Inputs are standardized using training-partition means and standard deviations.

The alpha.6 candidate defines ordered `math.fsum` accumulation for model contributions before adding the intercept and applying the clamped sigmoid. The Phase 2.5 reference path separately reproduces the same specified arithmetic. This is a deterministic implementation rule, not proof of cross-platform equivalence, model validity, calibration, or independent replication.

## Features

The feature set includes failed-login intensity, new device, impossible travel, threat-intelligence match, MFA fatigue, token reuse, credential dumping, lateral movement, unusual administrative activity, endpoint malware, after-hours activity, global-administrator status, asset criticality, known VPN, approved travel, maintenance window, service-account baseline, strong MFA, device noncompliance, and suspicious OAuth grant.

Free text, ticket instructions, ground-truth labels, scenario names, user names, and raw credentials are not model inputs.

## Authority boundary

The model returns only a probability, feature contributions, and source-event trace. It cannot call the target simulator, mint an authorization token, alter policy, approve an action, or access action credentials.

## Baseline performance

On the included 400-case synthetic test partition, the model achieved 0.998 ROC AUC, 0.969 precision, 0.989 recall, and 0.021 Brier score at the 0.5 classification threshold. These values are not operational claims because the train and test partitions originate from the same synthetic generator family.

These values remain the v0.1 result. They are not Phase 2 replay metrics and have not been established on historical or live data.

## Current assurance boundary

Published Phase 2.4 constrains the 20 modeled inputs by exact type, range, and authorized source role, requires exact canonical inventory binding, and uses a separately implemented in-process projector to reproduce serialized feature values and traces. `P2-CE-004` provides only its fixed SELF synthetic CE-2 result; it does not validate this model against operational data.

The predecessor alpha.6 design-freeze implementation extends same-process reference calculation through the model probability and ordered factors as one stage of a larger source-to-decision comparison. A match can establish calculation consistency for the exact tested boundary only. It cannot establish source truth, feature sufficiency, discrimination, calibration, policy fitness, outcome correctness, efficacy, fairness, robustness, or organizational independence. The historical CI result for `08ce203c` does not cover this package candidate; its 222/222 Phase 2.5 technical result is local, the separate 9/9 site result does not extend the model claim, and GitHub CI must pass after the exact package commit is published. The planned `P2-CE-005` campaign has no observed result.

## Known risks

- Synthetic-to-real distribution shift
- Overconfidence caused by simplified scenario structure
- Correlated or duplicated telemetry sources
- Missing contextual evidence
- Adversarial manipulation of structured fields
- Vendor schema drift
- Incorrect privilege or asset-criticality data
- Model calibration degradation over time

## Required controls before operational consideration

Historical replay evaluation, temporal holdout testing, source-ablation testing, calibration by action class, uncertainty quantification, drift monitoring, red-team testing, subgroup analysis, analyst adjudication, and a documented model-change approval process are required. Even after those controls, the model remains advisory and cannot receive action authority.

No approved historical replay or live-shadow evaluation has occurred. See [`phase2/VALIDATION_PLAN.md`](phase2/VALIDATION_PLAN.md) for the current evidence gates.
