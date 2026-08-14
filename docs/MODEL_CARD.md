# Model Card — Synthetic Logistic Risk Model

## Purpose

The model estimates compromise probability from allow-listed structured evidence features. It exists to test the surrounding decision-control architecture. It is not the product and is not authorized for operational use.

## Model type

Interpretable logistic regression trained with batch gradient descent and L2 regularization. Inputs are standardized using training-partition means and standard deviations.

## Features

The feature set includes failed-login intensity, new device, impossible travel, threat-intelligence match, MFA fatigue, token reuse, credential dumping, lateral movement, unusual administrative activity, endpoint malware, after-hours activity, global-administrator status, asset criticality, known VPN, approved travel, maintenance window, service-account baseline, strong MFA, device noncompliance, and suspicious OAuth grant.

Free text, ticket instructions, ground-truth labels, scenario names, user names, and raw credentials are not model inputs.

## Authority boundary

The model returns only a probability, feature contributions, and source-event trace. It cannot call the target simulator, mint an authorization token, alter policy, approve an action, or access action credentials.

## Baseline performance

On the included 400-case synthetic test partition, the model achieved 0.998 ROC AUC, 0.969 precision, 0.989 recall, and 0.021 Brier score at the 0.5 classification threshold. These values are not operational claims because the train and test partitions originate from the same synthetic generator family.

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
