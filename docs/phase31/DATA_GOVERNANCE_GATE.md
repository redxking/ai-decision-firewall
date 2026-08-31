# Phase 3.1 data-governance gate

## Gate rule

No historical or live payload may be opened, decoded, sampled, labeled or
evaluated because this repository contains a Phase 3.1 harness. The current
executable accepts only four SHA-256-bound synthetic repository fixtures.

The external Gate B package must be authenticated and `APPROVED` before a later
historical adapter is designed or enabled. Repository conformance cannot prove
that an approver holds authority, consent exists, de-identification is
effective, custody is accurate or labels are correct.

## Required accountable approvals

At minimum, the restricted package must identify and authenticate accountable
owners for:

- data/use authority and purpose limitation;
- privacy, de-identification and retention;
- source-system ownership and schema mapping;
- evidence and label custody;
- analyst adjudication and disagreement resolution;
- model-risk and statistical acceptance thresholds;
- cybersecurity architecture and threat model;
- incident, change and stop authority; and
- independent review.

## Required frozen contents

1. Population and time window, including exclusions and missing populations.
2. Source inventory, source-instance identity and field-level mapping.
3. Collection, transfer, de-identification, storage and destruction procedures.
4. Exact manifest, record counts, digests and complete-intake accounting.
5. Label definition, adjudicator qualifications, blinding, disagreement and
   uncertainty handling.
6. Temporal train/calibration/evaluation cutoffs and leakage controls.
7. Candidate list, feature allow-list, prohibited features and monotonicity
   constraints.
8. Owner-approved performance, calibration, subgroup, abstention, workflow and
   consequence thresholds.
9. Stop conditions for privacy, integrity, drift, label leakage, subgroup harm,
   threshold failure or incomplete intake.
10. Publication and evidence wording allowed for each result state.

## Separation requirements

- Model fitting must not receive evaluation labels.
- Calibration may receive calibration labels but not final evaluation labels.
- Candidate selection must not repeatedly query the final holdout.
- Runtime/shadow decision code must not receive evaluator labels.
- Model score and confidence remain advisory inputs.
- No action credential, broker or target is present in historical or shadow
  evaluation.
- The evaluator must report all accepted, quarantined and excluded inputs.

## Gate output

Approval permits only the exact frozen read-only evaluation described by the
package. It does not approve model promotion, operational action, a production
integration or reuse of the data for another purpose.
