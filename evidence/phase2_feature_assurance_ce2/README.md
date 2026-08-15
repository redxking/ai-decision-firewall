# P2-CE-004 synthetic feature-assurance campaign evidence

This directory contains the sanitized evidence bundle for `P2-CE-004`, a CE-2 `CONTROLLED_BEHAVIOR` claim over the fixed synthetic typed-feature and reference-projection campaign. The exact machine-readable claim is [`phase2-feature-assurance-ce2-evidence-record.json`](../../contracts/v0.2.0/examples/phase2-feature-assurance-ce2-evidence-record.json).

## Bound implementation and scope

- Release: `0.2.0-alpha.5`
- Implementation Commit A2: [`53e409d6ffa4af98ea892bc1a81302bf30870693`](https://github.com/redxking/ai-decision-firewall/commit/53e409d6ffa4af98ea892bc1a81302bf30870693)
- Implementation-freeze CI: [GitHub Actions run `31883987309`](https://github.com/redxking/ai-decision-firewall/actions/runs/31883987309), Python 3.11 and 3.12 passed
- Campaign: `P2-CE-004-FEATURE-ASSURANCE-SYNTHETIC`
- Evaluated at: `2026-08-15T12:13:03Z`
- Origin: `SYNTHETIC_FIXTURE`
- Historical records: `0`
- Stored organizational approval package: no
- Live feed, action credential, write-capable connector, or operational target: none
- Review: `SELF`, automated and project-controlled

Commit A2 freezes the generator, plan, schemas, validator, project sources, dependency declarations, seed, attempt order, expected outcomes, budget, and runtime binding before this result was generated. This public project-controlled freeze is not external preregistration.

An earlier unpublished package against Commit `1945ff283794c42f8eb649e320ba6adf91a6b982` was withheld after review found that its frozen validator accepted non-finite JSON. That package is invalidated, excluded from every claim denominator, and is not evidence. The present package is one new campaign execution against the corrected A2 freeze, not a retry within the current 32-attempt denominator.

## Observed result

Two complete deterministic same-process repetitions executed the same 16 fixed scenarios. All 32 observations matched the commit-frozen, project-controlled expected outcomes with zero retries, exclusions, failures, or deviations:

| Observation | Count |
|---|---:|
| Total attempt executions | 32 |
| Expected-outcome matches | 32 / 32 |
| Clean qualification and reference-projection matches | 16 |
| Qualification quarantines | 8 |
| `INVALID_BOOLEAN` / `INVALID_TYPE` / `UNAUTHORIZED_MODELED_SIGNAL` quarantines | 2 / 2 / 4 |
| `REFERENCE_FEATURE_PROJECTION_MISMATCH` blocks | 8 |
| Retries / exclusions / failed attempts / deviations | 0 / 0 / 0 / 0 |
| Model / policy / verifier / decision-engine calls | 0 / 0 / 0 / 0 |
| Authorization / broker / target-effect / operational-effect calls | 0 / 0 / 0 / 0 |
| Decision / audit / completed-run-manifest write calls | 0 / 0 / 0 |
| Historical cases | 0 |

The two sanitized 16-row result ledgers are byte-identical. The 32 observations are two repetitions of 16 project-selected scenarios, not 32 independent or representative trials.

## Artifact index

| Artifact | SHA-256 | Purpose |
|---|---|---|
| [`campaign_profile.json`](campaign_profile.json) | `863cee8a6a898c6fed8e11cece24d6b668e66932a5b1bcbec2c64d81a7bb44ef` | Exact commit, source/configuration, runtime, scenario, seed, and budget bindings |
| [`campaign_results_run1.jsonl`](campaign_results_run1.jsonl) | `39a16a007fa71b1038190510f4d48ab8891e350a4a2264e4966896e8548195f3` | Sixteen sanitized observations from repetition one |
| [`campaign_results_run2.jsonl`](campaign_results_run2.jsonl) | `39a16a007fa71b1038190510f4d48ab8891e350a4a2264e4966896e8548195f3` | Sixteen sanitized observations from repetition two |
| [`campaign_summary.json`](campaign_summary.json) | `77697844f256c9336a31651af09e39332fd3a5ca43e2e39f37ec0ac82a7ded2a` | Raw denominator, stage outcomes, scoped counters, receipts, and artifact bindings |
| [`phase2-feature-assurance-ce2-evidence-record.json`](../../contracts/v0.2.0/examples/phase2-feature-assurance-ce2-evidence-record.json) | `3f380d385e8acc9a8515fa49c5222919dee7a06a037ff22472b3b658d06f947e` | Exact claim, evaluation boundary, validity assessment, lifecycle, and nonclaims |
| [`config/feature_assurance_ce2_campaign_plan.json`](../../config/feature_assurance_ce2_campaign_plan.json) | `25538fb7904e8ac7f897c1bb2df6bea8e87a28b4e6925a4195b6a29bd9b1b856` | Commit-frozen scenario registry and project-controlled expectations |
| [`contracts/v0.2.0/feature-assurance-ce2-campaign.schema.json`](../../contracts/v0.2.0/feature-assurance-ce2-campaign.schema.json) | `17530ea30238cc6ca64620472b4f47dcb5650dbbc9d1777c1130af5e4b79b3d7` | Closed schema for profile, result rows, and summary |

The artifacts and review remain project-controlled and self-custodied. These hashes are integrity bindings, not external signatures or independent custody.

## Verification

Run from the repository root:

```bash
python scripts/generate_feature_assurance_ce2_campaign.py --validate-plan
python -m scripts.validate_claim_evidence \
  --record contracts/v0.2.0/examples/phase2-feature-assurance-ce2-evidence-record.json \
  --profile P2-CE-004
```

The claim-evidence command validates the committed bundle and freshly re-executes the frozen evaluator without rewriting the published artifacts. An optional direct byte-comparison check is:

```bash
python scripts/generate_feature_assurance_ce2_campaign.py \
  --implementation-commit 53e409d6ffa4af98ea892bc1a81302bf30870693 \
  --evaluated-at 2026-08-15T12:13:03Z \
  --check
```

That optional check is a new verification execution and is not added to the published 32-attempt denominator.

## Limits and prohibited inferences

This bundle does not establish:

- performance on historical or live identity incidents, source-system correctness, operational calibration, or efficacy;
- a real approval, authenticated approver or source, custody truth, privacy compliance, effective de-identification, or records-management compliance;
- correctness of `source_conflict`, evidence quality, model probability, policy/disposition, verifier behavior, or the full source-to-decision path;
- a live or shadow feed, production deployment, authorization for containment, or a target-side outcome;
- OS-level isolation, filesystem nonaccess, process-wide network nonuse, non-egress, external custody, or tamper resistance;
- independent replication, independent assurance, or external preregistration;
- exhaustive mutation coverage, statistical representativeness, a bounded failure rate, zero risk, or production readiness; or
- alignment, misalignment, scheming, sabotage resistance, sandbagging, or monitor effectiveness.

Any bound source, dependency declaration, schema, plan, runtime, seed, budget, wording, claim class, or downstream integration change invalidates this record and requires a new result rather than overwriting this one. The claim expires at `2026-11-13T12:13:03Z` unless a revalidation trigger occurs earlier.
