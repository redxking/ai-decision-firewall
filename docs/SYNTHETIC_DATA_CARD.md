# Synthetic Data Card

> **Version boundary.** The dataset below remains the v0.1.0 generated training/test baseline. `0.2.0-alpha.5` is the prior published evidence baseline. Exact Commit `08ce203c` is the predecessor untagged `0.2.0-alpha.6` Phase 2.5 design-freeze baseline, with historical CI and Dependency Graph success bound to that commit. This package candidate's Phase 2.5 technical suite passed 222/222; the separate public-site module passed 9/9; and the combined repository aggregate passed 231/231. The site module is outside Phase 2.5 evidence and does not validate the dataset. The candidate includes a generated-and-verified integrity manifest and inspected final-source status renders. Package publication and GitHub CI on the exact published package commit remain external gates. Tracked data and baseline outputs remain at their committed bytes. No tag, release, or evidence package exists. Phase 2 fixtures and campaign inputs are separate synthetic controls; they do not create a new historical dataset or an observed `P2-CE-005` result.

## Dataset identity

**Name:** ADF Synthetic Privileged Identity Dataset  
**Version:** 0.1.0  
**Generator seed:** 20260814  
**Default partitions:** 800 training cases and 400 test cases

## Intended use

The dataset exists to exercise architecture, policy, safety, auditability, and test automation before real telemetry is available. It is suitable for software testing, interface development, requirements validation, and failure-mode analysis. It is not suitable for estimating real-world attack prevalence, detection efficacy, analyst workload, or production risk.

## Data separation

Case input files contain only case metadata and evidence events. Ground-truth files contain scenario, compromise label, expected disposition, and rationale. Runtime engine code receives only the case file. The evaluator joins decisions with labels after execution.

## Evidence sources represented

- Identity provider
- Endpoint detection and response
- Network analytics
- Threat intelligence
- Asset inventory / CMDB
- Change management
- Workforce travel context
- Free-text ticket content

Each event includes event identity, case identity, source type and instance, observation and collection times, integrity status, provenance identifier, source trust, entity references, structured attributes, and optional untrusted text.

## Scenario catalog

Malicious scenarios include stolen privileged tokens, password spray followed by success, credential dumping with lateral movement, and malicious OAuth consent. Benign scenarios include approved travel, VPN geolocation artifacts, approved maintenance, known service-account batch activity, and a break-glass drill. Ambiguous or adversarial scenarios include sensor conflict, telemetry gaps, and prompt-injection content embedded in a ticket.

## Generation limitations

The generator encodes the engineering team's current assumptions. Feature relationships, base rates, event correlations, source reliability, attack timing, and contextual evidence are simplified. The model is trained and tested on partitions from the same generator family, so apparent discrimination is optimistic. Real data will exhibit unmodeled vendor differences, missing fields, semantic drift, adversarial adaptation, human process variation, and class imbalance.

## Additional Phase 2 synthetic fixtures

These versioned controls are distinct from the v0.1 train/test partitions:

| Fixture or campaign | Synthetic scope | Evidence status |
|---|---|---|
| Phase 2 starter | Three read-only cases | Published version-bound `P2-CE-001`; zero historical cases |
| Phase 2.1 qualification | Seven nonblank records: three accepted and four deliberately quarantined | Published version-bound `P2-CE-002`; designed accounting result, not a data-quality estimate |
| Phase 2.3 Gate B campaign | Ephemeral test-only authorization and fixed positive/negative scenarios | Published `P2-CE-003` SELF synthetic result; not an actual approval or historical pilot |
| Phase 2.4 feature-assurance campaign | Fixed clean/mutant feature-contract and projection controls | Published `P2-CE-004` SELF synthetic result; not model or operational validation |
| Phase 2.5 source-to-decision campaign | Ten planned clean/mutant pairs per run and two planned runs | CE-0 `NOT_EVALUATED`; expected outcomes are not observations |

All committed observed results declare `historical_case_count: 0`. Synthetic campaign inputs are designed controls and are not representative samples of an operational identity environment.

## Required dataset evolution

A future dataset release—not merely a code version bump—would require approved de-identified historical replay under Gate B, vendor-specific schema mappings, analyst disagreement and indeterminate adjudications, uncertain outcome treatment, delayed and duplicate evidence, multi-identity campaigns, and sector-specific mission consequence. The current code already tests some delayed/out-of-order, duplicate-identifier, malformed-record, and source-conflict mechanics with synthetic controls; that does not satisfy the historical-data, vendor-semantic, representativeness, privacy, or adjudication obligations.

Historical data must not be added to the public repository. Any future restricted dataset requires authenticated authority, tested de-identification, protected custody, complete-intake accounting, predeclared sampling and stop conditions, and evidence lifecycle controls described in [`phase2/GATE_B_HISTORICAL_PILOT.md`](phase2/GATE_B_HISTORICAL_PILOT.md).
