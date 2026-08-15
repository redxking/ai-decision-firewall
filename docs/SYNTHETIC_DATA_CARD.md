# Synthetic Data Card

> **Version boundary.** The dataset below remains the v0.1.0 generated
> training/test baseline. Exact Phase 2.5 Commit
> `854b15c56397a81de6326b719d3d7d1dc847608f` is published on `main`, and its
> exact-commit CI/Dependency Graph checks passed. Tracked data and baseline
> outputs remain at their committed bytes. Phase 2 fixtures/campaigns and Phase
> 3 runtime scenarios are separate synthetic controls; they do not create a new
> historical dataset. `P2-CE-005` was not executed and remains CE-0
> `NOT_EVALUATED`.

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

## Phase 3 synthetic runtime fixtures

Phase 3 does not use the v0.1 training/test partitions. It constructs raw
v0.3.0 requests at runtime for two policy-inventory targets:

| Fixture | Synthetic scope | Current observation boundary |
|---|---|---|
| `DOMAIN_CONTROLLER_01` | Tier-0 authentication dependency, stale/conflicting evidence, insufficient Tier-0 agent authority, high consequence | Published raw-request demo returns `ESCALATE`; no authorization/effect |
| `WORKSTATION_042` | Low-criticality endpoint, fresh corroborated evidence, exact workstation-containment authority | Published raw-request demo returns `ALLOW`; one in-memory isolation; same-project readback `VERIFIED` |
| Phase 3 adversarial corpus | 46 declarative canonical, evidence, identity, consequence, authorization, bypass, broker/verifier, metamorphic, and combined cases | 46/46 project-controlled matches at exact Commit `423685d`; exact-commit CI passed |
| Phase 3 focused controls | Contract, credential identity, evidence, policy/consequence, decision, authorization, broker, approval, verifier/fault, audit/metrics, and runner boundaries | 57/57 focused and then-current 288/288 repository tests at exact Commit `423685d` |

Phase 3.1 reuses the 1,200 committed v0.1 synthetic case/label records only to
exercise a temporal training/calibration/evaluation mechanism. The logical
trainer receives training labels only; the project-controlled evaluator holds
all fixture labels to calculate final aggregate metrics. This same-process
separation is not independent custody, and the results are not representative
of operational performance.

The Stage A durability tests create only ephemeral synthetic requests and
temporary local SQLite databases. They add no dataset, historical record,
representative sample, external source, or permission to process one.

Each synthetic evidence item has a canonical content digest and a runtime HMAC
attestation binding source identity/type, provenance, observation time,
support/contradiction semantics, relevance, and subject target. Source keys are
supplied at runtime and are not serialized into the demo/corpus output or
policy. Deterministic corpus key material exists only to reproduce synthetic
tests. This is not enterprise provenance, device identity, PKI/HSM custody,
nonrepudiation, rotation/revocation evidence, or proof that a source assertion
is true.

The Phase 3 targets, evidence, principals, timing, policy, dependencies,
consequences, and injected failures are engineering fixtures. They are not a
representative SOC population and cannot support detection efficacy, action
safety, efficacy, calibration, prevalence, workload, false-containment,
recovery, or mission-impact estimates.

## Required dataset evolution

A future dataset release—not merely a code version bump—would require approved de-identified historical replay under Gate B, vendor-specific schema mappings, analyst disagreement and indeterminate adjudications, uncertain outcome treatment, delayed and duplicate evidence, multi-identity campaigns, and sector-specific mission consequence. The current code already tests some delayed/out-of-order, duplicate-identifier, malformed-record, and source-conflict mechanics with synthetic controls; that does not satisfy the historical-data, vendor-semantic, representativeness, privacy, or adjudication obligations.

Historical data must not be added to the public repository. Any future restricted dataset requires authenticated authority, tested de-identification, protected custody, complete-intake accounting, predeclared sampling and stop conditions, and evidence lifecycle controls described in [`phase2/GATE_B_HISTORICAL_PILOT.md`](phase2/GATE_B_HISTORICAL_PILOT.md).
