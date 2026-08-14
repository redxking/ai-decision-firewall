# AI Decision Firewall

**Current baseline:** v0.1.0 proof of concept  
**Decision domain:** privileged-identity containment  
**Operational status:** synthetic data and an in-memory action simulator only  
**Safety boundary:** not approved for production integration, operational decision-making, or live containment

AI systems can rank alerts and recommend actions, but consequential operations require a stronger control boundary: the system must determine whether the available evidence is trustworthy and sufficient, whether an action is within delegated authority, and whether the intended effect actually occurred.

This repository implements an **AI Decision Firewall**—a model-agnostic control plane between AI-assisted analysis and operational execution. The first bounded decision is:

> Based on the available evidence, should suspicious privileged-identity activity result in no action, further investigation, reversible low-impact containment, or escalation to a human authority?

The model is advisory. Deterministic policy, independent verification, scoped authorization, and post-action verification control the action boundary.

## Why this problem matters

An alert score or model confidence is not action authority. Real telemetry can be stale, incomplete, contradictory, duplicated, or adversarially manipulated. The operational cost of a false containment can also differ radically by identity, asset, mission, and timing.

The POC therefore treats the decision as an evidence-and-authority problem, not merely a classification problem. It is designed to make five questions explicit and testable:

1. What evidence supports the decision, and where did it come from?
2. Is that evidence fresh, intact, corroborated, and sufficient for the proposed consequence?
3. Is the proposed action permitted for this case, identity, asset, and risk level?
4. Did an independent control agree before authorization was issued?
5. Did the target reach the intended state, or did execution fail or remain uncertain?

## POC scope

Version 0.1 implements a complete synthetic decision transaction for privileged identities:

- deterministic generation of benign, malicious, ambiguous, degraded-telemetry, break-glass, sensor-conflict, and evidence-poisoning scenarios;
- separate runtime evidence and evaluator-only ground-truth files;
- structured evidence from simulated identity, endpoint, network, threat-intelligence, CMDB, change-management, workforce, travel, and ticketing sources;
- evidence-quality assessment for provenance, integrity, freshness, source diversity, corroboration, missing telemetry, conflicts, and adversarial instructions;
- an interpretable logistic risk model used only as an advisory component;
- deterministic selection of `NO_ACTION`, `INVESTIGATE`, `CONTAIN_REVERSIBLE`, or `ESCALATE_HUMAN`;
- independent, non-model verification of the decision and action boundary;
- HMAC-SHA-256-signed, short-lived, case-bound, action-scoped authorization tokens;
- an in-memory identity-provider simulator for session revocation, step-up authentication, and increased monitoring;
- deliberate downstream failure injection and post-action state verification against the simulator result;
- a SHA-256 hash-chained audit log, evaluation reports, requirements traceability, and automated safety tests.

There are no production credentials, production connectors, or external action interfaces in this repository.

## Architecture

```text
Synthetic evidence
      |
      v
Schema and evidence-quality assessment -----> Traceable evidence record
      |
      v
Allow-listed features -----> Advisory risk model
      |                            |
      +-------------+--------------+
                    v
          Deterministic policy engine
                    |
                    v
           Independent verifier
                    |
          approved reversible action?
              /                 \
            no                   yes
            |                     |
   abstain or escalate     scoped authorization token
                                  |
                                  v
                         simulated action broker
                                  |
                                  v
                         post-action verification
                                  |
                                  v
                          hash-chained audit log
```

![AI Decision Firewall logical architecture](docs/architecture/02_logical_architecture.png)

The model has no signing key, target credentials, action-broker reference, or direct execution path. Only an independently verified, policy-compliant proposal can cause the authorization gate to mint a token. The broker validates that token before changing simulated state.

Additional diagrams are available in [`docs/architecture/`](docs/architecture/), including the system context, decision state machine, and trust boundaries.

## Safety and authority model

The executable safety invariants are:

- free text is treated as untrusted content and never as action authority;
- ground truth is evaluator-only and never enters a runtime decision;
- only allow-listed structured fields enter the risk model;
- missing, stale, conflicted, poisoned, or low-integrity evidence forces abstention;
- canonical cases marked as break-glass or above the configured asset-criticality threshold require human authority;
- human-only actions cannot appear in an autonomous authorization token;
- no token is issued without independent-verifier approval;
- tokens are signed, short-lived, case-bound, and action-scoped;
- no action is declared successful solely because a command returned success;
- material decision and execution events are recorded in a tamper-evident audit chain.

The three POC action types—revoke active sessions, require step-up authentication, and increase monitoring—operate only against the in-memory simulator. The `CONTAIN_REVERSIBLE` label means bounded and operationally recoverable in this POC; it does not imply exact transactional reversal. For example, a revoked session is recovered through reauthentication rather than restoration of the original session. Account disablement, endpoint isolation, network blocking, and persistent policy changes remain human-only in policy and are not implemented as live actions.

See [`docs/SECURITY_AND_SAFETY_CASE.md`](docs/SECURITY_AND_SAFETY_CASE.md) for the argument structure and residual risks.

## Reproducible synthetic baseline

The included baseline uses seed `20260814`, 800 synthetic training cases, and 400 synthetic evaluation cases. The evaluation set contains 187 compromised and 213 benign cases.

| Measure | Included result |
|---|---:|
| `NO_ACTION` | 161 cases |
| `INVESTIGATE` | 64 cases |
| `CONTAIN_REVERSIBLE` | 112 cases |
| `ESCALATE_HUMAN` | 63 cases |
| Expected-disposition agreement | 98.75% |
| False autonomous containment | 0 cases |
| Unsafe automation under encoded test rules | 0 cases |
| Autonomous actions involving poisoned evidence | 0 cases |
| Evidence-ID trace coverage | 100% |
| Authorization without independent-verifier approval | 0 cases |
| Simulated command-execution success | 97.6% |
| Complete post-action verification | 92.9% |
| Audit-chain verification | Valid |
| Automated tests | 7 of 7 passed |

The lower execution and post-action verification rates are intentional: deterministic downstream failures test whether the system distinguishes an accepted command from a verified state change.

The trace-coverage metric confirms that every cited and feature-linked event ID resolves to an input event. It does not validate the semantic truth, cryptographic provenance, or completeness of that evidence.

The v0.1 verifier evaluates the state returned by the in-memory simulator. It is not an independent readback from a production target. Independent target observation is a requirement for later controlled-action phases.

These results establish that the encoded control and safety invariants are executable and reproducible against the supplied generator. They **do not** establish operational detection accuracy, real-world false-positive rates, production safety, or suitability for live containment. The model and evaluation data share the same synthetic scenario family, so model-performance metrics are intentionally optimistic.

The complete results are in [`outputs/baseline/metrics.json`](outputs/baseline/metrics.json) and the self-contained [`baseline_report.html`](outputs/baseline/baseline_report.html).

## Run the POC

Requirements: Python 3.11 or later and NumPy.

```bash
git clone https://github.com/redxking/ai-decision-firewall.git
cd ai-decision-firewall

python -m venv .venv
# Linux/macOS
source .venv/bin/activate
# Windows PowerShell
# .venv\Scripts\Activate.ps1

python -m pip install --upgrade pip
python -m pip install -r requirements.txt
python run_poc.py
```

The default run regenerates the dataset, trains the synthetic advisory model, processes 400 cases, verifies the audit chain, and writes artifacts to `outputs/baseline/`.

The default paths are tracked baseline artifacts, so this command rewrites `data/` and `outputs/baseline/`. Use temporary or separate directories when you want to preserve the checked-in baseline:

```bash
python run_poc.py \
  --data-dir /tmp/adf-data \
  --output-dir /tmp/adf-output
```

Run the safety and pipeline tests:

```bash
PYTHONPATH=src python -m unittest discover -s tests -v
```

Run with different synthetic counts, seed, or output location:

```bash
python run_poc.py \
  --train-count 800 \
  --test-count 400 \
  --seed 20260814 \
  --output-dir outputs/baseline
```

Rebuild the editable engineering baseline after changing its source inputs:

```bash
python -m pip install -r requirements-docs.txt
python docs/build_engineering_doc.py
```

Verify the imported v0.1 package files against the integrity manifest:

```bash
shasum -a 256 -c MANIFEST.sha256
```

## Repository layout

```text
.
├── config/
│   └── policy.json                 # Decision, evidence, authority, and safety policy
├── data/                           # Synthetic cases and separate evaluator labels
├── docs/
│   ├── adr/                        # Architecture decision records
│   ├── architecture/               # Source and rendered diagrams
│   ├── CONCEPT_OF_OPERATIONS.md
│   ├── REQUIREMENTS_TRACEABILITY_MATRIX.csv
│   ├── SECURITY_AND_SAFETY_CASE.md
│   ├── SYNTHETIC_DATA_CARD.md
│   └── TEST_AND_EVALUATION_PLAN.md
├── outputs/baseline/               # Reproducible decisions, metrics, audit, and report
├── src/adf_poc/                    # Decision-control implementation
├── tests/                          # Safety and end-to-end tests
├── run_poc.py                      # End-to-end synthetic baseline entry point
├── pyproject.toml
└── requirements.txt
```

## Limitations and non-claims

The current baseline has not established:

- performance against historical or live identity, endpoint, network, or cloud telemetry;
- generalization to unseen attack or benign-administration patterns;
- operational false-positive or false-negative rates;
- analyst agreement, workflow fit, or mission/business consequences;
- behavior under vendor API semantics, race conditions, eventual consistency, or production-scale load;
- cryptographic provenance rooted in enterprise trust infrastructure;
- production key management, token replay protection, or durable broker idempotency;
- an externally anchored or independently signed audit trail (a process able to rewrite the log can recompute the v0.1 hash chain);
- independent target-state readback or executable rollback orchestration;
- reconciliation of conflicting break-glass or asset-criticality values between top-level case context and evidence events;
- suitability for safety-critical, operational-technology, or critical-infrastructure control environments.

The policy engine and verifier also share configuration and may share design defects. The POC signing key has a documented non-production fallback. These limitations are deliberate release constraints, not deferred permission to connect the software to a live environment.

## Roadmap

The next step is **Phase 2: historical replay and shadow-mode framework**, with live actions remaining disabled.

Phase 2 will introduce a canonical evidence contract, de-identified historical-case ingestion, replay manifests, read-only adapter boundaries, analyst adjudication contracts, counterfactual evaluation, source-availability and schema-gap metrics, temporal and adversarial validation, and explicit release gates. It will not enable production containment.

Later phases, each requiring separate evidence and authorization, are:

1. live read-only shadow evaluation in an approved environment;
2. reversible actions against non-production test identities under change control;
3. a limited operational pilot with human approval for all actions;
4. action-class-specific autonomy only if statistically and operationally defensible gates are met and an authorizing official accepts the residual risk.

See [`docs/ROADMAP.md`](docs/ROADMAP.md) for the full sequence and exit conditions.

## Documentation

- [`DELIVERY_NOTES.md`](DELIVERY_NOTES.md) — v0.1 scope, results, and handoff
- [`docs/AI_Decision_Firewall_POC_Engineering_Baseline_v0.1.pdf`](docs/AI_Decision_Firewall_POC_Engineering_Baseline_v0.1.pdf) — engineering baseline
- [`docs/CONCEPT_OF_OPERATIONS.md`](docs/CONCEPT_OF_OPERATIONS.md) — actors, modes, decisions, and off-nominal behavior
- [`docs/REQUIREMENTS_TRACEABILITY_MATRIX.csv`](docs/REQUIREMENTS_TRACEABILITY_MATRIX.csv) — requirement-to-design-and-test traceability
- [`docs/MODEL_CARD.md`](docs/MODEL_CARD.md) — advisory model purpose, performance, and limits
- [`docs/SYNTHETIC_DATA_CARD.md`](docs/SYNTHETIC_DATA_CARD.md) — dataset design and appropriate use
- [`docs/TEST_AND_EVALUATION_PLAN.md`](docs/TEST_AND_EVALUATION_PLAN.md) — acceptance criteria and required next-phase tests

## Licensing

No open-source license is included in the v0.1 package. Public availability of this repository does not itself grant permission to use, modify, or redistribute the work.
