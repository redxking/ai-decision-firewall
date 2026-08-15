# AI Decision Firewall POC v0.1 — Delivery Notes

> **Historical delivery record.** This document preserves the 14 August 2026 v0.1 handoff and its exact results. `0.2.0-alpha.5` remains the prior published evidence baseline. Exact Commit `08ce203c` is the predecessor untagged `0.2.0-alpha.6` design-freeze baseline; its historical CI and Dependency Graph results remain bound to that commit. The complete Phase 2.5 package was subsequently published on `main` at exact Commit `854b15c56397a81de6326b719d3d7d1dc847608f`; its exact-commit CI and Dependency Graph checks passed. That boundary includes 222/222 Phase 2.5 technical tests, separate 9/9 public-site tests, the then-current 231/231 aggregate, a generated-and-verified integrity manifest, and inspected final-source status renders. The site module is outside Phase 2.5 evidence. The tracked data, model, and baseline-output bytes remain at their committed baselines. No tag, release/evidence package, historical-data approval, Gate B package, live feed, operational connector, or action authority exists. `P2-CE-005` is CE-0 `NOT_EVALUATED`. Phase 3 `0.3.0-alpha.1` is a separate uncommitted local simulation-only candidate; its current 57/57 focused, 288/288 full-suite, demo PASS, and 46/46 corpus observations do not alter this historical record.

**Delivery date:** 2026-08-14  
**Author:** Angelis Pseftis  
**Status:** Historical working engineering baseline
**Restriction:** Synthetic data and simulated reversible actions only. Not approved for production integration, operational decision-making, or live containment.

## Objective

Demonstrate that an AI-assisted cybersecurity decision can be placed inside an enforceable decision-control architecture that separates evidence, model advice, deterministic policy, functionally separate deterministic non-model verification, authorization, action execution, post-action verification, and audit. The verifier is not organizationally independent.

The bounded POC decision is whether suspicious privileged-identity activity should result in no action, additional investigation, reversible containment, or human escalation.

## Delivered capability

The package contains a deterministic synthetic-data generator, an advisory interpretable risk model, evidence-quality assessment, four-way disposition logic, a functionally separate deterministic non-model verifier, signed and scoped authorization tokens, an in-memory identity-system simulator, post-action verification, a SHA-256 hash-chained audit log, automated tests, architecture diagrams, requirements traceability, and a 32-page engineering baseline. The verifier is not organizationally independent. The self-custodied chain supports internal consistency checks; it is not resistant to wholesale replacement by a writer that can recompute the chain.

## Run the POC locally

```bash
python -m venv .venv
# Windows: .venv\Scripts\activate
# Linux/macOS: source .venv/bin/activate
pip install -r requirements.txt
python run_poc.py
PYTHONPATH=src python -m unittest discover -s tests -v
```

At the v0.1 delivery, the default run used seed `20260814`, generated 800 training cases and 400 test cases, and wrote results to `outputs/baseline/`. The current command writes ignored local data and output artifacts under `data/local/synthetic-baseline/` and `outputs/local/synthetic-baseline/` so an ordinary run cannot replace the governed baseline. It does not promise byte-identical model reconstruction across permitted numeric runtimes.

## Included baseline result

The supplied 400-case synthetic evaluation produced 112 reversible-containment decisions, zero false autonomous containment decisions, zero unsafe automation, zero autonomous actions on poisoned evidence, 100 percent evidence-ID trace coverage, zero authorization without independent-verifier approval, and a valid audit chain. Trace coverage means cited and feature-linked identifiers resolve to supplied input events; it is not semantic or cryptographic provenance validation. Deliberate downstream failures reduce simulated command success to 97.6 percent and complete post-action verification to 92.9 percent.

These results validate software behavior against the included synthetic generator. They do not establish real-world detection accuracy or production safety because training and test cases share the same synthetic scenario family.

## Recommendation at the v0.1 delivery

Proceed to de-identified historical replay and data-contract discovery under a strict no-live-action constraint. The next phase should measure telemetry availability, source trust, schema gaps, analyst agreement, calibration, counterfactual decision quality, and failure behavior before any consideration of production connectivity.

That recommendation was a proposed direction, not an approval to acquire or process historical data. Subsequent work implemented a synthetic-only read-only replay boundary, record qualification, Gate B machine preflight, exact audit checks, Phase 2.4 feature assurance, and a published Phase 2.5 source-to-decision package. `P2-CE-005` was not executed, no externally authenticated Gate B package exists, and no historical pilot has begun. The separate local Phase 3 simulation candidate does not change those data/authority boundaries.

## Primary review artifacts

- `docs/AI_Decision_Firewall_POC_Engineering_Baseline_v0.1.docx`
- `outputs/baseline/baseline_report.html`
- `README.md`
- `docs/REQUIREMENTS_TRACEABILITY_MATRIX.csv`
- `docs/SECURITY_AND_SAFETY_CASE.md`
- `docs/TEST_AND_EVALUATION_PLAN.md`
- `outputs/baseline/unit_test_results.txt`

The DOCX/PDF and the seven-test result remain v0.1 artifacts. Current Phase 2 status, requirements, and claim limits are maintained in `README.md` and `docs/phase2/`; the v0.1 engineering baseline must not be overwritten to imply later-phase validation.
