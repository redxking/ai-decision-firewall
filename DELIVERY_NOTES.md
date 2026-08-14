# AI Decision Firewall POC v0.1 — Delivery Notes

**Delivery date:** 2026-08-14  
**Author:** Angelis Pseftis  
**Status:** Working engineering baseline  
**Restriction:** Synthetic data and simulated reversible actions only. Not approved for production integration, operational decision-making, or live containment.

## Objective

Demonstrate that an AI-assisted cybersecurity decision can be placed inside an enforceable decision-control architecture that separates evidence, model advice, deterministic policy, independent verification, authorization, action execution, post-action verification, and audit.

The bounded POC decision is whether suspicious privileged-identity activity should result in no action, additional investigation, reversible containment, or human escalation.

## Delivered capability

The package contains a deterministic synthetic-data generator, an advisory interpretable risk model, evidence-quality assessment, four-way disposition logic, an independent verifier, signed and scoped authorization tokens, an in-memory identity-system simulator, post-action verification, a tamper-evident audit chain, automated tests, architecture diagrams, requirements traceability, and a 32-page engineering baseline.

## Reproduce the baseline

```bash
python -m venv .venv
# Windows: .venv\Scripts\activate
# Linux/macOS: source .venv/bin/activate
pip install -r requirements.txt
python run_poc.py
PYTHONPATH=src python -m unittest discover -s tests -v
```

The default run uses seed `20260814`, generates 800 training cases and 400 test cases, and writes results to `outputs/baseline/`.

## Included baseline result

The supplied 400-case synthetic evaluation produced 112 reversible-containment decisions, zero false autonomous containment decisions, zero unsafe automation, zero autonomous actions on poisoned evidence, 100 percent evidence-ID trace coverage, zero authorization without independent-verifier approval, and a valid audit chain. Trace coverage means cited and feature-linked identifiers resolve to supplied input events; it is not semantic or cryptographic provenance validation. Deliberate downstream failures reduce simulated command success to 97.6 percent and complete post-action verification to 92.9 percent.

These results validate software behavior against the included synthetic generator. They do not establish real-world detection accuracy or production safety because training and test cases share the same synthetic scenario family.

## Recommended next phase

Proceed to de-identified historical replay and data-contract discovery under a strict no-live-action constraint. The next phase should measure telemetry availability, source trust, schema gaps, analyst agreement, calibration, counterfactual decision quality, and failure behavior before any consideration of production connectivity.

## Primary review artifacts

- `docs/AI_Decision_Firewall_POC_Engineering_Baseline_v0.1.docx`
- `outputs/baseline/baseline_report.html`
- `README.md`
- `docs/REQUIREMENTS_TRACEABILITY_MATRIX.csv`
- `docs/SECURITY_AND_SAFETY_CASE.md`
- `docs/TEST_AND_EVALUATION_PLAN.md`
- `outputs/baseline/unit_test_results.txt`
