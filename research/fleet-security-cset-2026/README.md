# Fleet Security CSET 2026 Experiment Harness

Reproducible research code supporting the paper **From Single-Agent Safety to Fleet Security: A Reproducible Experimental Methodology for Evaluating Agentic AI at Scale**.

Project lead: Angelis Pseftis

## Purpose

This repository implements a controlled synthetic experiment harness for testing the CSET 2026 methodology. It measures compromise propagation, authorization-integrity loss, privilege-weighted blast radius, containment latency, supervisory/security signals, and security-qualified throughput as agent populations and architectures scale.

The included simulator does **not** claim to reproduce any commercial LLM or agent platform. It validates the experiment architecture, metrics, reproducibility pipeline, and falsification tests before real agent runtimes are substituted.

## Requirements

Python 3.10+ is sufficient for the baseline. No API keys or cloud resources are required.

## Run without installing

```bash
cd research/fleet-security-cset-2026
export PYTHONPATH="$PWD/src"
bash scripts/verify.sh
bash scripts/run_baseline.sh
```

## Optional editable install

```bash
python -m venv .venv
source .venv/bin/activate
python -m pip install -e ".[dev]"
```

If build isolation is blocked but setuptools is already available:

```bash
python -m pip install --no-build-isolation -e ".[dev]"
```

## Baseline experiment

The publication baseline evaluates N={1,4,16,64}, least-privilege and shared-privilege authorization models, 30 deterministic repetitions per configuration, and 20 simulation steps. The fixed root seed is 20260831.

Outputs:
- `results/raw.csv`: one row per trial.
- `results/summary.csv`: grouped means and bounded 95% confidence intervals.
- `results/manifest.json`: configuration, environment, and SHA-256 of the raw result file.

## Claim boundaries

Synthetic results validate the **method and software pipeline**, not the security properties of OpenAI, Anthropic, Google, Microsoft, or any other vendor. Vendor-specific claims require a real-agent adapter and separately identified runs.

See `docs/TUNING.md`, `docs/PROVING.md`, and `docs/ARCHITECTURE.md` before modifying the experiment or using its outputs in a publication.

## Safety

The baseline uses synthetic principals, resources, and effects only. It performs no exploitation of external systems, credential theft, or destructive action.

## License

MIT.
