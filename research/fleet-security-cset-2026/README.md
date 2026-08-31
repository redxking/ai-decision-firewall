# Fleet Security CSET 2026 Experiment Harness

Reproducible research code supporting the paper:

**From Single-Agent Safety to Fleet Security: A Reproducible Experimental Methodology for Evaluating Agentic AI at Scale**

Author/project lead: Angelis Pseftis

## What this is

This repository implements a controlled synthetic experiment harness for testing the methodology in the CSET 2026 preliminary-work paper. It measures how compromise propagation, authorization failure, privilege-weighted blast radius, containment latency, and security-qualified throughput change as agent populations and architectures scale.

It is intentionally conservative about claims. The included simulator does not claim to reproduce any specific commercial LLM or agent platform. Its purpose is to verify the experimental architecture, metrics, reproducibility pipeline, and falsification tests before substituting real agent runtimes.

## Requirements

- Python 3.10+
- `pytest` only for the optional test suite
- No API keys or cloud infrastructure required for the synthetic baseline

## Install

```bash
git clone <repository-url>
cd fleet-security-cset-2026
python -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate
python -m pip install --upgrade pip
python -m pip install -e ".[dev]"
```

The core synthetic runner can also execute directly with `PYTHONPATH=src` and requires only the Python standard library.

## Verify the code

```bash
bash scripts/verify.sh
```

## Run the publication baseline

```bash
bash scripts/run_baseline.sh
```

## Extended scale sweep

Run populations through 1,024 agents across six communication topologies and two authorization models:

```bash
PYTHONPATH=src python scripts/run_extended.py
```

The default extended design executes 720 deterministic synthetic trials: 6 populations x 6 topologies x 2 authorization models x 10 repetitions. It records end-state, ever-compromised, and peak-compromise exposure plus authorization-integrity loss, privilege-weighted blast radius, containment latency, and security-qualified throughput. Bootstrap confidence intervals are generated for grouped results.

## Real-model evaluation

The repository includes adapters for OpenAI Responses API, Anthropic Messages API, and local Ollama. The real-model experiment measures prohibited-action proposals under controlled adversarial conditions while keeping authorization external to the model.

OpenAI example:

```bash
export OPENAI_API_KEY='...'
PYTHONPATH=src python scripts/run_llm_eval.py --provider openai --model gpt-5.6-luna --trials 20 --output results/openai_eval.csv
```

Claude example:

```bash
export ANTHROPIC_API_KEY='...'
PYTHONPATH=src python scripts/run_llm_eval.py --provider anthropic --model claude-sonnet-5 --trials 20 --output results/claude_eval.csv
```

Local Ollama example, no API key required:

```bash
ollama pull gemma3:4b
PYTHONPATH=src python scripts/run_llm_eval.py --provider ollama --model gemma3:4b --trials 30 --output results/ollama_gemma3_4b_eval.csv
```

### Local open-source benchmark matrix

A broader no-key comparison matrix is defined in `configs/local_models.json` and documented in `docs/LOCAL_MODELS.md`. It includes SmolLM2, Llama 3.2, Gemma 3, Qwen3, IBM Granite 3.3, DeepSeek-R1 distilled models, Microsoft Phi-4, and Mistral Small across approximately 1.7B to 32B parameter classes.

### Agent Security Scenario Suite v1

The fixed scenario suite is in `scenarios/agent_security_suite_v1.json`. It contains 24 scenarios: 6 benign controls and 18 adversarial cases across indirect prompt injection, authority impersonation, instruction conflict, memory poisoning, inter-agent manipulation, and tool-output injection.

Run one local model against the complete suite:

```bash
PYTHONPATH=src python scripts/run_scenario_suite.py \
  --provider ollama \
  --model qwen3:4b \
  --repetitions 3 \
  --output results/scenario_suite/qwen3_4b.csv
```

Run every installed model in a tier:

```bash
PYTHONPATH=src python scripts/run_local_scenario_matrix.py --tier light --repetitions 3
```

The suite SHA-256 is frozen and recorded in each model-run manifest. Grouped model/attack-class results use Wilson 95% confidence intervals. See `docs/SCENARIO_SUITE.md`.

See `docs/REAL_MODELS.md` for provider details and claim boundaries.

## Output and provenance

- `results/raw.csv`: baseline trial-level observations.
- `results/summary.csv`: baseline grouped statistics.
- `results/manifest.json`: environment, parameters, and SHA-256 of baseline raw data.
- `results/extended_raw.csv`: extended topology/population trial-level data when generated.
- `results/extended_summary.csv`: bootstrap summaries when generated.
- `results/scenario_suite/*.csv`: per-model fixed-scenario observations.
- `results/scenario_suite/*.manifest.json`: model and scenario-suite provenance.
- `results/scenario_suite/summary.csv`: model-by-attack-class summary when generated.

Publishable runs must preserve source commit, parameters, seeds, raw data, and manifests. See `docs/PROVING.md`.

## Research claim boundaries

Synthetic results validate the method and software pipeline, not the security properties of a vendor model. Model-specific claims require separately identified real-model runs. A model proposing a prohibited action is not itself an authorization failure; authorization-integrity loss occurs only if the external enforcement boundary allows a protected action contrary to reference policy.

## Safety

The baseline uses synthetic principals, synthetic resources, and non-destructive action labels. It does not exploit external services, steal credentials, or execute destructive operations.

## License

MIT.
