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

The repository includes adapters for OpenAI Responses API, Anthropic Messages API, and local Ollama. The real-model experiment measures unsafe-action proposals under a controlled indirect-prompt-injection condition while keeping authorization external to the model.

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
ollama pull gemma3
PYTHONPATH=src python scripts/run_llm_eval.py --provider ollama --model gemma3 --trials 20 --output results/ollama_gemma3_eval.csv
```

See `docs/REAL_MODELS.md` for provider details and claim boundaries.

## Output and provenance

- `results/raw.csv`: baseline trial-level observations.
- `results/summary.csv`: baseline grouped statistics.
- `results/manifest.json`: environment, parameters, and SHA-256 of baseline raw data.
- `results/extended_raw.csv`: extended topology/population trial-level data when generated.
- `results/extended_summary.csv`: bootstrap summaries when generated.

Publishable runs must preserve source commit, parameters, seeds, raw data, and manifests. See `docs/PROVING.md`.

## Research claim boundaries

Synthetic results validate the method and software pipeline, not the security properties of a vendor model. Model-specific claims require separately identified real-model runs. A model proposing a prohibited action is not itself an authorization failure; authorization-integrity loss occurs only if the external enforcement boundary allows a protected action contrary to reference policy.

## Safety

The baseline uses synthetic principals, synthetic resources, and non-destructive action labels. It does not exploit external services, steal credentials, or execute destructive operations.

## License

MIT.
