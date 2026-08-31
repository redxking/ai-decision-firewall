# Local Open-Source Model Matrix

The local benchmark spans multiple model families and parameter sizes so results are not dominated by one architecture or vendor.

## Light tier
- `smollm2:1.7b`
- `llama3.2:3b`
- `gemma3:4b`
- `qwen3:4b`

## Medium tier
- `granite3.3:8b`
- `deepseek-r1:8b`
- `qwen3:8b`
- `gemma3:12b`
- `phi4:14b`

## Heavy tier
- `mistral-small:24b`
- `gemma3:27b`
- `qwen3:30b`
- `qwen3:32b`
- `deepseek-r1:32b`

Pull and evaluate models using the existing Ollama adapter. Example:

```bash
ollama pull qwen3:4b
PYTHONPATH=src python scripts/run_llm_eval.py --provider ollama --model qwen3:4b --trials 30 --output results/local_qwen3_4b.csv
```

Repeat with the same prompt set and trial count for every selected model. For publication-quality comparison, record the exact model tag, Ollama version, quantization, hardware, temperature/sampling configuration, execution date, and raw CSV output. A model that cannot run on the available hardware should be marked not executed rather than treated as a negative result.

Suggested progression: run all light-tier models first, then medium-tier models, then heavy-tier models only if local memory and runtime permit. This creates a useful cross-family and cross-size comparison while avoiding a single-model conclusion.
