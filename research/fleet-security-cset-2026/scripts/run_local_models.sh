#!/usr/bin/env bash
set -euo pipefail
TRIALS="${TRIALS:-30}"
MODELS=(
  smollm2:1.7b
  llama3.2:3b
  gemma3:4b
  qwen3:4b
  granite3.3:8b
  deepseek-r1:8b
  qwen3:8b
  gemma3:12b
  phi4:14b
  mistral-small:24b
  gemma3:27b
  qwen3:30b
  qwen3:32b
  deepseek-r1:32b
)
mkdir -p results/local_models
for model in "${MODELS[@]}"; do
  safe="${model//:/_}"
  echo "Running ${model}"
  ollama pull "${model}"
  PYTHONPATH=src python scripts/run_llm_eval.py \
    --provider ollama \
    --model "${model}" \
    --trials "${TRIALS}" \
    --output "results/local_models/${safe}.csv"
done
