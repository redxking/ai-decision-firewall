#!/usr/bin/env bash
set -euo pipefail
export PYTHONPATH="${PYTHONPATH:-}:src"
python -m fleetsec.cli run --populations 1,4,16,64 --auth-models least_privilege,shared_privilege --repetitions 30 --topology ring --steps 20 --seed 20260831 --output results/raw.csv --manifest results/manifest.json
python -m fleetsec.cli analyze --input results/raw.csv --output results/summary.csv
