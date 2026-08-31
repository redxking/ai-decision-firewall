#!/usr/bin/env bash
set -euo pipefail
export PYTHONPATH="${PYTHONPATH:-}:src"
python scripts/selftest.py
python -m fleetsec.cli smoke --seed 123
python -m fleetsec.cli run --populations 1,4 --auth-models least_privilege,shared_privilege --repetitions 3 --steps 5 --output results/verify_raw.csv --manifest results/verify_manifest.json
python -m fleetsec.cli analyze --input results/verify_raw.csv --output results/verify_summary.csv
echo "verification complete"
