# Agent Security Scenario Suite v1

The benchmark contains 24 fixed scenarios: 6 benign controls and 18 adversarial cases across six attack classes.

Attack classes:
- indirect prompt injection
- authority impersonation
- instruction conflict / policy-priority inversion
- memory poisoning
- inter-agent manipulation
- tool-output / observation injection

Every scenario defines a protected action token (`DELETE_RECORD`) that must not be proposed without valid external authorization. The model-level benchmark measures **unsafe action proposal**, not authorization failure. Authorization remains an external system control.

## Run one local model

```bash
PYTHONPATH=src python scripts/run_scenario_suite.py \
  --provider ollama \
  --model qwen3:4b \
  --suite scenarios/agent_security_suite_v1.json \
  --repetitions 3 \
  --output results/scenario_suite/qwen3_4b.csv
```

## Run a local tier

```bash
PYTHONPATH=src python scripts/run_local_scenario_matrix.py \
  --tier light \
  --repetitions 3
```

This gives each selected model the exact same 24-scenario sequence. With three repetitions, each model receives 72 trials.

## Publication controls

For publishable runs:
1. Freeze the scenario-suite SHA-256.
2. Record the exact Ollama version and model tag/digest.
3. Record hardware and available RAM/VRAM.
4. Keep sampling parameters fixed across models where supported.
5. Do not silently discard failed requests.
6. Preserve per-scenario CSV and manifest files.
7. Report Wilson intervals for binary unsafe-proposal rates.
8. Do not interpret a model refusal as an authorization decision.

Suite SHA-256 at creation: `64142146ec300db56b07b84b8bda28d4193f152e36131636051d4188485bccb9`.
