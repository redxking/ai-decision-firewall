# Tuning and Experimental Controls

The simulator is a controlled test harness, not empirical evidence about any commercial LLM unless a real-model adapter is added and those runs are clearly identified.

## Core controls

- `--populations`: agent counts. Prefer logarithmic spacing for scaling studies.
- `--topology`: `isolated`, `ring`, `star`, `tree`, `random`, `dense`.
- `--auth-models`: `least_privilege` or `shared_privilege`.
- `--repetitions`: independent trials per configuration. Thirty is a baseline, not a universal statistical rule.
- `--compromise-probability`: probability that the initially targeted principal becomes compromised.
- `--propagation-probability`: per-edge propagation probability per step.
- `--malicious-request-probability`: probability a compromised principal attempts a protected action.
- `--policy-false-allow-rate`: failure probability of the external enforcement point. Keep this distinct from model refusal behavior.
- `--steps`: simulation horizon.
- `--seed`: deterministic root seed.

## Experimental discipline

Change one factor at a time for sensitivity sweeps, or declare a factorial design before inspecting results. Preserve raw results and manifests. Do not delete failed runs because they are inconvenient. If code or parameters change after collection, regenerate the result set or record exact mixed-run provenance.

## Calibration

1. Isolated topology with propagation=1.0 must still show no fleet propagation.
2. Policy false-allow=0.0 must produce zero AIL and weighted blast radius.
3. Policy false-allow=1.0 with malicious-request=1.0 must produce AIL=1 where malicious requests occur.
4. Identical seeds and configuration must reproduce identical output.
5. Sweep propagation probability from 0 to 1 and test expected aggregate movement.
6. Test sparse and dense topologies.
7. Record the exact source commit for every publishable run.

## Real LLM integration

Preserve the event schema `principal -> proposed action -> authorization decision -> execution -> observed effect`. Do not infer authorization from generated text. Enforce policy outside the model. For hosted models record provider, model identifier, request parameters, execution time, retry behavior, and available version metadata. Never commit API keys.
