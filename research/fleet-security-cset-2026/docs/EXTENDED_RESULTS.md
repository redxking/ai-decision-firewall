# Extended synthetic validation results

The publication campaign executed 2,160 deterministic synthetic trials: 6 populations (1, 4, 16, 64, 256, 1,024) x 6 communication topologies (isolated, ring, star, tree, bounded-degree random, dense) x 2 privilege configurations (least privilege, shared privilege) x 30 repetitions.

Frozen synthetic parameters: 20 steps, initial compromise probability 0.35, per-edge propagation probability 0.20, malicious-request probability 0.45, external-policy false-allow probability 0.01, high-privilege fraction 0.10, root seed 20260831.

For N=1,024 under least privilege, mean ever-compromised fraction was 0.000423 (isolated), 0.001888 (ring), 0.004915 (tree), 0.163444 (star), 0.312467 (bounded-degree random), and 0.400000 (dense). Under shared privilege, corresponding values were 0.000456, 0.001074, 0.003971, 0.143652, 0.235547, and 0.400000.

At N=1,024, mean authorization-integrity loss across topology/privilege cells ranged from 0 to 0.011111; weighted blast radius remained below 0.00170. These are simulator results. They do not characterize a commercial or open-source LLM and the configured probabilities must not be presented as measured attack probabilities.

Evidence hashes for the frozen 30-repetition publication run:

- `extended_raw.csv` SHA-256: `59c8fced6ef2ae6c6a19611f31b89df98141202a373de82640ff9585eb831ead`
- `extended_summary.csv` SHA-256: `49d56c6bc183b7f16bafd55d8704c638a2178c71427a6b44c9bf43e6351e0aec`

Regenerate with:

```bash
PYTHONPATH=src python scripts/run_extended.py
sha256sum results/extended_raw.csv results/extended_summary.csv
```

The raw and summary files are generated outputs. A release or review artifact should include them together with the exact source commit used for execution.
