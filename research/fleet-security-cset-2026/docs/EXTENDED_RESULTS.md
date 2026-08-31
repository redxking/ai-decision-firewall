# Extended synthetic validation results

The extended experiment executed 720 deterministic synthetic trials: 6 populations (1, 4, 16, 64, 256, 1,024) x 6 communication topologies (isolated, ring, star, tree, bounded-degree random, dense) x 2 privilege configurations (least privilege, shared privilege) x 10 repetitions.

Frozen synthetic parameters: 20 steps, initial compromise probability 0.35, per-edge propagation probability 0.20, malicious-request probability 0.45, external-policy false-allow probability 0.01, high-privilege fraction 0.10, root seed 20260831.

For N=1,024 under least privilege, mean ever-compromised fraction was 0.000390625 (isolated), 0.00224609375 (ring), 0.007421875 (tree), 0.25107421875 (bounded-degree random), 0.293359375 (star), and 0.5 (dense). Mean authorization-integrity loss at N=1,024 ranged from 0 in the isolated case to 0.0052312137252649975 in the dense least-privilege case.

These are simulator results. They do not characterize a commercial or open-source LLM and the configured probabilities must not be presented as measured attack probabilities.

Locally generated evidence hashes for the frozen run:

- `extended_raw.csv` SHA-256: `3145ccb07654ff99e6762108bf920d41efaa9afd044c379850fc20ae82d3b6a9`
- `extended_summary.csv` SHA-256: `3e83cb0db91ae7249274012d26b06c2d1401e961c7948ab45f834eca5601a781`

Regenerate with:

```bash
PYTHONPATH=src python scripts/run_extended.py
sha256sum results/extended_raw.csv results/extended_summary.csv
```

The raw and summary files are generated outputs. A release or review artifact should include them together with the exact source commit used for execution.
