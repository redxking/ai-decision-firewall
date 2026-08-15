# Architecture and Metrics Visuals

## Scope

Diagrams 01–04 are the frozen Phase 2.5 package views included in exact Commit `854b15c`, which is published on `main`; exact-commit CI and Dependency Graph checks passed. Their internal labels preserve the evidence state at the time each Phase 2 view was frozen. Phase 2 has no route to a live connector, action credential, authorization token, broker, operational target, or external effect.

Diagram 08 is the published Phase 3 `0.3.0-alpha.1` operational-MVP architecture view at exact Commit `423685d105be813056617db738297eba83d3d9d0`. Exact-commit CI and Dependency Graph checks passed. The boundary includes 57/57 focused tests, 288/288 then-current repository tests, two demo acceptance checks PASS, and a 46/46 corpus. It shows the additive, simulation-only action path and its hard identity, evidence, policy, decision, authorization, broker, target, readback, audit, and metrics boundaries. The in-memory target and private mutation capability are application-level controls, not operating-system, process, or security isolation. The observer/verifier performs a functionally separate same-project readback and does not trust the broker return value; it is not an externally independent verifier. Human approval authorizes a signed reevaluation receipt for the bound request only; it never directly authorizes execution or itself causes reevaluation.

Diagram 09 is the Phase 3.1 working model-evaluation view. It shows the SHA-256-bound synthetic source pools, disjoint temporal training/calibration/evaluation roles, logistic baseline, calibration challenger, aggregate metrics, unconditional `NOT_AUTHORIZED` promotion state, and the separate future Gate B authority boundary. The Phase 3.1 package has no historical/live adapter or action path.

The Phase 2.5 technical suite at `854b15c` passed 222/222; the separate public-site module passed 9/9; and the combined repository aggregate passed 231/231 before publication. The site module is outside the architecture and Phase 2.5 evidence claims. Presence in a diagram is not a tag, release, campaign, or evidence claim. `P2-CE-005` remains CE-0 `NOT_EVALUATED`: no campaign result, result ledger, evidence record, or evidence-only Commit B exists. It is unrelated to the Phase 3 MVP and must not be used as Phase 3 evidence.

Figure 1 (`01_system_context.*`) depicts an application path designed to stop before governed payload access when the selected Gate B controls fail. It is not evidence that the operating system, mount namespace, network, or another same-user process cannot access those bytes.

The three metric charts remain historical Phase 1 `v0.1.0` synthetic-simulation results. Their sources consume the committed Phase 1 baseline outputs; the chart renders passed the check in the frozen renderer and are covered by published Phase 2.5 Commit `854b15c` and its generated-and-verified manifest. Their scope remains Phase 1; they must not be interpreted as Phase 2 replay, historical, live, efficacy, or production-readiness evidence.

## Visual inventory

| Files | Meaning | Evidence boundary |
|---|---|---|
| `01_system_context.*` | Current Phase 2 context and forward boundary | Alpha.5 prior evidence baseline; predecessor alpha.6 design freeze plus the published Phase 2.5 package visual refresh |
| `02_logical_architecture.*` | Read-only control, decision, assurance, and evaluation layers | No operational action path |
| `03_decision_state_machine.*` | Completion and fail-closed sequencing | A file's presence alone does not establish a completed run |
| `04_trust_boundaries.*` | Authority, input, application, evaluation, and excluded target zones | Same-process reference logic is not independent custody |
| `05_disposition_counts.*` | Historical Phase 1 v0.1 synthetic disposition totals | 400 generated synthetic cases; seed `20260814`; not Phase 2.5 evidence |
| `06_probability_distribution.*` | Historical Phase 1 v0.1 synthetic model-score distribution | Uncalibrated model mechanics only; not operational probability |
| `07_scenario_outcomes.*` | Historical Phase 1 v0.1 dispositions by generated scenario | Synthetic generator family; not historical or operational outcomes |
| [`08_phase3_operational_mvp.dot`](08_phase3_operational_mvp.dot), [`PNG`](08_phase3_operational_mvp.png), [`SVG`](08_phase3_operational_mvp.svg) | Published Phase 3 credential-to-decision-to-synthetic-effect architecture, including no-action branches and functionally separate same-project readback | Exact Commit `423685d`; simulation-only CE-1; no live connectors |
| [`09_phase31_model_evaluation.dot`](09_phase31_model_evaluation.dot), [`PNG`](09_phase31_model_evaluation.png), [`SVG`](09_phase31_model_evaluation.svg) | Phase 3.1 synthetic source binding, temporal split, baseline/challenger comparison, metrics, and no-promotion boundary | Working candidate; synthetic mechanism only; no historical/live adapter or action path |

## Reproducible rendering

The DOT sources are authoritative for diagrams 01–04, 08, and 09. The checked-in renders were produced with Graphviz `dot` 15.1.1:

```bash
for source in docs/architecture/0[1-4]_*.dot docs/architecture/08_phase3_operational_mvp.dot docs/architecture/09_phase31_model_evaluation.dot; do
  dot -Tpng -Gdpi=180 "$source" -o "${source%.dot}.png"
  dot -Tsvg "$source" -o "${source%.dot}.svg"
done
```

For a Phase 3/3.1-only refresh, render diagrams 08 and 09 with the same two commands and inspect both outputs. Each DOT source, PNG, and SVG must represent the same status and assurance boundaries. Use SVG for print.

Charts 05–07 are generated by [`generate_metric_charts.py`](generate_metric_charts.py):

```bash
python -m pip install -r requirements-docs.txt
python docs/architecture/generate_metric_charts.py
python docs/architecture/generate_metric_charts.py --check
```

The generator verifies source totals, labels every chart with its historical Phase 1 scope, and emits both PNG and SVG. It also checks frozen SHA-256 digests over the normalized fields consumed by the charts: disposition totals and denominator, manifest version/seed/counts, case identity/label/model score, and per-scenario disposition counts. The bindings were derived from the restored committed Phase 1 v0.1 baseline. Runtime latency and other unused fields are intentionally outside these chart-projection bindings because none of the three charts consumes them; whole-file output integrity remains a separate repository concern. Byte comparison is bound to the renderer declared in `requirements-docs.txt`: Matplotlib 3.11.1 with its FreeType 2.14.3 runtime and Pillow 12.3.0. The generator rejects a different renderer before comparing files.

A rendering-tool version change can alter bytes without altering meaning. Run `--check` in the declared documentation environment and inspect every rendered image whenever tools, fonts, source bindings, or chart labels change. The byte check is a package-reproduction control, not a claim that arbitrary Python, plotting, operating-system, or font environments will produce identical files.
