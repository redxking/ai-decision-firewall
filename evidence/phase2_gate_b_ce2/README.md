# P2-CE-003 synthetic Gate B campaign evidence

This directory contains the sanitized evidence bundle for `P2-CE-003`, a CE-2 `CONTROLLED_BEHAVIOR` claim over the fixed synthetic Gate B campaign. The exact machine-readable claim is [`phase2-gate-b-ce2-evidence-record.json`](../../contracts/v0.2.0/examples/phase2-gate-b-ce2-evidence-record.json).

## Bound implementation and scope

- Release: `0.2.0-alpha.4`
- Implementation Commit A: [`e8aa8b0efc7d54efdf74f49fb3d10ee067f2b49b`](https://github.com/redxking/ai-decision-firewall/commit/e8aa8b0efc7d54efdf74f49fb3d10ee067f2b49b)
- Campaign: `P2-CE-003-GATE-B-SYNTHETIC`
- Evaluated at: `2026-08-15T03:12:44Z`
- Origin: `SYNTHETIC_FIXTURE`
- Actual historical records: `0`
- Stored organizational approval package: no
- Live feed, action credential, write-capable connector, or operational target: none
- Review: `SELF`, automated and project-controlled

The implementation commit freezes the generator, plan, schema, validator, Gate B and replay sources, fixtures, model, policy, seed, attempt order, expected outcomes, and budget before this result was generated. This public project-controlled freeze is not external preregistration.

## Observed result

Two complete repetitions executed the same 16 fixed scenarios in fresh temporary state. All 32 observations matched the project-controlled expected outcomes with no exclusions:

| Observation | Count |
|---|---:|
| Total attempt executions | 32 |
| Expected-outcome matches | 32 |
| Test-only validate-only passes | 2 |
| Structural pre-payload blocks | 28 |
| Structural blocks with a governed payload-role open/read attempt observed by declared hooks during harness invocation | 0 / 28 |
| Post-qualification, pre-engine threshold blocks | 2 |
| Engine / authorization / broker / target-effect boundary reaches | 0 / 0 / 0 / 0 |
| Completed run manifests / decision artifacts / audit artifacts | 0 / 0 / 0 |
| Exclusions | 0 |

The two sanitized 16-row result ledgers are byte-identical.

The positive validate-only control and the post-qualification threshold control each open both governed payload roles by design. The narrower pre-payload observation applies only to the 28 structural-block harness invocations and only to the declared `Path.open`, `Path.read_text`, `Path.read_bytes`, and `os.open` hooks.

## Artifact index

| Artifact | SHA-256 | Purpose |
|---|---|---|
| [`campaign_profile.json`](campaign_profile.json) | `de88e2c700e828f5afdf9b6f454014e98e3b58da60a1923aaa9182ff6d5dc4ec` | Exact commit, source/configuration, runtime, scenario, seed, and budget bindings |
| [`campaign_results_run1.jsonl`](campaign_results_run1.jsonl) | `95520da714a0ac7aa69f82bb529838006cf50e9481b27424bb77149d8bbffd6f` | Sixteen sanitized observations from repetition one |
| [`campaign_results_run2.jsonl`](campaign_results_run2.jsonl) | `95520da714a0ac7aa69f82bb529838006cf50e9481b27424bb77149d8bbffd6f` | Sixteen sanitized observations from repetition two |
| [`campaign_summary.json`](campaign_summary.json) | `7735f21a7599034ffd6fbc72904b01d50162546171fcbeeb90df7c71715912cf` | Raw denominators, stage outcomes, boundary counters, and artifact bindings |
| [`config/gate_b_ce2_campaign_plan.json`](../../config/gate_b_ce2_campaign_plan.json) | `cd94608ade5dcb6a6ff09d289b1eb8fa124805bff98dd703283d1c2e672cee12` | Commit-frozen scenario registry and project-controlled expectations |
| [`contracts/v0.2.0/gate-b-ce2-campaign.schema.json`](../../contracts/v0.2.0/gate-b-ce2-campaign.schema.json) | `c4cb4672a3d780975561146348a66cb55f472f62d69503f6f28d1f4325964bdb` | Closed schema for profile, result rows, and summary |

The evidence remains project-controlled and self-custodied; these hashes are integrity bindings, not independent custody or external signatures.

## Verification

Run from the repository root:

```bash
python3 scripts/generate_gate_b_ce2_campaign.py --validate-plan
python3 scripts/validate_claim_evidence.py \
  --record contracts/v0.2.0/examples/phase2-gate-b-ce2-evidence-record.json \
  --profile P2-CE-003
```

The claim-evidence command statically validates the committed artifacts and bindings. To perform a new verification execution of the same two ledgers and byte-compare them with the committed bundle without rewriting it:

```bash
python3 scripts/generate_gate_b_ce2_campaign.py \
  --implementation-commit e8aa8b0efc7d54efdf74f49fb3d10ee067f2b49b \
  --evaluated-at 2026-08-15T03:12:44Z \
  --check
```

That optional `--check` execution is not part of the published 32-observation denominator.

## Limits and prohibited inferences

This bundle does not establish:

- a real organizational Gate B approval, authenticated approver, external signature, custody truth, privacy compliance, or effective de-identification;
- processing or performance over actual historical data;
- a live or shadow feed, operational recommendation workflow, live action, or target-side outcome;
- OS-level payload nonaccess, process-wide network nonuse, or egress denial;
- exhaustive mutation coverage, an operational failure-rate estimate, independent replication, statistical representativeness, efficacy, production readiness, or zero risk; or
- alignment, misalignment, scheming, sabotage resistance, sandbagging, or monitor effectiveness.

The two complete executions are repetitions of the same fixed registry, not 32 independent trials. Any bound source, dependency, schema, configuration, fixture, model, policy, generator, validator, seed, budget, wording, or claim-class change invalidates this record and requires a new result rather than overwriting this one.
