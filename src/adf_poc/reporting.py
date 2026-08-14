from __future__ import annotations

import html
import json
from pathlib import Path
from typing import Any


def _pct(value: float) -> str:
    return f"{100.0 * value:.1f}%"


def _metric_card(label: str, value: str, note: str = "") -> str:
    return (
        '<div class="card"><div class="card-label">' + html.escape(label) + '</div>'
        '<div class="card-value">' + html.escape(value) + '</div>'
        '<div class="card-note">' + html.escape(note) + '</div></div>'
    )


def _bar_chart(rows: list[tuple[str, int]], title: str) -> str:
    maximum = max((value for _, value in rows), default=1)
    bars = []
    y = 35
    for label, value in rows:
        width = 520 * value / maximum if maximum else 0
        bars.append(f'<text x="0" y="{y + 15}" font-size="13">{html.escape(label)}</text>')
        bars.append(f'<rect x="170" y="{y}" width="{width:.1f}" height="20" rx="3" class="bar"/>')
        bars.append(f'<text x="{180 + width:.1f}" y="{y + 15}" font-size="13">{value}</text>')
        y += 34
    height = y + 10
    return (
        f'<div class="chart"><h3>{html.escape(title)}</h3>'
        f'<svg viewBox="0 0 760 {height}" role="img" aria-label="{html.escape(title)}">'
        + ''.join(bars) + '</svg></div>'
    )


def generate_html_report(metrics: dict[str, Any], output_path: str | Path) -> None:
    decision = metrics["decision_control"]
    safety = metrics["safety_and_assurance"]
    model = metrics["model"]
    scope = metrics["scope"]
    perf = metrics["performance"]
    counts = decision["disposition_counts"]

    cards = ''.join([
        _metric_card("Cases", str(scope["cases_evaluated"]), "Synthetic test partition"),
        _metric_card("Autonomous containment precision", _pct(decision["autonomous_containment_precision"]), "Precision among reversible actions"),
        _metric_card("False containment", str(decision["false_containment_count"]), "Synthetic benign cases acted upon"),
        _metric_card("Unsafe automation", str(safety["unsafe_automation_count"]), "Critical, break-glass, conflicted, or poisoned"),
        _metric_card("Traceability", _pct(safety["evidence_traceability_rate"]), "Decision evidence resolves to source events"),
        _metric_card("Audit chain", "VALID" if safety["audit_chain_valid"] else "INVALID", "SHA-256 chained records"),
        _metric_card("ROC AUC", f'{model["roc_auc"]:.3f}', "Synthetic model discrimination"),
        _metric_card("Median latency", f'{perf["median_decision_latency_ms"]:.2f} ms', "Local POC execution"),
    ])

    chart = _bar_chart([
        ("No action", counts.get("NO_ACTION", 0)),
        ("Investigate", counts.get("INVESTIGATE", 0)),
        ("Contain reversible", counts.get("CONTAIN_REVERSIBLE", 0)),
        ("Escalate human", counts.get("ESCALATE_HUMAN", 0)),
    ], "Decision dispositions")

    scenario_rows = []
    for row in metrics["per_scenario"]:
        scenario_rows.append(
            "<tr>"
            f"<td>{html.escape(row['scenario'])}</td>"
            f"<td>{row['cases']}</td>"
            f"<td>{row['compromised']}</td>"
            f"<td>{row['contain_reversible']}</td>"
            f"<td>{row['false_containment']}</td>"
            f"<td>{row['investigate']}</td>"
            f"<td>{row['escalate_human']}</td>"
            f"<td>{row['no_action']}</td>"
            f"<td>{_pct(row['expected_disposition_match_rate'])}</td>"
            "</tr>"
        )

    report = f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>AI Decision Firewall POC Baseline Report</title>
<style>
:root {{ --ink:#172033; --muted:#5a6475; --panel:#f5f7fa; --line:#d8dee8; --accent:#2856a6; --warn:#8a4b00; }}
* {{ box-sizing:border-box; }}
body {{ margin:0; font-family:Arial, Helvetica, sans-serif; color:var(--ink); background:white; line-height:1.45; }}
header {{ padding:42px 6vw 30px; background:linear-gradient(120deg,#172033,#284a80); color:white; }}
header h1 {{ margin:0 0 8px; font-size:34px; }}
header p {{ margin:0; max-width:980px; color:#e6ecf7; }}
main {{ padding:30px 6vw 60px; max-width:1500px; margin:auto; }}
.notice {{ padding:16px 18px; border-left:5px solid var(--warn); background:#fff7e8; margin-bottom:24px; }}
.grid {{ display:grid; grid-template-columns:repeat(auto-fit,minmax(220px,1fr)); gap:14px; }}
.card {{ border:1px solid var(--line); border-radius:10px; padding:16px; background:var(--panel); min-height:130px; }}
.card-label {{ color:var(--muted); font-size:13px; text-transform:uppercase; letter-spacing:.04em; }}
.card-value {{ font-size:30px; font-weight:700; margin:8px 0 4px; }}
.card-note {{ color:var(--muted); font-size:13px; }}
section {{ margin-top:30px; }}
.chart {{ border:1px solid var(--line); border-radius:10px; padding:12px 18px; overflow:auto; }}
.chart svg {{ width:100%; min-width:700px; }}
.bar {{ fill:var(--accent); }}
table {{ width:100%; border-collapse:collapse; font-size:13px; }}
th, td {{ border-bottom:1px solid var(--line); text-align:right; padding:9px 8px; }}
th:first-child, td:first-child {{ text-align:left; }}
th {{ background:var(--panel); position:sticky; top:0; }}
pre {{ white-space:pre-wrap; background:#101724; color:#e7edf7; padding:16px; border-radius:8px; overflow:auto; }}
footer {{ margin-top:35px; color:var(--muted); font-size:12px; }}
</style>
</head>
<body>
<header>
<h1>AI Decision Firewall POC — Baseline Evaluation</h1>
<p>Privileged-identity containment using synthetic evidence, a replaceable learned risk model, deterministic policy enforcement, independent verification, signed authorization, simulated reversible actions, and hash-chained audit records.</p>
</header>
<main>
<div class="notice"><strong>Interpretation boundary:</strong> This is a mechanics and assurance test against generated data. It does not establish operational detection accuracy, production safety, or authorization to act on real systems.</div>
<div class="grid">{cards}</div>
<section>{chart}</section>
<section>
<h2>Scenario-level results</h2>
<div style="overflow:auto"><table>
<thead><tr><th>Scenario</th><th>Cases</th><th>Compromised</th><th>Contain</th><th>False contain</th><th>Investigate</th><th>Escalate</th><th>No action</th><th>Expected match</th></tr></thead>
<tbody>{''.join(scenario_rows)}</tbody>
</table></div>
</section>
<section>
<h2>What this baseline proves</h2>
<ul>
<li>Ground-truth labels are separate from runtime case inputs.</li>
<li>Untrusted free text is excluded from model features and can force abstention.</li>
<li>The model has no direct action path and holds no target-system credentials.</li>
<li>Only an independently verified, deterministic policy decision can mint an action token.</li>
<li>Actions are confined to an in-memory simulator and are verified after execution.</li>
<li>Every decision and action is captured in a tamper-evident hash chain.</li>
</ul>
</section>
<section>
<h2>Raw metrics</h2>
<pre>{html.escape(json.dumps(metrics, indent=2, sort_keys=True))}</pre>
</section>
<footer>AI Decision Firewall POC v0.1 — Synthetic data only — Working engineering baseline.</footer>
</main>
</body>
</html>"""
    Path(output_path).write_text(report, encoding="utf-8")
