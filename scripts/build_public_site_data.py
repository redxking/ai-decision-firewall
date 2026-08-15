#!/usr/bin/env python3
"""Build the closed, sanitized data bundle consumed by the public website."""

from __future__ import annotations

import argparse
import json
import math
import re
import subprocess
import sys
import tomllib
from pathlib import Path
from typing import Any

import jsonschema


ROOT = Path(__file__).resolve().parents[1]
GITHUB_REPOSITORY = "https://github.com/redxking/ai-decision-firewall"
SCHEMA_PATH = ROOT / "contracts/v0.2.0/public-site-data.schema.json"
DEFAULT_OUTPUT = ROOT / "site/data/public-results.json"

STARTER_DECISIONS = Path("evidence/phase2_starter/replay_decisions.jsonl")
STARTER_ADJUDICATIONS = Path("evidence/phase2_starter/adjudication_comparison.jsonl")
BASELINE_DECISIONS = Path("outputs/baseline/decisions.jsonl")
BASELINE_METRICS = Path("outputs/baseline/metrics.json")
BASELINE_MANIFEST = Path("outputs/baseline/run_manifest.json")
SOURCE_TO_DECISION_PLAN = Path("config/source_to_decision_ce2_campaign_plan.json")

CLAIM_PRESENTATION = {
    "P2-CE-003": {
        "title": "Gate B fail-closed campaign",
        "evidence_level": "CE-2",
        "summary": Path("evidence/phase2_gate_b_ce2/campaign_summary.json"),
        "highlights": [
            "28 structural blocks; 0 governed payload-role opens or reads observed through declared hooks",
            "2 attempts blocked after qualification and before the engine",
            "2 test-only validation passes",
            "0 operational effects",
        ],
    },
    "P2-CE-004": {
        "title": "Feature-boundary assurance campaign",
        "evidence_level": "CE-2",
        "summary": Path("evidence/phase2_feature_assurance_ce2/campaign_summary.json"),
        "highlights": [
            "16 clean projection matches",
            "8 malformed or unauthorized records quarantined",
            "8 altered projections blocked by the reference path",
            "0 operational effects",
        ],
    },
}

SCENARIO_PRESENTATION = {
    "phase2-synthetic-benign-001": {
        "id": "approved-maintenance",
        "title": "Approved maintenance",
        "summary": "After-hours activity is explained by an approved maintenance window and strong authentication.",
        "signals": [
            {"label": "Approved maintenance window", "stance": "BENIGN"},
            {"label": "Strong authentication", "stance": "BENIGN"},
            {"label": "Evidence integrity verified", "stance": "CONTROL"},
        ],
        "decision_label": "No action",
        "explanation": "Risk remains below the no-action threshold and the available context supports benign activity.",
        "evaluation_explanation": "The decision matched the project-authored synthetic expectation.",
    },
    "phase2-synthetic-conflict-001": {
        "id": "conflicting-telemetry",
        "title": "Conflicting telemetry",
        "summary": "A suspicious sign appears, but separate network telemetry disagrees with it.",
        "signals": [
            {"label": "Impossible-travel indicator", "stance": "SUPPORTING"},
            {"label": "New device observed", "stance": "SUPPORTING"},
            {"label": "Separate source types conflict", "stance": "CONFLICTING"},
        ],
        "decision_label": "Investigate",
        "explanation": "Conflicting evidence prevents automation, so the firewall abstains and requests more evidence.",
        "evaluation_explanation": "The system correctly treated abstention as the expected safe outcome.",
    },
    "phase2-synthetic-malicious-001": {
        "id": "suspicious-token-reuse",
        "title": "Suspicious token reuse",
        "summary": "Token reuse, a threat-listed address, and an unusual administrative action corroborate one another.",
        "signals": [
            {"label": "Token reuse", "stance": "SUPPORTING"},
            {"label": "Threat-listed address", "stance": "SUPPORTING"},
            {"label": "Unusual administrative action", "stance": "SUPPORTING"},
            {"label": "Four-source corroboration", "stance": "CONTROL"},
        ],
        "decision_label": "Contain reversibly",
        "explanation": "Risk, evidence quality, corroboration, and the action boundary satisfy the reversible-containment policy.",
        "evaluation_explanation": "The decision matched expectation, while read-only replay prevented authorization and execution.",
    },
}


class PublicDataError(RuntimeError):
    """Raised when a source cannot safely support the public data bundle."""


def _reject_duplicate_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise PublicDataError(f"Duplicate JSON member: {key}")
        value[key] = item
    return value


def _reject_constant(value: str) -> None:
    raise PublicDataError(f"Non-finite JSON number is prohibited: {value}")


def load_json(relative_path: Path) -> dict[str, Any]:
    path = ROOT / relative_path
    try:
        value = json.loads(
            path.read_text(encoding="utf-8"),
            object_pairs_hook=_reject_duplicate_pairs,
            parse_constant=_reject_constant,
        )
    except (OSError, json.JSONDecodeError) as exc:
        raise PublicDataError(f"Unable to load {relative_path}: {exc}") from exc
    if not isinstance(value, dict):
        raise PublicDataError(f"Expected a JSON object in {relative_path}")
    return value


def load_jsonl(relative_path: Path) -> list[dict[str, Any]]:
    path = ROOT / relative_path
    rows: list[dict[str, Any]] = []
    try:
        for line_number, line in enumerate(
            path.read_text(encoding="utf-8").splitlines(), start=1
        ):
            if not line.strip():
                continue
            value = json.loads(
                line,
                object_pairs_hook=_reject_duplicate_pairs,
                parse_constant=_reject_constant,
            )
            if not isinstance(value, dict):
                raise PublicDataError(
                    f"Expected a JSON object at {relative_path}:{line_number}"
                )
            rows.append(value)
    except (OSError, json.JSONDecodeError) as exc:
        raise PublicDataError(f"Unable to load {relative_path}: {exc}") from exc
    return rows


def git(*args: str) -> str:
    completed = subprocess.run(
        ["git", *args],
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
    )
    return completed.stdout.strip()


def commit_for(relative_path: Path) -> str:
    commit = git("log", "-1", "--format=%H", "--", relative_path.as_posix())
    if not re.fullmatch(r"[0-9a-f]{40}", commit):
        raise PublicDataError(f"No immutable Git commit found for {relative_path}")
    return commit


def project_version_at_commit(commit: str) -> str:
    """Return the project version frozen with an immutable design commit."""

    if not re.fullmatch(r"[0-9a-f]{40}", commit):
        raise PublicDataError("Project-version lookup requires an exact Git commit.")
    try:
        value = tomllib.loads(git("show", f"{commit}:pyproject.toml"))
        version = value["project"]["version"]
    except (
        subprocess.CalledProcessError,
        tomllib.TOMLDecodeError,
        KeyError,
        TypeError,
    ) as exc:
        raise PublicDataError(
            f"Unable to resolve the project version at commit {commit}."
        ) from exc
    if not isinstance(version, str):
        raise PublicDataError(
            f"The project version at commit {commit} is not a string."
        )
    return normalize_version(version)


def ensure_clean_sources(paths: set[Path]) -> None:
    for relative_path in sorted(paths):
        if git("status", "--porcelain", "--", relative_path.as_posix()):
            raise PublicDataError(
                f"Public source is modified or untracked: {relative_path}"
            )


def source_url(commit: str, relative_path: Path) -> str:
    return f"{GITHUB_REPOSITORY}/blob/{commit}/{relative_path.as_posix()}"


def normalize_version(value: str) -> str:
    match = re.fullmatch(r"(\d+)\.(\d+)\.(\d+)a(\d+)", value)
    if match:
        return f"v{match.group(1)}.{match.group(2)}.{match.group(3)}-alpha.{match.group(4)}"
    if re.fullmatch(r"\d+\.\d+\.\d+(?:-alpha\.\d+)?", value):
        return f"v{value}"
    raise PublicDataError(f"Unsupported public version: {value}")


def claim_number(claim_id: str) -> int:
    match = re.fullmatch(r"P2-CE-(\d{3})", claim_id)
    if not match:
        raise PublicDataError(f"Invalid Phase 2 claim identifier: {claim_id}")
    return int(match.group(1))


def implementation_commit(record: dict[str, Any]) -> str:
    reference = record.get("system_under_test", {}).get("source_reference", "")
    match = re.search(r"\b[0-9a-f]{40}\b", reference)
    if not match:
        raise PublicDataError(
            f"Evidence record {record.get('claim_id')} lacks an implementation commit"
        )
    return match.group(0)


def validate_claim_record(record: dict[str, Any]) -> None:
    results = record.get("results", {})
    denominator = results.get("denominator")
    passed = results.get("passed")
    failed = results.get("failed")
    excluded = results.get("excluded")
    if record.get("claim_status") != "OBSERVED":
        raise PublicDataError(f"Claim {record.get('claim_id')} is not OBSERVED")
    if record.get("claim_class") != "CONTROLLED_BEHAVIOR":
        raise PublicDataError(
            f"Claim {record.get('claim_id')} is not controlled-behavior evidence"
        )
    scope = record.get("evaluation_scope", {})
    if (
        scope.get("data_origin") != "SYNTHETIC_FIXTURE"
        or scope.get("historical_case_count") != 0
    ):
        raise PublicDataError(
            f"Claim {record.get('claim_id')} exceeds the public synthetic boundary"
        )
    if record.get("review", {}).get("review_type") != "SELF":
        raise PublicDataError(
            f"Unexpected review boundary for {record.get('claim_id')}"
        )
    if not isinstance(denominator, int) or denominator <= 0:
        raise PublicDataError(
            f"Claim {record.get('claim_id')} has no valid denominator"
        )
    if any(
        not isinstance(value, int) or value < 0 for value in (passed, failed, excluded)
    ):
        raise PublicDataError(
            f"Claim {record.get('claim_id')} has invalid result accounting"
        )
    if passed + failed + excluded != denominator:
        raise PublicDataError(
            f"Claim {record.get('claim_id')} result accounting does not reconcile"
        )


def load_claim_records() -> list[tuple[Path, dict[str, Any]]]:
    records: list[tuple[Path, dict[str, Any]]] = []
    for path in sorted(
        (ROOT / "contracts/v0.2.0/examples").glob("phase2-*-evidence-record.json")
    ):
        relative_path = path.relative_to(ROOT)
        record = load_json(relative_path)
        claim_id = record.get("claim_id", "")
        if claim_id in CLAIM_PRESENTATION:
            validate_claim_record(record)
            records.append((relative_path, record))
    if not records:
        raise PublicDataError("No publishable claim evidence records were found")
    return records


def build_scenarios(starter_commit: str, baseline_commit: str) -> list[dict[str, Any]]:
    decisions = {row["case_id"]: row for row in load_jsonl(STARTER_DECISIONS)}
    adjudications = {row["case_id"]: row for row in load_jsonl(STARTER_ADJUDICATIONS)}
    scenarios: list[dict[str, Any]] = []
    for case_id, presentation in SCENARIO_PRESENTATION.items():
        decision = decisions.get(case_id)
        adjudication = adjudications.get(case_id)
        if decision is None or adjudication is None:
            raise PublicDataError(f"Starter scenario is missing: {case_id}")
        if decision["final_disposition"] != adjudication["decision_disposition"]:
            raise PublicDataError(f"Decision/adjudication join failed for {case_id}")
        evaluation_status = (
            "MATCHED_EXPECTATION"
            if adjudication["disposition_match"]
            else "MISMATCHED_EXPECTATION"
        )
        counterfactual_actions = [
            action.replace("_", " ") for action in decision["counterfactual_actions"]
        ]
        scenarios.append(
            {
                "id": presentation["id"],
                "title": presentation["title"],
                "summary": presentation["summary"],
                "phase": "PHASE_2_READ_ONLY",
                "signals": presentation["signals"],
                "model": {
                    "compromise_probability": decision["compromise_probability"],
                    "evidence_quality": decision["evidence_quality"],
                    "label": "ADVISORY_ONLY",
                },
                "decision": {
                    "disposition": decision["final_disposition"],
                    "label": presentation["decision_label"],
                    "policy_rule": decision["policy_rules_applied"][0],
                    "explanation": presentation["explanation"],
                    "counterfactual_actions": counterfactual_actions,
                },
                "effect": {
                    "status": "NOT_ATTEMPTED_READ_ONLY",
                    "authorization_issued": bool(decision["authorization_issued"]),
                    "broker_invocations": int(decision["broker_invocations"]),
                    "operational_effects": int(decision["operational_effects"]),
                    "explanation": "Authorization and execution were structurally suppressed in offline read-only replay.",
                },
                "evaluation": {
                    "status": evaluation_status,
                    "label": (
                        "Matched expectation"
                        if adjudication["disposition_match"]
                        else "Did not match expectation"
                    ),
                    "expected_disposition": adjudication["adjudicated_disposition"],
                    "explanation": presentation["evaluation_explanation"],
                },
                "source_url": source_url(starter_commit, STARTER_DECISIONS),
            }
        )

    failure = next(
        (
            row
            for row in load_jsonl(BASELINE_DECISIONS)
            if row.get("case_id") == "test-00081-8c62233"
        ),
        None,
    )
    if (
        failure is None
        or failure.get("post_action_verification", {}).get("passed") is not False
    ):
        raise PublicDataError(
            "The bounded synthetic effect-failure demonstration is unavailable"
        )
    failed_actions = [
        row for row in failure.get("action_results", []) if row.get("success") is False
    ]
    if [row.get("action") for row in failed_actions] != ["force_step_up_auth"]:
        raise PublicDataError(
            "The synthetic effect-failure demonstration changed unexpectedly"
        )
    scenarios.append(
        {
            "id": "simulated-effect-failure",
            "title": "Simulated downstream failure",
            "summary": "A synthetic action command is accepted, but one intended state change does not occur.",
            "phase": "V0_1_SYNTHETIC_SIMULATOR",
            "signals": [
                {"label": "High-confidence synthetic case", "stance": "SUPPORTING"},
                {"label": "Reversible actions authorized", "stance": "CONTROL"},
                {"label": "Step-up state unchanged", "stance": "CONFLICTING"},
            ],
            "model": {
                "compromise_probability": failure["compromise_probability"],
                "evidence_quality": failure["evidence_assessment"]["evidence_quality"],
                "label": "ADVISORY_ONLY",
            },
            "decision": {
                "disposition": failure["final_disposition"],
                "label": "Contain reversibly",
                "policy_rule": failure["proposal"]["policy_rules_applied"][0],
                "explanation": "The synthetic-simulation compatibility path authorized three reversible simulator actions.",
                "counterfactual_actions": [],
            },
            "effect": {
                "status": "FAILED",
                "authorization_issued": bool(failure["authorization"]["issued"]),
                "broker_invocations": len(failure["action_results"]),
                "operational_effects": sum(
                    1 for row in failure["action_results"] if row.get("success")
                ),
                "explanation": "Post-action verification detected that forced step-up authentication did not reach the intended simulator state.",
            },
            "evaluation": {
                "status": "NOT_EVALUATED",
                "label": "Effect failure detected",
                "expected_disposition": None,
                "explanation": "This demonstrates failure reporting in the v0.1 synthetic simulator; it is not current operational evidence.",
            },
            "source_url": source_url(baseline_commit, BASELINE_DECISIONS),
        }
    )
    return scenarios


def build_claims(records: list[tuple[Path, dict[str, Any]]]) -> list[dict[str, Any]]:
    claims: list[dict[str, Any]] = []
    for path, record in sorted(
        records, key=lambda item: claim_number(item[1]["claim_id"])
    ):
        claim_id = record["claim_id"]
        presentation = CLAIM_PRESENTATION[claim_id]
        summary = load_json(presentation["summary"])
        if summary.get("claim_id") != claim_id:
            raise PublicDataError(f"Campaign summary does not match {claim_id}")
        if (
            summary.get("raw_outcomes", {}).get("denominator")
            != record["results"]["denominator"]
        ):
            raise PublicDataError(f"Campaign denominator does not match {claim_id}")
        publication_commit = commit_for(path)
        claims.append(
            {
                "claim_id": claim_id,
                "title": presentation["title"],
                "evidence_level": presentation["evidence_level"],
                "claim_class": record["claim_class"],
                "status": record["claim_status"],
                "version": normalize_version(
                    record["system_under_test"]["release_version"]
                ),
                "implementation_commit": implementation_commit(record),
                "publication_commit": publication_commit,
                "evaluated_at": record["evaluated_at"],
                "review_type": record["review"]["review_type"],
                "data_origin": record["evaluation_scope"]["data_origin"],
                "historical_case_count": record["evaluation_scope"][
                    "historical_case_count"
                ],
                "results": {
                    "denominator": record["results"]["denominator"],
                    "passed": record["results"]["passed"],
                    "failed": record["results"]["failed"],
                    "excluded": record["results"]["excluded"],
                },
                "highlights": presentation["highlights"],
                "limitation": " ".join(record["review"]["unresolved_objections"]),
                "source_url": source_url(publication_commit, path),
            }
        )
    return claims


def build_model_snapshot() -> dict[str, Any]:
    metrics = load_json(BASELINE_METRICS)
    manifest = load_json(BASELINE_MANIFEST)
    scope = metrics["scope"]
    if (
        scope.get("data_type") != "synthetic"
        or scope.get("operational_validity") != "not established"
    ):
        raise PublicDataError(
            "The model snapshot exceeds the synthetic mechanics boundary"
        )
    source_commit = commit_for(BASELINE_METRICS)
    model = metrics["model"]
    decision = metrics["decision_control"]
    safety = metrics["safety_and_assurance"]
    numeric_values = [
        model["accuracy_at_0_5"],
        model["brier_score"],
        model["roc_auc"],
        decision["expected_disposition_match_rate"],
        safety["post_action_verification_pass_rate"],
    ]
    if not all(
        isinstance(value, (int, float)) and math.isfinite(value)
        for value in numeric_values
    ):
        raise PublicDataError("The model snapshot contains a non-finite metric")
    return {
        "label": "V0.1 synthetic mechanics baseline",
        "version": manifest["model_version"],
        "data_origin": "SYNTHETIC_GENERATOR",
        "evaluated_cases": scope["cases_evaluated"],
        "operational_validity": "NOT_ESTABLISHED",
        "metrics": {
            "accuracy_at_0_5": model["accuracy_at_0_5"],
            "brier_score": model["brier_score"],
            "roc_auc": model["roc_auc"],
            "expected_disposition_match_rate": decision[
                "expected_disposition_match_rate"
            ],
            "false_containment_count": decision["false_containment_count"],
            "post_action_verification_pass_rate": safety[
                "post_action_verification_pass_rate"
            ],
        },
        "disposition_counts": decision["disposition_counts"],
        "interpretation": "These generator-consistent synthetic results validate POC mechanics, not operational detection accuracy, real-world error rates, or production safety.",
        "source_url": source_url(source_commit, BASELINE_METRICS),
    }


def build_public_data() -> dict[str, Any]:
    records = load_claim_records()
    latest_path, latest_record = max(
        records, key=lambda item: claim_number(item[1]["claim_id"])
    )
    claims = build_claims(records)
    latest_publication_commit = commit_for(latest_path)

    plan = load_json(SOURCE_TO_DECISION_PLAN)
    plan_claim_id = plan["claim_id"]
    observed_claim_ids = {record["claim_id"] for _, record in records}
    candidate = None
    if plan_claim_id not in observed_claim_ids:
        design_commit = commit_for(SOURCE_TO_DECISION_PLAN)
        candidate = {
            "label": "Design candidate",
            "version": project_version_at_commit(design_commit),
            "design_commit": design_commit,
            "claim_id": plan_claim_id,
            "evaluation": "NOT_EVALUATED",
        }

    starter_commit = commit_for(STARTER_DECISIONS)
    baseline_commit = commit_for(BASELINE_DECISIONS)
    source_paths = {
        STARTER_DECISIONS,
        STARTER_ADJUDICATIONS,
        BASELINE_DECISIONS,
        BASELINE_METRICS,
        BASELINE_MANIFEST,
        SOURCE_TO_DECISION_PLAN,
        *(path for path, _ in records),
        *(presentation["summary"] for presentation in CLAIM_PRESENTATION.values()),
    }
    ensure_clean_sources(source_paths)

    data = {
        "schema_version": "1.0.0",
        "updated_through": max(record["evaluated_at"] for _, record in records),
        "site_status": {
            "evidence_baseline": {
                "label": "Published evidence baseline",
                "version": normalize_version(
                    latest_record["system_under_test"]["release_version"]
                ),
                "publication_commit": latest_publication_commit,
                "latest_claim_id": latest_record["claim_id"],
                "evaluated_at": latest_record["evaluated_at"],
                "source_url": source_url(latest_publication_commit, latest_path),
            },
            "candidate": candidate,
        },
        "boundary": {
            "data_origin": "SYNTHETIC_FIXTURE",
            "historical_case_count": 0,
            "execution_mode": "OFFLINE_READ_ONLY_REPLAY",
            "live_actions_enabled": False,
            "operational_authority": "NONE",
            "review_type": "SELF",
        },
        "scenarios": build_scenarios(starter_commit, baseline_commit),
        "claims": claims,
        "model_snapshot": build_model_snapshot(),
        "non_inferences": [
            "Synthetic results do not establish performance on historical or live identity incidents.",
            "A matched fixed campaign does not establish zero risk or a bounded operational failure rate.",
            "SELF review does not establish independent replication, independent custody, or external assurance.",
            "The current POC is not approved for production integration, operational decisions, or live containment.",
            "A counterfactual action in read-only replay is not an authorization, broker call, or operational effect.",
        ],
    }
    schema = load_json(SCHEMA_PATH.relative_to(ROOT))
    jsonschema.Draft202012Validator(
        schema, format_checker=jsonschema.FormatChecker()
    ).validate(data)
    return data


def serialize(data: dict[str, Any]) -> str:
    return (
        json.dumps(data, indent=2, sort_keys=True, ensure_ascii=False, allow_nan=False)
        + "\n"
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument(
        "--check", action="store_true", help="Fail if the checked-in bundle is stale"
    )
    args = parser.parse_args()
    output = args.output if args.output.is_absolute() else ROOT / args.output
    try:
        rendered = serialize(build_public_data())
        if args.check:
            if not output.exists() or output.read_text(encoding="utf-8") != rendered:
                raise PublicDataError(
                    f"Public website data is stale: {output.relative_to(ROOT)}"
                )
            print(f"Public website data is current: {output.relative_to(ROOT)}")
            return 0
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(rendered, encoding="utf-8")
        print(f"Wrote sanitized public website data: {output.relative_to(ROOT)}")
        return 0
    except (
        PublicDataError,
        KeyError,
        TypeError,
        subprocess.CalledProcessError,
        jsonschema.ValidationError,
    ) as exc:
        print(f"Public website data build failed: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
