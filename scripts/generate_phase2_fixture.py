from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
VERSION = "0.2.0"


def _canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def _write_jsonl(path: Path, rows: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("".join(_canonical_json(row) + "\n" for row in rows), encoding="utf-8")


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while chunk := handle.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def _event(
    *,
    case_id: str,
    suffix: str,
    source_type: str,
    source_instance: str,
    observed_at: str,
    collected_at: str,
    trust_score: float,
    subject_id: str,
    asset_id: str,
    attributes: dict[str, Any],
    integrity: str = "verified",
    untrusted_text: str = "",
    instructional: bool = False,
) -> dict[str, Any]:
    return {
        "event_id": f"evt-{case_id}-{suffix}",
        "case_id": case_id,
        "source_type": source_type,
        "source_instance": source_instance,
        "observed_at": observed_at,
        "collected_at": collected_at,
        "integrity": integrity,
        "provenance_id": f"prov-{case_id}-{suffix}",
        "trust_score": trust_score,
        "entity_refs": [subject_id, asset_id],
        "attributes": attributes,
        "untrusted_text": untrusted_text,
        "contains_instructional_content": instructional,
    }


def _case(
    *,
    case_id: str,
    subject_id: str,
    asset_id: str,
    asset_criticality: float,
    break_glass: bool,
    indicators: dict[str, Any],
) -> dict[str, Any]:
    opened = "2026-08-01T12:00:00+00:00"
    common: dict[str, Any] = {
        "case_id": case_id,
        "subject_id": subject_id,
        "asset_id": asset_id,
    }
    # The identity event intentionally precedes the earlier inventory event in the
    # source file so the deterministic temporal normalizer is exercised.
    events = [
        _event(
            **common,
            suffix="identity",
            source_type="identity",
            source_instance="synthetic-idp",
            observed_at="2026-08-01T12:02:00+00:00",
            collected_at="2026-08-01T12:03:00+00:00",
            trust_score=0.94,
            attributes={
                "failed_logins": indicators.get("failed_logins", 0),
                "new_device": indicators.get("new_device", False),
                "impossible_travel": indicators.get("impossible_travel", False),
                "strong_mfa": indicators.get("strong_mfa", True),
                "mfa_fatigue": indicators.get("mfa_fatigue", False),
                "token_reuse": indicators.get("token_reuse", False),
                "oauth_grant": indicators.get("oauth_grant", False),
                "after_hours": indicators.get("after_hours", False),
            },
        ),
        _event(
            **common,
            suffix="inventory",
            source_type="asset_inventory",
            source_instance="synthetic-cmdb",
            observed_at="2026-08-01T12:00:00+00:00",
            collected_at="2026-08-01T12:01:00+00:00",
            trust_score=0.96,
            attributes={
                "asset_id": asset_id,
                "asset_criticality": asset_criticality,
                "privilege_level": "privileged",
                "break_glass": break_glass,
                "service_account": False,
            },
        ),
        _event(
            **common,
            suffix="network",
            source_type="network",
            source_instance="synthetic-network",
            observed_at="2026-08-01T12:04:00+00:00",
            collected_at="2026-08-01T12:05:00+00:00",
            trust_score=0.90,
            attributes={
                "threat_ip": indicators.get("threat_ip", False),
                "known_vpn": indicators.get("known_vpn", False),
                "lateral_movement": indicators.get("lateral_movement", False),
                "source_conflict": indicators.get("source_conflict", False),
            },
        ),
        _event(
            **common,
            suffix="endpoint",
            source_type="endpoint",
            source_instance="synthetic-edr",
            observed_at="2026-08-01T12:05:00+00:00",
            collected_at="2026-08-01T12:06:00+00:00",
            trust_score=0.93,
            attributes={
                "credential_dumping": indicators.get("credential_dumping", False),
                "edr_malware": indicators.get("edr_malware", False),
                "device_noncompliant": indicators.get("device_noncompliant", False),
                "unusual_admin_action": indicators.get("unusual_admin_action", False),
            },
        ),
        _event(
            **common,
            suffix="cti",
            source_type="threat_intel",
            source_instance="synthetic-cti",
            observed_at="2026-08-01T12:06:00+00:00",
            collected_at="2026-08-01T12:07:00+00:00",
            trust_score=0.88,
            attributes={"threat_ip": indicators.get("threat_ip", False)},
        ),
        _event(
            **common,
            suffix="change",
            source_type="change_management",
            source_instance="synthetic-itsm",
            observed_at="2026-08-01T11:57:00+00:00",
            collected_at="2026-08-01T11:58:00+00:00",
            trust_score=0.91,
            attributes={
                "maintenance_window": indicators.get("maintenance_window", False),
                "approved_change_id": (
                    "CHG-SYNTHETIC-001" if indicators.get("maintenance_window") else ""
                ),
                "service_account_baseline": False,
            },
        ),
        _event(
            **common,
            suffix="context",
            source_type="user_context",
            source_instance="synthetic-workforce-context",
            observed_at="2026-08-01T11:55:00+00:00",
            collected_at="2026-08-01T11:56:00+00:00",
            trust_score=0.84,
            attributes={
                "approved_travel": indicators.get("approved_travel", False),
                "travel_record_id": "",
            },
        ),
    ]
    return {
        "schema_version": VERSION,
        "case_id": case_id,
        "opened_at": opened,
        "subject_id": subject_id,
        "privilege_level": "privileged",
        "break_glass": break_glass,
        "asset_id": asset_id,
        "asset_criticality": asset_criticality,
        "events": events,
    }


def build_fixture() -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    cases = [
        _case(
            case_id="phase2-synthetic-benign-001",
            subject_id="pseudonym-user-001",
            asset_id="pseudonym-asset-001",
            asset_criticality=0.42,
            break_glass=False,
            indicators={"maintenance_window": True, "strong_mfa": True, "after_hours": True},
        ),
        _case(
            case_id="phase2-synthetic-malicious-001",
            subject_id="pseudonym-user-002",
            asset_id="pseudonym-asset-002",
            asset_criticality=0.40,
            break_glass=False,
            indicators={
                "token_reuse": True,
                "threat_ip": True,
                "new_device": True,
                "unusual_admin_action": True,
                "after_hours": True,
            },
        ),
        _case(
            case_id="phase2-synthetic-conflict-001",
            subject_id="pseudonym-user-003",
            asset_id="pseudonym-asset-003",
            asset_criticality=0.55,
            break_glass=False,
            indicators={
                "impossible_travel": True,
                "source_conflict": True,
                "new_device": True,
                "strong_mfa": True,
            },
        ),
    ]
    adjudications = [
        {
            "schema_version": VERSION,
            "adjudication_id": "adj-phase2-synthetic-benign-001",
            "case_id": "phase2-synthetic-benign-001",
            "adjudicated_at": "2026-08-02T12:00:00+00:00",
            "adjudicator_role": "synthetic-fixture-author",
            "adjudicated_disposition": "NO_ACTION",
            "compromised": False,
            "confidence": 1.0,
            "rationale_codes": ["SYNTHETIC_APPROVED_MAINTENANCE"],
        },
        {
            "schema_version": VERSION,
            "adjudication_id": "adj-phase2-synthetic-malicious-001",
            "case_id": "phase2-synthetic-malicious-001",
            "adjudicated_at": "2026-08-02T12:01:00+00:00",
            "adjudicator_role": "synthetic-fixture-author",
            "adjudicated_disposition": "CONTAIN_REVERSIBLE",
            "compromised": True,
            "confidence": 1.0,
            "rationale_codes": ["SYNTHETIC_TOKEN_REUSE"],
        },
        {
            "schema_version": VERSION,
            "adjudication_id": "adj-phase2-synthetic-conflict-001",
            "case_id": "phase2-synthetic-conflict-001",
            "adjudicated_at": "2026-08-02T12:02:00+00:00",
            "adjudicator_role": "synthetic-fixture-author",
            "adjudicated_disposition": "INVESTIGATE",
            "compromised": True,
            "confidence": 0.65,
            "rationale_codes": ["SYNTHETIC_SENSOR_CONFLICT"],
        },
    ]
    return cases, adjudications


def generate(output_dir: Path) -> Path:
    output_dir.mkdir(parents=True, exist_ok=True)
    cases, adjudications = build_fixture()
    cases_path = output_dir / "cases.jsonl"
    adjudications_path = output_dir / "adjudications.jsonl"
    manifest_path = output_dir / "manifest.json"
    _write_jsonl(cases_path, cases)
    _write_jsonl(adjudications_path, adjudications)
    manifest = {
        "schema_version": VERSION,
        "dataset_id": "adf-phase2-starter-synthetic",
        "data_origin": "SYNTHETIC_FIXTURE",
        "historical_case_count": 0,
        "intended_mode": "HISTORICAL_REPLAY",
        "created_at": "2026-08-14T00:00:00+00:00",
        "attestations": {
            "approved_for_replay": True,
            "approval_reference": "SYNTHETIC-FIXTURE-NO-EXTERNAL-DATA",
            "deidentified": True,
            "deidentification_method": "synthetic-by-construction",
            "direct_identifiers_present": False,
            "attested_by": "phase2-fixture-generator",
            "attested_at": "2026-08-14T00:00:00+00:00",
        },
        "files": [
            {
                "role": "cases",
                "path": cases_path.name,
                "sha256": _sha256(cases_path),
                "record_count": len(cases),
                "adapter": "canonical_jsonl_v0.2",
            },
            {
                "role": "adjudications",
                "path": adjudications_path.name,
                "sha256": _sha256(adjudications_path),
                "record_count": len(adjudications),
                "adapter": "canonical_jsonl_v0.2",
            },
        ],
    }
    manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True), encoding="utf-8")
    return manifest_path


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Generate the clearly synthetic Phase 2 replay starter fixture."
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=ROOT / "data" / "phase2_starter",
    )
    args = parser.parse_args()
    manifest_path = generate(args.output_dir.resolve())
    print(f"Generated synthetic Phase 2 fixture: {manifest_path}")


if __name__ == "__main__":
    main()
