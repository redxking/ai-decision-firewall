from __future__ import annotations

import json
import re
import tempfile
import unittest
from pathlib import Path

from scripts.validate_claim_evidence import (
    EvidenceValidationError,
    validate_evidence_record,
)


ROOT = Path(__file__).resolve().parents[1]


class ClaimEvidenceContractTests(unittest.TestCase):
    def test_starter_record_preserves_narrow_synthetic_claim_boundary(self) -> None:
        schema = json.loads(
            (ROOT / "contracts/v0.2.0/evaluation-evidence.schema.json").read_text(
                encoding="utf-8"
            )
        )
        record = json.loads(
            (
                ROOT
                / "contracts/v0.2.0/examples/phase2-starter-evidence-record.json"
            ).read_text(encoding="utf-8")
        )
        validated = validate_evidence_record()

        self.assertEqual(validated["status"], "VALID")
        self.assertEqual(validated["artifact_count"], 14)
        self.assertEqual(validated["audit_record_count"], 24)
        self.assertEqual(schema["properties"]["schema_version"]["const"], "0.2.0")
        self.assertEqual(record["schema_version"], "0.2.0")
        self.assertEqual(record["claim_class"], "CONTROLLED_BEHAVIOR")
        self.assertEqual(record["claim_status"], "OBSERVED")
        self.assertEqual(record["research_basis"]["reviewed_through"], "2026-08-14")
        self.assertTrue(record["research_basis"]["not_yet_evaluated"])
        self.assertEqual(record["evaluation_scope"]["data_origin"], "SYNTHETIC_FIXTURE")
        self.assertEqual(record["evaluation_scope"]["historical_case_count"], 0)
        self.assertEqual(record["results"]["denominator"], 3)
        self.assertEqual(record["results"]["passed"], 3)
        self.assertEqual(record["results"]["failed"], 0)
        self.assertEqual(record["results"]["excluded"], 0)

        metrics = record["results"]["metrics"]
        for key in (
            "authorization_attempts",
            "authorization_tokens_issued",
            "broker_invocations",
            "action_results",
            "operational_effects",
            "historical_case_count",
        ):
            self.assertEqual(metrics[key], 0, key)

        prohibited = " ".join(record["prohibited_inferences"]).lower()
        for phrase in ("historical", "aligned", "production ready", "zero risk", "monitor"):
            self.assertIn(phrase, prohibited)

        roles = set()
        for artifact in record["evidence_artifacts"]:
            self.assertRegex(artifact["sha256"], re.compile(r"^[0-9a-f]{64}$"))
            self.assertTrue(artifact["committed"])
            roles.add(artifact["artifact_role"])
        self.assertEqual(len(roles), 14)

        with tempfile.TemporaryDirectory() as directory:
            invalid_path = Path(directory) / "invalid-evidence.json"
            invalid = json.loads(json.dumps(record))
            invalid["evidence_artifacts"][0]["sha256"] = "0" * 64
            invalid_path.write_text(json.dumps(invalid), encoding="utf-8")
            with self.assertRaises(EvidenceValidationError):
                validate_evidence_record(invalid_path)

            invalid = json.loads(json.dumps(record))
            del invalid["budget"]
            invalid_path.write_text(json.dumps(invalid), encoding="utf-8")
            with self.assertRaises(EvidenceValidationError):
                validate_evidence_record(invalid_path)

    def test_standard_cites_primary_research_and_states_nonclaim(self) -> None:
        standard = (ROOT / "docs/phase2/CLAIM_EVIDENCE_STANDARD.md").read_text(
            encoding="utf-8"
        )
        for url in (
            "https://www.anthropic.com/research/agentic-misalignment",
            "https://www.anthropic.com/research/sabotage-evaluations",
            "https://www.anthropic.com/research/auditing-hidden-objectives",
            "https://openai.com/index/trustworthy-third-party-evaluations-foundations/",
            "https://openai.com/index/how-we-monitor-internal-coding-agents-misalignment/",
        ):
            self.assertIn(url, standard)
        self.assertIn(
            "does **not** contain an autonomous generative-language-model agent",
            standard,
        )
        self.assertIn("A repository test may block a release", standard)

        coverage = (
            ROOT / "docs/phase2/RESEARCH_COVERAGE_REGISTER.md"
        ).read_text(encoding="utf-8")
        for url in (
            "https://openai.com/research/index/",
            "https://openai.com/index/unlocking-self-improvement-gpt-red/",
            "https://openai.com/index/separating-signal-from-noise-coding-evaluations/",
            "https://openai.com/index/why-language-models-hallucinate/",
            "https://openai.com/index/strengthening-safety-with-external-testing/",
        ):
            self.assertIn(url, coverage)
        self.assertIn("Not applicable to the present decision-control claim", coverage)
        self.assertIn("Rescreen the OpenAI Research Index", coverage)


if __name__ == "__main__":
    unittest.main()
