from __future__ import annotations

import json
import unittest
from html.parser import HTMLParser
from pathlib import Path

import jsonschema

from scripts.build_public_site_data import (
    ROOT,
    SCHEMA_PATH,
    SOURCE_TO_DECISION_PLAN,
    build_public_data,
    commit_for,
    load_claim_records,
    serialize,
)


class _SiteHTMLParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.ids: set[str] = set()
        self.scripts: list[str | None] = []
        self.stylesheets: list[str | None] = []
        self.has_main = False
        self.has_h1 = False
        self.run_decision_links: list[str | None] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        values = dict(attrs)
        if values.get("id"):
            self.ids.add(str(values["id"]))
        if tag == "script":
            self.scripts.append(values.get("src"))
        if tag == "link" and values.get("rel") == "stylesheet":
            self.stylesheets.append(values.get("href"))
        if tag == "main":
            self.has_main = True
        if tag == "h1":
            self.has_h1 = True
        if tag == "a" and "data-run-decision" in values:
            self.run_decision_links.append(values.get("href"))


def _walk(value):
    if isinstance(value, dict):
        yield value
        for nested in value.values():
            yield from _walk(nested)
    elif isinstance(value, list):
        for nested in value:
            yield from _walk(nested)


class PublicSiteDataTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.data = build_public_data()
        cls.schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))

    def test_bundle_matches_closed_schema(self) -> None:
        jsonschema.Draft202012Validator(
            self.schema,
            format_checker=jsonschema.FormatChecker(),
        ).validate(self.data)

    def test_checked_in_bundle_is_current(self) -> None:
        current = (ROOT / "site/data/public-results.json").read_text(encoding="utf-8")
        self.assertEqual(current, serialize(self.data))

    def test_phase2_scenarios_are_read_only_and_synthetic(self) -> None:
        phase2 = [row for row in self.data["scenarios"] if row["phase"] == "PHASE_2_READ_ONLY"]
        self.assertEqual(len(phase2), 3)
        for scenario in phase2:
            self.assertFalse(scenario["effect"]["authorization_issued"])
            self.assertEqual(scenario["effect"]["broker_invocations"], 0)
            self.assertEqual(scenario["effect"]["operational_effects"], 0)
            self.assertEqual(scenario["effect"]["status"], "NOT_ATTEMPTED_READ_ONLY")

    def test_public_bundle_omits_sensitive_and_raw_fields(self) -> None:
        prohibited = {
            "subject_id",
            "asset_id",
            "case_id",
            "event_id",
            "decision_id",
            "token_id",
            "state_before",
            "state_after",
            "feature_trace",
            "raw_payload",
            "exception",
            "signature",
        }
        for mapping in _walk(self.data):
            self.assertTrue(prohibited.isdisjoint(mapping.keys()))

    def test_candidate_has_no_observed_result_counts(self) -> None:
        candidate = self.data["site_status"]["candidate"]
        self.assertIsNotNone(candidate)
        self.assertEqual(candidate["evaluation"], "NOT_EVALUATED")
        self.assertEqual(candidate["design_commit"], commit_for(SOURCE_TO_DECISION_PLAN))
        self.assertNotIn("results", candidate)

    def test_claim_accounting_reconciles(self) -> None:
        source_records = {
            record["claim_id"]: record for _, record in load_claim_records()
        }
        for claim in self.data["claims"]:
            result = claim["results"]
            self.assertEqual(
                result["denominator"],
                result["passed"] + result["failed"] + result["excluded"],
            )
            for objection in source_records[claim["claim_id"]]["review"][
                "unresolved_objections"
            ]:
                self.assertIn(objection, claim["limitation"])


class PublicSiteStructureTests(unittest.TestCase):
    def test_page_has_expected_accessible_structure_and_local_assets(self) -> None:
        parser = _SiteHTMLParser()
        parser.feed((ROOT / "site/index.html").read_text(encoding="utf-8"))
        self.assertTrue(parser.has_main)
        self.assertTrue(parser.has_h1)
        self.assertTrue({"decision-demo", "how-it-works", "evidence", "boundaries"}.issubset(parser.ids))
        self.assertEqual(parser.scripts, ["./app.js?v=1.0.4"])
        self.assertEqual(parser.stylesheets, ["./styles.css?v=1.0.4"])
        self.assertEqual(parser.run_decision_links, ["#decision-demo", "#decision-demo"])
        source = (ROOT / "site/index.html").read_text(encoding="utf-8")
        self.assertNotIn("independent verification", source.lower())
        self.assertNotIn("independent verify", source.lower())

    def test_evidence_loader_is_versioned_bounded_and_fail_closed(self) -> None:
        script = (ROOT / "site/app.js").read_text(encoding="utf-8")
        self.assertIn('const PUBLIC_DATA_URL = "./data/public-results.json?v=1.0.4";', script)
        self.assertIn("const PUBLIC_DATA_ATTEMPTS = 3;", script)
        self.assertIn("The validated public evidence bundle could not be loaded.", script)
        self.assertNotIn("independent checks approve", script.lower())
        self.assertNotIn("an independent, non-model control", script.lower())

    def test_social_preview_asset_is_present(self) -> None:
        image = ROOT / "site/assets/og.png"
        self.assertTrue(image.is_file())
        self.assertGreater(image.stat().st_size, 50_000)


if __name__ == "__main__":
    unittest.main()
