from __future__ import annotations

import re
import unittest
from pathlib import Path


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
WORKFLOW_ROOT = REPOSITORY_ROOT / ".github" / "workflows"
ACTION_REFERENCE = re.compile(r"^\s*(?:-\s*)?uses:\s*([^\s#]+)")
FULL_COMMIT_SHA = re.compile(r"^[0-9a-f]{40}$")


class WorkflowSupplyChainTests(unittest.TestCase):
    def test_external_actions_are_pinned_to_full_commit_shas(self) -> None:
        observed: list[tuple[Path, int, str]] = []
        unpinned: list[str] = []

        workflows = sorted(WORKFLOW_ROOT.glob("*.yml")) + sorted(
            WORKFLOW_ROOT.glob("*.yaml")
        )
        for workflow in workflows:
            for line_number, line in enumerate(
                workflow.read_text(encoding="utf-8").splitlines(), start=1
            ):
                match = ACTION_REFERENCE.match(line)
                if match is None:
                    continue
                reference = match.group(1)
                if reference.startswith("./"):
                    continue
                observed.append((workflow, line_number, reference))
                _, separator, revision = reference.rpartition("@")
                if not separator or FULL_COMMIT_SHA.fullmatch(revision) is None:
                    unpinned.append(
                        f"{workflow.relative_to(REPOSITORY_ROOT)}:{line_number}: {reference}"
                    )

        self.assertTrue(observed, "No external GitHub Action references were found")
        self.assertEqual([], unpinned, "Unpinned GitHub Actions:\n" + "\n".join(unpinned))


if __name__ == "__main__":
    unittest.main()
