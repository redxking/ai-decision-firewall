from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from scripts.validate_supply_chain import SupplyChainValidationError, validate_repository


ROOT = Path(__file__).resolve().parents[1]


class SupplyChainArtifactTests(unittest.TestCase):
    def test_repository_lockfiles_and_sbom_are_consistent(self) -> None:
        result = validate_repository(ROOT)
        self.assertEqual(result["runtime_locked"], result["sbom_components"])
        self.assertGreaterEqual(result["runtime_locked"], result["runtime_direct"])

    def test_sbom_missing_direct_root_edge_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            candidate = Path(temporary_directory)
            for name in ("requirements.txt", "requirements.lock", "requirements-docs.txt", "requirements-docs.lock", "pyproject.toml"):
                (candidate / name).write_bytes((ROOT / name).read_bytes())
            target = candidate / "artifacts" / "supply-chain"
            target.mkdir(parents=True)
            sbom = json.loads((ROOT / "artifacts/supply-chain/runtime.cdx.json").read_text(encoding="utf-8"))
            root_reference = sbom["metadata"]["component"]["bom-ref"]
            next(row for row in sbom["dependencies"] if row["ref"] == root_reference)["dependsOn"] = []
            (target / "runtime.cdx.json").write_text(json.dumps(sbom), encoding="utf-8")
            with self.assertRaisesRegex(SupplyChainValidationError, "root dependency edges"):
                validate_repository(candidate)


if __name__ == "__main__":
    unittest.main()
