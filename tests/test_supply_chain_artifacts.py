from __future__ import annotations

import hashlib
import json
import shutil
import tempfile
import unittest
from pathlib import Path

from scripts.validate_manifest import ManifestValidationError, validate_manifest
from scripts.validate_supply_chain import (
    SupplyChainValidationError,
    validate_repository,
)


ROOT = Path(__file__).resolve().parents[1]
SUPPLY_FILES = (
    "requirements.txt",
    "requirements.lock",
    "requirements-docs.txt",
    "requirements-docs.lock",
    "pyproject.toml",
    "artifacts/supply-chain/runtime.cdx.json",
)


def _copy_supply_candidate(destination: Path) -> None:
    for relative in SUPPLY_FILES:
        source = ROOT / relative
        target = destination / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, target)


def _file_sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _write_manifest(root: Path, entries: list[tuple[str, str]]) -> None:
    (root / "MANIFEST.sha256").write_text(
        "".join(f"{digest}  {path}\n" for path, digest in entries),
        encoding="utf-8",
    )


class SupplyChainArtifactTests(unittest.TestCase):
    def test_repository_lockfiles_and_sbom_are_consistent(self) -> None:
        result = validate_repository(ROOT)
        self.assertEqual(result["runtime_locked"], result["sbom_components"])
        self.assertGreaterEqual(result["runtime_locked"], result["runtime_direct"])
        self.assertGreater(result["runtime_distribution_hashes"], 0)

    def test_sbom_missing_direct_root_edge_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            candidate = Path(temporary_directory)
            _copy_supply_candidate(candidate)
            sbom_path = candidate / "artifacts/supply-chain/runtime.cdx.json"
            sbom = json.loads(sbom_path.read_text(encoding="utf-8"))
            root_reference = sbom["metadata"]["component"]["bom-ref"]
            next(row for row in sbom["dependencies"] if row["ref"] == root_reference)[
                "dependsOn"
            ] = []
            sbom_path.write_text(json.dumps(sbom), encoding="utf-8")
            with self.assertRaisesRegex(
                SupplyChainValidationError, "root dependency edges"
            ):
                validate_repository(candidate)

    def test_sbom_missing_conditional_transitive_edge_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            candidate = Path(temporary_directory)
            _copy_supply_candidate(candidate)
            sbom_path = candidate / "artifacts/supply-chain/runtime.cdx.json"
            sbom = json.loads(sbom_path.read_text(encoding="utf-8"))
            references = {
                component["name"]: component["bom-ref"]
                for component in sbom["components"]
            }
            referencing_row = next(
                row
                for row in sbom["dependencies"]
                if row["ref"] == references["referencing"]
            )
            referencing_row["dependsOn"].remove(references["typing-extensions"])
            sbom_path.write_text(json.dumps(sbom), encoding="utf-8")
            with self.assertRaisesRegex(
                SupplyChainValidationError,
                "reviewed graph for referencing",
            ):
                validate_repository(candidate)

    def test_runtime_lock_must_match_reviewed_transitive_graph(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            candidate = Path(temporary_directory)
            _copy_supply_candidate(candidate)
            lock_path = candidate / "requirements.lock"
            lock_path.write_text(
                lock_path.read_text(encoding="utf-8").replace(
                    "typing-extensions==4.16.0", "unreviewed-package==4.16.0", 1
                ),
                encoding="utf-8",
            )
            sbom_path = candidate / "artifacts/supply-chain/runtime.cdx.json"
            sbom = json.loads(sbom_path.read_text(encoding="utf-8"))
            component = next(
                item for item in sbom["components"] if item["name"] == "typing-extensions"
            )
            component["name"] = "unreviewed-package"
            component["purl"] = "pkg:pypi/unreviewed-package@4.16.0"
            component["externalReferences"][0]["url"] = (
                "https://pypi.org/simple/unreviewed-package/"
            )
            sbom_path.write_text(json.dumps(sbom), encoding="utf-8")
            with self.assertRaisesRegex(
                SupplyChainValidationError, "reviewed transitive dependency graph"
            ):
                validate_repository(candidate)

    def test_lock_parser_rejects_every_unparsed_directive(self) -> None:
        mutations = (
            "--extra-index-url https://packages.invalid/simple\n",
            "-r unreviewed.lock\n",
            "unparsed trailing content\n",
        )
        for mutation in mutations:
            with (
                self.subTest(mutation=mutation),
                tempfile.TemporaryDirectory() as directory,
            ):
                candidate = Path(directory)
                _copy_supply_candidate(candidate)
                lock_path = candidate / "requirements.lock"
                lock_path.write_text(
                    mutation + lock_path.read_text(encoding="utf-8"),
                    encoding="utf-8",
                )
                with self.assertRaisesRegex(
                    SupplyChainValidationError, "unsupported or unparsed lock content"
                ):
                    validate_repository(candidate)

    def test_lock_parser_rejects_duplicate_hashes(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            candidate = Path(directory)
            _copy_supply_candidate(candidate)
            lock_path = candidate / "requirements.lock"
            text = lock_path.read_text(encoding="utf-8")
            first_hash_line = next(
                line for line in text.splitlines() if "--hash=sha256:" in line
            )
            text = text.replace(
                first_hash_line, first_hash_line + "\n" + first_hash_line, 1
            )
            lock_path.write_text(text, encoding="utf-8")
            with self.assertRaisesRegex(
                SupplyChainValidationError, "repeats a SHA-256"
            ):
                validate_repository(candidate)

    def test_locked_direct_version_must_satisfy_declared_range(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            candidate = Path(directory)
            _copy_supply_candidate(candidate)
            lock_path = candidate / "requirements.lock"
            lock_path.write_text(
                lock_path.read_text(encoding="utf-8").replace(
                    "jsonschema==4.26.0", "jsonschema==5.0.0", 1
                ),
                encoding="utf-8",
            )
            with self.assertRaisesRegex(
                SupplyChainValidationError, "does not satisfy direct specifier"
            ):
                validate_repository(candidate)

    def test_sbom_strict_json_rejects_duplicate_and_nonfinite_members(self) -> None:
        for mutation, expected in (
            (
                lambda text: text.replace("{", '{\n  "version": 1,', 1),
                "duplicate JSON member",
            ),
            (
                lambda text: text.replace('"version": 1', '"version": NaN', 1),
                "non-finite JSON",
            ),
        ):
            with (
                self.subTest(expected=expected),
                tempfile.TemporaryDirectory() as directory,
            ):
                candidate = Path(directory)
                _copy_supply_candidate(candidate)
                sbom_path = candidate / "artifacts/supply-chain/runtime.cdx.json"
                sbom_path.write_text(
                    mutation(sbom_path.read_text(encoding="utf-8")), encoding="utf-8"
                )
                with self.assertRaisesRegex(SupplyChainValidationError, expected):
                    validate_repository(candidate)

    def test_sbom_distribution_hashes_must_equal_the_lock(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            candidate = Path(directory)
            _copy_supply_candidate(candidate)
            sbom_path = candidate / "artifacts/supply-chain/runtime.cdx.json"
            sbom = json.loads(sbom_path.read_text(encoding="utf-8"))
            sbom["components"][0]["externalReferences"][0]["hashes"][0]["content"] = (
                "0" * 64
            )
            sbom_path.write_text(json.dumps(sbom), encoding="utf-8")
            with self.assertRaisesRegex(
                SupplyChainValidationError, "hashes differ from requirements.lock"
            ):
                validate_repository(candidate)

    def test_runtime_direct_requirements_must_equal_project_metadata(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            candidate = Path(directory)
            _copy_supply_candidate(candidate)
            requirements = candidate / "requirements.txt"
            requirements.write_text(
                requirements.read_text(encoding="utf-8").replace(
                    "numpy>=1.26,<2.5", "numpy>=1.27,<2.5"
                ),
                encoding="utf-8",
            )
            with self.assertRaisesRegex(
                SupplyChainValidationError, "does not exactly match pyproject.toml"
            ):
                validate_repository(candidate)

    def test_repository_manifest_exactly_covers_tracked_files(self) -> None:
        result = validate_manifest(ROOT, verify_hashes=False)
        self.assertEqual(result["manifest_entries"], result["tracked_files"] - 1)
        self.assertEqual(result["verified_hashes"], 0)

    def test_manifest_accepts_one_sorted_entry_per_tracked_regular_file(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "nested").mkdir()
            (root / "a.txt").write_text("alpha\n", encoding="utf-8")
            (root / "nested/b.txt").write_text("bravo\n", encoding="utf-8")
            _write_manifest(
                root,
                [
                    ("a.txt", _file_sha256(root / "a.txt")),
                    ("nested/b.txt", _file_sha256(root / "nested/b.txt")),
                ],
            )
            result = validate_manifest(
                root,
                tracked_paths=("MANIFEST.sha256", "a.txt", "nested/b.txt"),
            )
            self.assertEqual(result["manifest_entries"], 2)
            self.assertEqual(result["verified_hashes"], 2)

    def test_manifest_rejects_omission_extra_duplicate_and_unsafe_path(self) -> None:
        cases = (
            (
                [("a.txt", "0" * 64)],
                ("MANIFEST.sha256", "a.txt", "b.txt"),
                "coverage differs",
            ),
            (
                [("a.txt", "0" * 64), ("extra.txt", "0" * 64)],
                ("MANIFEST.sha256", "a.txt"),
                "coverage differs",
            ),
            (
                [("a.txt", "0" * 64), ("a.txt", "0" * 64)],
                ("MANIFEST.sha256", "a.txt"),
                "repeats path",
            ),
            (
                [("../a.txt", "0" * 64)],
                ("MANIFEST.sha256", "a.txt"),
                "canonical repository-relative",
            ),
            (
                [("nested//a.txt", "0" * 64)],
                ("MANIFEST.sha256", "nested/a.txt"),
                "canonical repository-relative",
            ),
            (
                [("a\t.txt", "0" * 64)],
                ("MANIFEST.sha256", "a.txt"),
                "canonical repository-relative",
            ),
        )
        for entries, tracked, expected in cases:
            with (
                self.subTest(expected=expected),
                tempfile.TemporaryDirectory() as directory,
            ):
                root = Path(directory)
                (root / "a.txt").write_text("alpha\n", encoding="utf-8")
                (root / "b.txt").write_text("bravo\n", encoding="utf-8")
                (root / "extra.txt").write_text("extra\n", encoding="utf-8")
                _write_manifest(root, entries)
                with self.assertRaisesRegex(ManifestValidationError, expected):
                    validate_manifest(root, tracked_paths=tracked, verify_hashes=False)

    def test_manifest_rejects_symlink_and_digest_mismatch(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / "target.txt"
            target.write_text("target\n", encoding="utf-8")
            link = root / "linked.txt"
            link.symlink_to(target)
            _write_manifest(root, [("linked.txt", _file_sha256(target))])
            with self.assertRaisesRegex(ManifestValidationError, "regular file"):
                validate_manifest(
                    root,
                    tracked_paths=("MANIFEST.sha256", "linked.txt"),
                )

            link.unlink()
            link.write_text("different\n", encoding="utf-8")
            with self.assertRaisesRegex(ManifestValidationError, "digest mismatch"):
                validate_manifest(
                    root,
                    tracked_paths=("MANIFEST.sha256", "linked.txt"),
                )

    def test_manifest_must_itself_be_tracked(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / "a.txt"
            target.write_text("alpha\n", encoding="utf-8")
            _write_manifest(root, [("a.txt", _file_sha256(target))])
            with self.assertRaisesRegex(ManifestValidationError, "itself be a tracked"):
                validate_manifest(root, tracked_paths=("a.txt",))


if __name__ == "__main__":
    unittest.main()
