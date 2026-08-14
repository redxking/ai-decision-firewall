from __future__ import annotations

import os
import shutil
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from scripts import generate_phase2_qualification_fixture as generator


ROOT = Path(__file__).resolve().parents[1]


class QualificationFixtureGeneratorTests(unittest.TestCase):
    def _patched_generator(self, repository_root: Path):
        repository_root = repository_root.resolve()
        return patch.multiple(
            generator,
            ROOT=repository_root,
            SOURCE_DIR=repository_root / "data" / "phase2_starter",
            TARGET_DIR=repository_root / "data" / "phase2_qualification",
            CONFIG_PATH=repository_root / "config" / "phase2_qualification.json",
        )

    def test_symlinked_target_directory_cannot_redirect_fixture_writes(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            repository = (base / "repository").resolve()
            outside = base / "outside"
            shutil.copytree(
                ROOT / "data" / "phase2_starter",
                repository / "data" / "phase2_starter",
            )
            outside.mkdir()
            os.symlink(
                outside,
                repository / "data" / "phase2_qualification",
                target_is_directory=True,
            )

            with self._patched_generator(repository), self.assertRaises(ValueError):
                artifacts = generator._build_artifacts()
                generator._write(artifacts, overwrite=False)

            self.assertEqual(list(outside.iterdir()), [])

    def test_hard_linked_target_is_never_overwritten(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            repository = (base / "repository").resolve()
            shutil.copytree(
                ROOT / "data" / "phase2_starter",
                repository / "data" / "phase2_starter",
            )
            (repository / "data" / "phase2_qualification").mkdir()

            with self._patched_generator(repository):
                artifacts = generator._build_artifacts()
                target = repository / "data" / "phase2_qualification" / "cases.jsonl"
                target.write_bytes(artifacts[target])
                linked_copy = base / "linked-cases.jsonl"
                os.link(target, linked_copy)
                with self.assertRaises(ValueError):
                    generator._write(artifacts, overwrite=True)

            self.assertEqual(target.read_bytes(), linked_copy.read_bytes())

    def test_target_swap_after_preflight_cannot_escape_held_directory_walk(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            repository = (base / "repository").resolve()
            outside = base / "outside"
            parked = base / "parked-target"
            shutil.copytree(
                ROOT / "data" / "phase2_starter",
                repository / "data" / "phase2_starter",
            )
            target = repository / "data" / "phase2_qualification"
            target.mkdir()
            outside.mkdir()

            with self._patched_generator(repository):
                artifacts = generator._build_artifacts()
                original_preflight = generator._assert_safe_target_set

                def swap_after_preflight() -> None:
                    original_preflight()
                    target.rename(parked)
                    os.symlink(outside, target, target_is_directory=True)

                with patch.object(
                    generator,
                    "_assert_safe_target_set",
                    side_effect=swap_after_preflight,
                ), self.assertRaises(ValueError):
                    generator._write(artifacts, overwrite=False)

            self.assertEqual(list(outside.iterdir()), [])
            self.assertTrue(parked.is_dir())

    def test_reviewed_source_is_hashed_from_the_single_read_byte_string(self) -> None:
        source = ROOT / "data" / "phase2_starter" / "cases.jsonl"
        reviewed_bytes = source.read_bytes()
        read_count = 0

        def controlled_read(_: Path) -> bytes:
            nonlocal read_count
            read_count += 1
            return reviewed_bytes

        with patch.object(generator, "_secure_read", side_effect=controlled_read):
            lines, records = generator._load_reviewed_controls("cases.jsonl")

        self.assertEqual(read_count, 1)
        self.assertEqual(len(lines), 3)
        self.assertEqual(len(records), 3)


if __name__ == "__main__":
    unittest.main()
