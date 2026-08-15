from __future__ import annotations

import io
import json
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest.mock import patch

import run_poc
from run_poc import (
    DEFAULT_DATA_DIR,
    DEFAULT_OUTPUT_DIR,
    TrackedArtifactOverwriteError,
    require_explicit_tracked_artifact_overwrite,
    require_safe_existing_leaf_targets,
)


ROOT = Path(__file__).resolve().parents[1]


class RunPocSafetyTests(unittest.TestCase):
    def test_default_targets_are_local_and_ungoverned(self) -> None:
        self.assertTrue(DEFAULT_DATA_DIR.is_relative_to(ROOT / "data" / "local"))
        self.assertTrue(DEFAULT_OUTPUT_DIR.is_relative_to(ROOT / "outputs" / "local"))
        normalized = require_explicit_tracked_artifact_overwrite(
            DEFAULT_DATA_DIR,
            DEFAULT_OUTPUT_DIR,
            allowed=False,
        )
        self.assertEqual(normalized, (DEFAULT_DATA_DIR, DEFAULT_OUTPUT_DIR))

    def test_tracked_baseline_requires_explicit_freeze_authority(self) -> None:
        with self.assertRaises(TrackedArtifactOverwriteError):
            require_explicit_tracked_artifact_overwrite(
                ROOT / "data",
                ROOT / "outputs" / "baseline",
                allowed=False,
            )

    def test_nested_tracked_targets_are_also_protected(self) -> None:
        with self.assertRaises(TrackedArtifactOverwriteError):
            require_explicit_tracked_artifact_overwrite(
                ROOT / "data" / "phase2_starter",
                DEFAULT_OUTPUT_DIR,
                allowed=False,
            )
        with self.assertRaises(TrackedArtifactOverwriteError):
            require_explicit_tracked_artifact_overwrite(
                DEFAULT_DATA_DIR,
                ROOT / "outputs" / "baseline" / "candidate",
                allowed=False,
            )

    def test_any_nonlocal_repository_destination_requires_explicit_authority(self) -> None:
        for data_dir, output_dir in (
            (ROOT, DEFAULT_OUTPUT_DIR),
            (DEFAULT_DATA_DIR, ROOT),
            (DEFAULT_DATA_DIR, ROOT / "config"),
            (ROOT / "docs", DEFAULT_OUTPUT_DIR),
        ):
            with self.subTest(data_dir=data_dir, output_dir=output_dir):
                with self.assertRaises(TrackedArtifactOverwriteError):
                    require_explicit_tracked_artifact_overwrite(
                        data_dir,
                        output_dir,
                        allowed=False,
                    )

    def test_cli_guard_runs_before_generation_or_directory_creation(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            external_root = Path(directory)
            cases = (
                (
                    external_root / "data",
                    ROOT / "config" / "poc-output-must-not-exist",
                ),
                (ROOT, external_root / "output-must-not-exist"),
            )
            for data_dir, output_dir in cases:
                with self.subTest(data_dir=data_dir, output_dir=output_dir):
                    self.assertFalse(output_dir.exists())
                    argv = [
                        "run_poc.py",
                        "--data-dir",
                        str(data_dir),
                        "--output-dir",
                        str(output_dir),
                    ]
                    with patch.object(run_poc.sys, "argv", argv), patch.object(
                        run_poc, "generate_dataset"
                    ) as generate_dataset:
                        with self.assertRaises(SystemExit) as raised:
                            run_poc.main()
                    self.assertEqual(raised.exception.code, 2)
                    generate_dataset.assert_not_called()
                    self.assertFalse(output_dir.exists())

    def test_external_temporary_targets_are_allowed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            require_explicit_tracked_artifact_overwrite(
                root / "data",
                root / "output",
                allowed=False,
            )

    def test_explicit_freeze_authority_allows_tracked_targets(self) -> None:
        require_explicit_tracked_artifact_overwrite(
            ROOT / "data",
            ROOT / "outputs" / "baseline",
            allowed=True,
        )

    def test_explicit_freeze_authority_is_not_a_general_clobber_switch(self) -> None:
        for data_dir, output_dir in (
            (ROOT, ROOT / "outputs" / "baseline"),
            (ROOT / "data", ROOT),
            (ROOT / "config", ROOT / "outputs" / "baseline"),
            (ROOT / "data", ROOT / ".git"),
            (ROOT / "data", ROOT / "outputs" / "replay" / "candidate"),
        ):
            with self.subTest(data_dir=data_dir, output_dir=output_dir):
                with self.assertRaises(TrackedArtifactOverwriteError):
                    require_explicit_tracked_artifact_overwrite(
                        data_dir,
                        output_dir,
                        allowed=True,
                    )

    def test_overlap_and_symlink_redirection_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with self.assertRaises(TrackedArtifactOverwriteError):
                require_explicit_tracked_artifact_overwrite(
                    root / "shared",
                    root / "shared" / "output",
                    allowed=False,
                )

            redirected_output = root / "redirected-output"
            redirected_output.symlink_to(ROOT / "config", target_is_directory=True)
            with self.assertRaises(TrackedArtifactOverwriteError):
                require_explicit_tracked_artifact_overwrite(
                    root / "data",
                    redirected_output,
                    allowed=False,
                )

    def test_case_variant_repository_alias_cannot_bypass_confinement(self) -> None:
        alternate_root = ROOT.with_name(ROOT.name.swapcase())
        try:
            same_repository = alternate_root.exists() and alternate_root.samefile(ROOT)
        except OSError:
            same_repository = False
        if not same_repository:
            self.skipTest("Repository filesystem is case-sensitive.")

        with self.assertRaises(TrackedArtifactOverwriteError):
            require_explicit_tracked_artifact_overwrite(
                Path(tempfile.gettempdir()) / "adf-case-probe-data",
                alternate_root / "CoNfIg",
                allowed=False,
            )
        with self.assertRaises(TrackedArtifactOverwriteError):
            require_explicit_tracked_artifact_overwrite(
                alternate_root / "DaTa",
                DEFAULT_OUTPUT_DIR,
                allowed=False,
            )
        with self.assertRaises(TrackedArtifactOverwriteError):
            require_explicit_tracked_artifact_overwrite(
                DEFAULT_DATA_DIR,
                alternate_root / "OuTpUtS" / "BaSeLiNe",
                allowed=False,
            )

    def test_existing_leaf_symlink_is_rejected_before_generation(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            data_dir = root / "data"
            output_dir = root / "output"
            output_dir.mkdir()
            protected = root / "protected-model.json"
            protected.write_text("protected\n", encoding="utf-8")
            (output_dir / "model.json").symlink_to(protected)

            with self.assertRaises(TrackedArtifactOverwriteError):
                require_safe_existing_leaf_targets(data_dir, output_dir)
            self.assertEqual(protected.read_text(encoding="utf-8"), "protected\n")

    def test_existing_hard_link_is_rejected_before_generation(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            data_dir = root / "data"
            output_dir = root / "output"
            data_dir.mkdir()
            protected = root / "protected-cases.jsonl"
            protected.write_text("{}\n", encoding="utf-8")
            (data_dir / "train_cases.jsonl").hardlink_to(protected)

            with self.assertRaises(TrackedArtifactOverwriteError):
                require_safe_existing_leaf_targets(data_dir, output_dir)
            self.assertEqual(protected.read_text(encoding="utf-8"), "{}\n")

    def test_existing_run_manifest_symlink_or_hard_link_is_rejected(self) -> None:
        for link_kind in ("symlink", "hardlink"):
            with self.subTest(link_kind=link_kind), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                output_dir = root / "output"
                output_dir.mkdir()
                protected = root / "protected-manifest.json"
                protected.write_text("protected\n", encoding="utf-8")
                target = output_dir / "run_manifest.json"
                if link_kind == "symlink":
                    target.symlink_to(protected)
                else:
                    target.hardlink_to(protected)

                with self.assertRaises(TrackedArtifactOverwriteError):
                    require_safe_existing_leaf_targets(root / "data", output_dir)
                self.assertEqual(protected.read_text(encoding="utf-8"), "protected\n")

    def test_local_run_manifest_binds_each_named_output(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            data_dir = root / "data"
            output_dir = root / "output"
            argv = [
                "run_poc.py",
                "--train-count",
                "120",
                "--test-count",
                "60",
                "--data-dir",
                str(data_dir),
                "--output-dir",
                str(output_dir),
            ]
            with patch.object(run_poc.sys, "argv", argv), redirect_stdout(io.StringIO()):
                run_poc.main()

            manifest = json.loads(
                (output_dir / "run_manifest.json").read_text(encoding="utf-8")
            )
            self.assertEqual(set(manifest["outputs"]), set(manifest["output_bindings"]))
            for name in manifest["outputs"]:
                self.assertEqual(
                    manifest["output_bindings"][name],
                    run_poc.sha256_file(output_dir / name),
                )


if __name__ == "__main__":
    unittest.main()
