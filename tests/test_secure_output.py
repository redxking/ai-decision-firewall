from __future__ import annotations

import hashlib
import json
import stat
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from adf_poc.replay.secure_output import (
    HistoricalOutputError,
    HistoricalOutputGuard,
)
from adf_poc.utils import canonical_json


class HistoricalOutputGuardTests(unittest.TestCase):
    def test_owner_only_descriptor_bound_artifact_helpers(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            with HistoricalOutputGuard.create(
                root, "outputs/replay/secure-run", max_file_bytes=4096
            ) as guard:
                self.assertEqual(
                    guard.display_path,
                    root / "outputs" / "replay" / "secure-run",
                )
                guard.write_bytes("input_snapshot/cases.jsonl", b'{"case":1}\n')
                guard.write_json("summary.json", {"z": 2, "a": 1})
                count = guard.write_jsonl(
                    "decisions.jsonl", [{"z": 2, "a": 1}, {"case": 2}]
                )

                self.assertEqual(count, 2)
                self.assertEqual(
                    guard.read_bytes("summary.json"),
                    json.dumps({"z": 2, "a": 1}, indent=2, sort_keys=True).encode(
                        "utf-8"
                    ),
                )
                expected_jsonl = (
                    canonical_json({"z": 2, "a": 1})
                    + "\n"
                    + canonical_json({"case": 2})
                    + "\n"
                ).encode("utf-8")
                self.assertEqual(guard.read_bytes("decisions.jsonl"), expected_jsonl)
                self.assertEqual(
                    guard.read_jsonl("decisions.jsonl"),
                    [{"a": 1, "z": 2}, {"case": 2}],
                )
                guard.write_bytes(
                    "duplicate.jsonl",
                    b'{"matched":false,"matched":true}\n',
                )
                guard.write_bytes("nonfinite.jsonl", b'{"value":1e400}\n')
                for invalid in ("duplicate.jsonl", "nonfinite.jsonl"):
                    with self.subTest(invalid=invalid):
                        with self.assertRaises(HistoricalOutputError):
                            guard.read_jsonl(invalid)
                self.assertEqual(guard.count_nonblank_lines("decisions.jsonl"), 2)
                self.assertEqual(
                    guard.sha256("decisions.jsonl"),
                    hashlib.sha256(expected_jsonl).hexdigest(),
                )

                run_path = root / "outputs" / "replay" / "secure-run"
                snapshot_path = run_path / "input_snapshot"
                self.assertEqual(stat.S_IMODE(run_path.stat().st_mode), 0o700)
                self.assertEqual(stat.S_IMODE(snapshot_path.stat().st_mode), 0o700)
                for artifact in (
                    snapshot_path / "cases.jsonl",
                    run_path / "summary.json",
                    run_path / "decisions.jsonl",
                ):
                    self.assertEqual(stat.S_IMODE(artifact.stat().st_mode), 0o600)

                with self.assertRaises(HistoricalOutputError):
                    guard.write_bytes("summary.json", b"replacement")
                with self.assertRaises(HistoricalOutputError):
                    guard.write_bytes("oversized.bin", b"12345", max_bytes=4)
                with self.assertRaises(HistoricalOutputError):
                    guard.write_json("nonfinite.json", {"value": float("inf")})
                with self.assertRaises(HistoricalOutputError):
                    guard.write_jsonl(
                        "nonfinite-write.jsonl", [{"value": float("nan")}]
                    )
                self.assertFalse((run_path / "oversized.bin").exists())

            with self.assertRaises(HistoricalOutputError):
                guard.read_bytes("summary.json")

    def test_rejects_noncanonical_out_of_scope_and_preexisting_paths(self) -> None:
        invalid_paths = (
            "replay/run",
            "outputs/replay",
            "outputs/replay/run/nested",
            "outputs//replay/run",
            "outputs/replay/run/",
            "outputs/replay/../run",
        )
        for invalid in invalid_paths:
            with self.subTest(path=invalid), tempfile.TemporaryDirectory() as temporary:
                with self.assertRaises(HistoricalOutputError):
                    HistoricalOutputGuard.create(Path(temporary), invalid)

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            existing = root / "outputs" / "replay" / "existing"
            existing.mkdir(parents=True)
            with self.assertRaises(HistoricalOutputError):
                HistoricalOutputGuard.create(root, "outputs/replay/existing")

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            outside = root / "outside"
            outside.mkdir()
            (root / "outputs").mkdir()
            (root / "outputs" / "replay").symlink_to(outside, target_is_directory=True)
            with self.assertRaises(HistoricalOutputError):
                HistoricalOutputGuard.create(root, "outputs/replay/symlinked")
            self.assertEqual(list(outside.iterdir()), [])

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            linked_root = root.parent / f"{root.name}-link"
            linked_root.symlink_to(root, target_is_directory=True)
            try:
                with self.assertRaises(HistoricalOutputError):
                    HistoricalOutputGuard.create(
                        linked_root, "outputs/replay/root-link"
                    )
            finally:
                linked_root.unlink()

    def test_replay_ancestor_relocation_cannot_redirect_writes(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            guard = HistoricalOutputGuard.create(root, "outputs/replay/bound-run")
            try:
                replay_path = root / "outputs" / "replay"
                retained_replay = root / "retained-replay"
                attacker_directory = root / "attacker-selected"
                attacker_directory.mkdir()
                original_write_all = HistoricalOutputGuard._write_all
                observed_bound_content: list[bytes] = []

                def relocate_during_write(descriptor: int, content: bytes) -> None:
                    replay_path.rename(retained_replay)
                    replay_path.symlink_to(attacker_directory, target_is_directory=True)
                    original_write_all(descriptor, content)
                    observed_bound_content.append(
                        (retained_replay / "bound-run" / "decision.txt").read_bytes()
                    )

                with patch.object(
                    HistoricalOutputGuard,
                    "_write_all",
                    side_effect=relocate_during_write,
                ):
                    with self.assertRaises(HistoricalOutputError):
                        guard.write_bytes("decision.txt", b"fd-bound")

                self.assertEqual(observed_bound_content, [b"fd-bound"])
                self.assertFalse(
                    (retained_replay / "bound-run" / "decision.txt").exists()
                )
                with self.assertRaises(HistoricalOutputError):
                    guard.verify_bindings()
                self.assertEqual(list(attacker_directory.iterdir()), [])
            finally:
                guard.close()

    def test_run_directory_swap_cannot_redirect_writes(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            guard = HistoricalOutputGuard.create(root, "outputs/replay/bound-run")
            try:
                replay_path = root / "outputs" / "replay"
                public_run_path = replay_path / "bound-run"
                retained_run = replay_path / "retained-run"
                public_run_path.rename(retained_run)
                attacker_directory = root / "attacker-selected"
                attacker_directory.mkdir()
                public_run_path.symlink_to(attacker_directory, target_is_directory=True)

                with self.assertRaises(HistoricalOutputError):
                    guard.verify_bindings()
                with self.assertRaises(HistoricalOutputError):
                    guard.write_json("summary.json", {"custody": "retained"})
                with self.assertRaises(HistoricalOutputError):
                    guard.write_bytes("input_snapshot/source.bin", b"frozen")

                self.assertFalse((retained_run / "summary.json").exists())
                self.assertFalse(
                    (retained_run / "input_snapshot" / "source.bin").exists()
                )
                self.assertEqual(list(attacker_directory.iterdir()), [])
            finally:
                guard.close()

    def test_read_helpers_reject_hardlinks_and_enforce_bounds(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            with HistoricalOutputGuard.create(
                root, "outputs/replay/bounds", max_file_bytes=128
            ) as guard:
                guard.write_bytes("bounded.bin", b"12345678")
                with self.assertRaises(HistoricalOutputError):
                    guard.read_bytes("bounded.bin", max_bytes=4)

                linked = guard.display_path / "linked.bin"
                linked.hardlink_to(guard.display_path / "bounded.bin")
                with self.assertRaises(HistoricalOutputError):
                    guard.sha256("bounded.bin")


if __name__ == "__main__":
    unittest.main()
