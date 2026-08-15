from __future__ import annotations

import builtins
import io
import os
import tempfile
import unittest
from pathlib import Path

from adf_poc.replay.payload_observer import observe_python_payload_access


class PayloadObserverTests(unittest.TestCase):
    def test_enumerated_python_apis_observe_governed_payload_access(self) -> None:
        operations = (
            lambda path: builtins.open(path, "rb").close(),
            lambda path: builtins.open(os.fsencode(path), "rb").close(),
            lambda path: io.open(path, "rb").close(),
            self._os_open_and_close,
            lambda path: path.open("rb").close(),
            lambda path: path.read_bytes(),
            lambda path: path.read_text(encoding="utf-8"),
        )
        for operation in operations:
            with self.subTest(operation=operation), tempfile.TemporaryDirectory() as directory:
                payload = Path(directory) / "cases.jsonl"
                payload.write_text("{}\n", encoding="utf-8")
                with observe_python_payload_access({payload: "cases"}) as observation:
                    operation(payload)
                self.assertEqual(observation.accessed_roles, {"cases"})

    def test_unrelated_file_does_not_create_a_payload_observation(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            governed = root / "cases.jsonl"
            unrelated = root / "notes.txt"
            governed.write_text("{}\n", encoding="utf-8")
            unrelated.write_text("safe\n", encoding="utf-8")
            with observe_python_payload_access({governed: "cases"}) as observation:
                unrelated.read_text(encoding="utf-8")
            self.assertEqual(observation.accessed_roles, set())

    def test_dir_fd_relative_os_open_is_observed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            payload = root / "cases.jsonl"
            payload.write_text("{}\n", encoding="utf-8")
            directory_fd = os.open(root, os.O_RDONLY)
            try:
                with observe_python_payload_access({payload: "cases"}) as observation:
                    payload_fd = os.open(
                        payload.name,
                        os.O_RDONLY,
                        dir_fd=directory_fd,
                    )
                    os.close(payload_fd)
            finally:
                os.close(directory_fd)
            self.assertEqual(observation.accessed_roles, {"cases"})

    def test_observer_self_describes_its_non_enforcement_boundary(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            payload = Path(directory) / "cases.jsonl"
            payload.write_text("{}\n", encoding="utf-8")
            with observe_python_payload_access({payload: "cases"}) as observation:
                pass
            self.assertEqual(
                observation.assurance_class,
                "PYTHON_API_OBSERVED_ACCESS",
            )
            self.assertIn("builtins.open", observation.monitor_scope)
            self.assertTrue(
                any("direct syscalls" in item for item in observation.monitor_exclusions)
            )
            self.assertTrue(
                any("pre-captured aliases" in item for item in observation.monitor_exclusions)
            )
            self.assertTrue(
                any("hard-link aliases" in item for item in observation.monitor_exclusions)
            )

    @staticmethod
    def _os_open_and_close(path: Path) -> None:
        descriptor = os.open(path, os.O_RDONLY)
        os.close(descriptor)


if __name__ == "__main__":
    unittest.main()
