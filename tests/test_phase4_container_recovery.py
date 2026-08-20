from __future__ import annotations

import io
import os
import socket
import subprocess
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest.mock import patch

from adf_poc.lab_nodes import (
    EXECUTOR_AFTER_RESERVATION,
    OBSERVER_AFTER_OBSERVATION,
    LabNodeError,
    _create_or_read_private_file,
    recover_stale_socket,
    run_executor,
    run_observer,
)
from scripts.run_phase4_container_recovery import (
    SCENARIOS,
    Phase4ContainerRecoveryCampaign,
    main,
)
from scripts.run_phase4_container_lab import ContainerLabError


IMAGE = "sha256:" + ("a" * 64)


class Phase4ContainerRecoveryTests(unittest.TestCase):
    def test_cli_and_scenario_require_explicit_closed_authority(self) -> None:
        output = io.StringIO()
        with redirect_stdout(output):
            self.assertEqual(
                main(
                    [
                        "--image",
                        IMAGE,
                        "--scenario",
                        "executor-after-reservation",
                    ]
                ),
                2,
            )
        self.assertIn("LAB_NOT_AUTHORIZED", output.getvalue())
        with self.assertRaises(ContainerLabError) as raised:
            Phase4ContainerRecoveryCampaign(
                image=IMAGE, lab_id="abcdef123456", scenario="arbitrary"
            )
        self.assertEqual(
            getattr(raised.exception, "reason_code", None),
            "LAB_RECOVERY_SCENARIO_INVALID",
        )

    def test_service_fault_stages_are_denied_without_second_opt_in(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for function, stage in (
                (run_executor, EXECUTOR_AFTER_RESERVATION),
                (run_observer, OBSERVER_AFTER_OBSERVATION),
            ):
                with (
                    self.subTest(function=function.__name__),
                    self.assertRaises(LabNodeError) as raised,
                ):
                    function(
                        root,
                        root / "facts.json",
                        fault_stage=stage,
                        allow_fault_injection=False,
                    )
                self.assertEqual(
                    raised.exception.reason_code,
                    "LAB_FAULT_INJECTION_NOT_AUTHORIZED",
                )

    def test_persisted_control_command_is_create_once_and_exact(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            root.chmod(0o700)
            path = root / "command.json"
            first = _create_or_read_private_file(path, b'{"first":true}')
            second = _create_or_read_private_file(path, b'{"forged":true}')
            self.assertEqual(first, b'{"first":true}')
            self.assertEqual(second, first)
            self.assertEqual(path.read_bytes(), first)
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)

    def test_socket_recovery_refuses_any_still_mounted_volume(self) -> None:
        campaign = Phase4ContainerRecoveryCampaign(
            image=IMAGE,
            lab_id="abcdef123456",
            scenario="executor-after-reservation",
        )
        completed = subprocess.CompletedProcess(
            args=[], returncode=0, stdout="rogue-container\n", stderr=""
        )
        with (
            patch(
                "scripts.run_phase4_container_recovery._docker",
                return_value=completed,
            ),
            self.assertRaises(ContainerLabError) as raised,
        ):
            campaign._recover_socket(
                volume="executor-volume", socket_name="executor.sock"
            )
        self.assertEqual(
            getattr(raised.exception, "reason_code", None),
            "LAB_STALE_SOCKET_IN_USE",
        )

    @unittest.skipUnless(sys.platform == "linux", "requires Linux Unix socket path")
    def test_stale_socket_recovery_is_exact_owner_checked_and_explicit(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            root.chmod(0o700)
            path = root / "executor.sock"
            endpoint = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            endpoint.bind(str(path))
            path.chmod(0o600)
            endpoint.close()
            with self.assertRaises(LabNodeError) as raised:
                recover_stale_socket(
                    root,
                    socket_name="executor.sock",
                    explicitly_enabled=False,
                )
            self.assertEqual(
                raised.exception.reason_code, "LAB_SOCKET_RECOVERY_NOT_AUTHORIZED"
            )
            self.assertTrue(path.exists())
            recover_stale_socket(
                root,
                socket_name="executor.sock",
                explicitly_enabled=True,
            )
            self.assertFalse(path.exists())

    @unittest.skipUnless(
        os.environ.get("ADF_PHASE4_CONTAINER_RECOVERY") == "1",
        "real container recovery matrix requires explicit opt-in",
    )
    def test_real_container_recovery_matrix(self) -> None:
        image = os.environ["ADF_PHASE4_LAB_IMAGE"]
        for index, scenario in enumerate(sorted(SCENARIOS), start=1):
            with self.subTest(scenario=scenario):
                self.assertEqual(
                    main(
                        [
                            "--allow-container-recovery",
                            "--image",
                            image,
                            "--scenario",
                            scenario,
                            "--lab-id",
                            f"abcdef12345{index}",
                        ]
                    ),
                    0,
                )


if __name__ == "__main__":
    unittest.main()
