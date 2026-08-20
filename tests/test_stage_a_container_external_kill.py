from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import time
import unittest
import uuid


ROOT = Path(__file__).resolve().parents[1]
WORKER = "/opt/adf/tests/container_stage_a_external_kill.py"
BOUNDARIES = ("T1", "OBSERVATION", "T2", "AUDIT", "T3")


def _run(
    arguments: list[str],
    *,
    check: bool = True,
    timeout: float = 30,
) -> subprocess.CompletedProcess[str]:
    completed = subprocess.run(
        ["docker", *arguments],
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
        timeout=timeout,
    )
    if check and completed.returncode != 0:
        raise AssertionError(
            f"docker {' '.join(arguments[:3])} failed ({completed.returncode}): "
            f"{completed.stderr or completed.stdout}"
        )
    return completed


@unittest.skipUnless(
    os.environ.get("ADF_CONTAINER_EXTERNAL_KILL_CAMPAIGN") == "1",
    "external container-kill campaign requires an explicit marker",
)
class StageAContainerExternalKillTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.image = os.environ.get("ADF_IMAGE_TAG", "")
        if not cls.image:
            raise unittest.SkipTest("ADF_IMAGE_TAG is required")
        inspected = _run(["image", "inspect", cls.image])
        if not inspected.stdout:
            raise unittest.SkipTest("The exact campaign image is unavailable")

    def _container_arguments(
        self,
        *,
        state_volume: str,
        control_volume: str,
    ) -> list[str]:
        return [
            "--network=none",
            "--read-only",
            "--cap-drop=ALL",
            "--security-opt=no-new-privileges",
            "--pids-limit=64",
            "--memory=512m",
            "--cpus=2",
            "--tmpfs",
            "/tmp:rw,noexec,nosuid,nodev,size=128m",
            "--user",
            "10001:10001",
            "--volume",
            f"{state_volume}:/state",
            "--volume",
            f"{control_volume}:/campaign-control",
            "--volume",
            f"{ROOT / 'tests'}:/opt/adf/tests:ro",
            "--env",
            "PYTHONPATH=/opt/adf/src:/opt/adf/dependencies:/opt/adf",
            "--env",
            "PYTHONDONTWRITEBYTECODE=1",
            "--env",
            "ADF_CONTAINER_EXTERNAL_KILL_CAMPAIGN=1",
            "--entrypoint",
            "python",
        ]

    def _initialize_volumes(self, state_volume: str, control_volume: str) -> None:
        code = (
            "import os; "
            "[(os.chown(path,10001,10001),os.chmod(path,0o700)) "
            "for path in ('/state','/campaign-control')]"
        )
        _run(
            [
                "run",
                "--rm",
                "--network=none",
                "--read-only",
                "--user",
                "0:0",
                "--volume",
                f"{state_volume}:/state",
                "--volume",
                f"{control_volume}:/campaign-control",
                "--entrypoint",
                "python",
                self.image,
                "-c",
                code,
            ]
        )

    def test_external_sigkill_preserves_exactly_once_effect_boundary(self) -> None:
        for boundary in BOUNDARIES:
            suffix = uuid.uuid4().hex[:12]
            worker_name = f"adf-external-kill-{boundary.lower()}-{suffix}"
            state_volume = f"adf-stage-a-state-{suffix}"
            control_volume = f"adf-stage-a-control-{suffix}"
            created_worker = False
            try:
                _run(["volume", "create", state_volume])
                _run(["volume", "create", control_volume])
                self._initialize_volumes(state_volume, control_volume)
                common = self._container_arguments(
                    state_volume=state_volume,
                    control_volume=control_volume,
                )
                _run(
                    [
                        "create",
                        "--name",
                        worker_name,
                        *common,
                        self.image,
                        WORKER,
                        "worker",
                        boundary,
                    ]
                )
                created_worker = True
                _run(["start", worker_name])

                marker = f"/campaign-control/{boundary.lower()}.ready"
                deadline = time.monotonic() + 30
                while time.monotonic() < deadline:
                    observed = _run(
                        ["exec", worker_name, "test", "-f", marker],
                        check=False,
                        timeout=5,
                    )
                    if observed.returncode == 0:
                        break
                    running = _run(
                        ["inspect", "--format", "{{.State.Running}}", worker_name]
                    )
                    if running.stdout.strip() != "true":
                        logs = _run(["logs", worker_name], check=False)
                        self.fail(
                            f"{boundary} worker exited before its marker: "
                            f"{logs.stderr or logs.stdout}"
                        )
                    time.sleep(0.1)
                else:
                    self.fail(f"{boundary} worker did not reach its boundary")

                _run(["kill", "--signal", "KILL", worker_name])
                waited = _run(["wait", worker_name])
                self.assertEqual("137", waited.stdout.strip())

                verified = _run(
                    [
                        "run",
                        "--rm",
                        *common,
                        self.image,
                        WORKER,
                        "verify",
                        boundary,
                    ]
                )
                payload = json.loads(verified.stdout.strip().splitlines()[-1])
                self.assertEqual(boundary, payload["boundary"])
                self.assertTrue(payload["audit_chain_valid"])
                self.assertEqual(
                    0 if boundary == "T1" else 1,
                    payload["receipts_before"],
                )
                self.assertEqual(payload["receipts_before"], payload["receipts_after"])
            finally:
                if created_worker:
                    _run(["rm", "--force", worker_name], check=False)
                _run(["volume", "rm", "--force", state_volume], check=False)
                _run(["volume", "rm", "--force", control_volume], check=False)


if __name__ == "__main__":
    unittest.main()
