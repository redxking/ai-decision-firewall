from __future__ import annotations

import io
import json
import os
import subprocess
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest.mock import patch

from adf_poc.lab_nodes import (
    LabNodeError,
    initialize_executor_volume,
    initialize_observer_volume,
)
from scripts.run_phase4_container_lab import (
    LABEL_KEY,
    ROLE_LABEL,
    ContainerLabError,
    ContainerSpec,
    Phase4ContainerLab,
    _docker,
    main,
)


IMAGE = "sha256:" + ("a" * 64)
LAB_ID = "abcdef123456"


def _container_row(
    spec: ContainerSpec,
    *,
    image: str = IMAGE,
    lab_id: str = LAB_ID,
) -> dict:
    return {
        "Image": image,
        "Config": {
            "User": spec.user,
            "Labels": {LABEL_KEY: lab_id, ROLE_LABEL: spec.role},
        },
        "HostConfig": {
            "Privileged": False,
            "ReadonlyRootfs": True,
            "NetworkMode": spec.network_mode,
            "PidMode": "",
            "IpcMode": "private",
            "PidsLimit": 64,
            "Memory": 128 * 1024 * 1024,
            "NanoCpus": 500_000_000,
            "CapDrop": ["ALL"],
            "CapAdd": list(spec.cap_add) or None,
            "SecurityOpt": ["no-new-privileges=true"],
            "PortBindings": {},
            "Binds": None,
        },
        "Mounts": [
            {
                "Type": "volume",
                "Name": source,
                "Destination": destination,
                "Source": f"/var/lib/docker/volumes/{source}/_data",
                "RW": not read_only,
            }
            for source, destination, read_only in spec.mounts
        ],
    }


class Phase4ContainerHarnessTests(unittest.TestCase):
    def test_cli_requires_explicit_opt_in_and_immutable_image_id(self) -> None:
        output = io.StringIO()
        with redirect_stdout(output):
            self.assertEqual(main(["--image", IMAGE]), 2)
        self.assertEqual(
            json.loads(output.getvalue())["reason_code"], "LAB_NOT_AUTHORIZED"
        )
        for image, lab_id in (("adf:test", LAB_ID), (IMAGE, "unsafe")):
            with self.subTest(image=image, lab_id=lab_id):
                with self.assertRaises(ContainerLabError):
                    Phase4ContainerLab(image=image, lab_id=lab_id)

    def test_docker_runner_uses_argument_vector_bounded_environment_and_no_shell(
        self,
    ) -> None:
        completed = subprocess.CompletedProcess(
            args=["docker", "version"], returncode=0, stdout="ok", stderr=""
        )
        with patch(
            "scripts.run_phase4_container_lab.subprocess.run", return_value=completed
        ) as run:
            self.assertEqual(_docker("version").stdout, "ok")
        args, kwargs = run.call_args
        self.assertEqual(args[0], ["docker", "version"])
        self.assertNotIn("shell", kwargs)
        self.assertLessEqual(
            set(kwargs["env"]),
            {"PATH", "DOCKER_HOST", "DOCKER_CONTEXT", "DOCKER_CONFIG"},
        )

    def test_application_hardening_has_no_privileged_or_host_escape(self) -> None:
        arguments = Phase4ContainerLab._hardening_args(user="10001:10001", cap_add=())
        joined = " ".join(arguments)
        for required in (
            "--read-only",
            "--cap-drop ALL",
            "no-new-privileges=true",
            "--pids-limit 64",
            "--memory 128m",
            "--cpus 0.5",
        ):
            self.assertIn(required, joined)
        for prohibited in (
            "--privileged",
            "--pid=host",
            "--network=host",
            "docker.sock",
        ):
            self.assertNotIn(prohibited, joined)

    def test_exact_container_inspection_accepts_only_closed_topology(self) -> None:
        lab = Phase4ContainerLab(image=IMAGE, lab_id=LAB_ID)
        spec = ContainerSpec(
            role="executor",
            identifier="b" * 64,
            network_mode="container:" + ("c" * 64),
            mounts=(
                ("exec-volume", "/executor", False),
                ("facts-volume", "/facts", True),
            ),
        )
        valid = _container_row(spec)
        with patch(
            "scripts.run_phase4_container_lab._json_output", return_value=[valid]
        ):
            lab.inspect_container(spec)

        mutations = (
            (
                "privileged",
                lambda row: row["HostConfig"].__setitem__("Privileged", True),
            ),
            (
                "writable-root",
                lambda row: row["HostConfig"].__setitem__("ReadonlyRootfs", False),
            ),
            ("wrong-user", lambda row: row["Config"].__setitem__("User", "0:0")),
            (
                "extra-capability",
                lambda row: row["HostConfig"].__setitem__("CapAdd", ["NET_ADMIN"]),
            ),
            (
                "host-bind",
                lambda row: row["HostConfig"].__setitem__("Binds", ["/:/host"]),
            ),
        )
        for label, mutate in mutations:
            with self.subTest(label=label):
                candidate = json.loads(json.dumps(valid))
                mutate(candidate)
                with (
                    patch(
                        "scripts.run_phase4_container_lab._json_output",
                        return_value=[candidate],
                    ),
                    self.assertRaises(ContainerLabError),
                ):
                    lab.inspect_container(spec)

    def test_network_inspection_requires_internal_exact_membership_and_subnet(
        self,
    ) -> None:
        lab = Phase4ContainerLab(image=IMAGE, lab_id=LAB_ID)
        beacon = ContainerSpec("beacon", "b" * 64, "lab-network", ())
        target = ContainerSpec("target", "c" * 64, "lab-network", ())
        executor = ContainerSpec(
            "executor", "d" * 64, "container:" + target.identifier, ()
        )
        row = {
            "Internal": True,
            "Driver": "bridge",
            "IPAM": {"Config": [{"Subnet": "172.31.254.0/28"}]},
            "Containers": {beacon.identifier: {}, target.identifier: {}},
        }
        with patch("scripts.run_phase4_container_lab._json_output", return_value=[row]):
            lab.validate_network("network-id", (beacon, target, executor))
        row["Internal"] = False
        with (
            patch("scripts.run_phase4_container_lab._json_output", return_value=[row]),
            self.assertRaises(ContainerLabError),
        ):
            lab.validate_network("network-id", (beacon, target, executor))

    def test_cleanup_targets_only_recorded_exact_resource_ids(self) -> None:
        lab = Phase4ContainerLab(image=IMAGE, lab_id=LAB_ID)
        lab.containers = ["container-exact"]
        lab.networks = ["network-exact"]
        lab.volumes = ["volume-exact"]
        completed = subprocess.CompletedProcess(
            args=[], returncode=0, stdout="", stderr=""
        )
        calls: list[tuple[str, ...]] = []

        def record(*arguments: str, check: bool = True):
            del check
            calls.append(arguments)
            return completed

        with patch("scripts.run_phase4_container_lab._docker", side_effect=record):
            self.assertTrue(lab.cleanup())
        self.assertEqual(
            calls,
            [
                ("rm", "--force", "container-exact"),
                ("network", "rm", "network-exact"),
                ("volume", "rm", "volume-exact"),
            ],
        )

    def test_nonroot_volume_initializers_are_create_once_and_owner_private(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            private = Path(directory) / "private"
            private.mkdir(mode=0o700)
            initialize_executor_volume(private)
            key = private / "channel.key"
            journal = private / "executor-replay.jsonl"
            self.assertEqual(len(key.read_bytes()), 32)
            self.assertEqual(key.stat().st_mode & 0o777, 0o600)
            self.assertEqual(journal.stat().st_mode & 0o777, 0o600)
            with self.assertRaises(LabNodeError):
                initialize_executor_volume(private)

        with tempfile.TemporaryDirectory() as directory:
            private = Path(directory) / "private"
            private.mkdir(mode=0o700)
            initialize_observer_volume(private)
            self.assertEqual(len((private / "channel.key").read_bytes()), 32)

    @unittest.skipUnless(
        os.environ.get("ADF_PHASE4_CONTAINER_LAB") == "1",
        "real container lab requires an explicit marker and immutable image ID",
    )
    def test_real_disposable_container_lab(self) -> None:
        image = os.environ["ADF_PHASE4_LAB_IMAGE"]
        self.assertEqual(
            main(
                [
                    "--allow-container-lab",
                    "--image",
                    image,
                    "--lab-id",
                    LAB_ID,
                ]
            ),
            0,
        )


if __name__ == "__main__":
    unittest.main()
