#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import re
import secrets
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Sequence


IMAGE_ID = re.compile(r"^sha256:[0-9a-f]{64}$")
LAB_ID = re.compile(r"^[0-9a-f]{12}$")
MAX_DOCKER_OUTPUT = 256 * 1024
NETWORK_SUBNET = "172.31.254.0/28"
BEACON_IP = "172.31.254.2"
TARGET_IP = "172.31.254.3"
LABEL_KEY = "adf.phase4.lab_id"
ROLE_LABEL = "adf.phase4.role"


class ContainerLabError(RuntimeError):
    def __init__(self, reason_code: str, message: str) -> None:
        self.reason_code = reason_code
        self.code = reason_code
        self.message = message
        super().__init__(f"{reason_code}: {message}")


def _docker_environment() -> dict[str, str]:
    allowed = ("PATH", "DOCKER_HOST", "DOCKER_CONTEXT", "DOCKER_CONFIG")
    return {name: os.environ[name] for name in allowed if name in os.environ}


def _docker(*arguments: str, check: bool = True) -> subprocess.CompletedProcess[str]:
    completed = subprocess.run(
        ["docker", *arguments],
        check=False,
        capture_output=True,
        text=True,
        timeout=60,
        env=_docker_environment(),
    )
    if (
        len(completed.stdout.encode("utf-8")) > MAX_DOCKER_OUTPUT
        or len(completed.stderr.encode("utf-8")) > MAX_DOCKER_OUTPUT
    ):
        raise ContainerLabError(
            "LAB_DOCKER_OUTPUT_TOO_LARGE", "Docker output exceeded its bound."
        )
    if check and completed.returncode != 0:
        raise ContainerLabError(
            "LAB_DOCKER_COMMAND_FAILED",
            f"Docker command failed with exit {completed.returncode}: {completed.stderr.strip()[:500]}",
        )
    return completed


def _json_output(*arguments: str) -> Any:
    completed = _docker(*arguments)
    try:
        return json.loads(completed.stdout)
    except (json.JSONDecodeError, TypeError, ValueError) as exc:
        raise ContainerLabError(
            "LAB_DOCKER_OUTPUT_INVALID", "Docker returned invalid JSON."
        ) from exc


@dataclass(frozen=True)
class ContainerSpec:
    role: str
    identifier: str
    network_mode: str
    mounts: tuple[tuple[str, str, bool], ...]
    user: str = "10001:10001"
    cap_add: tuple[str, ...] = ()


class Phase4ContainerLab:
    def __init__(self, *, image: str, lab_id: str) -> None:
        if IMAGE_ID.fullmatch(image) is None or LAB_ID.fullmatch(lab_id) is None:
            raise ContainerLabError(
                "LAB_CONFIGURATION_INVALID",
                "Image and lab identifiers must be exact digests.",
            )
        self.image = image
        self.lab_id = lab_id
        self.prefix = f"adf-p4-{lab_id}"
        self.containers: list[str] = []
        self.volumes: list[str] = []
        self.networks: list[str] = []
        self.initializer_inspections = 0

    def _labels(self, role: str) -> list[str]:
        return [
            "--label",
            f"{LABEL_KEY}={self.lab_id}",
            "--label",
            f"{ROLE_LABEL}={role}",
        ]

    @staticmethod
    def _control_client_mounts(
        *, executor_volume: str, observer_volume: str, facts_volume: str
    ) -> tuple[tuple[str, str, bool], ...]:
        """Expose service IPC and facts to the client without write authority."""

        return (
            (executor_volume, "/executor", True),
            (observer_volume, "/observer", True),
            (facts_volume, "/facts", True),
        )

    def preflight(self) -> None:
        version = _json_output("version", "--format", "{{json .}}")
        if version.get("Server", {}).get("Os") != "linux":
            raise ContainerLabError(
                "LAB_DOCKER_PLATFORM_INVALID", "A Linux Docker engine is required."
            )
        inspected = _json_output("image", "inspect", self.image)
        if type(inspected) is not list or len(inspected) != 1:
            raise ContainerLabError(
                "LAB_IMAGE_INVALID", "Image inspection was ambiguous."
            )
        image = inspected[0]
        if image.get("Id") != self.image or image.get("Os") != "linux":
            raise ContainerLabError(
                "LAB_IMAGE_INVALID",
                "Image reference must equal its immutable local image ID.",
            )

    def create_network(self) -> str:
        name = f"{self.prefix}-internal"
        identifier = _docker(
            "network",
            "create",
            "--driver",
            "bridge",
            "--internal",
            "--subnet",
            NETWORK_SUBNET,
            *self._labels("network"),
            name,
        ).stdout.strip()
        if not identifier:
            raise ContainerLabError("LAB_NETWORK_CREATE_FAILED", "Network ID is empty.")
        self.networks.append(identifier)
        return identifier

    def create_volume(self, role: str) -> str:
        name = f"{self.prefix}-{role}"
        created = _docker("volume", "create", *self._labels(role), name).stdout.strip()
        if created != name:
            raise ContainerLabError(
                "LAB_VOLUME_CREATE_FAILED", "Volume identity is unexpected."
            )
        self.volumes.append(name)
        return name

    @staticmethod
    def _hardening_args(*, user: str, cap_add: tuple[str, ...]) -> list[str]:
        arguments = [
            "--user",
            user,
            "--read-only",
            "--cap-drop",
            "ALL",
            "--security-opt",
            "no-new-privileges=true",
            "--pids-limit",
            "64",
            "--memory",
            "128m",
            "--cpus",
            "0.5",
            "--tmpfs",
            "/tmp:rw,noexec,nosuid,nodev,size=16m",
        ]
        for capability in cap_add:
            arguments.extend(("--cap-add", capability))
        return arguments

    def create_container(
        self,
        *,
        role: str,
        network_mode: str,
        command: Sequence[str],
        mounts: Sequence[tuple[str, str, bool]] = (),
        user: str = "10001:10001",
        cap_add: tuple[str, ...] = (),
        ip_address: str | None = None,
        environment: Sequence[tuple[str, str]] = (),
    ) -> ContainerSpec:
        name = f"{self.prefix}-{role}"
        arguments = [
            "create",
            "--name",
            name,
            *self._labels(role),
            *self._hardening_args(user=user, cap_add=cap_add),
            "--network",
            network_mode,
        ]
        if ip_address is not None:
            arguments.extend(("--ip", ip_address))
        for source, destination, read_only in mounts:
            mount = f"type=volume,src={source},dst={destination}"
            if read_only:
                mount += ",readonly"
            arguments.extend(("--mount", mount))
        for name_key, value in environment:
            arguments.extend(("--env", f"{name_key}={value}"))
        arguments.extend(
            ("--entrypoint", "python", self.image, "/opt/adf/run_lab_node.py")
        )
        arguments.extend(command)
        identifier = _docker(*arguments).stdout.strip()
        if not identifier:
            raise ContainerLabError(
                "LAB_CONTAINER_CREATE_FAILED", "Container ID is empty."
            )
        self.containers.append(identifier)
        return ContainerSpec(
            role=role,
            identifier=identifier,
            network_mode=network_mode,
            mounts=tuple(mounts),
            user=user,
            cap_add=cap_add,
        )

    def inspect_container(self, spec: ContainerSpec) -> dict[str, Any]:
        rows = _json_output("inspect", spec.identifier)
        if type(rows) is not list or len(rows) != 1 or type(rows[0]) is not dict:
            raise ContainerLabError(
                "LAB_INSPECTION_INVALID", "Container inspection is ambiguous."
            )
        row = rows[0]
        config = row.get("Config", {})
        host = row.get("HostConfig", {})
        if row.get("Image") != self.image or config.get("User") != spec.user:
            raise ContainerLabError(
                "LAB_INSPECTION_FAILED", f"{spec.role} image or UID drifted."
            )
        if (
            host.get("Privileged") is not False
            or host.get("ReadonlyRootfs") is not True
            or host.get("NetworkMode") != spec.network_mode
            or host.get("PidMode") not in ("", None)
            or host.get("IpcMode") not in ("", "private", None)
            or host.get("PidsLimit") != 64
            or host.get("Memory") != 128 * 1024 * 1024
            or host.get("NanoCpus") != 500_000_000
        ):
            raise ContainerLabError(
                "LAB_INSPECTION_FAILED", f"{spec.role} isolation drifted."
            )
        cap_drop = {
            str(value).removeprefix("CAP_").upper()
            for value in (host.get("CapDrop") or ())
        }
        cap_add = {
            str(value).removeprefix("CAP_").upper()
            for value in (host.get("CapAdd") or ())
        }
        security = tuple(host.get("SecurityOpt") or ())
        if (
            "ALL" not in cap_drop
            or cap_add != set(spec.cap_add)
            or not any(value.startswith("no-new-privileges") for value in security)
        ):
            raise ContainerLabError(
                "LAB_INSPECTION_FAILED", f"{spec.role} capability drifted."
            )
        if host.get("PortBindings") not in (None, {}) or host.get("Binds") not in (
            None,
            [],
        ):
            raise ContainerLabError(
                "LAB_INSPECTION_FAILED", f"{spec.role} exposes host access."
            )
        expected_mounts = {
            destination: (source, not read_only)
            for source, destination, read_only in spec.mounts
        }
        observed_mounts: dict[str, tuple[str, bool]] = {}
        for mount in row.get("Mounts", []):
            destination = mount.get("Destination")
            source_name = mount.get("Name")
            if mount.get("Type") != "volume" or not destination or not source_name:
                raise ContainerLabError(
                    "LAB_INSPECTION_FAILED", f"{spec.role} mount is unsafe."
                )
            if destination == "/var/run/docker.sock" or str(
                mount.get("Source", "")
            ).endswith("/docker.sock"):
                raise ContainerLabError(
                    "LAB_INSPECTION_FAILED", "Container runtime socket exposed."
                )
            observed_mounts[destination] = (source_name, bool(mount.get("RW")))
        if observed_mounts != expected_mounts:
            raise ContainerLabError(
                "LAB_INSPECTION_FAILED", f"{spec.role} mount set drifted."
            )
        labels = config.get("Labels") or {}
        if labels.get(LABEL_KEY) != self.lab_id or labels.get(ROLE_LABEL) != spec.role:
            raise ContainerLabError(
                "LAB_INSPECTION_FAILED", f"{spec.role} labels drifted."
            )
        return row

    def start(self, spec: ContainerSpec, *, attach: bool = False) -> str:
        arguments = ["start"]
        if attach:
            arguments.append("--attach")
        arguments.append(spec.identifier)
        return _docker(*arguments).stdout.strip()

    def run_initializer(
        self,
        *,
        role: str,
        volume: str,
        command: Sequence[str],
        user: str,
        cap_add: tuple[str, ...] = (),
    ) -> None:
        spec = self.create_container(
            role=role,
            network_mode="none",
            command=command,
            mounts=((volume, "/lab", False),),
            user=user,
            cap_add=cap_add,
        )
        self.inspect_container(spec)
        self.initializer_inspections += 1
        self.start(spec, attach=True)
        state = _json_output("inspect", spec.identifier)[0].get("State", {})
        if state.get("ExitCode") != 0:
            raise ContainerLabError(
                "LAB_INITIALIZER_FAILED", f"{role} initializer failed."
            )
        _docker("rm", spec.identifier)
        self.containers.remove(spec.identifier)

    def validate_network(
        self, network_identifier: str, app_specs: Sequence[ContainerSpec]
    ) -> None:
        rows = _json_output("network", "inspect", network_identifier)
        if type(rows) is not list or len(rows) != 1:
            raise ContainerLabError(
                "LAB_NETWORK_INSPECTION_INVALID", "Network inspection failed."
            )
        row = rows[0]
        if row.get("Internal") is not True or row.get("Driver") != "bridge":
            raise ContainerLabError(
                "LAB_NETWORK_INSPECTION_FAILED", "Lab network is not internal."
            )
        subnets = {
            config.get("Subnet")
            for config in row.get("IPAM", {}).get("Config", [])
            if type(config) is dict
        }
        if subnets != {NETWORK_SUBNET}:
            raise ContainerLabError(
                "LAB_NETWORK_INSPECTION_FAILED", "Lab subnet drifted."
            )
        expected = {
            spec.identifier for spec in app_specs if spec.role in ("beacon", "target")
        }
        observed = set((row.get("Containers") or {}).keys())
        if observed != expected:
            raise ContainerLabError(
                "LAB_NETWORK_INSPECTION_FAILED",
                "Unexpected container joined the lab network.",
            )

    def cleanup(self) -> bool:
        complete = True
        for identifier in reversed(self.containers):
            result = _docker("rm", "--force", identifier, check=False)
            complete = complete and result.returncode == 0
        self.containers.clear()
        for identifier in reversed(self.networks):
            result = _docker("network", "rm", identifier, check=False)
            complete = complete and result.returncode == 0
        self.networks.clear()
        for name in reversed(self.volumes):
            result = _docker("volume", "rm", name, check=False)
            complete = complete and result.returncode == 0
        self.volumes.clear()
        return complete

    def execute(self) -> dict[str, Any]:
        self.preflight()
        network = self.create_network()
        executor_volume = self.create_volume("executor")
        observer_volume = self.create_volume("observer")
        facts_volume = self.create_volume("facts")
        for role, volume in (
            ("prepare-executor", executor_volume),
            ("prepare-observer", observer_volume),
            ("prepare-facts", facts_volume),
        ):
            self.run_initializer(
                role=role,
                volume=volume,
                command=("prepare-empty-volume", "--root", "/lab"),
                user="0:0",
                cap_add=("CHOWN",),
            )
        self.run_initializer(
            role="initialize-executor",
            volume=executor_volume,
            command=("initialize-executor", "--private", "/lab/private"),
            user="10001:10001",
        )
        self.run_initializer(
            role="initialize-observer",
            volume=observer_volume,
            command=("initialize-observer", "--private", "/lab/private"),
            user="10001:10001",
        )

        beacon = self.create_container(
            role="beacon",
            network_mode=f"{self.prefix}-internal",
            ip_address=BEACON_IP,
            command=("beacon",),
        )
        target = self.create_container(
            role="target",
            network_mode=f"{self.prefix}-internal",
            ip_address=TARGET_IP,
            mounts=((facts_volume, "/facts", False),),
            command=("target", "--facts", "/facts/private/target.json"),
        )
        self.inspect_container(beacon)
        self.inspect_container(target)
        self.start(beacon)
        self.start(target)

        target_network_mode = f"container:{target.identifier}"
        executor = self.create_container(
            role="executor",
            network_mode=target_network_mode,
            mounts=(
                (executor_volume, "/executor", False),
                (facts_volume, "/facts", True),
            ),
            command=(
                "executor",
                "--private",
                "/executor/private",
                "--facts",
                "/facts/private/target.json",
            ),
        )
        observer = self.create_container(
            role="observer",
            network_mode=target_network_mode,
            mounts=(
                (observer_volume, "/observer", False),
                (facts_volume, "/facts", True),
            ),
            command=(
                "observer",
                "--private",
                "/observer/private",
                "--facts",
                "/facts/private/target.json",
            ),
        )
        self.inspect_container(executor)
        self.inspect_container(observer)
        self.start(executor)
        self.start(observer)

        client = self.create_container(
            role="control-client",
            network_mode="none",
            mounts=self._control_client_mounts(
                executor_volume=executor_volume,
                observer_volume=observer_volume,
                facts_volume=facts_volume,
            ),
            environment=(("ADF_LAB_SESSION_ID", f"lab-{self.lab_id}"),),
            command=(
                "control-client",
                "--executor-private",
                "/executor/private",
                "--observer-private",
                "/observer/private",
                "--facts",
                "/facts/private/target.json",
            ),
        )
        all_specs = (beacon, target, executor, observer, client)
        for spec in all_specs:
            self.inspect_container(spec)
        self.validate_network(network, all_specs)
        output = self.start(client, attach=True)
        try:
            result = json.loads(output)
        except json.JSONDecodeError as exc:
            raise ContainerLabError(
                "LAB_CLIENT_OUTPUT_INVALID", "Client output is invalid."
            ) from exc
        expected_result = {
            "receipt_status": "NO_EFFECT",
            "effect_possible": False,
            "beacon_reachable": True,
            "management_reachable": True,
            "correlation_valid": True,
            "authorization_integrated": False,
            "live_actions_possible": False,
        }
        if any(result.get(key) != value for key, value in expected_result.items()):
            raise ContainerLabError(
                "LAB_CLIENT_RESULT_INVALID", "Lab result violated its boundary."
            )
        for spec in (executor, observer, client):
            state = _json_output("inspect", spec.identifier)[0].get("State", {})
            if state.get("ExitCode") != 0:
                raise ContainerLabError(
                    "LAB_CONTAINER_EXIT_INVALID", f"{spec.role} failed."
                )
        return {
            "status": "PASS",
            "schema_version": "0.4.0",
            "lab_id": self.lab_id,
            "image_id": self.image,
            "network_internal": True,
            "application_containers_inspected": len(all_specs),
            "initializers_inspected": self.initializer_inspections,
            **expected_result,
        }


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Run the disposable Phase 4 container lab"
    )
    parser.add_argument("--allow-container-lab", action="store_true")
    parser.add_argument("--image", required=True)
    parser.add_argument("--lab-id", default=None)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    if args.allow_container_lab is not True:
        print(json.dumps({"status": "FAILED", "reason_code": "LAB_NOT_AUTHORIZED"}))
        return 2
    lab_id = args.lab_id or secrets.token_hex(6)
    lab: Phase4ContainerLab | None = None
    result: dict[str, Any]
    cleanup_complete = False
    try:
        lab = Phase4ContainerLab(image=args.image, lab_id=lab_id)
        result = lab.execute()
    except Exception as exc:
        result = {
            "status": "FAILED",
            "reason_code": getattr(exc, "reason_code", "LAB_UNEXPECTED_FAILURE"),
        }
    finally:
        if lab is not None:
            cleanup_complete = lab.cleanup()
    result["cleanup_complete"] = cleanup_complete
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0 if result.get("status") == "PASS" and cleanup_complete else 1


if __name__ == "__main__":
    raise SystemExit(main())
