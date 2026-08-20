#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import secrets
import time
from typing import Any, Sequence

from adf_poc.lab_nodes import (
    EXECUTOR_AFTER_COMPLETION,
    EXECUTOR_AFTER_RESERVATION,
    OBSERVER_AFTER_OBSERVATION,
)
from adf_poc.utils import canonical_json, strict_json_loads
from scripts.run_phase4_container_lab import (
    BEACON_IP,
    TARGET_IP,
    ContainerLabError,
    ContainerSpec,
    Phase4ContainerLab,
    _docker,
    _json_output,
)


SCENARIOS = frozenset(
    {
        "executor-after-reservation",
        "executor-after-completion",
        "observer-after-observation",
    }
)
FAULT_LINE = {
    "executor-after-reservation": EXECUTOR_AFTER_RESERVATION,
    "executor-after-completion": EXECUTOR_AFTER_COMPLETION,
    "observer-after-observation": OBSERVER_AFTER_OBSERVATION,
}


class Phase4ContainerRecoveryCampaign(Phase4ContainerLab):
    def __init__(self, *, image: str, lab_id: str, scenario: str) -> None:
        super().__init__(image=image, lab_id=lab_id)
        if scenario not in SCENARIOS:
            raise ContainerLabError(
                "LAB_RECOVERY_SCENARIO_INVALID", "Recovery scenario is not closed."
            )
        self.scenario = scenario

    def _remove_container(self, spec: ContainerSpec) -> None:
        if spec.identifier not in self.containers:
            raise ContainerLabError(
                "LAB_CLEANUP_IDENTITY_INVALID", "Container is not controller-owned."
            )
        _docker("rm", spec.identifier)
        self.containers.remove(spec.identifier)

    @staticmethod
    def _wait_exit(spec: ContainerSpec) -> int:
        output = _docker("wait", spec.identifier).stdout.strip()
        try:
            return int(output)
        except ValueError as exc:
            raise ContainerLabError(
                "LAB_CONTAINER_EXIT_INVALID", "Container exit was not an integer."
            ) from exc

    @staticmethod
    def _logs(spec: ContainerSpec) -> tuple[str, ...]:
        completed = _docker("logs", spec.identifier, check=False)
        if completed.returncode != 0:
            raise ContainerLabError(
                "LAB_DOCKER_COMMAND_FAILED", "Container logs were unavailable."
            )
        return tuple(
            line for line in (completed.stdout + completed.stderr).splitlines() if line
        )

    def _wait_fault(self, spec: ContainerSpec, expected_stage: str) -> None:
        expected = canonical_json(
            {"fault_stage": expected_stage, "status": "FAULT_READY"}
        )
        deadline = time.monotonic() + 15.0
        while time.monotonic() < deadline:
            if expected in self._logs(spec):
                return
            state = _json_output("inspect", spec.identifier)[0].get("State", {})
            if state.get("Running") is not True:
                raise ContainerLabError(
                    "LAB_FAULT_BOUNDARY_NOT_REACHED",
                    "Faulted service exited before its declared boundary.",
                )
            time.sleep(0.05)
        raise ContainerLabError(
            "LAB_FAULT_BOUNDARY_TIMEOUT", "Fault boundary was not observed in time."
        )

    def _kill_at_fault(self, spec: ContainerSpec, expected_stage: str) -> None:
        self._wait_fault(spec, expected_stage)
        killed = _docker("kill", spec.identifier).stdout.strip()
        if killed not in (spec.identifier, f"{self.prefix}-{spec.role}"):
            raise ContainerLabError(
                "LAB_CONTAINER_KILL_INVALID", "Killed container identity drifted."
            )
        if self._wait_exit(spec) != 137:
            raise ContainerLabError(
                "LAB_CONTAINER_KILL_INVALID", "Container did not exit from SIGKILL."
            )

    def _recover_socket(self, *, volume: str, socket_name: str) -> None:
        mounted = tuple(
            value
            for value in _docker(
                "ps", "--all", "--quiet", "--filter", f"volume={volume}"
            ).stdout.splitlines()
            if value
        )
        if mounted:
            raise ContainerLabError(
                "LAB_STALE_SOCKET_IN_USE",
                "Socket volume is still mounted by another container.",
            )
        self.run_initializer(
            role=f"recover-{socket_name[:-5]}",
            volume=volume,
            command=(
                "recover-stale-socket",
                "--private",
                "/lab/private",
                "--socket",
                socket_name,
                "--allow-stale-socket-recovery",
            ),
            user="10001:10001",
        )

    def _executor(
        self,
        *,
        executor_volume: str,
        facts_volume: str,
        target: ContainerSpec,
        fault_stage: str | None = None,
    ) -> ContainerSpec:
        command = [
            "executor",
            "--private",
            "/executor/private",
            "--facts",
            "/facts/private/target.json",
        ]
        if fault_stage is not None:
            command.extend(("--fault-stage", fault_stage, "--allow-fault-injection"))
        return self.create_container(
            role="executor",
            network_mode=f"container:{target.identifier}",
            mounts=(
                (executor_volume, "/executor", False),
                (facts_volume, "/facts", True),
            ),
            command=tuple(command),
        )

    def _observer(
        self,
        *,
        observer_volume: str,
        facts_volume: str,
        target: ContainerSpec,
        fault_stage: str | None = None,
    ) -> ContainerSpec:
        command = [
            "observer",
            "--private",
            "/observer/private",
            "--facts",
            "/facts/private/target.json",
        ]
        if fault_stage is not None:
            command.extend(("--fault-stage", fault_stage, "--allow-fault-injection"))
        return self.create_container(
            role="observer",
            network_mode=f"container:{target.identifier}",
            mounts=(
                (observer_volume, "/observer", False),
                (facts_volume, "/facts", True),
            ),
            command=tuple(command),
        )

    def _client(
        self,
        *,
        executor_volume: str,
        observer_volume: str,
        facts_volume: str,
        control_volume: str,
    ) -> ContainerSpec:
        return self.create_container(
            role="control-client",
            network_mode="none",
            mounts=(
                (executor_volume, "/executor", False),
                (observer_volume, "/observer", False),
                (facts_volume, "/facts", True),
                (control_volume, "/control", False),
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
                "--control-private",
                "/control/private",
            ),
        )

    @staticmethod
    def _validate_success(output: str) -> dict[str, Any]:
        try:
            result = strict_json_loads(output)
        except (TypeError, ValueError, json.JSONDecodeError) as exc:
            raise ContainerLabError(
                "LAB_CLIENT_OUTPUT_INVALID", "Recovery client output is invalid."
            ) from exc
        expected = {
            "receipt_status": "NO_EFFECT",
            "effect_possible": False,
            "beacon_reachable": True,
            "management_reachable": True,
            "correlation_valid": True,
            "authorization_integrated": False,
            "live_actions_possible": False,
        }
        if type(result) is not dict or any(
            result.get(key) != value for key, value in expected.items()
        ):
            raise ContainerLabError(
                "LAB_CLIENT_RESULT_INVALID", "Recovery result violated its boundary."
            )
        return result

    def execute(self) -> dict[str, Any]:
        self.preflight()
        network = self.create_network()
        executor_volume = self.create_volume("executor")
        observer_volume = self.create_volume("observer")
        facts_volume = self.create_volume("facts")
        control_volume = self.create_volume("control")
        for role, volume in (
            ("prepare-executor", executor_volume),
            ("prepare-observer", observer_volume),
            ("prepare-facts", facts_volume),
            ("prepare-control", control_volume),
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

        executor_fault = (
            FAULT_LINE[self.scenario] if self.scenario.startswith("executor-") else None
        )
        observer_fault = (
            FAULT_LINE[self.scenario] if self.scenario.startswith("observer-") else None
        )
        executor = self._executor(
            executor_volume=executor_volume,
            facts_volume=facts_volume,
            target=target,
            fault_stage=executor_fault,
        )
        observer = self._observer(
            observer_volume=observer_volume,
            facts_volume=facts_volume,
            target=target,
            fault_stage=observer_fault,
        )
        self.inspect_container(executor)
        self.inspect_container(observer)
        self.start(executor)
        self.start(observer)
        client = self._client(
            executor_volume=executor_volume,
            observer_volume=observer_volume,
            facts_volume=facts_volume,
            control_volume=control_volume,
        )
        all_specs = (beacon, target, executor, observer, client)
        for spec in all_specs:
            self.inspect_container(spec)
        self.validate_network(network, all_specs)
        self.start(client)

        faulted = executor if executor_fault is not None else observer
        fault_stage = executor_fault or observer_fault
        if fault_stage is None:  # pragma: no cover - constructor owns scenario set
            raise ContainerLabError(
                "LAB_RECOVERY_SCENARIO_INVALID", "Scenario has no fault boundary."
            )
        self._kill_at_fault(faulted, fault_stage)
        if self._wait_exit(client) == 0:
            raise ContainerLabError(
                "LAB_EXPECTED_FAILURE_MISSING", "Client accepted a killed service."
            )
        self._remove_container(client)
        self._remove_container(faulted)

        if executor_fault is not None:
            self._recover_socket(volume=executor_volume, socket_name="executor.sock")
            executor = self._executor(
                executor_volume=executor_volume,
                facts_volume=facts_volume,
                target=target,
            )
            self.inspect_container(executor)
            self.start(executor)
        else:
            if self._wait_exit(executor) != 0:
                raise ContainerLabError(
                    "LAB_CONTAINER_EXIT_INVALID", "Initial executor failed."
                )
            self._remove_container(executor)
            self._recover_socket(volume=observer_volume, socket_name="observer.sock")
            executor = self._executor(
                executor_volume=executor_volume,
                facts_volume=facts_volume,
                target=target,
            )
            observer = self._observer(
                observer_volume=observer_volume,
                facts_volume=facts_volume,
                target=target,
            )
            self.inspect_container(executor)
            self.inspect_container(observer)
            self.start(executor)
            self.start(observer)

        retry = self._client(
            executor_volume=executor_volume,
            observer_volume=observer_volume,
            facts_volume=facts_volume,
            control_volume=control_volume,
        )
        self.inspect_container(retry)
        if self.scenario == "executor-after-reservation":
            retry_result = _docker("start", "--attach", retry.identifier, check=False)
            if retry_result.returncode == 0 or self._wait_exit(executor) == 0:
                raise ContainerLabError(
                    "LAB_RECOVERY_FENCE_MISSING", "Open reservation was not fenced."
                )
            expected_error = canonical_json(
                {
                    "reason_code": "LAB_EXECUTOR_RECOVERY_REQUIRED",
                    "status": "FAILED",
                }
            )
            if expected_error not in self._logs(executor):
                raise ContainerLabError(
                    "LAB_RECOVERY_FENCE_MISSING", "Recovery reason was not exact."
                )
            recovery_outcome = "RECOVERY_REQUIRED"
            correlation_valid = False
        else:
            self._validate_success(self.start(retry, attach=True))
            if self._wait_exit(executor) != 0 or self._wait_exit(observer) != 0:
                raise ContainerLabError(
                    "LAB_CONTAINER_EXIT_INVALID", "Recovery service failed."
                )
            recovery_outcome = "EXACT_REPLAY_COMPLETED"
            correlation_valid = True

        return {
            "status": "PASS",
            "schema_version": "0.4.0",
            "lab_id": self.lab_id,
            "image_id": self.image,
            "scenario": self.scenario,
            "container_kill_observed": True,
            "exact_command_reused": True,
            "recovery_outcome": recovery_outcome,
            "correlation_valid": correlation_valid,
            "effect_possible": False,
            "authorization_integrated": False,
            "live_actions_possible": False,
            "network_internal": True,
            "initializers_inspected": self.initializer_inspections,
        }


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Run one Phase 4 container recovery scenario"
    )
    parser.add_argument("--allow-container-recovery", action="store_true")
    parser.add_argument("--image", required=True)
    parser.add_argument("--scenario", choices=sorted(SCENARIOS), required=True)
    parser.add_argument("--lab-id")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    if args.allow_container_recovery is not True:
        print(canonical_json({"status": "FAILED", "reason_code": "LAB_NOT_AUTHORIZED"}))
        return 2
    campaign: Phase4ContainerRecoveryCampaign | None = None
    cleanup_complete = False
    try:
        campaign = Phase4ContainerRecoveryCampaign(
            image=args.image,
            lab_id=args.lab_id or secrets.token_hex(6),
            scenario=args.scenario,
        )
        result = campaign.execute()
    except Exception as exc:
        result = {
            "status": "FAILED",
            "reason_code": getattr(exc, "reason_code", "LAB_UNEXPECTED_FAILURE"),
        }
    finally:
        if campaign is not None:
            cleanup_complete = campaign.cleanup()
    result["cleanup_complete"] = cleanup_complete
    print(canonical_json(result))
    return 0 if result.get("status") == "PASS" and cleanup_complete else 1


if __name__ == "__main__":
    raise SystemExit(main())
