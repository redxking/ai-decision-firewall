from __future__ import annotations

import argparse
import hashlib
import os
import secrets
import signal
import socket
import stat
import sys
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Callable, Sequence

from adf_poc.lab_contracts import (
    COMMAND,
    OBSERVATION,
    OBSERVATION_REQUEST,
    RECEIPT,
    lab_message_sha256,
    load_authenticated_lab_message,
    sign_lab_message,
    validate_lab_channel_keys,
    validate_lab_message_correlation,
)
from adf_poc.lab_services import (
    EXECUTOR_AFTER_COMPLETION,
    EXECUTOR_AFTER_RESERVATION,
    OBSERVER_AFTER_OBSERVATION,
    ExecutorReplayJournal,
    LabExecutorService,
    LabObservedState,
    LabObserverService,
    initialize_executor_journal,
)
from adf_poc.lab_transport import LabSeqpacketServer, lab_seqpacket_exchange
from adf_poc.utils import canonical_json, strict_json_loads


LAB_UID = 10001
LAB_GID = 10001
BEACON_HOST = "172.31.254.2"
BEACON_PORT = 18081
MANAGEMENT_HOST = "127.0.0.1"
MANAGEMENT_PORT = 18080
TARGET_ID = "LAB_ENDPOINT_001"
RULESET_OPEN_SHA256 = hashlib.sha256(b"ADF-LAB-RULESET-OPEN-V1").hexdigest()
POLICY_SHA256 = hashlib.sha256(b"ADF-LAB-POLICY-V1").hexdigest()
ADAPTER_CONTRACT_SHA256 = hashlib.sha256(b"ADF-LAB-ADAPTER-V1").hexdigest()
EXECUTOR_KEY_ID = "LAB_EXECUTOR_KEY_001"
OBSERVER_KEY_ID = "LAB_OBSERVER_KEY_001"
MAX_SMALL_FILE = 4096
FAULT_NONE = "NONE"
EXECUTOR_FAULT_STAGES = frozenset(
    {FAULT_NONE, EXECUTOR_AFTER_RESERVATION, EXECUTOR_AFTER_COMPLETION}
)
OBSERVER_FAULT_STAGES = frozenset({FAULT_NONE, OBSERVER_AFTER_OBSERVATION})


class LabNodeError(RuntimeError):
    def __init__(self, reason_code: str, message: str) -> None:
        self.reason_code = reason_code
        self.code = reason_code
        self.message = message
        super().__init__(f"{reason_code}: {message}")


def _fsync_directory(directory: Path) -> None:
    descriptor = os.open(
        directory,
        os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_CLOEXEC", 0),
    )
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _validate_private_directory(directory: Path, *, expected_uid: int) -> None:
    try:
        metadata = directory.lstat()
    except OSError as exc:
        raise LabNodeError(
            "LAB_NODE_PATH_UNSAFE", "Private directory is unavailable."
        ) from exc
    if (
        directory.is_symlink()
        or not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != expected_uid
        or stat.S_IMODE(metadata.st_mode) != 0o700
    ):
        raise LabNodeError(
            "LAB_NODE_PATH_UNSAFE",
            "Private directory must be a non-symlink exact-0700 owner directory.",
        )


def _create_private_file(path: Path, payload: bytes) -> None:
    _validate_private_directory(path.parent, expected_uid=os.geteuid())
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    flags |= getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
    try:
        descriptor = os.open(path, flags, 0o600)
    except OSError as exc:
        raise LabNodeError(
            "LAB_NODE_PATH_UNSAFE", "Private file could not be created."
        ) from exc
    try:
        os.fchmod(descriptor, 0o600)
        offset = 0
        while offset < len(payload):
            written = os.write(descriptor, payload[offset:])
            if written <= 0:
                raise LabNodeError(
                    "LAB_NODE_WRITE_FAILED", "Private file write was incomplete."
                )
            offset += written
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    _fsync_directory(path.parent)


def _create_or_read_private_file(path: Path, payload: bytes) -> bytes:
    try:
        _create_private_file(path, payload)
        return payload
    except LabNodeError as exc:
        if not isinstance(exc.__cause__, FileExistsError):
            raise
    return _read_private_file(path, expected_uid=os.geteuid())


def _fault_hook(expected_stage: str) -> Callable[[str], None] | None:
    if expected_stage == FAULT_NONE:
        return None

    def stop_at(observed_stage: str) -> None:
        if observed_stage != expected_stage:
            return
        print(
            canonical_json({"fault_stage": observed_stage, "status": "FAULT_READY"}),
            file=sys.stderr,
            flush=True,
        )
        while True:
            signal.pause()

    return stop_at


def recover_stale_socket(
    private: Path, *, socket_name: str, explicitly_enabled: bool
) -> None:
    if explicitly_enabled is not True or socket_name not in (
        "executor.sock",
        "observer.sock",
    ):
        raise LabNodeError(
            "LAB_SOCKET_RECOVERY_NOT_AUTHORIZED",
            "Stale-socket recovery requires an explicit closed target.",
        )
    _validate_private_directory(private, expected_uid=os.geteuid())
    path = private / socket_name
    try:
        metadata = path.lstat()
    except OSError as exc:
        raise LabNodeError(
            "LAB_STALE_SOCKET_INVALID", "Expected stale socket is unavailable."
        ) from exc
    if (
        path.is_symlink()
        or not stat.S_ISSOCK(metadata.st_mode)
        or metadata.st_nlink != 1
        or metadata.st_uid != os.geteuid()
        or stat.S_IMODE(metadata.st_mode) != 0o600
    ):
        raise LabNodeError(
            "LAB_STALE_SOCKET_INVALID",
            "Stale socket metadata is not the exact safe shape.",
        )
    path.unlink()
    _fsync_directory(private)


def _read_private_file(
    path: Path, *, expected_uid: int, exact_size: int | None = None
) -> bytes:
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise LabNodeError(
            "LAB_NODE_PATH_UNSAFE", "Private file is unavailable."
        ) from exc
    try:
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_nlink != 1
            or metadata.st_uid != expected_uid
            or stat.S_IMODE(metadata.st_mode) != 0o600
            or metadata.st_size < 0
            or metadata.st_size > MAX_SMALL_FILE
            or (exact_size is not None and metadata.st_size != exact_size)
        ):
            raise LabNodeError(
                "LAB_NODE_PATH_UNSAFE", "Private file metadata is unsafe."
            )
        payload = os.read(descriptor, metadata.st_size + 1)
        if len(payload) != metadata.st_size:
            raise LabNodeError(
                "LAB_NODE_READ_FAILED", "Private file read was incomplete."
            )
        return payload
    finally:
        os.close(descriptor)


def _netns_id() -> str:
    try:
        metadata = os.stat("/proc/self/ns/net", follow_symlinks=True)
    except OSError as exc:
        raise LabNodeError(
            "LAB_NETNS_UNAVAILABLE", "Network namespace identity is unavailable."
        ) from exc
    return f"netns:{metadata.st_ino}"


def prepare_empty_volume(root: Path, *, uid: int = LAB_UID, gid: int = LAB_GID) -> None:
    if os.geteuid() != 0 or type(uid) is not int or type(gid) is not int:
        raise LabNodeError(
            "LAB_VOLUME_PREPARE_NOT_AUTHORIZED",
            "Empty-volume preparation requires root.",
        )
    try:
        metadata = root.lstat()
        entries = list(root.iterdir())
    except OSError as exc:
        raise LabNodeError(
            "LAB_NODE_PATH_UNSAFE", "Volume root is unavailable."
        ) from exc
    if root.is_symlink() or not stat.S_ISDIR(metadata.st_mode) or entries:
        raise LabNodeError(
            "LAB_VOLUME_NOT_EMPTY",
            "Volume preparation accepts only an empty mount root.",
        )
    private = root / "private"
    private.mkdir(mode=0o700)
    os.chmod(private, 0o700, follow_symlinks=False)
    os.chown(private, uid, gid, follow_symlinks=False)
    _fsync_directory(root)


def initialize_executor_volume(private: Path) -> None:
    _validate_private_directory(private, expected_uid=os.geteuid())
    _create_private_file(private / "channel.key", secrets.token_bytes(32))
    initialize_executor_journal(private / "executor-replay.jsonl", expect_empty=True)


def initialize_observer_volume(private: Path) -> None:
    _validate_private_directory(private, expected_uid=os.geteuid())
    _create_private_file(private / "channel.key", secrets.token_bytes(32))


def _target_facts(path: Path, *, wait_seconds: float = 10.0) -> dict[str, object]:
    deadline = time.monotonic() + wait_seconds
    while True:
        try:
            raw = _read_private_file(path, expected_uid=LAB_UID)
            value = strict_json_loads(raw)
            if type(value) is not dict or set(value) != {
                "target_id",
                "target_boot_id",
                "ruleset_sha256",
            }:
                raise ValueError("unexpected target facts")
            if (
                value["target_id"] != TARGET_ID
                or type(value["target_boot_id"]) is not str
                or type(value["ruleset_sha256"]) is not str
                or value["ruleset_sha256"] != RULESET_OPEN_SHA256
            ):
                raise ValueError("invalid target facts")
            return value
        except FileNotFoundError:
            pass
        except (LabNodeError, ValueError, TypeError) as exc:
            if time.monotonic() >= deadline:
                raise LabNodeError(
                    "LAB_TARGET_FACTS_INVALID", "Target facts did not become valid."
                ) from exc
        if time.monotonic() >= deadline:
            raise LabNodeError(
                "LAB_TARGET_FACTS_TIMEOUT", "Timed out waiting for target facts."
            )
        time.sleep(0.05)


def _serve_fixed_tcp(host: str, port: int) -> None:
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind((host, port))
    listener.listen(8)
    while True:
        connection, _ = listener.accept()
        with connection:
            connection.settimeout(1.0)
            connection.sendall(b"OK")


def run_target(facts_path: Path) -> None:
    facts = {
        "target_id": TARGET_ID,
        "target_boot_id": _netns_id(),
        "ruleset_sha256": RULESET_OPEN_SHA256,
    }
    _create_private_file(facts_path, (canonical_json(facts) + "\n").encode("utf-8"))
    _serve_fixed_tcp(MANAGEMENT_HOST, MANAGEMENT_PORT)


def _probe(host: str, port: int) -> bool:
    try:
        with socket.create_connection((host, port), timeout=0.5) as connection:
            connection.settimeout(0.5)
            return connection.recv(2) == b"OK"
    except OSError:
        return False


def _state_reader(facts_path: Path) -> Callable[[], LabObservedState]:
    def read() -> LabObservedState:
        facts = _target_facts(facts_path)
        if facts["target_boot_id"] != _netns_id():
            raise LabNodeError(
                "LAB_TARGET_BOOT_ID_MISMATCH",
                "Service is outside the target namespace.",
            )
        return LabObservedState(
            target_boot_id=str(facts["target_boot_id"]),
            beacon_reachable=_probe(BEACON_HOST, BEACON_PORT),
            management_reachable=_probe(MANAGEMENT_HOST, MANAGEMENT_PORT),
            ruleset_sha256=str(facts["ruleset_sha256"]),
        )

    return read


def run_executor(
    private: Path,
    facts_path: Path,
    *,
    fault_stage: str = FAULT_NONE,
    allow_fault_injection: bool = False,
) -> None:
    if fault_stage not in EXECUTOR_FAULT_STAGES or (
        fault_stage != FAULT_NONE and allow_fault_injection is not True
    ):
        raise LabNodeError(
            "LAB_FAULT_INJECTION_NOT_AUTHORIZED",
            "Executor fault injection requires an explicit closed stage.",
        )
    key = _read_private_file(
        private / "channel.key", expected_uid=LAB_UID, exact_size=32
    )
    service = LabExecutorService(
        journal=ExecutorReplayJournal(
            private / "executor-replay.jsonl", require_existing=True
        ),
        key_id=EXECUTOR_KEY_ID,
        key=key,
        read_state=_state_reader(facts_path),
        failure_hook=_fault_hook(fault_stage),
        enabled=True,
    )
    with LabSeqpacketServer(
        private / "executor.sock",
        expected_client_uid=LAB_UID,
        enabled=True,
        timeout_seconds=15,
    ) as server:
        server.serve_once(service.handle)


def run_observer(
    private: Path,
    facts_path: Path,
    *,
    fault_stage: str = FAULT_NONE,
    allow_fault_injection: bool = False,
) -> None:
    if fault_stage not in OBSERVER_FAULT_STAGES or (
        fault_stage != FAULT_NONE and allow_fault_injection is not True
    ):
        raise LabNodeError(
            "LAB_FAULT_INJECTION_NOT_AUTHORIZED",
            "Observer fault injection requires an explicit closed stage.",
        )
    key = _read_private_file(
        private / "channel.key", expected_uid=LAB_UID, exact_size=32
    )
    service = LabObserverService(
        key_id=OBSERVER_KEY_ID,
        key=key,
        read_state=_state_reader(facts_path),
        failure_hook=_fault_hook(fault_stage),
        enabled=True,
    )
    with LabSeqpacketServer(
        private / "observer.sock",
        expected_client_uid=LAB_UID,
        enabled=True,
        timeout_seconds=15,
    ) as server:
        server.serve_once(service.handle)


def _wait_socket(path: Path, *, timeout_seconds: float = 10.0) -> None:
    deadline = time.monotonic() + timeout_seconds
    while True:
        try:
            metadata = path.lstat()
            if stat.S_ISSOCK(metadata.st_mode):
                return
        except FileNotFoundError:
            pass
        if time.monotonic() >= deadline:
            raise LabNodeError(
                "LAB_SOCKET_TIMEOUT", "Timed out waiting for lab socket."
            )
        time.sleep(0.05)


def run_control_client(
    executor_private: Path,
    observer_private: Path,
    facts_path: Path,
    control_private: Path | None = None,
) -> None:
    executor_key = _read_private_file(
        executor_private / "channel.key", expected_uid=LAB_UID, exact_size=32
    )
    observer_key = _read_private_file(
        observer_private / "channel.key", expected_uid=LAB_UID, exact_size=32
    )
    validate_lab_channel_keys(executor_key=executor_key, observer_key=observer_key)
    facts = _target_facts(facts_path)
    now = datetime.now(timezone.utc).replace(microsecond=0)
    generated_command = sign_lab_message(
        {
            "schema_version": "0.4.0",
            "message_type": COMMAND,
            "lab_session_id": os.environ["ADF_LAB_SESSION_ID"],
            "request_id": "request-001",
            "decision_id": "decision-001",
            "authorization_id": "authorization-not-integrated",
            "policy_sha256": POLICY_SHA256,
            "adapter_contract_sha256": ADAPTER_CONTRACT_SHA256,
            "target_id": TARGET_ID,
            "target_boot_id": facts["target_boot_id"],
            "action": "NETWORK_ISOLATE",
            "parameters": {
                "duration_seconds": 300,
                "preserve_management": True,
                "network_profile": "LAB_BEACON_BLOCK_MANAGEMENT_ALLOW_V1",
            },
            "prestate_sha256": facts["ruleset_sha256"],
            "idempotency_key": "idempotency-001",
            "sequence": 1,
            "nonce": secrets.token_hex(16),
            "issued_at": now.isoformat(),
            "expires_at": (now + timedelta(seconds=90)).isoformat(),
        },
        message_type=COMMAND,
        key_id=EXECUTOR_KEY_ID,
        key=executor_key,
        now=now,
    )
    command_raw = canonical_json(generated_command).encode("utf-8")
    if control_private is not None:
        _validate_private_directory(control_private, expected_uid=LAB_UID)
        command_raw = _create_or_read_private_file(
            control_private / "command.json", command_raw
        )
    command = load_authenticated_lab_message(
        command_raw,
        message_type=COMMAND,
        expected_key_id=EXECUTOR_KEY_ID,
        key=executor_key,
        now=now,
        allow_expired=True,
    )
    if (
        command["lab_session_id"] != os.environ["ADF_LAB_SESSION_ID"]
        or command["target_id"] != TARGET_ID
        or command["target_boot_id"] != facts["target_boot_id"]
        or command["prestate_sha256"] != facts["ruleset_sha256"]
    ):
        raise LabNodeError(
            "LAB_CONTROL_COMMAND_MISMATCH",
            "Persisted command does not match this exact lab target.",
        )
    executor_socket = executor_private / "executor.sock"
    _wait_socket(executor_socket)
    receipt_raw = lab_seqpacket_exchange(
        executor_socket,
        command_raw,
        expected_server_uid=LAB_UID,
        enabled=True,
        timeout_seconds=10,
    )
    receipt = load_authenticated_lab_message(
        receipt_raw,
        message_type=RECEIPT,
        expected_key_id=EXECUTOR_KEY_ID,
        key=executor_key,
        now=now,
    )
    observation_request = sign_lab_message(
        {
            "schema_version": "0.4.0",
            "message_type": OBSERVATION_REQUEST,
            "lab_session_id": command["lab_session_id"],
            "request_id": command["request_id"],
            "decision_id": command["decision_id"],
            "command_sha256": lab_message_sha256(command),
            "idempotency_key": command["idempotency_key"],
            "target_id": command["target_id"],
            "target_boot_id": command["target_boot_id"],
            "sequence": command["sequence"],
            "nonce": secrets.token_hex(16),
            "issued_at": now.isoformat(),
            "expires_at": (now + timedelta(seconds=90)).isoformat(),
        },
        message_type=OBSERVATION_REQUEST,
        key_id=OBSERVER_KEY_ID,
        key=observer_key,
        now=now,
    )
    observer_socket = observer_private / "observer.sock"
    _wait_socket(observer_socket)
    observation_raw = lab_seqpacket_exchange(
        observer_socket,
        canonical_json(observation_request).encode("utf-8"),
        expected_server_uid=LAB_UID,
        enabled=True,
        timeout_seconds=10,
    )
    observation = load_authenticated_lab_message(
        observation_raw,
        message_type=OBSERVATION,
        expected_key_id=OBSERVER_KEY_ID,
        key=observer_key,
        now=now,
    )
    validate_lab_message_correlation(
        command=command, receipt=receipt, observation=observation
    )
    print(
        canonical_json(
            {
                "schema_version": "0.4.0",
                "lab_session_id": command["lab_session_id"],
                "target_id": TARGET_ID,
                "receipt_status": receipt["status"],
                "effect_possible": receipt["effect_possible"],
                "beacon_reachable": observation["beacon_reachable"],
                "management_reachable": observation["management_reachable"],
                "correlation_valid": True,
                "authorization_integrated": False,
                "live_actions_possible": False,
            }
        ),
        flush=True,
    )


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Fixed-function Phase 4 lab node")
    subparsers = parser.add_subparsers(dest="role", required=True)
    prepare = subparsers.add_parser("prepare-empty-volume")
    prepare.add_argument("--root", type=Path, required=True)
    init_executor = subparsers.add_parser("initialize-executor")
    init_executor.add_argument("--private", type=Path, required=True)
    init_observer = subparsers.add_parser("initialize-observer")
    init_observer.add_argument("--private", type=Path, required=True)
    subparsers.add_parser("beacon")
    target = subparsers.add_parser("target")
    target.add_argument("--facts", type=Path, required=True)
    executor = subparsers.add_parser("executor")
    executor.add_argument("--private", type=Path, required=True)
    executor.add_argument("--facts", type=Path, required=True)
    executor.add_argument(
        "--fault-stage", choices=sorted(EXECUTOR_FAULT_STAGES), default=FAULT_NONE
    )
    executor.add_argument("--allow-fault-injection", action="store_true")
    observer = subparsers.add_parser("observer")
    observer.add_argument("--private", type=Path, required=True)
    observer.add_argument("--facts", type=Path, required=True)
    observer.add_argument(
        "--fault-stage", choices=sorted(OBSERVER_FAULT_STAGES), default=FAULT_NONE
    )
    observer.add_argument("--allow-fault-injection", action="store_true")
    client = subparsers.add_parser("control-client")
    client.add_argument("--executor-private", type=Path, required=True)
    client.add_argument("--observer-private", type=Path, required=True)
    client.add_argument("--facts", type=Path, required=True)
    client.add_argument("--control-private", type=Path)
    recover = subparsers.add_parser("recover-stale-socket")
    recover.add_argument("--private", type=Path, required=True)
    recover.add_argument(
        "--socket", choices=("executor.sock", "observer.sock"), required=True
    )
    recover.add_argument("--allow-stale-socket-recovery", action="store_true")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        if args.role == "prepare-empty-volume":
            prepare_empty_volume(args.root)
        elif args.role == "initialize-executor":
            initialize_executor_volume(args.private)
        elif args.role == "initialize-observer":
            initialize_observer_volume(args.private)
        elif args.role == "beacon":
            _serve_fixed_tcp("0.0.0.0", BEACON_PORT)
        elif args.role == "target":
            run_target(args.facts)
        elif args.role == "executor":
            run_executor(
                args.private,
                args.facts,
                fault_stage=args.fault_stage,
                allow_fault_injection=args.allow_fault_injection,
            )
        elif args.role == "observer":
            run_observer(
                args.private,
                args.facts,
                fault_stage=args.fault_stage,
                allow_fault_injection=args.allow_fault_injection,
            )
        elif args.role == "control-client":
            run_control_client(
                args.executor_private,
                args.observer_private,
                args.facts,
                args.control_private,
            )
        elif args.role == "recover-stale-socket":
            recover_stale_socket(
                args.private,
                socket_name=args.socket,
                explicitly_enabled=args.allow_stale_socket_recovery,
            )
        else:  # pragma: no cover - argparse owns the closed role set
            raise LabNodeError("LAB_ROLE_INVALID", "Unsupported lab role.")
    except Exception as exc:
        reason = getattr(exc, "reason_code", "LAB_NODE_FAILED")
        print(
            canonical_json({"status": "FAILED", "reason_code": reason}), file=sys.stderr
        )
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
