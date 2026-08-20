"""One-command, offline Stage A synthetic developer preview."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import secrets
import shutil
import stat
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from adf_poc.audit import AuditLogger
from adf_poc.phase3.scenarios import (
    request_json,
    trusted_soc_principal,
    valid_domain_controller_request,
    workstation_request,
)
from adf_poc.service import (
    RUNTIME_PROFILE,
    ServiceConfigurationError,
    create_application,
    initialize_service,
    invoke_wsgi,
)
from adf_poc.utils import canonical_json, strict_json_loads


PREVIEW_SCHEMA = "stage-a-developer-preview-v1"
DEFAULT_ROOT = Path("outputs/local/stage-a-preview")
SOURCE_NAMES = (
    "CMDB_PRIMARY",
    "CTI_PRIMARY",
    "EDR_PRIMARY",
    "IDP_PRIMARY",
    "NETWORK_PRIMARY",
)
ROOT_FILES = {"preview-profile.json", "service.json", "secrets", "state"}


class PreviewError(RuntimeError):
    """Bounded user-facing preview error."""


def _private_write(path: Path, value: bytes) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags, 0o600)
    try:
        view = memoryview(value)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise OSError("private write made no progress")
            view = view[written:]
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _bounded_read(path: Path, *, owner_private: bool, maximum: int) -> bytes:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags)
    try:
        opened = os.fstat(descriptor)
        current = path.lstat()
        mode = stat.S_IMODE(opened.st_mode)
        if (
            not stat.S_ISREG(opened.st_mode)
            or opened.st_nlink != 1
            or stat.S_ISLNK(current.st_mode)
            or (opened.st_dev, opened.st_ino) != (current.st_dev, current.st_ino)
            or opened.st_size < 1
            or opened.st_size > maximum
            or opened.st_uid != os.geteuid()
            or (owner_private and mode & 0o077)
            or (not owner_private and mode & 0o022)
        ):
            raise PreviewError("Preview input is not a safe bounded regular file")
        value = bytearray()
        while chunk := os.read(descriptor, min(64 * 1024, maximum + 1 - len(value))):
            value.extend(chunk)
            if len(value) > maximum:
                raise PreviewError("Preview input exceeds its size bound")
        after = os.fstat(descriptor)
        if (after.st_dev, after.st_ino, after.st_size) != (
            opened.st_dev,
            opened.st_ino,
            opened.st_size,
        ) or len(value) != opened.st_size:
            raise PreviewError("Preview input changed while being read")
        return bytes(value)
    finally:
        os.close(descriptor)


def _read_private(path: Path) -> bytes:
    return _bounded_read(path, owner_private=True, maximum=64 * 1024)


def _policy_path() -> Path:
    path = (Path(__file__).resolve().parent / "config" / "phase3_policy.json").resolve()
    if not path.is_file():
        raise PreviewError("Packaged Stage A policy is unavailable")
    return path


def _root(value: str) -> Path:
    return Path(value).expanduser().absolute()


def _assert_root(root: Path, *, existing: bool) -> None:
    if root == Path(root.anchor) or root == Path.home() or root == Path.cwd().resolve():
        raise PreviewError("Refusing an unsafe preview root")
    if not existing:
        return
    try:
        metadata = root.lstat()
    except OSError as exc:
        raise PreviewError("Preview state is not initialized") from exc
    if (
        stat.S_ISLNK(metadata.st_mode)
        or not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != os.geteuid()
        or stat.S_IMODE(metadata.st_mode) & 0o077
    ):
        raise PreviewError("Preview root is not an owner-private real directory")


def _marker(root: Path) -> dict[str, Any]:
    try:
        value = strict_json_loads(_read_private(root / "preview-profile.json"))
    except (OSError, ValueError) as exc:
        raise PreviewError("Preview profile marker is invalid") from exc
    expected = {
        "schema_version": PREVIEW_SCHEMA,
        "runtime_profile": RUNTIME_PROFILE,
        "live_actions_enabled": False,
    }
    if value != expected:
        raise PreviewError("Preview profile marker is invalid")
    return value


def _initialize(root: Path) -> dict[str, Any]:
    _assert_root(root, existing=False)
    if root.exists():
        _assert_root(root, existing=True)
        if any(root.iterdir()):
            raise PreviewError(
                "Initialization requires a missing or empty preview root"
            )
    else:
        root.mkdir(parents=True, mode=0o700)
        root.chmod(0o700)
    secrets_dir = root / "secrets"
    secrets_dir.mkdir(mode=0o700)
    signing = secrets_dir / "authorization.key"
    credential = secrets_dir / "caller.token"
    _private_write(signing, secrets.token_urlsafe(48).encode("ascii"))
    _private_write(credential, secrets.token_urlsafe(32).encode("ascii"))
    evidence_files: dict[str, str] = {}
    for name in SOURCE_NAMES:
        path = secrets_dir / f"{name}.key"
        _private_write(path, secrets.token_urlsafe(48).encode("ascii"))
        evidence_files[name] = str(path)
    config = {
        "schema_version": "1.0",
        "runtime_profile": RUNTIME_PROFILE,
        "policy_path": str(_policy_path()),
        "state_directory": str(root / "state"),
        "signing_key_file": str(signing),
        "evidence_key_files": evidence_files,
        "principals": [
            {
                "credential_file": str(credential),
                "principal": trusted_soc_principal().to_dict(),
            }
        ],
        "store_busy_timeout_ms": 1000,
    }
    _private_write(root / "service.json", canonical_json(config).encode("utf-8"))
    result = initialize_service(root / "service.json")
    _private_write(
        root / "preview-profile.json",
        canonical_json(
            {
                "schema_version": PREVIEW_SCHEMA,
                "runtime_profile": RUNTIME_PROFILE,
                "live_actions_enabled": False,
            }
        ).encode("utf-8"),
    )
    return result


def _ensure(root: Path) -> tuple[bool, dict[str, Any] | None]:
    if not root.exists():
        return True, _initialize(root)
    _assert_root(root, existing=True)
    if not any(root.iterdir()):
        return True, _initialize(root)
    _marker(root)
    return False, None


def _application(root: Path):
    _assert_root(root, existing=True)
    _marker(root)
    return create_application(root / "service.json")


def _source_keys(root: Path) -> dict[str, bytes]:
    return {
        name: _read_private(root / "secrets" / f"{name}.key") for name in SOURCE_NAMES
    }


def _credential(root: Path) -> str:
    return _read_private(root / "secrets" / "caller.token").decode("ascii")


def _scenario(root: Path, name: str, request_id: str | None) -> dict[str, Any]:
    now = datetime.now(timezone.utc).replace(microsecond=0)
    selected_id = request_id or f"PREVIEW-{name.upper()}-{uuid.uuid4().hex[:12]}"
    keys = _source_keys(root)
    if name == "workstation":
        return workstation_request(now, source_keys=keys, request_id=selected_id)
    if name == "domain-controller":
        return valid_domain_controller_request(
            now, source_keys=keys, request_id=selected_id
        )
    raise PreviewError("Unknown synthetic scenario")


def _submit(root: Path, name: str, request_id: str | None = None) -> dict[str, Any]:
    request = _scenario(root, name, request_id)
    response = _invoke_request(root, request_json(request).encode("utf-8"))
    return {"scenario": name, **_result_summary(response["result"])}


def _result_summary(result: dict[str, Any]) -> dict[str, Any]:
    return {
        "status": "DURABLE_RESULT_RETRIEVED",
        "request_id": result["request_id"],
        "decision_outcome": result["decision_outcome"],
        "disposition": result["disposition"],
        "verification_status": result["verification_status"],
        "reason_codes": result["reason_codes"],
        "attempt_recorded": result["attempt_id"] is not None,
        "adapter_receipt_recorded": result["adapter_receipt_sha256"] is not None,
        "recovery_required": result["recovery_required"],
    }


def _invoke_request(root: Path, body: bytes) -> dict[str, Any]:
    status, _headers, response = invoke_wsgi(
        _application(root),
        method="POST",
        path="/v1/synthetic/requests",
        body=body,
        authorization=f"Bearer {_credential(root)}",
    )
    if status != "200 OK" or "result" not in response:
        raise PreviewError(f"Synthetic request failed closed: {response}")
    return response


def _generate(
    root: Path, name: str, output: str, request_id: str | None
) -> dict[str, Any]:
    _ensure(root)
    body = request_json(_scenario(root, name, request_id)).encode("utf-8")
    target = Path(output).expanduser().absolute()
    target.parent.mkdir(parents=True, exist_ok=True)
    _private_write(target, body + b"\n")
    return {
        "status": "REQUEST_GENERATED",
        "scenario": name,
        "output": str(target),
        "request_sha256": hashlib.sha256(body).hexdigest(),
        "contains_operational_data": False,
    }


def _submit_file(root: Path, source: str) -> dict[str, Any]:
    _ensure(root)
    path = Path(source).expanduser().absolute()
    response = _invoke_request(
        root, _bounded_read(path, owner_private=False, maximum=1024 * 1024)
    )
    return _result_summary(response["result"])


def _status(root: Path) -> dict[str, Any]:
    status, _headers, response = invoke_wsgi(
        _application(root), method="GET", path="/readyz"
    )
    valid, errors = AuditLogger.verify(root / "state" / "audit.jsonl")
    rows = AuditLogger(root / "state" / "audit.jsonl").read_all()
    if status != "200 OK" or response.get("status") != "READY" or not valid:
        raise PreviewError("Preview readiness or audit integrity check failed closed")
    return {
        "status": response.get("status", status),
        "runtime_profile": RUNTIME_PROFILE,
        "live_actions_enabled": False,
        "audit_chain_valid": valid,
        "audit_errors": errors,
        "audit_rows": len(rows),
        "state_directory": str(root),
    }


def _reset(root: Path, confirmation: bool) -> dict[str, Any]:
    if not confirmation:
        raise PreviewError("Reset requires --confirm-synthetic-preview")
    _assert_root(root, existing=True)
    _marker(root)
    if {item.name for item in root.iterdir()} != ROOT_FILES:
        raise PreviewError("Preview root has an unexpected shape; refusing reset")
    shutil.rmtree(root)
    return {"status": "RESET", "removed": str(root)}


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Run the offline, synthetic-only Stage A developer preview."
    )
    commands = parser.add_subparsers(dest="command", required=True)

    def add_root(command: argparse.ArgumentParser) -> None:
        command.add_argument("--root", default=str(DEFAULT_ROOT))

    initialize = commands.add_parser("init", help="create new durable preview state")
    add_root(initialize)
    demo = commands.add_parser(
        "demo", help="initialize if needed and run both scenarios"
    )
    add_root(demo)
    scenario = commands.add_parser("scenario", help="run one synthetic scenario")
    add_root(scenario)
    scenario.add_argument("name", choices=("workstation", "domain-controller"))
    scenario.add_argument("--request-id")
    status = commands.add_parser("status", help="verify readiness and audit integrity")
    add_root(status)
    generate = commands.add_parser("generate", help="write a signed synthetic request")
    add_root(generate)
    generate.add_argument("name", choices=("workstation", "domain-controller"))
    generate.add_argument("--output", required=True)
    generate.add_argument("--request-id")
    submit = commands.add_parser("submit", help="submit a generated synthetic request")
    add_root(submit)
    submit.add_argument("--file", required=True)
    reset = commands.add_parser("reset", help="remove only marked preview state")
    add_root(reset)
    reset.add_argument("--confirm-synthetic-preview", action="store_true")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    root = _root(args.root)
    try:
        if args.command == "init":
            result = _initialize(root)
        elif args.command == "demo":
            created, initialization = _ensure(root)
            result = {
                "status": "DEMO_COMPLETE",
                "initialized_this_call": created,
                "initialization": initialization,
                "results": [
                    _submit(root, "workstation"),
                    _submit(root, "domain-controller"),
                ],
                "integrity": _status(root),
            }
        elif args.command == "scenario":
            _ensure(root)
            result = _submit(root, args.name, args.request_id)
        elif args.command == "status":
            result = _status(root)
        elif args.command == "generate":
            result = _generate(root, args.name, args.output, args.request_id)
        elif args.command == "submit":
            result = _submit_file(root, args.file)
        else:
            result = _reset(root, args.confirm_synthetic_preview)
        print(json.dumps(result, indent=2, sort_keys=True))
        return 0
    except (OSError, ValueError, ServiceConfigurationError, PreviewError) as exc:
        print(
            canonical_json({"status": "ERROR", "error": str(exc)}),
            file=sys.stderr,
        )
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
