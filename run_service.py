"""Lifecycle CLI for the bounded Stage A synthetic-only reference service."""

from __future__ import annotations

import argparse
import ipaddress
import sys
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import Request, urlopen
from wsgiref.simple_server import make_server

from adf_poc.service import (
    RUNTIME_PROFILE,
    ServiceConfigurationError,
    create_application,
    initialize_service,
)
from adf_poc.service_backup import create_cold_backup, restore_cold_backup
from adf_poc.service_secret_stage import stage_secret_directory
from adf_poc.utils import canonical_json, strict_json_loads


def _loopback_endpoint(args: argparse.Namespace) -> tuple[str, int]:
    if args.bind:
        if args.host is not None or args.port is not None:
            raise ServiceConfigurationError("Use --bind or --host/--port, not both")
        parsed = urlsplit(f"//{args.bind}")
        if (
            parsed.username
            or parsed.password
            or parsed.path
            or parsed.query
            or parsed.fragment
        ):
            raise ServiceConfigurationError("--bind must be a numeric host:port")
        host = parsed.hostname
        try:
            port = parsed.port
        except ValueError as exc:
            raise ServiceConfigurationError("--bind port is invalid") from exc
    else:
        host = args.host
        port = args.port
    if type(host) is not str or type(port) is not int or not 1 <= port <= 65535:
        raise ServiceConfigurationError(
            "A bounded numeric loopback endpoint is required"
        )
    try:
        address = ipaddress.ip_address(host)
    except ValueError as exc:
        raise ServiceConfigurationError(
            "Service bind host must be numeric loopback"
        ) from exc
    if not address.is_loopback or address.version != 4:
        raise ServiceConfigurationError(
            "Reference transport may bind only IPv4 loopback"
        )
    if args.workers != 1:
        raise ServiceConfigurationError(
            "The Stage A reference transport requires exactly one worker"
        )
    return str(address), port


def _probe(url: str) -> dict[str, object]:
    parsed = urlsplit(url)
    try:
        port = parsed.port
    except ValueError as exc:
        raise ServiceConfigurationError("Probe port is invalid") from exc
    if (
        parsed.scheme != "http"
        or parsed.username
        or parsed.password
        or parsed.query
        or parsed.fragment
        or parsed.path not in {"/livez", "/readyz"}
        or parsed.hostname is None
        or port is None
    ):
        raise ServiceConfigurationError(
            "Probe URL must name a loopback liveness/readiness route"
        )
    try:
        address = ipaddress.ip_address(parsed.hostname)
    except ValueError as exc:
        raise ServiceConfigurationError("Probe host must be numeric loopback") from exc
    if not address.is_loopback or not 1 <= port <= 65535:
        raise ServiceConfigurationError("Probe target must be bounded loopback")
    request = Request(url, method="GET", headers={"Accept": "application/json"})
    try:
        with urlopen(request, timeout=2.0) as response:
            body = response.read(64 * 1024 + 1)
            if len(body) > 64 * 1024:
                raise ServiceConfigurationError("Probe response exceeds its bound")
            value = strict_json_loads(body)
    except HTTPError as exc:
        raise ServiceConfigurationError(f"Probe returned HTTP {exc.code}") from exc
    except (OSError, URLError, ValueError) as exc:
        raise ServiceConfigurationError("Probe failed") from exc
    if type(value) is not dict:
        raise ServiceConfigurationError("Probe response is not a JSON object")
    return value


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Manage the bounded Stage A synthetic-only reference service. "
            "The stdlib WSGI transport is loopback-only and is not a production transport claim."
        )
    )
    commands = parser.add_subparsers(dest="command", required=True)

    stage = commands.add_parser("stage-secrets")
    stage.add_argument("--config")
    stage.add_argument("--source", "--source-directory", dest="source", required=True)
    stage.add_argument(
        "--destination",
        "--destination-directory",
        dest="destination",
        required=True,
    )

    initialize = commands.add_parser("initialize")
    initialize.add_argument("--config", required=True)
    initialize.add_argument("--expect-empty", action="store_true", required=True)

    backup = commands.add_parser("backup")
    backup.add_argument("--config", required=True)
    backup.add_argument("--destination", required=True)
    backup.add_argument("--expect-quiesced", action="store_true", required=True)

    restore = commands.add_parser("restore")
    restore.add_argument("--config", required=True)
    restore.add_argument("--source", required=True)
    restore.add_argument("--expect-empty", action="store_true", required=True)

    serve = commands.add_parser("serve")
    serve.add_argument("--config", required=True)
    serve.add_argument("--bind")
    serve.add_argument("--host")
    serve.add_argument("--port", type=int)
    serve.add_argument("--workers", type=int, required=True)
    serve.add_argument("--require-existing", action="store_true", required=True)

    probe = commands.add_parser("probe")
    probe.add_argument("--url", required=True)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        if args.command == "stage-secrets":
            if args.config is not None and not Path(args.config).is_absolute():
                raise ServiceConfigurationError(
                    "--config must be absolute when supplied"
                )
            staged = stage_secret_directory(args.source, args.destination)
            result: dict[str, object] = {
                "status": "STAGED",
                "runtime_profile": RUNTIME_PROFILE,
                "staged_files": list(staged),
            }
        elif args.command == "initialize":
            if not args.expect_empty:
                raise ServiceConfigurationError("initialize requires --expect-empty")
            result = initialize_service(args.config)
        elif args.command == "backup":
            result = create_cold_backup(
                args.config,
                args.destination,
                operator_asserted_quiesced=args.expect_quiesced,
            )
        elif args.command == "restore":
            result = restore_cold_backup(
                args.config,
                args.source,
                expect_empty=args.expect_empty,
            )
        elif args.command == "probe":
            result = _probe(args.url)
        else:
            host, port = _loopback_endpoint(args)
            application = create_application(args.config)
            print(
                canonical_json(
                    {
                        "status": "SERVING_REFERENCE_TRANSPORT",
                        "runtime_profile": RUNTIME_PROFILE,
                        "bind": f"{host}:{port}",
                        "workers": 1,
                        "production_transport_evidence": False,
                    }
                ),
                flush=True,
            )
            with make_server(host, port, application) as server:
                server.serve_forever()
            return 0
        print(canonical_json(result))
        return 0
    except ServiceConfigurationError as exc:
        print(canonical_json({"status": "ERROR", "error": str(exc)}), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
