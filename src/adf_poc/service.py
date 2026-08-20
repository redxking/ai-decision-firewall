"""Bounded, synthetic-only Stage A HTTP integration boundary.

This module deliberately exposes no live connector, approval, recovery,
target-observation, audit, or administrative interface. The stdlib WSGI
launcher in ``run_service.py`` is a loopback-only reference transport; it is
not evidence of production transport, availability, or deployment readiness.
"""

from __future__ import annotations

import hashlib
import hmac
import io
import os
import re
import stat
import threading
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Iterable

from adf_poc.phase3.config import Phase3PolicyConfig
from adf_poc.phase3.contracts import (
    AuthenticatedPrincipal,
    RequestValidationError,
    load_decision_request_json,
)
from adf_poc.phase3.engine import Phase3DecisionFirewall
from adf_poc.phase3.identity import TrustedPrincipalResolver
from adf_poc.stage_a import (
    ControlLedgerError,
    SQLiteControlLedger,
    SQLiteSyntheticAdapterStore,
    SyntheticAdapterError,
)
from adf_poc.utils import (
    StrictJSONError,
    canonical_json,
    sha256_json,
    strict_json_loads,
)


SERVICE_CONFIG_VERSION = "1.0"
SERVICE_STATE_VERSION = "stage-a-service-state-v1"
SECRET_BINDING_VERSION = "stage-a-service-secrets-v1"
SERVICE_RESPONSE_VERSION = "stage-a-synthetic-http-v1"
RUNTIME_PROFILE = "STAGE_A_SYNTHETIC_ONLY"
EXECUTION_MODE = "synthetic_simulation"
MAX_CONFIG_BYTES = 256 * 1024
MAX_POLICY_BYTES = 1024 * 1024
MAX_MARKER_BYTES = 16 * 1024
MAX_REQUEST_BYTES = 1024 * 1024
MAX_SECRET_BYTES = 4096
MAX_AUTHORIZATION_BYTES = 1024
STATE_FILES = {
    "audit": "audit.jsonl",
    "control": "control.sqlite3",
    "adapter": "synthetic-adapter.sqlite3",
    "marker": "service-state.json",
}
CORRELATION_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
BEARER_TOKEN = re.compile(rb"^[A-Za-z0-9._~-]{43,512}$")
CONFIG_FIELDS = {
    "schema_version",
    "runtime_profile",
    "policy_path",
    "state_directory",
    "signing_key_file",
    "evidence_key_files",
    "principals",
    "store_busy_timeout_ms",
}
PRINCIPAL_FIELDS = {"credential_file", "principal"}
PRINCIPAL_SHAPE = {
    "id",
    "type",
    "authenticated",
    "roles",
    "authority",
    "security_status",
    "identity_source",
    "human_session",
    "authentication_reason_code",
}
MARKER_FIELDS = {
    "schema_version",
    "runtime_profile",
    "config_sha256",
    "policy_sha256",
    "secret_bindings_sha256",
    "control_ledger_id",
    "synthetic_adapter_store_id",
    "audit_inode",
    "state_files",
}
KNOWN_ROUTES = {
    "/livez": "GET",
    "/readyz": "GET",
    "/v1/synthetic/requests": "POST",
    "/v1/synthetic/request-results:lookup": "POST",
}


class ServiceConfigurationError(ValueError):
    """Fail-closed startup/configuration error without secret-bearing detail."""


class RequestEnvelopeError(ValueError):
    def __init__(self, status: str, code: str) -> None:
        super().__init__(code)
        self.status = status
        self.code = code


@dataclass(frozen=True, slots=True)
class _LoadedConfiguration:
    value: dict[str, Any]
    config_sha256: str
    policy: Phase3PolicyConfig
    policy_sha256: str
    secret_bindings_sha256: str
    state: Path
    signing_key: bytes
    evidence_keys: dict[str, bytes]
    resolver: TrustedPrincipalResolver
    timeout_ms: int


def _json_bytes(value: dict[str, Any]) -> bytes:
    return canonical_json(value).encode("utf-8")


def _fsync_directory(path: Path, *, label: str) -> None:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
        try:
            opened = os.fstat(descriptor)
            current = path.lstat()
            if (
                not stat.S_ISDIR(opened.st_mode)
                or opened.st_dev != current.st_dev
                or opened.st_ino != current.st_ino
            ):
                raise OSError("directory identity changed")
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
    except OSError as exc:
        raise ServiceConfigurationError(f"{label} directory sync failed") from exc


def _require_absolute_path(value: object, *, label: str) -> Path:
    if type(value) is not str or not value:
        raise ServiceConfigurationError(f"{label} must be an absolute path")
    path = Path(value)
    if not path.is_absolute():
        raise ServiceConfigurationError(f"{label} must be an absolute path")
    return path


def _assert_no_symlink_parent(path: Path, *, label: str) -> None:
    absolute = path.absolute()
    for parent in reversed(absolute.parents):
        try:
            metadata = parent.lstat()
        except OSError as exc:
            raise ServiceConfigurationError(
                f"{label} parent chain is unavailable"
            ) from exc
        if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
            raise ServiceConfigurationError(f"{label} parent chain is unsafe")


def _bounded_regular_file(
    path: Path,
    *,
    label: str,
    maximum: int,
    owner_private: bool,
) -> tuple[bytes, os.stat_result]:
    """Read one exact regular file through an O_NOFOLLOW descriptor."""

    if not path.is_absolute():
        raise ServiceConfigurationError(f"{label} must be an absolute path")
    _assert_no_symlink_parent(path, label=label)
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise ServiceConfigurationError(f"{label} is unavailable") from exc
    try:
        opened = os.fstat(descriptor)
        current = path.lstat()
        mode = stat.S_IMODE(opened.st_mode)
        if (
            not stat.S_ISREG(opened.st_mode)
            or opened.st_nlink != 1
            or stat.S_ISLNK(current.st_mode)
            or opened.st_dev != current.st_dev
            or opened.st_ino != current.st_ino
            or opened.st_size > maximum
        ):
            raise ServiceConfigurationError(
                f"{label} is not a safe bounded regular file"
            )
        if opened.st_uid not in {0, os.geteuid()} or not mode & 0o400:
            raise ServiceConfigurationError(
                f"{label} ownership or readability is unsafe"
            )
        if owner_private:
            if opened.st_uid != os.geteuid() or mode & 0o077:
                raise ServiceConfigurationError(f"{label} must be owner-private")
        elif mode & 0o022:
            raise ServiceConfigurationError(f"{label} must not be group/other writable")
        chunks: list[bytes] = []
        remaining = maximum + 1
        while remaining:
            chunk = os.read(descriptor, min(64 * 1024, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        value = b"".join(chunks)
        after = os.fstat(descriptor)
        if (
            len(value) > maximum
            or after.st_dev != opened.st_dev
            or after.st_ino != opened.st_ino
            or after.st_size != opened.st_size
        ):
            raise ServiceConfigurationError(f"{label} changed or exceeded its bound")
        return value, opened
    finally:
        os.close(descriptor)


def _strict_json_object(raw: bytes, *, label: str) -> dict[str, Any]:
    try:
        value = strict_json_loads(raw)
    except (StrictJSONError, ValueError, UnicodeError) as exc:
        raise ServiceConfigurationError(f"{label} is not strict JSON") from exc
    if type(value) is not dict:
        raise ServiceConfigurationError(f"{label} must be a JSON object")
    return value


def _load_policy(path_text: object) -> tuple[Phase3PolicyConfig, str]:
    path = _require_absolute_path(path_text, label="policy_path")
    raw, _metadata = _bounded_regular_file(
        path,
        label="policy_path",
        maximum=MAX_POLICY_BYTES,
        owner_private=False,
    )
    value = _strict_json_object(raw, label="policy_path")
    try:
        policy = Phase3PolicyConfig.from_dict(value)
    except (TypeError, ValueError) as exc:
        raise ServiceConfigurationError("Policy validation failed") from exc
    return policy, sha256_json(policy.to_dict())


def _safe_secret(path_text: object, *, label: str, bearer: bool = False) -> bytes:
    path = _require_absolute_path(path_text, label=label)
    value, _metadata = _bounded_regular_file(
        path,
        label=label,
        maximum=MAX_SECRET_BYTES,
        owner_private=True,
    )
    if not 32 <= len(value) <= MAX_SECRET_BYTES or value != value.strip():
        raise ServiceConfigurationError(f"{label} has an invalid bounded value")
    if bearer and BEARER_TOKEN.fullmatch(value) is None:
        raise ServiceConfigurationError(f"{label} must contain a URL-safe bearer token")
    return value


def _state_directory(path_text: object, *, expect_empty: bool) -> Path:
    path = _require_absolute_path(path_text, label="state_directory")
    _assert_no_symlink_parent(path, label="state_directory")
    if not path.exists():
        if not expect_empty:
            raise ServiceConfigurationError("Existing initialized state is required")
        try:
            os.mkdir(path, 0o700)
            _fsync_directory(path.parent, label="state_directory parent")
        except OSError as exc:
            raise ServiceConfigurationError(
                "state_directory could not be created"
            ) from exc
    try:
        metadata = path.lstat()
    except OSError as exc:
        raise ServiceConfigurationError("state_directory is unavailable") from exc
    if (
        stat.S_ISLNK(metadata.st_mode)
        or not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != os.geteuid()
        or stat.S_IMODE(metadata.st_mode) & 0o077
        or not os.access(path, os.R_OK | os.W_OK | os.X_OK)
    ):
        raise ServiceConfigurationError(
            "state_directory must be an owner-private real directory"
        )
    if expect_empty:
        try:
            if any(path.iterdir()):
                raise ServiceConfigurationError(
                    "Initialization requires an empty state_directory"
                )
        except OSError as exc:
            raise ServiceConfigurationError(
                "state_directory could not be inspected"
            ) from exc
    else:
        for name in STATE_FILES.values():
            target = path / name
            try:
                target_metadata = target.lstat()
            except OSError as exc:
                raise ServiceConfigurationError(
                    "Initialized service state is incomplete"
                ) from exc
            if (
                stat.S_ISLNK(target_metadata.st_mode)
                or not stat.S_ISREG(target_metadata.st_mode)
                or target_metadata.st_nlink != 1
                or target_metadata.st_uid != os.geteuid()
                or stat.S_IMODE(target_metadata.st_mode) & 0o077
            ):
                raise ServiceConfigurationError(
                    "Initialized service state has unsafe files"
                )
    return path


def _load_configuration(
    config_path: str | Path, *, expect_empty: bool
) -> _LoadedConfiguration:
    path = Path(config_path)
    if not path.is_absolute():
        raise ServiceConfigurationError("Service configuration path must be absolute")
    raw, _metadata = _bounded_regular_file(
        path,
        label="service configuration",
        maximum=MAX_CONFIG_BYTES,
        owner_private=False,
    )
    config = _strict_json_object(raw, label="service configuration")
    if set(config) != CONFIG_FIELDS:
        raise ServiceConfigurationError(
            "Service configuration has an invalid closed shape"
        )
    if (
        config["schema_version"] != SERVICE_CONFIG_VERSION
        or config["runtime_profile"] != RUNTIME_PROFILE
    ):
        raise ServiceConfigurationError("Service configuration profile is unsupported")
    policy, policy_sha256 = _load_policy(config["policy_path"])
    state = _state_directory(config["state_directory"], expect_empty=expect_empty)
    timeout = config["store_busy_timeout_ms"]
    if type(timeout) is not int or not 100 <= timeout <= 30_000:
        raise ServiceConfigurationError(
            "store_busy_timeout_ms is outside its closed bound"
        )
    signing_key = _safe_secret(config["signing_key_file"], label="signing_key_file")
    key_files = config["evidence_key_files"]
    if type(key_files) is not dict or set(key_files) != set(
        policy.evidence.trusted_sources
    ):
        raise ServiceConfigurationError(
            "evidence_key_files must exactly cover policy trusted sources"
        )
    evidence_keys = {
        source: _safe_secret(key_files[source], label=f"evidence_key_files.{source}")
        for source in sorted(key_files)
    }
    principal_rows = config["principals"]
    if type(principal_rows) is not list or not 1 <= len(principal_rows) <= 32:
        raise ServiceConfigurationError("principals must be a bounded nonempty list")
    resolver_rows: list[tuple[bytes, AuthenticatedPrincipal]] = []
    credential_bindings: dict[str, str] = {}
    for index, row in enumerate(principal_rows):
        if (
            type(row) is not dict
            or set(row) != PRINCIPAL_FIELDS
            or type(row["principal"]) is not dict
            or set(row["principal"]) - PRINCIPAL_SHAPE
        ):
            raise ServiceConfigurationError(
                f"principals[{index}] has an invalid closed shape"
            )
        try:
            principal = AuthenticatedPrincipal.from_dict(dict(row["principal"]))
        except (TypeError, ValueError) as exc:
            raise ServiceConfigurationError(f"principals[{index}] is invalid") from exc
        if (
            not principal.identity_source.startswith("synthetic_")
            or not principal.authenticated
            or principal.security_status.value != "TRUSTED"
            or principal.human_session
        ):
            raise ServiceConfigurationError(
                "Service principals must be trusted nonhuman synthetic identities"
            )
        credential = _safe_secret(
            row["credential_file"],
            label=f"principals[{index}].credential_file",
            bearer=True,
        )
        resolver_rows.append((credential, principal))
        credential_bindings[principal.id] = hashlib.sha256(credential).hexdigest()
    try:
        resolver = TrustedPrincipalResolver(resolver_rows)
    except (TypeError, ValueError) as exc:
        raise ServiceConfigurationError(
            "Trusted principal configuration is invalid"
        ) from exc
    secret_bindings_sha256 = sha256_json(
        {
            "schema_version": SECRET_BINDING_VERSION,
            "signing_key_sha256": hashlib.sha256(signing_key).hexdigest(),
            "evidence_key_sha256": {
                source: hashlib.sha256(evidence_keys[source]).hexdigest()
                for source in sorted(evidence_keys)
            },
            "principal_credential_sha256": credential_bindings,
        }
    )
    return _LoadedConfiguration(
        value=config,
        config_sha256=hashlib.sha256(
            canonical_json(config).encode("utf-8")
        ).hexdigest(),
        policy=policy,
        policy_sha256=policy_sha256,
        secret_bindings_sha256=secret_bindings_sha256,
        state=state,
        signing_key=signing_key,
        evidence_keys=evidence_keys,
        resolver=resolver,
        timeout_ms=timeout,
    )


def _construct_firewall(loaded: _LoadedConfiguration) -> Phase3DecisionFirewall:
    try:
        firewall = Phase3DecisionFirewall(
            policy=loaded.policy,
            signing_key=loaded.signing_key,
            evidence_attestation_keys=loaded.evidence_keys,
            principal_resolver=loaded.resolver,
            audit_path=loaded.state / STATE_FILES["audit"],
            control_ledger_path=loaded.state / STATE_FILES["control"],
            control_ledger_busy_timeout_ms=loaded.timeout_ms,
            synthetic_adapter_path=loaded.state / STATE_FILES["adapter"],
            synthetic_adapter_busy_timeout_ms=loaded.timeout_ms,
            clock=lambda: datetime.now(timezone.utc).replace(microsecond=0),
            fault_modes=None,
        )
    except (
        OSError,
        TypeError,
        ValueError,
        RuntimeError,
        ControlLedgerError,
        SyntheticAdapterError,
    ) as exc:
        raise ServiceConfigurationError(
            "Durable service startup preflight failed"
        ) from exc
    if (
        type(firewall) is not Phase3DecisionFirewall
        or firewall.execution_mode != EXECUTION_MODE
        or type(firewall._control_ledger) is not SQLiteControlLedger
        or type(firewall._adapter_store) is not SQLiteSyntheticAdapterStore
    ):
        raise ServiceConfigurationError(
            "Exact synthetic durable boundary is unavailable"
        )
    return firewall


def _marker_value(
    loaded: _LoadedConfiguration, firewall: Phase3DecisionFirewall
) -> dict[str, Any]:
    audit = (loaded.state / STATE_FILES["audit"]).lstat()
    return {
        "schema_version": SERVICE_STATE_VERSION,
        "runtime_profile": RUNTIME_PROFILE,
        "config_sha256": loaded.config_sha256,
        "policy_sha256": loaded.policy_sha256,
        "secret_bindings_sha256": loaded.secret_bindings_sha256,
        "control_ledger_id": firewall._control_ledger.issuer_instance_id,
        "synthetic_adapter_store_id": firewall._adapter_store.adapter_store_id,
        "audit_inode": audit.st_ino,
        "state_files": dict(STATE_FILES),
    }


def _write_marker(path: Path, value: dict[str, Any]) -> None:
    body = _json_bytes(value)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags, 0o600)
        with os.fdopen(descriptor, "wb", closefd=True) as handle:
            handle.write(body)
            handle.flush()
            os.fsync(handle.fileno())
        _fsync_directory(path.parent, label="service state marker parent")
    except OSError as exc:
        raise ServiceConfigurationError(
            "Service state marker could not be committed"
        ) from exc


def initialize_service(config_path: str | Path) -> dict[str, Any]:
    """Initialize a new empty service state. Never overwrites partial state."""

    loaded = _load_configuration(config_path, expect_empty=True)
    firewall = _construct_firewall(loaded)
    snapshot = firewall.readiness_snapshot()
    if snapshot.get("status") != "READY":
        raise ServiceConfigurationError("New durable state did not pass readiness")
    marker = _marker_value(loaded, firewall)
    _write_marker(loaded.state / STATE_FILES["marker"], marker)
    return {
        "status": "INITIALIZED",
        "runtime_profile": RUNTIME_PROFILE,
        "execution_mode": EXECUTION_MODE,
        "live_actions_enabled": False,
        "config_sha256": loaded.config_sha256,
        "policy_sha256": loaded.policy_sha256,
    }


def _read_marker(loaded: _LoadedConfiguration) -> dict[str, Any]:
    raw, _metadata = _bounded_regular_file(
        loaded.state / STATE_FILES["marker"],
        label="service state marker",
        maximum=MAX_MARKER_BYTES,
        owner_private=True,
    )
    marker = _strict_json_object(raw, label="service state marker")
    if set(marker) != MARKER_FIELDS:
        raise ServiceConfigurationError("Service state marker binding is invalid")
    static_binding = {
        "schema_version": SERVICE_STATE_VERSION,
        "runtime_profile": RUNTIME_PROFILE,
        "config_sha256": loaded.config_sha256,
        "policy_sha256": loaded.policy_sha256,
        "secret_bindings_sha256": loaded.secret_bindings_sha256,
        "state_files": dict(STATE_FILES),
    }
    if any(marker.get(name) != value for name, value in static_binding.items()):
        raise ServiceConfigurationError("Service state marker binding is invalid")
    return marker


def _verify_marker(
    loaded: _LoadedConfiguration,
    firewall: Phase3DecisionFirewall,
    marker: dict[str, Any],
) -> None:
    if marker != _marker_value(loaded, firewall):
        raise ServiceConfigurationError("Service state marker binding is invalid")


def build_firewall(
    config_path: str | Path, *, require_existing: bool = True
) -> Phase3DecisionFirewall:
    if require_existing is not True:
        raise ServiceConfigurationError("Serving requires explicit existing-state mode")
    loaded = _load_configuration(config_path, expect_empty=False)
    marker = _read_marker(loaded)
    firewall = _construct_firewall(loaded)
    _verify_marker(loaded, firewall, marker)
    return firewall


def _correlation_id(environ: dict[str, Any]) -> str:
    supplied = environ.get("HTTP_X_REQUEST_ID")
    if type(supplied) is str and CORRELATION_ID.fullmatch(supplied):
        return supplied
    return f"adf-{uuid.uuid4()}"


def _bearer_credential(environ: dict[str, Any]) -> bytes:
    value = environ.get("HTTP_AUTHORIZATION")
    if (
        type(value) is not str
        or len(value.encode("utf-8", "ignore")) > MAX_AUTHORIZATION_BYTES
    ):
        raise PermissionError
    scheme, separator, token = value.partition(" ")
    if not separator or not hmac.compare_digest(scheme.lower(), "bearer"):
        raise PermissionError
    try:
        credential = token.encode("ascii")
    except UnicodeEncodeError as exc:
        raise PermissionError from exc
    if BEARER_TOKEN.fullmatch(credential) is None:
        raise PermissionError
    return credential


def _request_body(environ: dict[str, Any]) -> bytes:
    if environ.get("HTTP_TRANSFER_ENCODING"):
        raise RequestEnvelopeError("400 Bad Request", "TRANSFER_ENCODING_PROHIBITED")
    if environ.get("HTTP_CONTENT_ENCODING"):
        raise RequestEnvelopeError(
            "415 Unsupported Media Type", "CONTENT_ENCODING_PROHIBITED"
        )
    content_type = str(environ.get("CONTENT_TYPE", "")).split(";", 1)[0].strip().lower()
    if content_type != "application/json":
        raise RequestEnvelopeError(
            "415 Unsupported Media Type", "CONTENT_TYPE_UNSUPPORTED"
        )
    raw_length = environ.get("CONTENT_LENGTH")
    if (
        type(raw_length) is not str
        or not raw_length.isascii()
        or not raw_length.isdecimal()
    ):
        raise RequestEnvelopeError("400 Bad Request", "CONTENT_LENGTH_INVALID")
    length = int(raw_length)
    if length > MAX_REQUEST_BYTES:
        raise RequestEnvelopeError("413 Payload Too Large", "REQUEST_TOO_LARGE")
    if length < 1:
        raise RequestEnvelopeError("400 Bad Request", "REQUEST_BODY_EMPTY")
    stream = environ.get("wsgi.input")
    if not hasattr(stream, "read"):
        raise RequestEnvelopeError("400 Bad Request", "REQUEST_BODY_UNAVAILABLE")
    body = stream.read(length)
    if type(body) is not bytes or len(body) != length:
        raise RequestEnvelopeError("400 Bad Request", "CONTENT_LENGTH_MISMATCH")
    return body


def _validate_synthetic_request(body: bytes) -> None:
    request = load_decision_request_json(body)
    if (
        request.context.get("environment") != "synthetic_soc_demo"
        or request.context.get("live_action") is not False
        or any(item.payload.get("synthetic") is not True for item in request.evidence)
    ):
        raise RequestValidationError(
            "SYNTHETIC_PROFILE_REQUIRED",
            "Only explicitly marked synthetic requests are permitted.",
        )


@dataclass(slots=True)
class DecisionFirewallService:
    firewall: Phase3DecisionFirewall
    _submission_lock: threading.Lock = field(default_factory=threading.Lock, repr=False)

    def __post_init__(self) -> None:
        if (
            type(self.firewall) is not Phase3DecisionFirewall
            or self.firewall.execution_mode != EXECUTION_MODE
            or type(self.firewall._control_ledger) is not SQLiteControlLedger
            or type(self.firewall._adapter_store) is not SQLiteSyntheticAdapterStore
        ):
            raise ServiceConfigurationError(
                "Service requires the exact durable synthetic firewall"
            )

    def _respond(
        self,
        start_response: Callable[..., Any],
        status: str,
        payload: dict[str, Any],
        correlation_id: str,
        *,
        headers: tuple[tuple[str, str], ...] = (),
    ) -> Iterable[bytes]:
        body = _json_bytes(
            {
                "schema_version": SERVICE_RESPONSE_VERSION,
                "runtime_profile": RUNTIME_PROFILE,
                **payload,
                "correlation_id": correlation_id,
            }
        )
        start_response(
            status,
            [
                ("Content-Type", "application/json"),
                ("Content-Length", str(len(body))),
                ("Cache-Control", "no-store"),
                ("Pragma", "no-cache"),
                ("X-Content-Type-Options", "nosniff"),
                ("Referrer-Policy", "no-referrer"),
                ("X-Request-ID", correlation_id),
                *headers,
            ],
        )
        return [body]

    def _error(
        self,
        start_response: Callable[..., Any],
        status: str,
        code: str,
        correlation_id: str,
        *,
        lookup_required: bool = False,
        headers: tuple[tuple[str, str], ...] = (),
    ) -> Iterable[bytes]:
        return self._respond(
            start_response,
            status,
            {
                "error": {
                    "code": code,
                    "automatic_retry_permitted": False,
                    "lookup_required": lookup_required,
                }
            },
            correlation_id,
            headers=headers,
        )

    def __call__(
        self, environ: dict[str, Any], start_response: Callable[..., Any]
    ) -> Iterable[bytes]:
        correlation = _correlation_id(environ)
        method = str(environ.get("REQUEST_METHOD", ""))
        path = str(environ.get("PATH_INFO", ""))
        if environ.get("QUERY_STRING"):
            return self._error(
                start_response, "400 Bad Request", "QUERY_PROHIBITED", correlation
            )
        expected_method = KNOWN_ROUTES.get(path)
        if expected_method is None:
            return self._error(
                start_response, "404 Not Found", "NOT_FOUND", correlation
            )
        if method != expected_method:
            return self._error(
                start_response,
                "405 Method Not Allowed",
                "METHOD_NOT_ALLOWED",
                correlation,
                headers=(("Allow", expected_method),),
            )
        processing_started = False
        try:
            if path == "/livez":
                return self._respond(
                    start_response,
                    "200 OK",
                    {
                        "status": "LIVE",
                        "execution_mode": EXECUTION_MODE,
                        "live_actions_enabled": False,
                    },
                    correlation,
                )
            if path == "/readyz":
                snapshot = self.firewall.readiness_snapshot()
                status = (
                    "200 OK"
                    if snapshot.get("status") == "READY"
                    else "503 Service Unavailable"
                )
                return self._respond(start_response, status, snapshot, correlation)

            credential = _bearer_credential(environ)
            self.firewall.authenticate_transport_credential(credential)
            body = _request_body(environ)
            _validate_synthetic_request(body)
            if path.endswith(":lookup"):
                existing = self.firewall.lookup_request_result(
                    body, credential=credential
                )
                if existing is None:
                    return self._error(
                        start_response, "404 Not Found", "RESULT_NOT_FOUND", correlation
                    )
                return self._respond(
                    start_response,
                    "200 OK",
                    {
                        "operation": "REQUEST_RESULT_LOOKUP",
                        "result": existing.to_dict(),
                    },
                    correlation,
                )

            with self._submission_lock:
                existing = self.firewall.lookup_request_result(
                    body, credential=credential
                )
                if existing is None:
                    processing_started = True
                    self.firewall.process_json(body, credential=credential)
                    existing = self.firewall.lookup_request_result(
                        body, credential=credential
                    )
            if existing is None:
                return self._error(
                    start_response,
                    "503 Service Unavailable",
                    "TERMINAL_RESULT_NOT_DURABLE",
                    correlation,
                    lookup_required=True,
                )
            return self._respond(
                start_response,
                "200 OK",
                {"operation": "SUBMIT_AND_LOOKUP", "result": existing.to_dict()},
                correlation,
            )
        except PermissionError:
            return self._error(
                start_response,
                "401 Unauthorized",
                "AUTHENTICATION_REQUIRED",
                correlation,
                headers=(("WWW-Authenticate", 'Bearer realm="adf-synthetic"'),),
            )
        except RequestEnvelopeError as exc:
            return self._error(start_response, exc.status, exc.code, correlation)
        except RequestValidationError as exc:
            return self._error(
                start_response,
                "422 Unprocessable Entity",
                exc.reason_code,
                correlation,
                lookup_required=processing_started,
            )
        except ControlLedgerError as exc:
            if "AUTHENTICATION" in exc.reason_code:
                return self._error(
                    start_response,
                    "401 Unauthorized",
                    "AUTHENTICATION_REQUIRED",
                    correlation,
                    headers=(("WWW-Authenticate", 'Bearer realm="adf-synthetic"'),),
                )
            status = (
                "409 Conflict"
                if "CONFLICT" in exc.reason_code
                else "503 Service Unavailable"
            )
            return self._error(
                start_response,
                status,
                exc.reason_code,
                correlation,
                lookup_required=processing_started,
            )
        except Exception:
            return self._error(
                start_response,
                "503 Service Unavailable",
                "SERVICE_UNAVAILABLE",
                correlation,
                lookup_required=processing_started,
            )


def create_application(
    config_path: str | Path | None = None,
) -> DecisionFirewallService:
    selected = config_path or os.environ.get("ADF_SERVICE_CONFIG")
    if not isinstance(selected, (str, Path)) or not str(selected):
        raise ServiceConfigurationError(
            "ADF_SERVICE_CONFIG must name an absolute configuration file"
        )
    return DecisionFirewallService(build_firewall(selected, require_existing=True))


def invoke_wsgi(
    application: DecisionFirewallService,
    *,
    method: str,
    path: str,
    body: bytes = b"",
    authorization: str | None = None,
) -> tuple[str, dict[str, str], dict[str, Any]]:
    """Small test helper; not an alternate transport implementation."""

    captured: dict[str, Any] = {}

    def start_response(status: str, headers: list[tuple[str, str]]) -> None:
        captured["status"] = status
        captured["headers"] = dict(headers)

    environ: dict[str, Any] = {
        "REQUEST_METHOD": method,
        "PATH_INFO": path,
        "QUERY_STRING": "",
        "CONTENT_TYPE": "application/json" if body else "",
        "CONTENT_LENGTH": str(len(body)) if body else "",
        "wsgi.input": io.BytesIO(body),
    }
    if authorization is not None:
        environ["HTTP_AUTHORIZATION"] = authorization
    response = b"".join(application(environ, start_response))
    return (
        str(captured["status"]),
        dict(captured["headers"]),
        strict_json_loads(response),
    )
