from __future__ import annotations

import json
import os
import tempfile
import unittest
from argparse import Namespace
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

from adf_poc.phase3.scenarios import (
    request_json,
    trusted_soc_principal,
    workstation_request,
)
from adf_poc.service import (
    DecisionFirewallService,
    ServiceConfigurationError,
    create_application,
    initialize_service,
    invoke_wsgi,
)
from adf_poc.service_secret_stage import stage_secret_directory
from adf_poc.stage_a import ControlLedgerError
from run_service import _loopback_endpoint


ROOT = Path(__file__).resolve().parents[1]
POLICY = ROOT / "config" / "phase3_policy.json"
SOURCE_NAMES = (
    "CMDB_PRIMARY",
    "CTI_PRIMARY",
    "EDR_PRIMARY",
    "IDP_PRIMARY",
    "NETWORK_PRIMARY",
)
SOURCE_KEYS = {
    name: (f"evidence-key-{index}-".encode("ascii") + b"E" * 48)[:64]
    for index, name in enumerate(SOURCE_NAMES)
}
SIGNING_KEY = b"authorization-signing-domain-" + b"S" * 36
BEARER = b"C" * 43


def _write_private(path: Path, value: bytes) -> None:
    path.write_bytes(value)
    path.chmod(0o600)


def _contains_key(value: object, denied: set[str]) -> bool:
    if type(value) is dict:
        return any(
            key in denied or _contains_key(child, denied)
            for key, child in value.items()
        )
    if type(value) is list:
        return any(_contains_key(child, denied) for child in value)
    return False


class ServiceFixture:
    def __init__(self, root: Path) -> None:
        self.root = root
        self.secrets = root / "secrets"
        self.secrets.mkdir(mode=0o700)
        self.state = root / "state"
        self.signing = self.secrets / "signing.key"
        self.credential = self.secrets / "caller.token"
        _write_private(self.signing, SIGNING_KEY)
        _write_private(self.credential, BEARER)
        self.key_files: dict[str, str] = {}
        for name, key in SOURCE_KEYS.items():
            path = self.secrets / f"{name}.key"
            _write_private(path, key)
            self.key_files[name] = str(path)
        self.config_path = root / "service.json"
        principal = trusted_soc_principal().to_dict()
        self.config = {
            "schema_version": "1.0",
            "runtime_profile": "STAGE_A_SYNTHETIC_ONLY",
            "policy_path": str(POLICY),
            "state_directory": str(self.state),
            "signing_key_file": str(self.signing),
            "evidence_key_files": dict(self.key_files),
            "principals": [
                {
                    "credential_file": str(self.credential),
                    "principal": principal,
                }
            ],
            "store_busy_timeout_ms": 1000,
        }
        self.write_config()

    def write_config(self) -> None:
        self.config_path.write_text(json.dumps(self.config), encoding="utf-8")
        self.config_path.chmod(0o600)

    def initialize(self) -> DecisionFirewallService:
        result = initialize_service(self.config_path)
        if result["status"] != "INITIALIZED":
            raise AssertionError("fixture initialization failed")
        return create_application(self.config_path)

    @staticmethod
    def workstation(*, request_id: str = "SERVICE-WORKSTATION-001") -> bytes:
        now = datetime.now(timezone.utc).replace(microsecond=0)
        return request_json(
            workstation_request(now, source_keys=SOURCE_KEYS, request_id=request_id)
        ).encode("utf-8")


class SyntheticServiceTests(unittest.TestCase):
    def test_explicit_initialize_then_existing_only_serve(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            fixture = ServiceFixture(Path(directory).resolve())
            with self.assertRaises(ServiceConfigurationError):
                create_application(fixture.config_path)
            application = fixture.initialize()
            self.assertIsInstance(application, DecisionFirewallService)
            self.assertEqual(
                set(path.name for path in fixture.state.iterdir()),
                {
                    "audit.jsonl",
                    "control.sqlite3",
                    "synthetic-adapter.sqlite3",
                    "service-state.json",
                },
            )
            marker = json.loads(
                (fixture.state / "service-state.json").read_text(encoding="utf-8")
            )
            self.assertIn("audit_inode", marker)
            self.assertNotIn("audit_device", marker)
            self.assertIn("secret_bindings_sha256", marker)
            with self.assertRaises(ServiceConfigurationError):
                initialize_service(fixture.config_path)

    def test_marker_and_missing_state_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            fixture = ServiceFixture(Path(directory).resolve())
            fixture.initialize()
            marker = fixture.state / "service-state.json"
            marker.write_text("{}", encoding="utf-8")
            with self.assertRaises(ServiceConfigurationError):
                create_application(fixture.config_path)
            marker.unlink()
            with self.assertRaises(ServiceConfigurationError):
                create_application(fixture.config_path)

    def test_liveness_readiness_and_closed_route_surface(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            fixture = ServiceFixture(Path(directory).resolve())
            application = fixture.initialize()
            status, headers, body = invoke_wsgi(
                application, method="GET", path="/livez"
            )
            self.assertEqual(status, "200 OK")
            self.assertEqual(body["status"], "LIVE")
            self.assertFalse(body["live_actions_enabled"])
            self.assertEqual(headers["Cache-Control"], "no-store")
            status, _headers, body = invoke_wsgi(
                application, method="GET", path="/readyz"
            )
            self.assertEqual(status, "200 OK")
            self.assertEqual(body["status"], "READY")
            status, _headers, body = invoke_wsgi(
                application, method="GET", path="/v1/metrics"
            )
            self.assertEqual(status, "404 Not Found")
            self.assertEqual(body["error"]["code"], "NOT_FOUND")
            status, headers, _body = invoke_wsgi(
                application, method="POST", path="/livez"
            )
            self.assertEqual(status, "405 Method Not Allowed")
            self.assertEqual(headers["Allow"], "GET")

    def test_authentication_and_synthetic_markers_precede_processing(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            fixture = ServiceFixture(Path(directory).resolve())
            application = fixture.initialize()
            raw = fixture.workstation()
            status, headers, body = invoke_wsgi(
                application,
                method="POST",
                path="/v1/synthetic/requests",
                body=raw,
            )
            self.assertEqual(status, "401 Unauthorized")
            self.assertIn("Bearer", headers["WWW-Authenticate"])
            self.assertFalse(body["error"]["automatic_retry_permitted"])

            changed = json.loads(raw)
            changed["context"]["live_action"] = True
            status, _headers, body = invoke_wsgi(
                application,
                method="POST",
                path="/v1/synthetic/requests",
                body=request_json(changed).encode("utf-8"),
                authorization=f"Bearer {(b'U' * 43).decode('ascii')}",
            )
            self.assertEqual(status, "401 Unauthorized")
            self.assertEqual(body["error"]["code"], "AUTHENTICATION_REQUIRED")
            self.assertEqual(application.firewall._adapter_store.receipt_count(), 0)
            self.assertEqual(application.firewall.read_audit(), ())

            status, _headers, body = invoke_wsgi(
                application,
                method="POST",
                path="/v1/synthetic/requests",
                body=request_json(changed).encode("utf-8"),
                authorization=f"Bearer {BEARER.decode('ascii')}",
            )
            self.assertEqual(status, "422 Unprocessable Entity")
            self.assertEqual(body["error"]["code"], "SYNTHETIC_PROFILE_REQUIRED")
            self.assertEqual(application.firewall._adapter_store.receipt_count(), 0)

    def test_submission_and_lookup_return_only_sanitized_terminal_result(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            fixture = ServiceFixture(Path(directory).resolve())
            application = fixture.initialize()
            raw = fixture.workstation()
            authorization = f"Bearer {BEARER.decode('ascii')}"
            status, _headers, body = invoke_wsgi(
                application,
                method="POST",
                path="/v1/synthetic/requests",
                body=raw,
                authorization=authorization,
            )
            self.assertEqual(status, "200 OK")
            self.assertEqual(body["operation"], "SUBMIT_AND_LOOKUP")
            result = body["result"]
            self.assertTrue(result["replayed"])
            self.assertIsNone(result["authorization"])
            self.assertFalse(result["execution_attempted_this_call"])
            self.assertEqual(application.firewall._adapter_store.receipt_count(), 1)
            denied = {
                "authorization_token",
                "nonce",
                "signature",
                "credential",
                "secret",
                "token_id",
                "issuer_instance_id",
                "audit_records",
                "broker_result",
                "final_state",
                "permitted_action",
            }
            self.assertFalse(_contains_key(body, denied))

            status, _headers, duplicate = invoke_wsgi(
                application,
                method="POST",
                path="/v1/synthetic/requests",
                body=raw,
                authorization=authorization,
            )
            self.assertEqual(status, "200 OK")
            self.assertEqual(duplicate["result"], result)
            self.assertEqual(application.firewall._adapter_store.receipt_count(), 1)

            status, _headers, lookup = invoke_wsgi(
                application,
                method="POST",
                path="/v1/synthetic/request-results:lookup",
                body=raw,
                authorization=authorization,
            )
            self.assertEqual(status, "200 OK")
            self.assertEqual(lookup["operation"], "REQUEST_RESULT_LOOKUP")
            self.assertEqual(lookup["result"], result)

    def test_changed_request_binding_conflicts_without_prior_result(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            fixture = ServiceFixture(Path(directory).resolve())
            application = fixture.initialize()
            raw = fixture.workstation()
            authorization = f"Bearer {BEARER.decode('ascii')}"
            invoke_wsgi(
                application,
                method="POST",
                path="/v1/synthetic/requests",
                body=raw,
                authorization=authorization,
            )
            changed = json.loads(raw)
            changed["action"]["parameters"]["duration_seconds"] += 60
            status, _headers, body = invoke_wsgi(
                application,
                method="POST",
                path="/v1/synthetic/request-results:lookup",
                body=request_json(changed).encode("utf-8"),
                authorization=authorization,
            )
            self.assertEqual(status, "409 Conflict")
            self.assertEqual(body["error"]["code"], "REQUEST_ID_CONFLICT")
            self.assertNotIn("result", body)

    def test_nondurable_terminal_response_prohibits_automatic_retry(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            fixture = ServiceFixture(Path(directory).resolve())
            application = fixture.initialize()
            stale_at = datetime.now(timezone.utc).replace(microsecond=0) - timedelta(
                minutes=10
            )
            raw = request_json(
                workstation_request(
                    stale_at,
                    source_keys=SOURCE_KEYS,
                    request_id="SERVICE-STALE-NO-RETRY",
                )
            ).encode("utf-8")
            status, _headers, body = invoke_wsgi(
                application,
                method="POST",
                path="/v1/synthetic/requests",
                body=raw,
                authorization=f"Bearer {BEARER.decode('ascii')}",
            )
            self.assertEqual(status, "503 Service Unavailable")
            self.assertEqual(body["error"]["code"], "TERMINAL_RESULT_NOT_DURABLE")
            self.assertFalse(body["error"]["automatic_retry_permitted"])
            self.assertTrue(body["error"]["lookup_required"])
            self.assertEqual(application.firewall._adapter_store.receipt_count(), 0)

    def test_processing_exception_requires_lookup_and_never_permits_retry(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            fixture = ServiceFixture(Path(directory).resolve())
            application = fixture.initialize()
            with patch.object(
                application.firewall,
                "process_json",
                side_effect=ControlLedgerError(
                    "CONTROL_LEDGER_UNAVAILABLE", "must not escape"
                ),
            ):
                status, _headers, body = invoke_wsgi(
                    application,
                    method="POST",
                    path="/v1/synthetic/requests",
                    body=fixture.workstation(request_id="SERVICE-EXCEPTION-NO-RETRY"),
                    authorization=f"Bearer {BEARER.decode('ascii')}",
                )
            self.assertEqual(status, "503 Service Unavailable")
            self.assertEqual(body["error"]["code"], "CONTROL_LEDGER_UNAVAILABLE")
            self.assertFalse(body["error"]["automatic_retry_permitted"])
            self.assertTrue(body["error"]["lookup_required"])
            self.assertNotIn("must not escape", json.dumps(body))

    def test_config_change_and_secret_symlink_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            fixture = ServiceFixture(Path(directory).resolve())
            fixture.initialize()
            fixture.config["store_busy_timeout_ms"] = 2000
            fixture.write_config()
            with self.assertRaises(ServiceConfigurationError):
                create_application(fixture.config_path)

        with tempfile.TemporaryDirectory() as directory:
            fixture = ServiceFixture(Path(directory).resolve())
            real = fixture.secrets / "replacement.key"
            _write_private(real, b"R" * 64)
            fixture.signing.unlink()
            fixture.signing.symlink_to(real)
            with self.assertRaises(ServiceConfigurationError):
                initialize_service(fixture.config_path)

    def test_same_path_secret_substitution_fails_before_store_open(self) -> None:
        mutations = (
            ("signing", lambda fixture: fixture.signing, b"S" * 64),
            (
                "evidence",
                lambda fixture: Path(fixture.key_files["CMDB_PRIMARY"]),
                b"E" * 64,
            ),
            ("credential", lambda fixture: fixture.credential, b"D" * 43),
        )
        for label, select, replacement in mutations:
            with self.subTest(label=label), tempfile.TemporaryDirectory() as directory:
                fixture = ServiceFixture(Path(directory).resolve())
                fixture.initialize()
                target = select(fixture)
                target.write_bytes(replacement)
                target.chmod(0o600)
                with patch("adf_poc.service._construct_firewall") as construct:
                    with self.assertRaises(ServiceConfigurationError):
                        create_application(fixture.config_path)
                construct.assert_not_called()

    def test_secret_staging_is_create_once_and_owner_private(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            source = root / "projected"
            source.mkdir()
            secret = source / "signing.key"
            secret.write_bytes(b"S" * 64)
            secret.chmod(0o400)
            destination = root / "staged"
            self.assertEqual(
                stage_secret_directory(str(source), str(destination)),
                ("signing.key",),
            )
            self.assertEqual((destination / "signing.key").read_bytes(), b"S" * 64)
            self.assertEqual(
                os.stat(destination / "signing.key").st_mode & 0o777, 0o400
            )
            with self.assertRaises(ServiceConfigurationError):
                stage_secret_directory(str(source), str(destination))

    def test_reference_transport_rejects_nonloopback_and_multiworker(self) -> None:
        valid = Namespace(bind="127.0.0.1:8080", host=None, port=None, workers=1)
        self.assertEqual(_loopback_endpoint(valid), ("127.0.0.1", 8080))
        for candidate in (
            Namespace(bind="0.0.0.0:8080", host=None, port=None, workers=1),
            Namespace(bind="127.0.0.1:8080", host=None, port=None, workers=2),
            Namespace(bind="localhost:8080", host=None, port=None, workers=1),
        ):
            with self.subTest(candidate=candidate):
                with self.assertRaises(ServiceConfigurationError):
                    _loopback_endpoint(candidate)


if __name__ == "__main__":
    unittest.main()
