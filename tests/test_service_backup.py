from __future__ import annotations

import hashlib
import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import adf_poc.service_backup as service_backup
from adf_poc.service import ServiceConfigurationError, create_application, invoke_wsgi
from adf_poc.service_backup import (
    BACKUP_MANIFEST,
    BACKUP_STATE_FILES,
    create_cold_backup,
    restore_cold_backup,
)
from tests.test_service import BEARER, SIGNING_KEY, ServiceFixture, _write_private


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


class ServiceBackupTests(unittest.TestCase):
    def _state_with_result(
        self, root: Path, *, request_id: str = "SERVICE-BACKUP-001"
    ) -> tuple[ServiceFixture, bytes]:
        fixture = ServiceFixture(root)
        application = fixture.initialize()
        raw = fixture.workstation(request_id=request_id)
        status, _headers, _body = invoke_wsgi(
            application,
            method="POST",
            path="/v1/synthetic/requests",
            body=raw,
            authorization=f"Bearer {BEARER.decode('ascii')}",
        )
        self.assertEqual(status, "200 OK")
        self.assertEqual(application.firewall._adapter_store.receipt_count(), 1)
        return fixture, raw

    def test_cold_backup_restore_preserves_exact_result_without_new_effect(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            fixture, raw = self._state_with_result(root)
            backup = root / "backup"
            created = create_cold_backup(
                fixture.config_path,
                backup,
                operator_asserted_quiesced=True,
            )
            self.assertEqual(created["status"], "BACKUP_CREATED")
            self.assertFalse(created["live_actions_enabled"])
            self.assertFalse(created["trusted_time_claimed"])
            self.assertEqual(
                {path.name for path in backup.iterdir()},
                {BACKUP_MANIFEST, *BACKUP_STATE_FILES},
            )
            self.assertEqual(backup.stat().st_mode & 0o777, 0o700)
            for name in {BACKUP_MANIFEST, *BACKUP_STATE_FILES}:
                self.assertEqual((backup / name).stat().st_mode & 0o777, 0o600)
            before = {name: _sha256(backup / name) for name in BACKUP_STATE_FILES}

            original = root / "original-state"
            fixture.state.rename(original)
            restored = restore_cold_backup(
                fixture.config_path,
                backup,
                expect_empty=True,
            )
            self.assertEqual(restored["status"], "BACKUP_RESTORED")
            self.assertEqual(
                before, {name: _sha256(backup / name) for name in BACKUP_STATE_FILES}
            )
            application = create_application(fixture.config_path)
            self.assertEqual(application.firewall._adapter_store.receipt_count(), 1)
            status, _headers, body = invoke_wsgi(
                application,
                method="POST",
                path="/v1/synthetic/requests",
                body=raw,
                authorization=f"Bearer {BEARER.decode('ascii')}",
            )
            self.assertEqual(status, "200 OK")
            self.assertTrue(body["result"]["replayed"])
            self.assertEqual(application.firewall._adapter_store.receipt_count(), 1)

    def test_backup_requires_assertion_new_external_destination_and_valid_state(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            fixture, _raw = self._state_with_result(root)
            with self.assertRaisesRegex(
                ServiceConfigurationError, "quiesced-service assertion"
            ):
                create_cold_backup(
                    fixture.config_path,
                    root / "not-created",
                    operator_asserted_quiesced=False,
                )
            existing = root / "existing"
            existing.mkdir(mode=0o700)
            with self.assertRaisesRegex(
                ServiceConfigurationError, "must not already exist"
            ):
                create_cold_backup(
                    fixture.config_path,
                    existing,
                    operator_asserted_quiesced=True,
                )
            with self.assertRaisesRegex(
                ServiceConfigurationError, "outside authoritative"
            ):
                create_cold_backup(
                    fixture.config_path,
                    fixture.state / "backup",
                    operator_asserted_quiesced=True,
                )
            audit = fixture.state / "audit.jsonl"
            audit.write_bytes(audit.read_bytes() + b"{\n")
            with self.assertRaisesRegex(
                ServiceConfigurationError, "startup preflight failed"
            ):
                create_cold_backup(
                    fixture.config_path,
                    root / "invalid-state-backup",
                    operator_asserted_quiesced=True,
                )

    def test_backup_copy_failure_never_publishes_partial_candidate(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            fixture, _raw = self._state_with_result(root)
            destination = root / "backup"
            original_copy = service_backup._copy_bound_file
            calls = 0

            def fail_second_copy(*args, **kwargs):
                nonlocal calls
                calls += 1
                if calls == 2:
                    raise ServiceConfigurationError("injected backup copy failure")
                return original_copy(*args, **kwargs)

            with (
                mock.patch.object(
                    service_backup, "_copy_bound_file", side_effect=fail_second_copy
                ),
                self.assertRaisesRegex(
                    ServiceConfigurationError, "injected backup copy failure"
                ),
            ):
                create_cold_backup(
                    fixture.config_path,
                    destination,
                    operator_asserted_quiesced=True,
                )
            self.assertFalse(destination.exists())
            self.assertEqual(
                [path.name for path in root.iterdir() if path.name.startswith(".adf-")],
                [],
            )

    def test_backup_refuses_active_sqlite_sidecar(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            fixture, _raw = self._state_with_result(root)
            sidecar = fixture.state / "control.sqlite3-shm"
            sidecar.write_bytes(b"active")
            sidecar.chmod(0o600)
            destination = root / "backup"
            with self.assertRaisesRegex(
                ServiceConfigurationError, "startup preflight failed"
            ):
                create_cold_backup(
                    fixture.config_path,
                    destination,
                    operator_asserted_quiesced=True,
                )
            self.assertFalse(destination.exists())

    def test_restore_rejects_artifact_mutation_and_retains_partial_state_closed(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            fixture, _raw = self._state_with_result(root)
            backup = root / "backup"
            create_cold_backup(
                fixture.config_path, backup, operator_asserted_quiesced=True
            )
            fixture.state.rename(root / "original-state")
            audit = backup / "audit.jsonl"
            audit.write_bytes(audit.read_bytes() + b"tamper\n")
            with self.assertRaisesRegex(ServiceConfigurationError, "digest is invalid"):
                restore_cold_backup(fixture.config_path, backup, expect_empty=True)
            self.assertTrue((fixture.state / "audit.jsonl").exists())
            self.assertFalse((fixture.state / "service-state.json").exists())
            with self.assertRaises(ServiceConfigurationError):
                create_application(fixture.config_path)

    def test_restore_rejects_manifest_shape_timestamp_and_extra_files(self) -> None:
        mutations = (
            (lambda value: {**value, "unknown": True}, "closed shape"),
            (lambda value: {**value, "created_at": "2026-08-20"}, "timestamp"),
        )
        for mutate, expected in mutations:
            with (
                self.subTest(expected=expected),
                tempfile.TemporaryDirectory() as directory,
            ):
                root = Path(directory).resolve()
                fixture, _raw = self._state_with_result(root)
                backup = root / "backup"
                create_cold_backup(
                    fixture.config_path, backup, operator_asserted_quiesced=True
                )
                fixture.state.rename(root / "original-state")
                manifest_path = backup / BACKUP_MANIFEST
                manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
                manifest_path.write_text(json.dumps(mutate(manifest)), encoding="utf-8")
                with self.assertRaisesRegex(ServiceConfigurationError, expected):
                    restore_cold_backup(fixture.config_path, backup, expect_empty=True)
                self.assertEqual(tuple(fixture.state.iterdir()), ())

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            fixture, _raw = self._state_with_result(root)
            backup = root / "backup"
            create_cold_backup(
                fixture.config_path, backup, operator_asserted_quiesced=True
            )
            fixture.state.rename(root / "original-state")
            (backup / "unexpected.txt").write_text("ambiguous\n", encoding="utf-8")
            (backup / "unexpected.txt").chmod(0o600)
            with self.assertRaisesRegex(ServiceConfigurationError, "file set"):
                restore_cold_backup(fixture.config_path, backup, expect_empty=True)
            self.assertEqual(tuple(fixture.state.iterdir()), ())

    def test_restore_rejects_changed_secret_binding_before_copy(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            fixture, _raw = self._state_with_result(root)
            backup = root / "backup"
            create_cold_backup(
                fixture.config_path, backup, operator_asserted_quiesced=True
            )
            fixture.state.rename(root / "original-state")
            _write_private(fixture.signing, b"different-signing-domain-" + b"D" * 40)
            with self.assertRaisesRegex(
                ServiceConfigurationError, "binding is invalid"
            ):
                restore_cold_backup(fixture.config_path, backup, expect_empty=True)
            self.assertEqual(tuple(fixture.state.iterdir()), ())
            _write_private(fixture.signing, SIGNING_KEY)

    def test_rehashed_mixed_recovery_point_fails_cross_store_validation(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            fixture, _raw = self._state_with_result(
                root, request_id="SERVICE-BACKUP-MIX-001"
            )
            first = root / "backup-first"
            create_cold_backup(
                fixture.config_path, first, operator_asserted_quiesced=True
            )
            application = create_application(fixture.config_path)
            status, _headers, _body = invoke_wsgi(
                application,
                method="POST",
                path="/v1/synthetic/requests",
                body=fixture.workstation(request_id="SERVICE-BACKUP-MIX-002"),
                authorization=f"Bearer {BEARER.decode('ascii')}",
            )
            self.assertEqual(status, "200 OK")
            self.assertEqual(application.firewall._adapter_store.receipt_count(), 2)
            second = root / "backup-second"
            create_cold_backup(
                fixture.config_path, second, operator_asserted_quiesced=True
            )

            adapter_name = "synthetic-adapter.sqlite3"
            mixed = (first / adapter_name).read_bytes()
            (second / adapter_name).write_bytes(mixed)
            (second / adapter_name).chmod(0o600)
            manifest_path = second / BACKUP_MANIFEST
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            manifest["files"][adapter_name] = {
                "sha256": hashlib.sha256(mixed).hexdigest(),
                "size": len(mixed),
            }
            manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
            manifest_path.chmod(0o600)
            fixture.state.rename(root / "original-state")

            with self.assertRaisesRegex(
                ServiceConfigurationError, "startup preflight failed"
            ):
                restore_cold_backup(fixture.config_path, second, expect_empty=True)
            self.assertFalse((fixture.state / "service-state.json").exists())
            with self.assertRaises(ServiceConfigurationError):
                create_application(fixture.config_path)

    def test_restore_refuses_existing_state_and_requires_explicit_empty_mode(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            fixture, _raw = self._state_with_result(root)
            backup = root / "backup"
            create_cold_backup(
                fixture.config_path, backup, operator_asserted_quiesced=True
            )
            with self.assertRaisesRegex(ServiceConfigurationError, "empty-state mode"):
                restore_cold_backup(fixture.config_path, backup, expect_empty=False)
            with self.assertRaisesRegex(
                ServiceConfigurationError, "empty state_directory"
            ):
                restore_cold_backup(fixture.config_path, backup, expect_empty=True)


if __name__ == "__main__":
    unittest.main()
