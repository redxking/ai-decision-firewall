from __future__ import annotations

import os
import queue
import socket
import stat
import sys
import tempfile
import threading
import unittest
from pathlib import Path

from adf_poc.lab_contracts import MAX_MESSAGE_BYTES
from adf_poc.lab_transport import (
    LabSeqpacketServer,
    LabTransportError,
    lab_seqpacket_exchange,
    validate_lab_socket_directory,
)


LINUX_TRANSPORT = (
    sys.platform == "linux"
    and hasattr(socket, "SOCK_SEQPACKET")
    and hasattr(socket, "SO_PEERCRED")
)


class LabTransportPortableSafetyTests(unittest.TestCase):
    def test_transport_requires_explicit_true_opt_in_before_platform_use(self) -> None:
        with self.assertRaises(LabTransportError) as raised:
            LabSeqpacketServer(
                "/tmp/adf-lab-test.sock",
                expected_client_uid=os.geteuid(),
                enabled=False,
            )
        self.assertEqual(raised.exception.reason_code, "LAB_TRANSPORT_NOT_ENABLED")

    def test_owner_private_directory_is_accepted_without_mutation(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            root.chmod(0o700)
            before = root.stat()
            observed = validate_lab_socket_directory(root, expected_uid=os.geteuid())
            after = root.stat()
            self.assertEqual(
                (observed.st_dev, observed.st_ino), (before.st_dev, before.st_ino)
            )
            self.assertEqual(stat.S_IMODE(after.st_mode), 0o700)

    def test_directory_symlink_permissions_and_owner_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            private = root / "private"
            private.mkdir(mode=0o700)
            link = root / "link"
            link.symlink_to(private, target_is_directory=True)

            private.chmod(0o750)
            with self.assertRaises(LabTransportError) as raised:
                validate_lab_socket_directory(private, expected_uid=os.geteuid())
            self.assertEqual(
                raised.exception.reason_code, "LAB_SOCKET_DIRECTORY_UNSAFE"
            )

            private.chmod(0o700)
            for path, uid, label in (
                (link, os.geteuid(), "symlink"),
                (private, os.geteuid() + 1, "owner"),
            ):
                with (
                    self.subTest(label=label),
                    self.assertRaises(LabTransportError) as raised,
                ):
                    validate_lab_socket_directory(path, expected_uid=uid)
                self.assertEqual(
                    raised.exception.reason_code, "LAB_SOCKET_DIRECTORY_UNSAFE"
                )


@unittest.skipUnless(LINUX_TRANSPORT, "requires Linux SOCK_SEQPACKET/SO_PEERCRED")
class LabTransportLinuxIntegrationTests(unittest.TestCase):
    def _root(self, parent: str) -> Path:
        root = Path(parent) / "ipc"
        root.mkdir(mode=0o700)
        return root

    def _serve_in_thread(
        self, server: LabSeqpacketServer, handler
    ) -> tuple[threading.Thread, queue.Queue[BaseException | None]]:
        result: queue.Queue[BaseException | None] = queue.Queue()

        def run() -> None:
            try:
                server.serve_once(handler)
            except Exception as exc:  # captured for exact test assertion
                result.put(exc)
            else:
                result.put(None)

        thread = threading.Thread(target=run, daemon=True)
        thread.start()
        return thread, result

    def test_real_seqpacket_exchange_binds_peer_uid_and_one_packet(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = self._root(directory) / "executor.sock"
            with LabSeqpacketServer(
                path,
                expected_client_uid=os.geteuid(),
                enabled=True,
                timeout_seconds=2,
            ) as server:
                self.assertTrue(stat.S_ISSOCK(path.lstat().st_mode))
                self.assertEqual(stat.S_IMODE(path.lstat().st_mode), 0o600)
                thread, result = self._serve_in_thread(
                    server, lambda request: b"receipt:" + request
                )
                response = lab_seqpacket_exchange(
                    path,
                    b"command",
                    expected_server_uid=os.geteuid(),
                    enabled=True,
                    timeout_seconds=2,
                )
                thread.join(3)
                self.assertFalse(thread.is_alive())
                self.assertIsNone(result.get_nowait())
                self.assertEqual(response, b"receipt:command")
            self.assertFalse(path.exists())

    def test_wrong_client_uid_is_rejected_before_request_read(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = self._root(directory) / "executor.sock"
            with LabSeqpacketServer(
                path,
                expected_client_uid=os.geteuid() + 1,
                enabled=True,
                timeout_seconds=2,
            ) as server:
                called = False

                def handler(_: bytes) -> bytes:
                    nonlocal called
                    called = True
                    return b"unexpected"

                thread, result = self._serve_in_thread(server, handler)
                with self.assertRaises(LabTransportError):
                    lab_seqpacket_exchange(
                        path,
                        b"command",
                        expected_server_uid=os.geteuid(),
                        enabled=True,
                        timeout_seconds=2,
                    )
                thread.join(3)
                error = result.get_nowait()
                self.assertIsInstance(error, LabTransportError)
                self.assertEqual(error.reason_code, "LAB_PEER_UID_MISMATCH")
                self.assertFalse(called)

    def test_existing_leaf_is_never_replaced(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = self._root(directory) / "executor.sock"
            path.write_bytes(b"do-not-replace")
            before = path.read_bytes()
            server = LabSeqpacketServer(
                path,
                expected_client_uid=os.geteuid(),
                enabled=True,
            )
            with self.assertRaises(LabTransportError) as raised:
                server.open()
            self.assertEqual(raised.exception.reason_code, "LAB_SOCKET_PATH_EXISTS")
            self.assertEqual(path.read_bytes(), before)

    def test_endpoint_replacement_fails_and_cleanup_preserves_replacement(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = self._root(directory) / "executor.sock"
            server = LabSeqpacketServer(
                path,
                expected_client_uid=os.geteuid(),
                enabled=True,
            ).open()
            path.unlink()
            path.write_bytes(b"replacement")
            try:
                with self.assertRaises(LabTransportError) as raised:
                    server.serve_once(lambda _: b"response")
                self.assertIn(
                    raised.exception.reason_code,
                    {"LAB_SOCKET_PATH_UNSAFE", "LAB_SOCKET_IDENTITY_CHANGED"},
                )
            finally:
                server.close()
            self.assertEqual(path.read_bytes(), b"replacement")

    def test_accept_timeout_is_bounded(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = self._root(directory) / "executor.sock"
            with LabSeqpacketServer(
                path,
                expected_client_uid=os.geteuid(),
                enabled=True,
                timeout_seconds=0.05,
            ) as server:
                with self.assertRaises(LabTransportError) as raised:
                    server.serve_once(lambda _: b"response")
                self.assertEqual(raised.exception.reason_code, "LAB_TRANSPORT_TIMEOUT")

    def test_peer_close_before_packet_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = self._root(directory) / "executor.sock"
            with LabSeqpacketServer(
                path,
                expected_client_uid=os.geteuid(),
                enabled=True,
                timeout_seconds=2,
            ) as server:
                thread, result = self._serve_in_thread(server, lambda _: b"unexpected")
                client = socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET)
                client.connect(os.fspath(path))
                client.close()
                thread.join(3)
                error = result.get_nowait()
                self.assertIsInstance(error, LabTransportError)
                self.assertEqual(error.reason_code, "LAB_PEER_CLOSED")

    def test_oversize_request_is_rejected_without_handler_use(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = self._root(directory) / "executor.sock"
            with LabSeqpacketServer(
                path,
                expected_client_uid=os.geteuid(),
                enabled=True,
                timeout_seconds=2,
            ) as server:
                called = False

                def handler(_: bytes) -> bytes:
                    nonlocal called
                    called = True
                    return b"unexpected"

                thread, result = self._serve_in_thread(server, handler)
                with self.assertRaises(LabTransportError) as raised:
                    lab_seqpacket_exchange(
                        path,
                        b"x" * (MAX_MESSAGE_BYTES + 1),
                        expected_server_uid=os.geteuid(),
                        enabled=True,
                        timeout_seconds=2,
                    )
                self.assertEqual(raised.exception.reason_code, "LAB_PACKET_TOO_LARGE")
                thread.join(3)
                error = result.get_nowait()
                self.assertIsInstance(error, LabTransportError)
                self.assertEqual(error.reason_code, "LAB_PEER_CLOSED")
                self.assertFalse(called)


if __name__ == "__main__":
    unittest.main()
