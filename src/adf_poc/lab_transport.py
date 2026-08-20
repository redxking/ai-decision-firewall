from __future__ import annotations

import os
import re
import socket
import stat
import struct
import sys
from pathlib import Path
from typing import Callable

from adf_poc.lab_contracts import MAX_MESSAGE_BYTES


MAX_SOCKET_NAME_BYTES = 64
MAX_SOCKET_PATH_BYTES = 103
MAX_TIMEOUT_SECONDS = 30.0
SOCKET_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,62}\.sock$")


class LabTransportError(RuntimeError):
    """Fail-closed lab transport error with a stable reason code."""

    def __init__(self, reason_code: str, message: str) -> None:
        self.reason_code = reason_code
        self.code = reason_code
        self.message = message
        super().__init__(f"{reason_code}: {message}")


def _require_enabled(enabled: bool) -> None:
    if enabled is not True:
        raise LabTransportError(
            "LAB_TRANSPORT_NOT_ENABLED",
            "The isolated-lab transport requires an explicit true opt-in.",
        )


def _require_linux() -> None:
    if (
        sys.platform != "linux"
        or not hasattr(socket, "SOCK_SEQPACKET")
        or not hasattr(socket, "SO_PEERCRED")
    ):
        raise LabTransportError(
            "LAB_TRANSPORT_UNSUPPORTED",
            "The isolated-lab transport requires Linux SOCK_SEQPACKET and SO_PEERCRED.",
        )


def _require_uid(value: int, *, label: str) -> int:
    if type(value) is not int or value < 0 or value > 2**31 - 1:
        raise LabTransportError(
            "LAB_TRANSPORT_CONFIGURATION_INVALID",
            f"{label} must be a bounded exact integer UID.",
        )
    return value


def _require_timeout(value: float) -> float:
    if type(value) not in (int, float) or isinstance(value, bool):
        raise LabTransportError(
            "LAB_TRANSPORT_CONFIGURATION_INVALID",
            "Transport timeout must be a number.",
        )
    timeout = float(value)
    if not 0 < timeout <= MAX_TIMEOUT_SECONDS:
        raise LabTransportError(
            "LAB_TRANSPORT_CONFIGURATION_INVALID",
            "Transport timeout must be greater than zero and at most 30 seconds.",
        )
    return timeout


def _path_text(path: str | Path) -> Path:
    if not isinstance(path, (str, Path)):
        raise LabTransportError(
            "LAB_SOCKET_PATH_INVALID", "Socket path must be text or a Path."
        )
    value = Path(path)
    try:
        encoded = os.fsencode(value)
    except (TypeError, ValueError, UnicodeError) as exc:
        raise LabTransportError(
            "LAB_SOCKET_PATH_INVALID", "Socket path cannot be encoded safely."
        ) from exc
    if not value.is_absolute() or b"\x00" in encoded:
        raise LabTransportError(
            "LAB_SOCKET_PATH_INVALID", "Socket path must be absolute and NUL-free."
        )
    if len(encoded) > MAX_SOCKET_PATH_BYTES:
        raise LabTransportError(
            "LAB_SOCKET_PATH_INVALID",
            f"Socket path exceeds the {MAX_SOCKET_PATH_BYTES}-byte bound.",
        )
    name_bytes = os.fsencode(value.name)
    if (
        len(name_bytes) > MAX_SOCKET_NAME_BYTES
        or SOCKET_NAME.fullmatch(value.name) is None
    ):
        raise LabTransportError(
            "LAB_SOCKET_PATH_INVALID",
            "Socket leaf must be a bounded code-owned .sock name.",
        )
    return value


def validate_lab_socket_directory(
    directory: str | Path, *, expected_uid: int
) -> os.stat_result:
    """Validate the owner-private directory without repairing it."""

    owner_uid = _require_uid(expected_uid, label="Socket-directory owner")
    path = Path(directory)
    if not path.is_absolute():
        raise LabTransportError(
            "LAB_SOCKET_DIRECTORY_UNSAFE", "Socket directory must be absolute."
        )
    try:
        metadata = path.lstat()
    except OSError as exc:
        raise LabTransportError(
            "LAB_SOCKET_DIRECTORY_UNSAFE", "Socket directory is unavailable."
        ) from exc
    if path.is_symlink() or not stat.S_ISDIR(metadata.st_mode):
        raise LabTransportError(
            "LAB_SOCKET_DIRECTORY_UNSAFE",
            "Socket directory must be a non-symlink directory.",
        )
    if metadata.st_uid != owner_uid:
        raise LabTransportError(
            "LAB_SOCKET_DIRECTORY_UNSAFE", "Socket directory owner is unexpected."
        )
    if stat.S_IMODE(metadata.st_mode) != 0o700:
        raise LabTransportError(
            "LAB_SOCKET_DIRECTORY_UNSAFE",
            "Socket directory mode must be exactly 0700.",
        )
    return metadata


def _validate_socket_leaf(path: Path, *, expected_uid: int) -> os.stat_result:
    try:
        metadata = path.lstat()
    except OSError as exc:
        raise LabTransportError(
            "LAB_SOCKET_PATH_UNSAFE", "Socket endpoint is unavailable."
        ) from exc
    if (
        path.is_symlink()
        or not stat.S_ISSOCK(metadata.st_mode)
        or metadata.st_nlink != 1
        or metadata.st_uid != expected_uid
        or stat.S_IMODE(metadata.st_mode) != 0o600
    ):
        raise LabTransportError(
            "LAB_SOCKET_PATH_UNSAFE",
            "Socket endpoint must be an owner-private singly linked Unix socket.",
        )
    return metadata


def _same_identity(left: os.stat_result, right: os.stat_result) -> bool:
    return (left.st_dev, left.st_ino) == (right.st_dev, right.st_ino)


def _peer_credentials(connection: socket.socket) -> tuple[int, int, int]:
    try:
        raw = connection.getsockopt(
            socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i")
        )
        pid, uid, gid = struct.unpack("3i", raw)
    except (AttributeError, OSError, struct.error) as exc:
        raise LabTransportError(
            "LAB_PEER_CREDENTIALS_UNAVAILABLE",
            "Unix peer credentials could not be read.",
        ) from exc
    # Linux reports pid 0 when the peer process is outside the receiver's PID
    # namespace. UID and GID remain meaningful and the caller binds the exact
    # expected UID, so accept only that kernel sentinel in addition to a
    # positive PID.
    if pid < 0 or uid < 0 or gid < 0:
        raise LabTransportError(
            "LAB_PEER_CREDENTIALS_INVALID", "Unix peer credentials are invalid."
        )
    return pid, uid, gid


def _require_peer_uid(connection: socket.socket, expected_uid: int) -> None:
    _, observed_uid, _ = _peer_credentials(connection)
    if observed_uid != expected_uid:
        raise LabTransportError(
            "LAB_PEER_UID_MISMATCH", "Unix peer UID does not match configuration."
        )


def _receive_packet(connection: socket.socket) -> bytes:
    try:
        payload, _, flags, _ = connection.recvmsg(MAX_MESSAGE_BYTES + 1)
    except socket.timeout as exc:
        raise LabTransportError(
            "LAB_TRANSPORT_TIMEOUT", "Timed out while receiving a lab packet."
        ) from exc
    except OSError as exc:
        raise LabTransportError(
            "LAB_TRANSPORT_IO_ERROR", "Failed while receiving a lab packet."
        ) from exc
    if flags & getattr(socket, "MSG_TRUNC", 0) or len(payload) > MAX_MESSAGE_BYTES:
        raise LabTransportError(
            "LAB_PACKET_TOO_LARGE", "Lab packet exceeds the 16 KiB message bound."
        )
    if not payload:
        raise LabTransportError(
            "LAB_PEER_CLOSED", "Peer closed before sending one complete packet."
        )
    return payload


def _send_packet(connection: socket.socket, payload: bytes) -> None:
    if type(payload) is not bytes or not payload:
        raise LabTransportError(
            "LAB_PACKET_INVALID", "Lab packet must be a nonempty exact bytes value."
        )
    if len(payload) > MAX_MESSAGE_BYTES:
        raise LabTransportError(
            "LAB_PACKET_TOO_LARGE", "Lab packet exceeds the 16 KiB message bound."
        )
    try:
        sent = connection.send(payload)
    except socket.timeout as exc:
        raise LabTransportError(
            "LAB_TRANSPORT_TIMEOUT", "Timed out while sending a lab packet."
        ) from exc
    except OSError as exc:
        raise LabTransportError(
            "LAB_TRANSPORT_IO_ERROR", "Failed while sending a lab packet."
        ) from exc
    if sent != len(payload):
        raise LabTransportError(
            "LAB_PACKET_PARTIAL_WRITE",
            "The complete lab packet was not transmitted atomically.",
        )


class LabSeqpacketServer:
    """One-request-at-a-time Linux UDS transport; contains no action logic."""

    def __init__(
        self,
        socket_path: str | Path,
        *,
        expected_client_uid: int,
        enabled: bool,
        timeout_seconds: float = 2.0,
    ) -> None:
        _require_enabled(enabled)
        _require_linux()
        self.socket_path = _path_text(socket_path)
        self.owner_uid = os.geteuid()
        self.expected_client_uid = _require_uid(
            expected_client_uid, label="Expected client"
        )
        self.timeout_seconds = _require_timeout(timeout_seconds)
        self._directory_identity = validate_lab_socket_directory(
            self.socket_path.parent, expected_uid=self.owner_uid
        )
        self._socket_identity: os.stat_result | None = None
        self._listener: socket.socket | None = None

    def open(self) -> "LabSeqpacketServer":
        if self._listener is not None:
            raise LabTransportError(
                "LAB_TRANSPORT_STATE_INVALID", "Lab server is already open."
            )
        directory = validate_lab_socket_directory(
            self.socket_path.parent, expected_uid=self.owner_uid
        )
        if not _same_identity(directory, self._directory_identity):
            raise LabTransportError(
                "LAB_SOCKET_IDENTITY_CHANGED",
                "Socket directory identity changed before binding.",
            )
        try:
            self.socket_path.lstat()
        except FileNotFoundError:
            pass
        except OSError as exc:
            raise LabTransportError(
                "LAB_SOCKET_PATH_UNSAFE", "Socket path could not be inspected."
            ) from exc
        else:
            raise LabTransportError(
                "LAB_SOCKET_PATH_EXISTS",
                "Lab server never replaces an existing filesystem entry.",
            )

        self._socket_identity = None
        listener = socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET)
        listener.set_inheritable(False)
        listener.settimeout(self.timeout_seconds)
        try:
            listener.bind(os.fspath(self.socket_path))
            os.chmod(self.socket_path, 0o600, follow_symlinks=False)
            identity = _validate_socket_leaf(
                self.socket_path, expected_uid=self.owner_uid
            )
            self._socket_identity = identity
            listener.listen(1)
        except Exception:
            listener.close()
            self._unlink_if_owned()
            raise
        self._listener = listener
        return self

    def _revalidate(self) -> None:
        directory = validate_lab_socket_directory(
            self.socket_path.parent, expected_uid=self.owner_uid
        )
        endpoint = _validate_socket_leaf(self.socket_path, expected_uid=self.owner_uid)
        if not _same_identity(directory, self._directory_identity) or (
            self._socket_identity is not None
            and not _same_identity(endpoint, self._socket_identity)
        ):
            raise LabTransportError(
                "LAB_SOCKET_IDENTITY_CHANGED",
                "Socket directory or endpoint identity changed after binding.",
            )

    def serve_once(self, handler: Callable[[bytes], bytes]) -> None:
        if self._listener is None:
            raise LabTransportError(
                "LAB_TRANSPORT_STATE_INVALID", "Lab server is not open."
            )
        if not callable(handler):
            raise LabTransportError(
                "LAB_TRANSPORT_CONFIGURATION_INVALID", "Lab handler must be callable."
            )
        self._revalidate()
        try:
            connection, _ = self._listener.accept()
        except socket.timeout as exc:
            raise LabTransportError(
                "LAB_TRANSPORT_TIMEOUT", "Timed out waiting for a lab peer."
            ) from exc
        except OSError as exc:
            raise LabTransportError(
                "LAB_TRANSPORT_IO_ERROR", "Failed while accepting a lab peer."
            ) from exc
        with connection:
            connection.set_inheritable(False)
            connection.settimeout(self.timeout_seconds)
            _require_peer_uid(connection, self.expected_client_uid)
            request = _receive_packet(connection)
            response = handler(request)
            _send_packet(connection, response)

    def _unlink_if_owned(self) -> None:
        if self._socket_identity is None:
            return
        try:
            current = self.socket_path.lstat()
        except FileNotFoundError:
            return
        except OSError:
            return
        if _same_identity(current, self._socket_identity):
            try:
                self.socket_path.unlink()
            except OSError:
                return

    def close(self) -> None:
        listener, self._listener = self._listener, None
        if listener is not None:
            listener.close()
        self._unlink_if_owned()
        self._socket_identity = None

    def __enter__(self) -> "LabSeqpacketServer":
        return self.open()

    def __exit__(self, exc_type: object, exc: object, traceback: object) -> None:
        del exc_type, exc, traceback
        self.close()


def lab_seqpacket_exchange(
    socket_path: str | Path,
    request: bytes,
    *,
    expected_server_uid: int,
    enabled: bool,
    timeout_seconds: float = 2.0,
) -> bytes:
    """Exchange one bounded request/response packet with an exact-UID peer."""

    _require_enabled(enabled)
    _require_linux()
    path = _path_text(socket_path)
    server_uid = _require_uid(expected_server_uid, label="Expected server")
    timeout = _require_timeout(timeout_seconds)
    validate_lab_socket_directory(path.parent, expected_uid=server_uid)
    before = _validate_socket_leaf(path, expected_uid=server_uid)
    connection = socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET)
    connection.set_inheritable(False)
    connection.settimeout(timeout)
    try:
        connection.connect(os.fspath(path))
        after = _validate_socket_leaf(path, expected_uid=server_uid)
        if not _same_identity(before, after):
            raise LabTransportError(
                "LAB_SOCKET_IDENTITY_CHANGED",
                "Socket endpoint identity changed during connection.",
            )
        _require_peer_uid(connection, server_uid)
        _send_packet(connection, request)
        return _receive_packet(connection)
    except socket.timeout as exc:
        raise LabTransportError(
            "LAB_TRANSPORT_TIMEOUT", "Timed out connecting to the lab peer."
        ) from exc
    except LabTransportError:
        raise
    except OSError as exc:
        raise LabTransportError(
            "LAB_TRANSPORT_IO_ERROR", "Lab packet exchange failed."
        ) from exc
    finally:
        connection.close()
