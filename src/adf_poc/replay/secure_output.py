from __future__ import annotations

import hashlib
import io
import json
import os
import stat
import threading
from pathlib import Path, PurePosixPath
from typing import Any, Iterable

from adf_poc.utils import canonical_json


MAX_SECURE_OUTPUT_BYTES = 512 * 1024 * 1024
MAX_SECURE_JSONL_LINE_BYTES = 1024 * 1024
MAX_SECURE_JSONL_RECORDS = 1_000_000


class HistoricalOutputError(RuntimeError):
    """Raised when historical output custody cannot be preserved."""


class HistoricalOutputGuard:
    """Descriptor-bound writer for one historical replay output directory.

    The guard opens each trusted directory without following its final symlink and
    retains the directory descriptors until ``close``. All artifact operations are
    relative to the retained run or ``input_snapshot`` descriptor. The public path
    is therefore presentation metadata, not an authority for file operations.
    """

    def __init__(
        self,
        *,
        repository_root: Path,
        run_name: str,
        root_fd: int,
        outputs_fd: int,
        replay_fd: int,
        run_fd: int,
        snapshot_fd: int,
        max_file_bytes: int,
    ) -> None:
        self._repository_root = repository_root
        self._run_name = run_name
        self._root_fd = root_fd
        self._outputs_fd = outputs_fd
        self._replay_fd = replay_fd
        self._run_fd = run_fd
        self._snapshot_fd = snapshot_fd
        self._max_file_bytes = max_file_bytes
        self._closed = False
        self._lock = threading.RLock()

    @classmethod
    def create(
        cls,
        repository_root: str | Path,
        output_dir: str | Path,
        *,
        max_file_bytes: int = MAX_SECURE_OUTPUT_BYTES,
    ) -> HistoricalOutputGuard:
        """Atomically create ``outputs/replay/<run>`` and bind all directory FDs.

        ``output_dir`` may be that exact repository-relative path or its exact
        absolute spelling beneath ``repository_root``. Existing parent directories
        are accepted only when they are real directories; missing ``outputs`` and
        ``replay`` parents are created owner-only. The run directory must not exist.
        """

        cls._require_platform_support()
        if isinstance(max_file_bytes, bool) or not isinstance(max_file_bytes, int):
            raise HistoricalOutputError("max_file_bytes must be an integer.")
        if not 0 < max_file_bytes <= MAX_SECURE_OUTPUT_BYTES:
            raise HistoricalOutputError(
                f"max_file_bytes must be between 1 and {MAX_SECURE_OUTPUT_BYTES}."
            )

        root_raw = os.fspath(repository_root)
        if not isinstance(root_raw, str) or not root_raw or "\x00" in root_raw:
            raise HistoricalOutputError("repository_root must be a valid path.")
        root_path = Path(os.path.abspath(root_raw))
        run_name = cls._validate_output_path(root_path, output_dir)

        opened: list[int] = []
        try:
            root_fd = cls._open_root(root_path)
            opened.append(root_fd)
            outputs_fd = cls._open_or_create_directory(root_fd, "outputs")
            opened.append(outputs_fd)
            replay_fd = cls._open_or_create_directory(outputs_fd, "replay")
            opened.append(replay_fd)
            run_fd = cls._create_directory(replay_fd, run_name)
            opened.append(run_fd)
            snapshot_fd = cls._create_directory(run_fd, "input_snapshot")
            opened.append(snapshot_fd)
            guard = cls(
                repository_root=root_path,
                run_name=run_name,
                root_fd=root_fd,
                outputs_fd=outputs_fd,
                replay_fd=replay_fd,
                run_fd=run_fd,
                snapshot_fd=snapshot_fd,
                max_file_bytes=max_file_bytes,
            )
            guard.verify_bindings()
            return guard
        except Exception:
            for descriptor in reversed(opened):
                try:
                    os.close(descriptor)
                except OSError:
                    pass
            raise

    @property
    def display_path(self) -> Path:
        """Return the untrusted display path; callers must not use it for I/O."""

        return self._repository_root / "outputs" / "replay" / self._run_name

    def display_path_for(self, relative_path: str | Path) -> Path:
        """Return an untrusted display path for a validated artifact name."""

        _, _, normalized = self._select_parent(relative_path)
        return self.display_path / normalized

    def verify_bindings(self) -> None:
        """Fail unless every retained descriptor still has its bound parent name."""

        with self._lock:
            self._assert_open()
            self._verify_bindings_locked()

    def write_bytes(
        self,
        relative_path: str | Path,
        content: bytes,
        *,
        max_bytes: int | None = None,
    ) -> Path:
        if not isinstance(content, bytes):
            raise HistoricalOutputError("Secure output content must be bytes.")
        limit = self._validated_limit(max_bytes)
        if len(content) > limit:
            raise HistoricalOutputError(
                f"Secure output exceeds its {limit}-byte write limit."
            )
        with self._lock:
            self._verify_bindings_locked()
            parent_fd, name, normalized = self._select_parent(relative_path)
            file_fd, identity = self._create_file(parent_fd, name)
            try:
                self._write_all(file_fd, content)
                self._finish_write(file_fd, len(content))
                self._verify_bindings_locked()
            except Exception:
                os.close(file_fd)
                self._unlink_if_same(parent_fd, name, identity)
                raise
            os.close(file_fd)
            return self.display_path / normalized

    def write_json(
        self,
        relative_path: str | Path,
        value: Any,
        *,
        max_bytes: int | None = None,
    ) -> Path:
        content = json.dumps(value, indent=2, sort_keys=True).encode("utf-8")
        return self.write_bytes(relative_path, content, max_bytes=max_bytes)

    def write_jsonl(
        self,
        relative_path: str | Path,
        rows: Iterable[dict[str, Any]],
        *,
        max_bytes: int | None = None,
        max_records: int = MAX_SECURE_JSONL_RECORDS,
    ) -> int:
        if isinstance(max_records, bool) or not isinstance(max_records, int):
            raise HistoricalOutputError("max_records must be an integer.")
        if not 0 < max_records <= MAX_SECURE_JSONL_RECORDS:
            raise HistoricalOutputError(
                f"max_records must be between 1 and {MAX_SECURE_JSONL_RECORDS}."
            )
        limit = self._validated_limit(max_bytes)
        with self._lock:
            self._verify_bindings_locked()
            parent_fd, name, _ = self._select_parent(relative_path)
            file_fd, identity = self._create_file(parent_fd, name)
            total = 0
            count = 0
            try:
                for row in rows:
                    if count >= max_records:
                        raise HistoricalOutputError(
                            f"Secure JSONL output exceeds {max_records} records."
                        )
                    if not isinstance(row, dict):
                        raise HistoricalOutputError(
                            "Secure JSONL output records must be objects."
                        )
                    payload = (canonical_json(row) + "\n").encode("utf-8")
                    if len(payload) > MAX_SECURE_JSONL_LINE_BYTES + 1:
                        raise HistoricalOutputError(
                            "Secure JSONL output contains an oversized record."
                        )
                    total += len(payload)
                    if total > limit:
                        raise HistoricalOutputError(
                            f"Secure output exceeds its {limit}-byte write limit."
                        )
                    self._write_all(file_fd, payload)
                    count += 1
                self._finish_write(file_fd, total)
                self._verify_bindings_locked()
            except Exception:
                os.close(file_fd)
                self._unlink_if_same(parent_fd, name, identity)
                raise
            os.close(file_fd)
            return count

    def read_bytes(
        self,
        relative_path: str | Path,
        *,
        max_bytes: int | None = None,
    ) -> bytes:
        limit = self._validated_limit(max_bytes)
        with self._lock:
            self._verify_bindings_locked()
            parent_fd, name, _ = self._select_parent(relative_path)
            file_fd, before = self._open_file_for_read(parent_fd, name, limit)
            try:
                chunks: list[bytes] = []
                total = 0
                while True:
                    chunk = os.read(file_fd, min(1024 * 1024, limit - total + 1))
                    if not chunk:
                        break
                    total += len(chunk)
                    if total > limit:
                        raise HistoricalOutputError(
                            f"Secure output exceeds its {limit}-byte read limit."
                        )
                    chunks.append(chunk)
                self._assert_unchanged(file_fd, before)
                self._verify_bindings_locked()
                return b"".join(chunks)
            finally:
                os.close(file_fd)

    def read_json(
        self,
        relative_path: str | Path,
        *,
        max_bytes: int | None = None,
    ) -> Any:
        try:
            return json.loads(
                self.read_bytes(relative_path, max_bytes=max_bytes).decode("utf-8")
            )
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise HistoricalOutputError("Secure JSON output is invalid.") from exc

    def read_jsonl(
        self,
        relative_path: str | Path,
        *,
        max_bytes: int | None = None,
        max_records: int = MAX_SECURE_JSONL_RECORDS,
        max_line_bytes: int = MAX_SECURE_JSONL_LINE_BYTES,
    ) -> list[dict[str, Any]]:
        self._validate_jsonl_bounds(max_records, max_line_bytes)
        content = self.read_bytes(relative_path, max_bytes=max_bytes)
        rows: list[dict[str, Any]] = []
        stream = io.BytesIO(content)
        try:
            while True:
                raw = stream.readline(max_line_bytes + 2)
                if not raw:
                    break
                if len(raw) > max_line_bytes + 1 or (
                    len(raw) > max_line_bytes and not raw.endswith(b"\n")
                ):
                    raise HistoricalOutputError(
                        "Secure JSONL output contains an oversized line."
                    )
                payload = raw.strip()
                if not payload:
                    continue
                if len(rows) >= max_records:
                    raise HistoricalOutputError(
                        f"Secure JSONL output exceeds {max_records} records."
                    )
                value = json.loads(payload.decode("utf-8"))
                if not isinstance(value, dict):
                    raise HistoricalOutputError(
                        "Secure JSONL output contains a non-object record."
                    )
                rows.append(value)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise HistoricalOutputError("Secure JSONL output is invalid.") from exc
        return rows

    def sha256(
        self,
        relative_path: str | Path,
        *,
        max_bytes: int | None = None,
    ) -> str:
        limit = self._validated_limit(max_bytes)
        with self._lock:
            self._verify_bindings_locked()
            parent_fd, name, _ = self._select_parent(relative_path)
            file_fd, before = self._open_file_for_read(parent_fd, name, limit)
            try:
                digest = hashlib.sha256()
                total = 0
                while True:
                    chunk = os.read(file_fd, 1024 * 1024)
                    if not chunk:
                        break
                    total += len(chunk)
                    if total > limit:
                        raise HistoricalOutputError(
                            f"Secure output exceeds its {limit}-byte digest limit."
                        )
                    digest.update(chunk)
                self._assert_unchanged(file_fd, before)
                self._verify_bindings_locked()
                return digest.hexdigest()
            finally:
                os.close(file_fd)

    def count_nonblank_lines(
        self,
        relative_path: str | Path,
        *,
        max_bytes: int | None = None,
        max_lines: int = MAX_SECURE_JSONL_RECORDS,
    ) -> int:
        if isinstance(max_lines, bool) or not isinstance(max_lines, int):
            raise HistoricalOutputError("max_lines must be an integer.")
        if not 0 < max_lines <= MAX_SECURE_JSONL_RECORDS:
            raise HistoricalOutputError(
                f"max_lines must be between 1 and {MAX_SECURE_JSONL_RECORDS}."
            )
        content = self.read_bytes(relative_path, max_bytes=max_bytes)
        count = 0
        for line in io.BytesIO(content):
            if line.strip():
                count += 1
                if count > max_lines:
                    raise HistoricalOutputError(
                        f"Secure output exceeds {max_lines} nonblank lines."
                    )
        return count

    def close(self) -> None:
        with self._lock:
            if self._closed:
                return
            self._closed = True
            for descriptor in (
                self._snapshot_fd,
                self._run_fd,
                self._replay_fd,
                self._outputs_fd,
                self._root_fd,
            ):
                try:
                    os.close(descriptor)
                except OSError:
                    pass

    def __enter__(self) -> HistoricalOutputGuard:
        with self._lock:
            self._assert_open()
        return self

    def __exit__(self, exc_type: Any, exc: Any, traceback: Any) -> None:
        self.close()

    @classmethod
    def _require_platform_support(cls) -> None:
        required_constants = ("O_DIRECTORY", "O_NOFOLLOW")
        if any(not hasattr(os, name) for name in required_constants):
            raise HistoricalOutputError(
                "This platform lacks required descriptor-bound filesystem controls."
            )
        required_dir_fd = (os.open, os.mkdir, os.stat, os.unlink)
        if any(operation not in os.supports_dir_fd for operation in required_dir_fd):
            raise HistoricalOutputError(
                "This platform lacks required dir_fd filesystem controls."
            )

    @classmethod
    def _validate_output_path(cls, root: Path, output_dir: str | Path) -> str:
        raw = os.fspath(output_dir)
        if not isinstance(raw, str) or not raw or "\x00" in raw:
            raise HistoricalOutputError("output_dir must be a valid path.")

        candidate = Path(raw)
        if candidate.is_absolute():
            try:
                relative = candidate.relative_to(root)
            except ValueError as exc:
                raise HistoricalOutputError(
                    "Historical output must be beneath the repository root."
                ) from exc
            if raw != os.fspath(root / relative):
                raise HistoricalOutputError(
                    "Historical output must use a canonical absolute path."
                )
            relative_raw = relative.as_posix()
        else:
            relative_raw = raw
            if raw != PurePosixPath(raw).as_posix():
                raise HistoricalOutputError(
                    "Historical output must use a canonical relative path."
                )

        parts = relative_raw.split("/")
        if len(parts) != 3 or parts[:2] != ["outputs", "replay"]:
            raise HistoricalOutputError(
                "Historical output must be exactly outputs/replay/<run-name>."
            )
        run_name = parts[2]
        if run_name in {"", ".", ".."} or "/" in run_name:
            raise HistoricalOutputError("Historical run name must be one component.")
        if len(os.fsencode(run_name)) > 255:
            raise HistoricalOutputError("Historical run name exceeds 255 bytes.")
        return run_name

    @classmethod
    def _directory_open_flags(cls) -> int:
        return (
            os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)
        )

    @classmethod
    def _open_root(cls, root: Path) -> int:
        try:
            descriptor = os.open(root, cls._directory_open_flags())
        except OSError as exc:
            raise HistoricalOutputError(
                "Repository root is missing, linked, or not a directory."
            ) from exc
        metadata = os.fstat(descriptor)
        if not stat.S_ISDIR(metadata.st_mode):
            os.close(descriptor)
            raise HistoricalOutputError("Repository root is not a directory.")
        return descriptor

    @classmethod
    def _open_or_create_directory(cls, parent_fd: int, name: str) -> int:
        created = False
        try:
            os.mkdir(name, 0o700, dir_fd=parent_fd)
            created = True
        except FileExistsError:
            pass
        except OSError as exc:
            raise HistoricalOutputError(
                "Historical output parent could not be created."
            ) from exc
        descriptor = cls._open_bound_directory(parent_fd, name)
        try:
            if created:
                os.fchmod(descriptor, 0o700)
                cls._require_mode(descriptor, 0o700, "Historical output parent")
        except Exception:
            os.close(descriptor)
            raise
        return descriptor

    @classmethod
    def _create_directory(cls, parent_fd: int, name: str) -> int:
        try:
            os.mkdir(name, 0o700, dir_fd=parent_fd)
        except FileExistsError as exc:
            raise HistoricalOutputError(
                "Historical output directory already exists."
            ) from exc
        except OSError as exc:
            raise HistoricalOutputError(
                "Historical output directory could not be created."
            ) from exc
        descriptor = cls._open_bound_directory(parent_fd, name)
        try:
            os.fchmod(descriptor, 0o700)
            cls._require_mode(descriptor, 0o700, "Historical output directory")
        except Exception:
            os.close(descriptor)
            raise
        return descriptor

    @classmethod
    def _open_bound_directory(cls, parent_fd: int, name: str) -> int:
        try:
            before = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
            if not stat.S_ISDIR(before.st_mode):
                raise HistoricalOutputError(
                    "Historical output path is linked or not a directory."
                )
            descriptor = os.open(name, cls._directory_open_flags(), dir_fd=parent_fd)
        except HistoricalOutputError:
            raise
        except OSError as exc:
            raise HistoricalOutputError(
                "Historical output path is linked, missing, or not a directory."
            ) from exc
        after = os.fstat(descriptor)
        if not stat.S_ISDIR(after.st_mode) or not os.path.samestat(before, after):
            os.close(descriptor)
            raise HistoricalOutputError(
                "Historical output directory changed while it was being bound."
            )
        return descriptor

    @staticmethod
    def _require_mode(descriptor: int, expected: int, label: str) -> None:
        actual = stat.S_IMODE(os.fstat(descriptor).st_mode)
        if actual != expected:
            raise HistoricalOutputError(
                f"{label} does not have required owner-only permissions."
            )

    def _select_parent(self, relative_path: str | Path) -> tuple[int, str, str]:
        self._assert_open()
        raw = os.fspath(relative_path)
        if not isinstance(raw, str) or not raw or "\x00" in raw:
            raise HistoricalOutputError("Artifact path must be a valid relative path.")
        if raw != PurePosixPath(raw).as_posix():
            raise HistoricalOutputError("Artifact path must use canonical spelling.")
        parts = raw.split("/")
        if len(parts) == 1:
            parent_fd = self._run_fd
        elif len(parts) == 2 and parts[0] == "input_snapshot":
            parent_fd = self._snapshot_fd
        else:
            raise HistoricalOutputError(
                "Artifact path must be flat or input_snapshot/<file>."
            )
        name = parts[-1]
        if name in {"", ".", ".."} or len(os.fsencode(name)) > 255:
            raise HistoricalOutputError("Artifact name is not a safe component.")
        return parent_fd, name, raw

    def _validated_limit(self, requested: int | None) -> int:
        if requested is None:
            return self._max_file_bytes
        if isinstance(requested, bool) or not isinstance(requested, int):
            raise HistoricalOutputError("max_bytes must be an integer.")
        if not 0 < requested <= self._max_file_bytes:
            raise HistoricalOutputError(
                f"max_bytes must be between 1 and {self._max_file_bytes}."
            )
        return requested

    @staticmethod
    def _validate_jsonl_bounds(max_records: int, max_line_bytes: int) -> None:
        if (
            isinstance(max_records, bool)
            or not isinstance(max_records, int)
            or not 0 < max_records <= MAX_SECURE_JSONL_RECORDS
        ):
            raise HistoricalOutputError("max_records is outside its safe range.")
        if (
            isinstance(max_line_bytes, bool)
            or not isinstance(max_line_bytes, int)
            or not 0 < max_line_bytes <= MAX_SECURE_JSONL_LINE_BYTES
        ):
            raise HistoricalOutputError("max_line_bytes is outside its safe range.")

    def _create_file(self, parent_fd: int, name: str) -> tuple[int, tuple[int, int]]:
        flags = (
            os.O_WRONLY
            | os.O_CREAT
            | os.O_EXCL
            | os.O_NOFOLLOW
            | getattr(os, "O_CLOEXEC", 0)
        )
        try:
            descriptor = os.open(name, flags, 0o600, dir_fd=parent_fd)
        except OSError as exc:
            raise HistoricalOutputError(
                "Secure output file already exists or cannot be created."
            ) from exc
        identity: tuple[int, int] | None = None
        try:
            metadata = os.fstat(descriptor)
            identity = (metadata.st_dev, metadata.st_ino)
            if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
                raise HistoricalOutputError(
                    "Secure output target is not a private file."
                )
            os.fchmod(descriptor, 0o600)
            self._require_mode(descriptor, 0o600, "Secure output file")
            return descriptor, identity
        except Exception:
            os.close(descriptor)
            try:
                current = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
                if (
                    identity is not None
                    and (
                        current.st_dev,
                        current.st_ino,
                    )
                    == identity
                ):
                    os.unlink(name, dir_fd=parent_fd)
            except OSError:
                pass
            raise

    @classmethod
    def _open_file_for_read(
        cls, parent_fd: int, name: str, limit: int
    ) -> tuple[int, os.stat_result]:
        flags = os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)
        try:
            descriptor = os.open(name, flags, dir_fd=parent_fd)
        except OSError as exc:
            raise HistoricalOutputError(
                "Secure output file is missing, linked, or unreadable."
            ) from exc
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_nlink != 1
            or metadata.st_size > limit
        ):
            os.close(descriptor)
            raise HistoricalOutputError(
                "Secure output file violates type, link, or size constraints."
            )
        return descriptor, metadata

    @staticmethod
    def _write_all(descriptor: int, content: bytes) -> None:
        try:
            view = memoryview(content)
            offset = 0
            while offset < len(view):
                written = os.write(descriptor, view[offset:])
                if written <= 0:
                    raise HistoricalOutputError("Secure output write did not complete.")
                offset += written
        except HistoricalOutputError:
            raise
        except OSError as exc:
            raise HistoricalOutputError("Secure output write failed.") from exc

    @classmethod
    def _finish_write(cls, descriptor: int, expected_size: int) -> None:
        try:
            os.fsync(descriptor)
            metadata = os.fstat(descriptor)
        except OSError as exc:
            raise HistoricalOutputError(
                "Secure output could not be finalized."
            ) from exc
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_nlink != 1
            or metadata.st_size != expected_size
        ):
            raise HistoricalOutputError(
                "Secure output changed while it was being written."
            )
        cls._require_mode(descriptor, 0o600, "Secure output file")

    @staticmethod
    def _assert_unchanged(descriptor: int, before: os.stat_result) -> None:
        try:
            after = os.fstat(descriptor)
        except OSError as exc:
            raise HistoricalOutputError(
                "Secure output identity could not be revalidated."
            ) from exc
        stable_fields = (
            "st_dev",
            "st_ino",
            "st_size",
            "st_mtime_ns",
            "st_ctime_ns",
            "st_nlink",
        )
        if any(
            getattr(before, field) != getattr(after, field) for field in stable_fields
        ):
            raise HistoricalOutputError("Secure output changed while it was read.")

    @staticmethod
    def _unlink_if_same(parent_fd: int, name: str, identity: tuple[int, int]) -> None:
        try:
            current = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
            if (current.st_dev, current.st_ino) == identity:
                os.unlink(name, dir_fd=parent_fd)
        except OSError:
            pass

    def _assert_open(self) -> None:
        if self._closed:
            raise HistoricalOutputError("Historical output guard is closed.")

    def _verify_bindings_locked(self) -> None:
        self._assert_open()
        bindings = (
            (self._root_fd, "outputs", self._outputs_fd),
            (self._outputs_fd, "replay", self._replay_fd),
            (self._replay_fd, self._run_name, self._run_fd),
            (self._run_fd, "input_snapshot", self._snapshot_fd),
        )
        try:
            for parent_fd, name, child_fd in bindings:
                named = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
                bound = os.fstat(child_fd)
                if (
                    not stat.S_ISDIR(named.st_mode)
                    or not stat.S_ISDIR(bound.st_mode)
                    or not os.path.samestat(named, bound)
                ):
                    raise HistoricalOutputError(
                        "Historical output directory binding has changed."
                    )
            self._require_mode(self._run_fd, 0o700, "Historical output directory")
            self._require_mode(
                self._snapshot_fd, 0o700, "Historical snapshot directory"
            )
        except HistoricalOutputError:
            raise
        except OSError as exc:
            raise HistoricalOutputError(
                "Historical output directory binding cannot be verified."
            ) from exc
