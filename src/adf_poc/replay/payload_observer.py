from __future__ import annotations

import builtins
import io
import os
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterator
from unittest.mock import patch


PYTHON_PAYLOAD_MONITOR_SCOPE = (
    "builtins.open",
    "io.open",
    "os.open",
    "pathlib.Path.open",
    "pathlib.Path.read_bytes",
    "pathlib.Path.read_text",
)

PYTHON_PAYLOAD_MONITOR_EXCLUSIONS = (
    "descriptors inherited or opened before observation",
    "pre-captured aliases of patched Python functions",
    "nested or concurrent code that replaces the patched APIs",
    "mmap or native-extension access through pre-existing descriptors",
    "dir_fd-relative aliases that are not a governed-path ancestor",
    "hard-link aliases to governed files",
    "direct syscalls outside the patched Python APIs",
    "subprocesses and other processes",
    "same-user access outside the observed process",
)


@dataclass(slots=True)
class PayloadAccessObservation:
    """Bounded Python-API observation; never evidence of OS-enforced nonaccess."""

    accessed_roles: set[str] = field(default_factory=set)
    monitor_scope: tuple[str, ...] = PYTHON_PAYLOAD_MONITOR_SCOPE
    monitor_exclusions: tuple[str, ...] = PYTHON_PAYLOAD_MONITOR_EXCLUSIONS
    assurance_class: str = "PYTHON_API_OBSERVED_ACCESS"


@contextmanager
def observe_python_payload_access(
    governed_paths: dict[Path, str],
) -> Iterator[PayloadAccessObservation]:
    """Observe named payload paths through an explicit set of Python file APIs.

    This is diagnostic campaign instrumentation. It is not a reference monitor,
    sandbox, syscall monitor, capability boundary, or proof of nonaccess.
    """

    governed = {path.resolve(): role for path, role in governed_paths.items()}
    observation = PayloadAccessObservation()
    original_builtin_open = builtins.open
    original_io_open = io.open
    original_os_open = os.open
    original_path_open = Path.open
    original_read_text = Path.read_text
    original_read_bytes = Path.read_bytes

    def observe(value: Any, *, dir_fd: int | None = None) -> None:
        try:
            filesystem_value = os.fspath(value)
            if isinstance(filesystem_value, bytes):
                filesystem_value = os.fsdecode(filesystem_value)
            candidate = Path(filesystem_value)
        except (TypeError, ValueError, OSError):
            return
        if dir_fd is not None and not candidate.is_absolute():
            try:
                descriptor_stat = os.fstat(dir_fd)
            except OSError:
                return
            normalized = Path(os.path.normpath(candidate))
            for governed_path, role in governed.items():
                for ancestor in governed_path.parents:
                    try:
                        ancestor_stat = ancestor.stat()
                    except OSError:
                        continue
                    if (
                        descriptor_stat.st_dev == ancestor_stat.st_dev
                        and descriptor_stat.st_ino == ancestor_stat.st_ino
                        and normalized == governed_path.relative_to(ancestor)
                    ):
                        observation.accessed_roles.add(role)
                        return
            return
        try:
            resolved = candidate.resolve()
        except (OSError, RuntimeError):
            return
        role = governed.get(resolved)
        if role is not None:
            observation.accessed_roles.add(role)

    def observed_builtin_open(file: Any, *args: Any, **kwargs: Any):
        observe(file)
        return original_builtin_open(file, *args, **kwargs)

    def observed_io_open(file: Any, *args: Any, **kwargs: Any):
        observe(file)
        return original_io_open(file, *args, **kwargs)

    def observed_os_open(path: Any, flags: int, *args: Any, **kwargs: Any) -> int:
        observe(path, dir_fd=kwargs.get("dir_fd"))
        return original_os_open(path, flags, *args, **kwargs)

    def observed_path_open(path: Path, *args: Any, **kwargs: Any):
        observe(path)
        return original_path_open(path, *args, **kwargs)

    def observed_read_text(path: Path, *args: Any, **kwargs: Any) -> str:
        observe(path)
        return original_read_text(path, *args, **kwargs)

    def observed_read_bytes(path: Path, *args: Any, **kwargs: Any) -> bytes:
        observe(path)
        return original_read_bytes(path, *args, **kwargs)

    with (
        patch.object(builtins, "open", new=observed_builtin_open),
        patch.object(io, "open", new=observed_io_open),
        patch.object(os, "open", new=observed_os_open),
        patch.object(
            os,
            "supports_dir_fd",
            new=set(os.supports_dir_fd) | {observed_os_open},
        ),
        patch.object(Path, "open", new=observed_path_open),
        patch.object(Path, "read_text", new=observed_read_text),
        patch.object(Path, "read_bytes", new=observed_read_bytes),
    ):
        yield observation


__all__ = [
    "PYTHON_PAYLOAD_MONITOR_EXCLUSIONS",
    "PYTHON_PAYLOAD_MONITOR_SCOPE",
    "PayloadAccessObservation",
    "observe_python_payload_access",
]
