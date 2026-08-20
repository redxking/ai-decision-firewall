"""Copy projected secret files into an owner-private real-file directory."""

from __future__ import annotations

import os
import re
import stat
from pathlib import Path

from adf_poc.service import MAX_SECRET_BYTES, ServiceConfigurationError


SECRET_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
MAX_STAGED_SECRETS = 64


def _under(child: Path, parent: Path) -> bool:
    return child == parent or parent in child.parents


def _assert_real_parent_chain(path: Path) -> None:
    for parent in reversed(path.absolute().parents):
        try:
            metadata = parent.lstat()
        except OSError as exc:
            raise ServiceConfigurationError(
                "Secret destination parent chain is unavailable"
            ) from exc
        if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
            raise ServiceConfigurationError("Secret destination parent chain is unsafe")


def _fsync_directory(path: Path) -> None:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags)
    try:
        opened = os.fstat(descriptor)
        current = path.lstat()
        if (
            not stat.S_ISDIR(opened.st_mode)
            or opened.st_dev != current.st_dev
            or opened.st_ino != current.st_ino
        ):
            raise OSError("secret directory identity changed")
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def stage_secret_directory(source_text: str, destination_text: str) -> tuple[str, ...]:
    """Stage one flat projected-secret directory without overwriting anything.

    Source entries may be symlinks because Kubernetes-style projected secrets
    use them.  Every resolved target must remain inside the resolved source
    directory and be a bounded, non-writable regular file.  Destination files
    are created once with mode 0400.
    """

    source = Path(source_text)
    destination = Path(destination_text)
    if not source.is_absolute() or not destination.is_absolute():
        raise ServiceConfigurationError("Secret staging paths must be absolute")
    _assert_real_parent_chain(destination)
    try:
        source_root = source.resolve(strict=True)
        source_metadata = source_root.lstat()
    except (OSError, RuntimeError) as exc:
        raise ServiceConfigurationError(
            "Projected secret source is unavailable"
        ) from exc
    if not stat.S_ISDIR(source_metadata.st_mode):
        raise ServiceConfigurationError("Projected secret source must be a directory")
    if destination.exists():
        metadata = destination.lstat()
        if (
            stat.S_ISLNK(metadata.st_mode)
            or not stat.S_ISDIR(metadata.st_mode)
            or metadata.st_uid != os.geteuid()
            or stat.S_IMODE(metadata.st_mode) & 0o077
        ):
            raise ServiceConfigurationError("Secret destination is unsafe")
    else:
        try:
            os.mkdir(destination, 0o700)
            _fsync_directory(destination.parent)
        except OSError as exc:
            raise ServiceConfigurationError(
                "Secret destination could not be created"
            ) from exc
    try:
        if any(destination.iterdir()):
            raise ServiceConfigurationError("Secret destination must be empty")
        names = sorted(
            entry.name for entry in source.iterdir() if not entry.name.startswith(".")
        )
    except OSError as exc:
        raise ServiceConfigurationError(
            "Secret directories could not be inspected"
        ) from exc
    if not 1 <= len(names) <= MAX_STAGED_SECRETS or any(
        SECRET_NAME.fullmatch(name) is None for name in names
    ):
        raise ServiceConfigurationError(
            "Projected secret names are invalid or unbounded"
        )

    staged: list[str] = []
    for name in names:
        entry = source / name
        try:
            resolved = entry.resolve(strict=True)
            if not _under(resolved, source_root):
                raise ServiceConfigurationError("Projected secret escapes its source")
            flags = (
                os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
            )
            source_fd = os.open(resolved, flags)
        except ServiceConfigurationError:
            raise
        except (OSError, RuntimeError) as exc:
            raise ServiceConfigurationError(
                "Projected secret could not be opened"
            ) from exc
        try:
            metadata = os.fstat(source_fd)
            mode = stat.S_IMODE(metadata.st_mode)
            if (
                not stat.S_ISREG(metadata.st_mode)
                or metadata.st_nlink != 1
                or metadata.st_size < 32
                or metadata.st_size > MAX_SECRET_BYTES
                or mode & 0o022
            ):
                raise ServiceConfigurationError(
                    "Projected secret source file is unsafe"
                )
            value = os.read(source_fd, MAX_SECRET_BYTES + 1)
            after = os.fstat(source_fd)
            if (
                len(value) != metadata.st_size
                or value != value.strip()
                or after.st_dev != metadata.st_dev
                or after.st_ino != metadata.st_ino
                or after.st_size != metadata.st_size
            ):
                raise ServiceConfigurationError("Projected secret value is invalid")
        finally:
            os.close(source_fd)

        target = destination / name
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0)
        flags |= getattr(os, "O_NOFOLLOW", 0)
        try:
            target_fd = os.open(target, flags, 0o400)
            try:
                offset = 0
                while offset < len(value):
                    written = os.write(target_fd, value[offset:])
                    if written < 1:
                        raise OSError("short secret write")
                    offset += written
                os.fchmod(target_fd, 0o400)
                os.fsync(target_fd)
                opened = os.fstat(target_fd)
                current = target.lstat()
                if (
                    not stat.S_ISREG(opened.st_mode)
                    or opened.st_nlink != 1
                    or opened.st_uid != os.geteuid()
                    or stat.S_IMODE(opened.st_mode) != 0o400
                    or opened.st_dev != current.st_dev
                    or opened.st_ino != current.st_ino
                    or opened.st_size != len(value)
                ):
                    raise OSError("staged secret identity changed")
            finally:
                os.close(target_fd)
        except OSError as exc:
            raise ServiceConfigurationError(
                "Staged secret could not be committed"
            ) from exc
        staged.append(name)
    try:
        _fsync_directory(destination)
    except OSError as exc:
        raise ServiceConfigurationError(
            "Staged secret directory could not be committed"
        ) from exc
    return tuple(staged)
