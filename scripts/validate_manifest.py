#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import re
import stat
import subprocess
import sys
from pathlib import Path, PurePosixPath
from typing import Iterable, NoReturn


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_MANIFEST = "MANIFEST.sha256"
MAX_MANIFEST_BYTES = 16 * 1024 * 1024
MANIFEST_LINE = re.compile(r"^([0-9a-f]{64})  (.+)$")


class ManifestValidationError(ValueError):
    pass


def _raise(message: str) -> NoReturn:
    raise ManifestValidationError(message)


def _canonical_relative_path(value: str, *, label: str) -> str:
    if (
        not value
        or value != value.strip()
        or "\\" in value
        or "\x00" in value
        or "\n" in value
        or "\r" in value
        or any(ord(character) < 32 or ord(character) == 127 for character in value)
    ):
        _raise(f"{label} is not a canonical repository-relative POSIX path")
    candidate = PurePosixPath(value)
    if (
        candidate.is_absolute()
        or candidate.as_posix() != value
        or any(part in {"", ".", ".."} for part in candidate.parts)
    ):
        _raise(f"{label} is not a canonical repository-relative POSIX path")
    return value


def _tracked_paths(root: Path) -> tuple[str, ...]:
    try:
        result = subprocess.run(
            ["git", "-C", str(root), "ls-files", "-z", "--"],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
    except (OSError, subprocess.CalledProcessError) as exc:
        raise ManifestValidationError(
            "tracked-file inventory could not be read"
        ) from exc
    try:
        decoded = result.stdout.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ManifestValidationError("tracked paths must be UTF-8") from exc
    raw_paths = decoded.split("\x00")
    if raw_paths and raw_paths[-1] == "":
        raw_paths.pop()
    paths = tuple(
        _canonical_relative_path(path, label="tracked path") for path in raw_paths
    )
    if len(paths) != len(set(paths)):
        _raise("tracked-file inventory contains duplicate paths")
    return paths


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while chunk := handle.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def validate_manifest(
    root: Path = ROOT,
    *,
    manifest_name: str = DEFAULT_MANIFEST,
    tracked_paths: Iterable[str] | None = None,
    verify_hashes: bool = True,
) -> dict[str, int]:
    root = root.resolve(strict=True)
    manifest_name = _canonical_relative_path(manifest_name, label="manifest path")
    manifest_path = root.joinpath(*PurePosixPath(manifest_name).parts)
    try:
        metadata = manifest_path.lstat()
    except OSError as exc:
        raise ManifestValidationError("manifest is unavailable") from exc
    if (
        manifest_path.is_symlink()
        or not stat.S_ISREG(metadata.st_mode)
        or metadata.st_nlink != 1
    ):
        _raise("manifest must be a singly linked regular file")
    if metadata.st_size > MAX_MANIFEST_BYTES:
        _raise(f"manifest exceeds the {MAX_MANIFEST_BYTES}-byte bound")
    try:
        text = manifest_path.read_bytes().decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ManifestValidationError("manifest is not UTF-8") from exc
    if not text or not text.endswith("\n"):
        _raise("manifest must be nonempty and end with one newline")

    entries: dict[str, str] = {}
    ordered_paths: list[str] = []
    for line_number, line in enumerate(text.splitlines(), 1):
        match = MANIFEST_LINE.fullmatch(line)
        if match is None:
            _raise(f"manifest line {line_number} is not an exact SHA-256 entry")
        digest, raw_path = match.groups()
        path = _canonical_relative_path(
            raw_path, label=f"manifest line {line_number} path"
        )
        if path == manifest_name:
            _raise("manifest must not recursively inventory itself")
        if path in entries:
            _raise(f"manifest repeats path {path}")
        entries[path] = digest
        ordered_paths.append(path)
    if ordered_paths != sorted(ordered_paths):
        _raise("manifest entries must be sorted by canonical path")

    observed_tracked = (
        tuple(tracked_paths) if tracked_paths is not None else _tracked_paths(root)
    )
    canonical_tracked = tuple(
        _canonical_relative_path(path, label="tracked path")
        for path in observed_tracked
    )
    if len(canonical_tracked) != len(set(canonical_tracked)):
        _raise("tracked-file inventory contains duplicate paths")
    if manifest_name not in canonical_tracked:
        _raise("manifest must itself be a tracked repository file")
    expected = set(canonical_tracked) - {manifest_name}
    actual = set(entries)
    if actual != expected:
        _raise(
            "manifest coverage differs from tracked files; "
            f"missing={sorted(expected - actual)}, extra={sorted(actual - expected)}"
        )

    verified = 0
    for relative in ordered_paths:
        target = root.joinpath(*PurePosixPath(relative).parts)
        try:
            target_metadata = target.lstat()
            resolved = target.resolve(strict=True)
            resolved.relative_to(root)
        except (OSError, RuntimeError, ValueError) as exc:
            raise ManifestValidationError(
                f"manifest path is unavailable or escapes root: {relative}"
            ) from exc
        if (
            target.is_symlink()
            or not stat.S_ISREG(target_metadata.st_mode)
            or target_metadata.st_nlink != 1
        ):
            _raise(f"manifest path must be a singly linked regular file: {relative}")
        if verify_hashes:
            observed = _sha256(target)
            if observed != entries[relative]:
                _raise(f"manifest digest mismatch: {relative}")
            verified += 1

    return {
        "tracked_files": len(canonical_tracked),
        "manifest_entries": len(entries),
        "verified_hashes": verified,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Validate exact tracked-file coverage and SHA-256 manifest integrity."
    )
    parser.add_argument("--repo-root", type=Path, default=ROOT)
    parser.add_argument("--manifest", default=DEFAULT_MANIFEST)
    parser.add_argument(
        "--coverage-only",
        action="store_true",
        help="validate structure and tracked coverage without checking file digests",
    )
    args = parser.parse_args(argv)
    try:
        result = validate_manifest(
            args.repo_root,
            manifest_name=args.manifest,
            verify_hashes=not args.coverage_only,
        )
    except (OSError, ManifestValidationError) as exc:
        print(json.dumps({"status": "INVALID", "error": str(exc)}, sort_keys=True))
        return 2
    print(json.dumps({"status": "VALID", **result}, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
