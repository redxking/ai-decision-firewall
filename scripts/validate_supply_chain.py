#!/usr/bin/env python3
from __future__ import annotations

import json
import math
import re
import sys
import tomllib
from dataclasses import dataclass
from pathlib import Path
from typing import Any, NoReturn


ROOT = Path(__file__).resolve().parents[1]
MAX_INPUT_BYTES = 4 * 1024 * 1024
MAX_INPUT_LINES = 100_000
MAX_LINE_LENGTH = 131_072
MAX_SBOM_COMPONENTS = 2048

DIRECT_ENTRY = re.compile(
    r"^([A-Za-z0-9][A-Za-z0-9_.-]*)"
    r"((?:(?:==|<=|>=|<|>)[0-9]+(?:\.[0-9]+)*)(?:,(?:==|<=|>=|<|>)[0-9]+(?:\.[0-9]+)*)*)$"
)
LOCK_ENTRY = re.compile(
    r"^([A-Za-z0-9][A-Za-z0-9_.-]*)==([A-Za-z0-9][A-Za-z0-9._+!-]*) \\?$"
)
LOCK_HASH = re.compile(r"^    --hash=sha256:([0-9a-f]{64})(?: (\\))?$")
SHA256 = re.compile(r"^[0-9a-f]{64}$")


class SupplyChainValidationError(ValueError):
    pass


@dataclass(frozen=True, slots=True)
class LockedRequirement:
    version: str
    hashes: frozenset[str]


def _raise(message: str) -> NoReturn:
    raise SupplyChainValidationError(message)


def normalize_name(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def _read_bounded_text(path: Path) -> str:
    try:
        metadata = path.lstat()
    except OSError as exc:
        raise SupplyChainValidationError(f"{path.name} is unavailable") from exc
    if path.is_symlink() or not path.is_file():
        _raise(f"{path.name} must be a regular non-symbolic-link file")
    if metadata.st_size > MAX_INPUT_BYTES:
        _raise(f"{path.name} exceeds the {MAX_INPUT_BYTES}-byte input bound")
    try:
        text = path.read_bytes().decode("utf-8")
    except UnicodeDecodeError as exc:
        raise SupplyChainValidationError(f"{path.name} is not UTF-8") from exc
    if "\x00" in text:
        _raise(f"{path.name} contains a prohibited NUL character")
    lines = text.splitlines()
    if len(lines) > MAX_INPUT_LINES:
        _raise(f"{path.name} exceeds the {MAX_INPUT_LINES}-line input bound")
    for line_number, line in enumerate(lines, 1):
        if len(line) > MAX_LINE_LENGTH:
            _raise(
                f"{path.name}:{line_number} exceeds the {MAX_LINE_LENGTH}-character line bound"
            )
    return text


def _parse_direct_value(value: str, *, label: str) -> tuple[str, str]:
    if not value or value != value.strip() or len(value) > 512:
        _raise(f"{label} is not a bounded canonical requirement")
    match = DIRECT_ENTRY.fullmatch(value)
    if match is None:
        _raise(
            f"{label} must be a package name with a closed version specifier; "
            "extras, markers, URLs, local paths, and options are prohibited"
        )
    return normalize_name(match.group(1)), match.group(2)


def parse_direct_requirements(path: Path) -> dict[str, str]:
    requirements: dict[str, str] = {}
    for line_number, raw_line in enumerate(_read_bounded_text(path).splitlines(), 1):
        line = raw_line.split("#", 1)[0].strip()
        if not line:
            continue
        name, specifier = _parse_direct_value(line, label=f"{path.name}:{line_number}")
        if name in requirements:
            _raise(f"{path.name} repeats direct requirement {name}")
        requirements[name] = specifier
    if not requirements:
        _raise(f"{path.name} contains no direct requirements")
    return requirements


def _finish_lock_entry(
    *,
    path: Path,
    line_number: int,
    name: str,
    version: str,
    hashes: list[str],
    entries: dict[str, LockedRequirement],
) -> None:
    if not hashes:
        _raise(f"{path.name}:{line_number} does not hash-lock {name}")
    if len(hashes) != len(set(hashes)):
        _raise(f"{path.name}:{line_number} repeats a SHA-256 hash for {name}")
    entries[name] = LockedRequirement(version=version, hashes=frozenset(hashes))


def parse_lock(path: Path) -> dict[str, LockedRequirement]:
    """Parse the complete accepted pip-compile lock grammar without skipped text."""

    entries: dict[str, LockedRequirement] = {}
    current_name: str | None = None
    current_version = ""
    current_hashes: list[str] = []
    entry_line = 0
    lines = _read_bounded_text(path).splitlines()

    for line_number, line in enumerate(lines, 1):
        if current_name is None:
            if not line or line.lstrip().startswith("#"):
                continue
            match = LOCK_ENTRY.fullmatch(line)
            if match is None or not line.endswith(" \\"):
                _raise(
                    f"{path.name}:{line_number} contains unsupported or unparsed lock content"
                )
            current_name = normalize_name(match.group(1))
            current_version = match.group(2)
            entry_line = line_number
            current_hashes = []
            if current_name in entries:
                _raise(
                    f"{path.name}:{line_number} repeats locked package {current_name}"
                )
            continue

        hash_match = LOCK_HASH.fullmatch(line)
        if hash_match is None:
            _raise(
                f"{path.name}:{line_number} is not a SHA-256 continuation for {current_name}"
            )
        current_hashes.append(hash_match.group(1))
        if hash_match.group(2) is None:
            _finish_lock_entry(
                path=path,
                line_number=entry_line,
                name=current_name,
                version=current_version,
                hashes=current_hashes,
                entries=entries,
            )
            current_name = None
            current_version = ""
            current_hashes = []

    if current_name is not None:
        _raise(f"{path.name}:{entry_line} has an unterminated hash continuation")
    if not entries:
        _raise(f"{path.name} contains no locked packages")
    return entries


def _numeric_version(value: str, *, label: str) -> tuple[int, ...]:
    if re.fullmatch(r"[0-9]+(?:\.[0-9]+)*", value) is None:
        _raise(f"{label} is not a closed numeric version")
    return tuple(int(part) for part in value.split("."))


def _compare_numeric_versions(left: tuple[int, ...], right: tuple[int, ...]) -> int:
    width = max(len(left), len(right))
    padded_left = left + (0,) * (width - len(left))
    padded_right = right + (0,) * (width - len(right))
    return (padded_left > padded_right) - (padded_left < padded_right)


def _locked_version_satisfies(version: str, specifier: str, *, label: str) -> bool:
    locked = _numeric_version(version, label=f"{label} locked version")
    for clause in specifier.split(","):
        match = re.fullmatch(r"(==|<=|>=|<|>)([0-9]+(?:\.[0-9]+)*)", clause)
        if match is None:
            _raise(f"{label} contains an unsupported direct version clause")
        comparison = _compare_numeric_versions(
            locked,
            _numeric_version(match.group(2), label=f"{label} direct version"),
        )
        operator = match.group(1)
        satisfied = {
            "==": comparison == 0,
            "<=": comparison <= 0,
            ">=": comparison >= 0,
            "<": comparison < 0,
            ">": comparison > 0,
        }[operator]
        if not satisfied:
            return False
    return True


def validate_direct_locks(
    direct: dict[str, str],
    locked: dict[str, LockedRequirement],
    *,
    label: str,
) -> None:
    missing = sorted(set(direct) - set(locked))
    if missing:
        _raise(f"{label} lock omits direct requirements: {missing}")
    for name, specifier in direct.items():
        if not _locked_version_satisfies(
            locked[name].version,
            specifier,
            label=f"{label} requirement {name}",
        ):
            _raise(
                f"{label} locked version for {name} does not satisfy direct specifier "
                f"{specifier}"
            )


def _reject_constant(value: str) -> NoReturn:
    _raise(f"non-finite JSON constant is prohibited: {value}")


def _object_without_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, member in pairs:
        if key in value:
            _raise(f"duplicate JSON member is prohibited: {key}")
        value[key] = member
    return value


def _load_strict_json(path: Path) -> Any:
    text = _read_bounded_text(path)
    try:
        value = json.loads(
            text,
            object_pairs_hook=_object_without_duplicate_keys,
            parse_constant=_reject_constant,
        )
    except SupplyChainValidationError:
        raise
    except (json.JSONDecodeError, RecursionError) as exc:
        raise SupplyChainValidationError(f"{path.name} is not strict JSON") from exc

    pending = [value]
    node_count = 0
    while pending:
        child = pending.pop()
        node_count += 1
        if node_count > 250_000:
            _raise(f"{path.name} exceeds the strict JSON structural bound")
        if isinstance(child, float) and not math.isfinite(child):
            _raise(f"{path.name} contains a non-finite JSON number")
        if type(child) is dict:
            pending.extend(child.values())
        elif type(child) is list:
            pending.extend(child)
    return value


def _require_exact_fields(value: Any, expected: set[str], label: str) -> dict[str, Any]:
    if type(value) is not dict:
        _raise(f"{label} must be an object")
    actual = set(value)
    if actual != expected:
        _raise(
            f"{label} fields differ from the closed contract; "
            f"missing={sorted(expected - actual)}, unknown={sorted(actual - expected)}"
        )
    return value


def _require_bounded_string(value: Any, label: str, *, maximum: int = 4096) -> str:
    if (
        type(value) is not str
        or not value
        or value != value.strip()
        or len(value) > maximum
    ):
        _raise(f"{label} must be a nonempty bounded canonical string")
    return value


def _project_metadata(root: Path) -> dict[str, Any]:
    path = root / "pyproject.toml"
    try:
        document = tomllib.loads(_read_bounded_text(path))
        project = document["project"]
    except (tomllib.TOMLDecodeError, KeyError, TypeError) as exc:
        raise SupplyChainValidationError(
            "pyproject.toml project metadata is invalid"
        ) from exc
    if type(project) is not dict:
        _raise("pyproject.toml project metadata must be an object")
    for field in ("name", "version", "description"):
        _require_bounded_string(project.get(field), f"pyproject.toml project.{field}")
    dependencies = project.get("dependencies")
    if type(dependencies) is not list or not dependencies:
        _raise("pyproject.toml project.dependencies must be a nonempty array")
    parsed: dict[str, str] = {}
    for index, dependency in enumerate(dependencies):
        if type(dependency) is not str:
            _raise(f"pyproject.toml project.dependencies[{index}] must be a string")
        name, specifier = _parse_direct_value(
            dependency, label=f"pyproject.toml project.dependencies[{index}]"
        )
        if name in parsed:
            _raise(f"pyproject.toml repeats direct dependency {name}")
        parsed[name] = specifier
    return {**project, "_parsed_dependencies": parsed}


def validate_sbom(
    path: Path,
    locked: dict[str, LockedRequirement],
    direct: dict[str, str],
    *,
    project: dict[str, Any],
) -> None:
    document = _require_exact_fields(
        _load_strict_json(path),
        {
            "$schema",
            "bomFormat",
            "specVersion",
            "version",
            "metadata",
            "components",
            "dependencies",
        },
        "Runtime SBOM",
    )
    if (
        document["$schema"] != "http://cyclonedx.org/schema/bom-1.6.schema.json"
        or document["bomFormat"] != "CycloneDX"
        or document["specVersion"] != "1.6"
        or document["version"] != 1
    ):
        _raise("Runtime SBOM must be the exact supported CycloneDX 1.6 document")

    metadata = _require_exact_fields(
        document["metadata"],
        {"component", "properties", "tools"},
        "Runtime SBOM metadata",
    )
    root_component = _require_exact_fields(
        metadata["component"],
        {"bom-ref", "description", "name", "type", "version"},
        "Runtime SBOM root component",
    )
    if (
        root_component["bom-ref"] != "root-component"
        or root_component["type"] != "application"
        or root_component["name"] != project["name"]
        or root_component["version"] != project["version"]
        or root_component["description"] != project["description"]
    ):
        _raise("Runtime SBOM root component does not exactly match pyproject.toml")
    if metadata["properties"] != [{"name": "cdx:reproducible", "value": "true"}]:
        _raise("Runtime SBOM reproducible-generation marker is absent or ambiguous")
    if type(metadata["tools"]) is not dict:
        _raise("Runtime SBOM tools metadata must be an object")

    raw_components = document["components"]
    if (
        type(raw_components) is not list
        or not raw_components
        or len(raw_components) > MAX_SBOM_COMPONENTS
    ):
        _raise("Runtime SBOM components must be a nonempty bounded array")

    components: dict[str, tuple[str, str]] = {}
    component_references: set[str] = set()
    observed_order: list[str] = []
    for index, raw_component in enumerate(raw_components):
        component = _require_exact_fields(
            raw_component,
            {
                "bom-ref",
                "description",
                "externalReferences",
                "name",
                "purl",
                "type",
                "version",
            },
            f"Runtime SBOM components[{index}]",
        )
        raw_name = _require_bounded_string(
            component["name"], f"Runtime SBOM components[{index}].name", maximum=256
        )
        name = normalize_name(raw_name)
        version = _require_bounded_string(
            component["version"],
            f"Runtime SBOM components[{index}].version",
            maximum=256,
        )
        reference = _require_bounded_string(
            component["bom-ref"],
            f"Runtime SBOM components[{index}].bom-ref",
            maximum=512,
        )
        if raw_name != name or name not in locked or name in components:
            _raise("Runtime SBOM has an unknown, noncanonical, or duplicate component")
        if reference == root_component["bom-ref"] or reference in component_references:
            _raise("Runtime SBOM has a duplicate component reference")
        if (
            component["type"] != "library"
            or version != locked[name].version
            or component["purl"] != f"pkg:pypi/{name}@{version}"
        ):
            _raise(f"Runtime SBOM component identity differs from the lock for {name}")
        _require_bounded_string(
            component["description"],
            f"Runtime SBOM components[{index}].description",
            maximum=65_536,
        )

        references = component["externalReferences"]
        if type(references) is not list or len(references) != 1:
            _raise(
                f"Runtime SBOM component {name} must have one distribution reference"
            )
        distribution = _require_exact_fields(
            references[0],
            {"comment", "hashes", "type", "url"},
            f"Runtime SBOM component {name} distribution",
        )
        if (
            distribution["comment"] != "implicit dist url"
            or distribution["type"] != "distribution"
            or distribution["url"] != f"https://pypi.org/simple/{name}/"
        ):
            _raise(f"Runtime SBOM component {name} distribution identity is invalid")
        raw_hashes = distribution["hashes"]
        if type(raw_hashes) is not list or not raw_hashes:
            _raise(f"Runtime SBOM component {name} has no distribution hashes")
        observed_hashes: list[str] = []
        for hash_index, raw_hash in enumerate(raw_hashes):
            hash_row = _require_exact_fields(
                raw_hash,
                {"alg", "content"},
                f"Runtime SBOM component {name} hashes[{hash_index}]",
            )
            if hash_row["alg"] != "SHA-256" or type(hash_row["content"]) is not str:
                _raise(
                    f"Runtime SBOM component {name} has an unsupported distribution hash"
                )
            if SHA256.fullmatch(hash_row["content"]) is None:
                _raise(f"Runtime SBOM component {name} has a malformed SHA-256 digest")
            observed_hashes.append(hash_row["content"])
        if observed_hashes != sorted(observed_hashes) or len(observed_hashes) != len(
            set(observed_hashes)
        ):
            _raise(
                f"Runtime SBOM component {name} hashes are duplicate or noncanonical"
            )
        if frozenset(observed_hashes) != locked[name].hashes:
            _raise(
                f"Runtime SBOM distribution hashes differ from requirements.lock for {name}"
            )

        components[name] = (version, reference)
        component_references.add(reference)
        observed_order.append(name)

    if set(components) != set(locked):
        _raise("Runtime SBOM components do not exactly match requirements.lock")
    if observed_order != sorted(observed_order):
        _raise("Runtime SBOM components are not in deterministic name order")

    raw_dependencies = document["dependencies"]
    if (
        type(raw_dependencies) is not list
        or len(raw_dependencies) != len(components) + 1
    ):
        _raise("Runtime SBOM dependency rows do not cover the root and every component")
    dependency_rows: dict[str, set[str]] = {}
    dependency_order: list[str] = []
    allowed_references = {str(root_component["bom-ref"]), *component_references}
    for index, raw_row in enumerate(raw_dependencies):
        if type(raw_row) is not dict or set(raw_row) not in (
            {"ref"},
            {"ref", "dependsOn"},
        ):
            _raise(f"Runtime SBOM dependencies[{index}] has an invalid shape")
        reference = _require_bounded_string(
            raw_row.get("ref"), f"Runtime SBOM dependencies[{index}].ref", maximum=512
        )
        if reference not in allowed_references or reference in dependency_rows:
            _raise("Runtime SBOM dependency references are unknown or duplicate")
        depends_on = raw_row.get("dependsOn", [])
        if type(depends_on) is not list or any(
            type(item) is not str for item in depends_on
        ):
            _raise(
                f"Runtime SBOM dependencies[{index}].dependsOn must be a string array"
            )
        if depends_on != sorted(depends_on) or len(depends_on) != len(set(depends_on)):
            _raise("Runtime SBOM dependency edges are duplicate or noncanonical")
        if reference in depends_on or any(
            item not in component_references for item in depends_on
        ):
            _raise("Runtime SBOM dependency edge references an invalid component")
        dependency_rows[reference] = set(depends_on)
        dependency_order.append(reference)
    if dependency_order != sorted(dependency_order):
        _raise("Runtime SBOM dependency rows are not in deterministic reference order")
    if set(dependency_rows) != allowed_references:
        _raise("Runtime SBOM dependency graph does not cover every component")
    expected_direct_refs = {components[name][1] for name in direct}
    if dependency_rows[str(root_component["bom-ref"])] != expected_direct_refs:
        _raise("Runtime SBOM root dependency edges are incomplete")


def validate_repository(root: Path = ROOT) -> dict[str, int]:
    direct = parse_direct_requirements(root / "requirements.txt")
    locked = parse_lock(root / "requirements.lock")
    validate_direct_locks(direct, locked, label="runtime")

    docs_direct = parse_direct_requirements(root / "requirements-docs.txt")
    docs_locked = parse_lock(root / "requirements-docs.lock")
    validate_direct_locks(docs_direct, docs_locked, label="documentation")

    project = _project_metadata(root)
    if project["_parsed_dependencies"] != direct:
        _raise(
            "requirements.txt does not exactly match pyproject.toml runtime dependencies"
        )

    validate_sbom(
        root / "artifacts/supply-chain/runtime.cdx.json",
        locked,
        direct,
        project=project,
    )
    return {
        "runtime_direct": len(direct),
        "runtime_locked": len(locked),
        "docs_direct": len(docs_direct),
        "docs_locked": len(docs_locked),
        "sbom_components": len(locked),
        "runtime_distribution_hashes": sum(
            len(item.hashes) for item in locked.values()
        ),
    }


def main() -> int:
    try:
        result = validate_repository()
    except (OSError, SupplyChainValidationError) as exc:
        print(json.dumps({"status": "INVALID", "error": str(exc)}, sort_keys=True))
        return 2
    print(json.dumps({"status": "VALID", **result}, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
