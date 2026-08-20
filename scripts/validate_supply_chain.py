#!/usr/bin/env python3
from __future__ import annotations

import json
import re
import sys
import tomllib
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
LOCK_ENTRY = re.compile(
    r"(?ms)^([A-Za-z0-9_.-]+)==([^\s\\]+)\s*\\\n(.*?)(?=^[A-Za-z0-9_.-]+==|\Z)"
)
DIRECT_ENTRY = re.compile(r"^\s*([A-Za-z0-9_.-]+)\s*(?:\[.*?\])?\s*[<>=!~]")
SHA256_HASH = re.compile(r"--hash=sha256:[0-9a-f]{64}(?:\s|\\|$)")


class SupplyChainValidationError(ValueError):
    pass


def normalize_name(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def parse_direct_requirements(path: Path) -> set[str]:
    names: set[str] = set()
    for line_number, raw_line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        line = raw_line.split("#", 1)[0].strip()
        if not line:
            continue
        match = DIRECT_ENTRY.match(line)
        if match is None:
            raise SupplyChainValidationError(
                f"{path.name}:{line_number} is not a bounded package requirement"
            )
        name = normalize_name(match.group(1))
        if name in names:
            raise SupplyChainValidationError(f"{path.name} repeats {name}")
        names.add(name)
    return names


def parse_lock(path: Path) -> dict[str, str]:
    text = path.read_text(encoding="utf-8")
    entries: dict[str, str] = {}
    for match in LOCK_ENTRY.finditer(text):
        name = normalize_name(match.group(1))
        version = match.group(2)
        block = match.group(3)
        if name in entries:
            raise SupplyChainValidationError(f"{path.name} repeats locked package {name}")
        if SHA256_HASH.search(block) is None:
            raise SupplyChainValidationError(f"{path.name} does not hash-lock {name}")
        entries[name] = version
    if not entries:
        raise SupplyChainValidationError(f"{path.name} contains no locked packages")
    return entries


def validate_sbom(path: Path, locked: dict[str, str], direct: set[str]) -> None:
    document = json.loads(path.read_text(encoding="utf-8"))
    if document.get("bomFormat") != "CycloneDX" or document.get("specVersion") != "1.6":
        raise SupplyChainValidationError("Runtime SBOM must be CycloneDX 1.6")

    project = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))["project"]
    root_component = document.get("metadata", {}).get("component", {})
    if root_component.get("name") != project["name"] or root_component.get("version") != project["version"]:
        raise SupplyChainValidationError("Runtime SBOM root component does not match pyproject.toml")

    components: dict[str, tuple[str, str]] = {}
    for component in document.get("components", []):
        name = normalize_name(str(component.get("name", "")))
        version = str(component.get("version", ""))
        reference = str(component.get("bom-ref", ""))
        if not name or not version or not reference or name in components:
            raise SupplyChainValidationError("Runtime SBOM has an invalid or duplicate component")
        components[name] = (version, reference)
    observed = {name: version for name, (version, _) in components.items()}
    if observed != locked:
        raise SupplyChainValidationError("Runtime SBOM components do not exactly match requirements.lock")

    root_reference = str(root_component.get("bom-ref", ""))
    dependency_rows = {
        str(row.get("ref", "")): set(row.get("dependsOn", []))
        for row in document.get("dependencies", [])
    }
    expected_direct_refs = {components[name][1] for name in direct}
    if dependency_rows.get(root_reference) != expected_direct_refs:
        raise SupplyChainValidationError("Runtime SBOM root dependency edges are incomplete")
    if set(dependency_rows) != {root_reference} | {reference for _, reference in components.values()}:
        raise SupplyChainValidationError("Runtime SBOM dependency graph does not cover every component")


def validate_repository(root: Path = ROOT) -> dict[str, int]:
    direct = parse_direct_requirements(root / "requirements.txt")
    locked = parse_lock(root / "requirements.lock")
    if not direct.issubset(locked):
        raise SupplyChainValidationError("requirements.lock omits a direct runtime dependency")

    docs_direct = parse_direct_requirements(root / "requirements-docs.txt")
    docs_locked = parse_lock(root / "requirements-docs.lock")
    if not docs_direct.issubset(docs_locked):
        raise SupplyChainValidationError("requirements-docs.lock omits a direct documentation dependency")

    validate_sbom(root / "artifacts/supply-chain/runtime.cdx.json", locked, direct)
    return {
        "runtime_direct": len(direct),
        "runtime_locked": len(locked),
        "docs_direct": len(docs_direct),
        "docs_locked": len(docs_locked),
        "sbom_components": len(locked),
    }


def main() -> int:
    try:
        result = validate_repository()
    except (OSError, json.JSONDecodeError, KeyError, SupplyChainValidationError) as exc:
        print(json.dumps({"status": "INVALID", "error": str(exc)}, sort_keys=True))
        return 2
    print(json.dumps({"status": "VALID", **result}, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
