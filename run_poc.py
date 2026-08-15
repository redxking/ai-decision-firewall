from __future__ import annotations

import argparse
import importlib.metadata
import json
import os
import platform
import stat
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from adf_poc.engine import run_engine
from adf_poc.metrics import evaluate
from adf_poc.model import train_from_files
from adf_poc.reporting import generate_html_report
from adf_poc.synthetic import generate_dataset
from adf_poc.utils import sha256_file, write_json


REPOSITORY_ROOT = ROOT.resolve()
TRACKED_DATA_ROOT = REPOSITORY_ROOT / "data"
LOCAL_DATA_ROOT = TRACKED_DATA_ROOT / "local"
TRACKED_BASELINE_ROOT = REPOSITORY_ROOT / "outputs" / "baseline"
LOCAL_OUTPUT_ROOT = REPOSITORY_ROOT / "outputs" / "local"
DEFAULT_DATA_DIR = LOCAL_DATA_ROOT / "synthetic-baseline"
DEFAULT_OUTPUT_DIR = ROOT / "outputs" / "local" / "synthetic-baseline"
DATA_ARTIFACT_NAMES = (
    "train_cases.jsonl",
    "train_labels.jsonl",
    "test_cases.jsonl",
    "test_labels.jsonl",
    "dataset_manifest.json",
)
OUTPUT_ARTIFACT_NAMES = (
    "model.json",
    "decisions.jsonl",
    "audit_chain.jsonl",
    "metrics.json",
    "decision_summary.csv",
    "per_scenario_metrics.csv",
    "baseline_report.html",
)
WRITTEN_OUTPUT_ARTIFACT_NAMES = OUTPUT_ARTIFACT_NAMES + ("run_manifest.json",)


class TrackedArtifactOverwriteError(ValueError):
    """Raised when a routine POC run targets campaign-bound repository artifacts."""


def _is_relative_to(path: Path, parent: Path) -> bool:
    try:
        path.relative_to(parent)
    except ValueError:
        return False
    return True


def _relative_to_repository_identity(path: Path) -> Path | None:
    """Return the suffix below the repository using filesystem identity."""

    for ancestor in (path, *path.parents):
        try:
            if os.path.samefile(ancestor, REPOSITORY_ROOT):
                return path.relative_to(ancestor)
        except (FileNotFoundError, NotADirectoryError, OSError, ValueError):
            continue
    return None


def _canonical_repository_destination(
    relative: Path,
    *,
    label: str,
) -> Path:
    """Canonicalize existing repository components and reject symlink traversal."""

    current = REPOSITORY_ROOT
    parts = relative.parts
    for index, part in enumerate(parts):
        candidate = current / part
        if candidate.is_symlink():
            raise TrackedArtifactOverwriteError(
                f"{label} must not traverse a symbolic link inside the repository."
            )
        try:
            candidate.stat()
        except FileNotFoundError:
            return current.joinpath(*parts[index:])
        except (NotADirectoryError, OSError) as error:
            raise TrackedArtifactOverwriteError(
                f"{label} could not be inspected safely."
            ) from error

        actual_name: str | None = None
        try:
            with os.scandir(current) as entries:
                for entry in entries:
                    try:
                        if os.path.samefile(entry.path, candidate):
                            actual_name = entry.name
                            break
                    except (FileNotFoundError, OSError):
                        continue
        except OSError as error:
            raise TrackedArtifactOverwriteError(
                f"{label} could not be inspected safely."
            ) from error
        if actual_name is None:
            raise TrackedArtifactOverwriteError(
                f"{label} could not be bound to a repository entry safely."
            )
        current = current / actual_name
    return current


def _normalized_destination(path: Path, *, label: str) -> Path:
    """Resolve a destination using repository identity, not path spelling."""

    lexical = Path(os.path.abspath(path))
    relative = _relative_to_repository_identity(lexical)
    if relative is not None:
        return _canonical_repository_destination(relative, label=label)
    try:
        resolved = lexical.resolve(strict=False)
    except (OSError, RuntimeError) as error:
        raise TrackedArtifactOverwriteError(
            f"{label} could not be resolved safely."
        ) from error
    relative = _relative_to_repository_identity(resolved)
    if relative is not None:
        return _canonical_repository_destination(relative, label=label)
    return resolved


def _require_allowed_destination(
    path: Path,
    *,
    label: str,
    routine_root: Path,
    freeze_root: Path,
    freeze_allowed: bool,
) -> None:
    if not _is_relative_to(path, REPOSITORY_ROOT):
        return
    if _is_relative_to(path, routine_root):
        return
    if freeze_allowed and _is_relative_to(path, freeze_root):
        return
    raise TrackedArtifactOverwriteError(
        f"{label} is inside the repository but outside its permitted routine "
        f"or model-freeze root: {path}."
    )


def require_explicit_tracked_artifact_overwrite(
    data_dir: Path,
    output_dir: Path,
    *,
    allowed: bool,
) -> tuple[Path, Path]:
    """Keep routine synthetic runs from mutating tracked, evidence-bound artifacts."""

    resolved_data = _normalized_destination(data_dir, label="Data directory")
    resolved_output = _normalized_destination(output_dir, label="Output directory")
    if _is_relative_to(resolved_data, resolved_output) or _is_relative_to(
        resolved_output, resolved_data
    ):
        raise TrackedArtifactOverwriteError(
            "Data and output directories must not overlap."
        )
    _require_allowed_destination(
        resolved_data,
        label="Data directory",
        routine_root=LOCAL_DATA_ROOT,
        freeze_root=TRACKED_DATA_ROOT,
        freeze_allowed=allowed,
    )
    _require_allowed_destination(
        resolved_output,
        label="Output directory",
        routine_root=LOCAL_OUTPUT_ROOT,
        freeze_root=TRACKED_BASELINE_ROOT,
        freeze_allowed=allowed,
    )
    return resolved_data, resolved_output


def require_safe_existing_leaf_targets(data_dir: Path, output_dir: Path) -> None:
    """Reject existing leaves that could redirect or alias generated bytes.

    This is a local operator-safety check. It does not replace descriptor-bound,
    no-follow writes or an OS sandbox when hostile concurrent mutation is in scope.
    """

    for directory, names, label in (
        (data_dir, DATA_ARTIFACT_NAMES, "Data artifact"),
        (output_dir, WRITTEN_OUTPUT_ARTIFACT_NAMES, "Output artifact"),
    ):
        for name in names:
            target = directory / name
            try:
                metadata = os.lstat(target)
            except FileNotFoundError:
                continue
            except OSError as error:
                raise TrackedArtifactOverwriteError(
                    f"{label} could not be inspected safely: {target}."
                ) from error
            if stat.S_ISLNK(metadata.st_mode):
                raise TrackedArtifactOverwriteError(
                    f"{label} must not be a symbolic link: {target}."
                )
            if not stat.S_ISREG(metadata.st_mode):
                raise TrackedArtifactOverwriteError(
                    f"{label} must be a regular file when it already exists: {target}."
                )
            if metadata.st_nlink != 1:
                raise TrackedArtifactOverwriteError(
                    f"{label} must not be a hard-linked file: {target}."
                )


def main() -> None:
    parser = argparse.ArgumentParser(description="Build and execute the AI Decision Firewall synthetic POC baseline.")
    parser.add_argument("--train-count", type=int, default=800)
    parser.add_argument("--test-count", type=int, default=400)
    parser.add_argument("--seed", type=int, default=20260814)
    parser.add_argument("--data-dir", default=str(DEFAULT_DATA_DIR))
    parser.add_argument("--output-dir", default=str(DEFAULT_OUTPUT_DIR))
    parser.add_argument("--policy", default=str(ROOT / "config" / "policy.json"))
    parser.add_argument(
        "--allow-tracked-artifact-overwrite",
        action="store_true",
        help=(
            "Permit data/** and outputs/baseline/** model-freeze destinations. "
            "Other repository paths remain prohibited. Reserved for an explicitly "
            "approved model-freeze workflow; ordinary runs must omit it."
        ),
    )
    args = parser.parse_args()

    data_dir = Path(args.data_dir)
    output_dir = Path(args.output_dir)
    try:
        data_dir, output_dir = require_explicit_tracked_artifact_overwrite(
            data_dir,
            output_dir,
            allowed=args.allow_tracked_artifact_overwrite,
        )
        require_safe_existing_leaf_targets(data_dir, output_dir)
    except TrackedArtifactOverwriteError as error:
        parser.error(str(error))
    output_dir.mkdir(parents=True, exist_ok=True)

    manifest = generate_dataset(data_dir, args.train_count, args.test_count, args.seed)
    model_path = output_dir / "model.json"
    model = train_from_files(data_dir / "train_cases.jsonl", data_dir / "train_labels.jsonl", model_path)
    decisions_path = output_dir / "decisions.jsonl"
    audit_path = output_dir / "audit_chain.jsonl"
    decisions = run_engine(
        cases_path=data_dir / "test_cases.jsonl",
        model_path=model_path,
        policy_path=args.policy,
        decisions_path=decisions_path,
        audit_path=audit_path,
    )
    metrics = evaluate(
        decisions_path=decisions_path,
        labels_path=data_dir / "test_labels.jsonl",
        audit_path=audit_path,
        output_dir=output_dir,
    )
    generate_html_report(metrics, output_dir / "baseline_report.html")
    policy_path = Path(args.policy).resolve()
    try:
        policy_reference = str(policy_path.relative_to(ROOT.resolve()))
    except ValueError:
        policy_reference = str(policy_path)

    outputs = list(OUTPUT_ARTIFACT_NAMES)
    output_bindings = {
        name: sha256_file(output_dir / name)
        for name in outputs
    }
    run_manifest = {
        "poc_version": "0.1.0",
        "dataset_manifest_hash": manifest["manifest_hash"],
        "model_version": model.version,
        "policy_file": policy_reference,
        "policy_sha256": sha256_file(policy_path),
        "train_cases": args.train_count,
        "test_cases": len(decisions),
        "seed": args.seed,
        "runtime_fingerprint": {
            "python_implementation": platform.python_implementation(),
            "python_version": platform.python_version(),
            "numpy_version": importlib.metadata.version("numpy"),
            "platform_system": platform.system(),
            "platform_release": platform.release(),
            "platform_machine": platform.machine(),
        },
        "reproducibility_boundary": (
            "This manifest records the runtime and binds the named output bytes as "
            "written. It does not establish builder identity, source-commit identity, "
            "BLAS or thread configuration, or cross-runtime retraining reproducibility; "
            "the frozen model digest is authoritative for campaign replay."
        ),
        "outputs": outputs,
        "output_bindings": output_bindings,
        "safety_notice": "Synthetic data and simulated actions only. Not approved for operational use.",
    }
    write_json(output_dir / "run_manifest.json", run_manifest)
    print(json.dumps({
        "cases": metrics["scope"]["cases_evaluated"],
        "autonomous_containment_precision": metrics["decision_control"]["autonomous_containment_precision"],
        "false_containment_count": metrics["decision_control"]["false_containment_count"],
        "unsafe_automation_count": metrics["safety_and_assurance"]["unsafe_automation_count"],
        "audit_chain_valid": metrics["safety_and_assurance"]["audit_chain_valid"],
        "report": str(output_dir / "baseline_report.html"),
    }, indent=2))


if __name__ == "__main__":
    main()
