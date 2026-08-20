#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from pathlib import Path
import subprocess
import uuid


ROOT = Path(__file__).resolve().parents[1]
LAB_DOCKERFILE = ROOT / "tests" / "Dockerfile.stage-a-storage-lab"
FAULT_MODES = {
    "dm-error": "DM_ERROR",
    "dm-flakey-error-writes": "DM_FLAKEY_ERROR_WRITES",
}


def _run(
    arguments: list[str], *, capture: bool = False
) -> subprocess.CompletedProcess[str]:
    completed = subprocess.run(
        ["docker", *arguments],
        cwd=ROOT,
        check=False,
        capture_output=capture,
        text=True,
        timeout=180,
    )
    if completed.returncode != 0:
        detail = completed.stderr or completed.stdout or "see streamed output above"
        raise RuntimeError(
            f"docker {' '.join(arguments[:3])} failed ({completed.returncode}): "
            f"{detail}"
        )
    return completed


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Run the destructive Stage A dm-error and dm-flakey/error_writes "
            "ext4 campaign on loopback files inside a disposable privileged "
            "Linux container."
        )
    )
    parser.add_argument("--image", required=True, help="Exact local Stage A image tag")
    parser.add_argument(
        "--fault-mode",
        choices=tuple(FAULT_MODES),
        default="dm-error",
        help=(
            "Exact device-mapper mode to run; flakey requires kernel target support "
            "and fails closed when unavailable"
        ),
    )
    parser.add_argument(
        "--allow-privileged-lab",
        action="store_true",
        help="Required acknowledgement for the disposable privileged container",
    )
    parser.add_argument(
        "--keep-lab-image",
        action="store_true",
        help="Retain the locally derived lab image after the campaign",
    )
    return parser


def main() -> int:
    arguments = _parser().parse_args()
    if not arguments.allow_privileged_lab:
        raise SystemExit(
            "Refusing to start: --allow-privileged-lab is required. The lab uses "
            "isolated loopback files but receives Docker privileged mode."
        )
    server_os = _run(["info", "--format", "{{.OSType}}"], capture=True).stdout.strip()
    if server_os != "linux":
        raise SystemExit(
            f"The block-device campaign requires a Linux engine, got {server_os!r}."
        )
    inspected = _run(
        ["image", "inspect", "--format", "{{.Id}}", arguments.image],
        capture=True,
    ).stdout.strip()
    if not inspected.startswith("sha256:") or len(inspected) != 71:
        raise SystemExit(
            "The selected image did not resolve to an exact local image ID."
        )

    suffix = uuid.uuid4().hex[:12]
    base_alias = f"adf-stage-a-storage-base:{inspected[7:19]}-{suffix}"
    lab_image = f"adf-stage-a-storage-lab:{inspected[7:19]}-{suffix}"
    container_name = f"adf-stage-a-storage-lab-{suffix}"
    try:
        _run(["image", "tag", inspected, base_alias])
        _run(
            [
                "build",
                "--file",
                str(LAB_DOCKERFILE),
                "--build-arg",
                f"ADF_BASE_IMAGE={base_alias}",
                "--tag",
                lab_image,
                str(ROOT),
            ]
        )
        _run(
            [
                "run",
                "--rm",
                "--name",
                container_name,
                "--label",
                "org.opencontainers.image.title=ADF Stage A disposable storage lab",
                "--privileged",
                "--network=none",
                "--user",
                "0:0",
                "--pids-limit=128",
                "--memory=1g",
                "--cpus=2",
                "--tmpfs",
                "/lab:rw,nosuid,nodev,size=256m",
                "--volume",
                f"{ROOT / 'tests'}:/opt/adf/tests:ro",
                "--env",
                "PYTHONPATH=/opt/adf/src:/opt/adf/dependencies:/opt/adf",
                "--env",
                "PYTHONDONTWRITEBYTECODE=1",
                "--env",
                "PYTHONWARNINGS=error",
                "--env",
                "ADF_CONTAINER_BLOCK_DEVICE_CAMPAIGN=1",
                "--env",
                f"ADF_BLOCK_DEVICE_FAULT_MODE={FAULT_MODES[arguments.fault_mode]}",
                lab_image,
            ]
        )
        print(
            json.dumps(
                {
                    "base_image_id": inspected,
                    "campaign": "STAGE_A_DEVICE_MAPPER_EXT4",
                    "fault_mode": arguments.fault_mode,
                    "lab_image": lab_image,
                    "status": "PASSED",
                },
                sort_keys=True,
            )
        )
    finally:
        subprocess.run(
            ["docker", "stop", "--time", "20", container_name],
            cwd=ROOT,
            check=False,
            capture_output=True,
            text=True,
            timeout=30,
        )
        subprocess.run(
            ["docker", "rm", "--force", container_name],
            cwd=ROOT,
            check=False,
            capture_output=True,
            text=True,
            timeout=30,
        )
        if not arguments.keep_lab_image:
            for created_tag in (lab_image, base_alias):
                subprocess.run(
                    ["docker", "image", "rm", created_tag],
                    cwd=ROOT,
                    check=False,
                    capture_output=True,
                    text=True,
                    timeout=30,
                )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
