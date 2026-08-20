from __future__ import annotations

import re
import unittest
from pathlib import Path


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
WORKFLOW_ROOT = REPOSITORY_ROOT / ".github" / "workflows"
ACTION_REFERENCE = re.compile(r"^\s*(?:-\s*)?uses:\s*([^\s#]+)")
FULL_COMMIT_SHA = re.compile(r"^[0-9a-f]{40}$")


def _workflows() -> tuple[Path, ...]:
    return tuple(
        sorted(WORKFLOW_ROOT.glob("*.yml")) + sorted(WORKFLOW_ROOT.glob("*.yaml"))
    )


class WorkflowSupplyChainTests(unittest.TestCase):
    def test_external_actions_are_pinned_to_full_commit_shas(self) -> None:
        observed: list[tuple[Path, int, str]] = []
        unpinned: list[str] = []

        for workflow in _workflows():
            for line_number, line in enumerate(
                workflow.read_text(encoding="utf-8").splitlines(), start=1
            ):
                match = ACTION_REFERENCE.match(line)
                if match is None:
                    continue
                reference = match.group(1)
                if reference.startswith("./"):
                    continue
                observed.append((workflow, line_number, reference))
                _, separator, revision = reference.rpartition("@")
                if not separator or FULL_COMMIT_SHA.fullmatch(revision) is None:
                    unpinned.append(
                        f"{workflow.relative_to(REPOSITORY_ROOT)}:{line_number}: {reference}"
                    )

        self.assertTrue(observed, "No external GitHub Action references were found")
        self.assertEqual(
            [], unpinned, "Unpinned GitHub Actions:\n" + "\n".join(unpinned)
        )

    def test_checkout_never_persists_repository_credentials(self) -> None:
        observed = 0
        missing: list[str] = []
        for workflow in _workflows():
            lines = workflow.read_text(encoding="utf-8").splitlines()
            for index, line in enumerate(lines):
                if "uses: actions/checkout@" not in line:
                    continue
                observed += 1
                block = "\n".join(lines[index : index + 8])
                if "persist-credentials: false" not in block:
                    missing.append(str(workflow.relative_to(REPOSITORY_ROOT)))
        self.assertGreater(observed, 0)
        self.assertEqual(
            [], missing, "Checkout credentials persisted in: " + ", ".join(missing)
        )

    def test_locked_installs_require_hashes_and_binary_distributions(self) -> None:
        installs: list[tuple[Path, int, str]] = []
        invalid: list[str] = []
        for workflow in _workflows():
            for line_number, line in enumerate(
                workflow.read_text(encoding="utf-8").splitlines(), start=1
            ):
                if "pip install" not in line:
                    continue
                installs.append((workflow, line_number, line))
                if (
                    "--require-hashes" not in line
                    or "--only-binary=:all:" not in line
                    or "-r requirements.lock" not in line
                ):
                    invalid.append(
                        f"{workflow.relative_to(REPOSITORY_ROOT)}:{line_number}: {line.strip()}"
                    )
        self.assertTrue(installs, "No workflow dependency installation was found")
        self.assertEqual(
            [], invalid, "Unsafe workflow installs:\n" + "\n".join(invalid)
        )

    def test_complete_test_suites_are_warning_fatal_and_bytecode_free(self) -> None:
        missing: list[str] = []
        for workflow in _workflows():
            text = workflow.read_text(encoding="utf-8")
            suite_lines = [
                line
                for line in text.splitlines()
                if "python -m unittest discover -s tests" in line
            ]
            if not suite_lines or any(
                "PYTHONWARNINGS=error" not in line
                or "PYTHONDONTWRITEBYTECODE=1" not in line
                for line in suite_lines
            ):
                missing.append(str(workflow.relative_to(REPOSITORY_ROOT)))
        self.assertEqual(
            [], missing, "Non-warning-fatal suites in: " + ", ".join(missing)
        )

    def test_pages_write_authority_is_scoped_to_deploy_job(self) -> None:
        pages = (WORKFLOW_ROOT / "pages.yml").read_text(encoding="utf-8")
        pre_jobs, jobs = pages.split("\njobs:\n", 1)
        validate, deploy = jobs.split("\n  deploy:\n", 1)
        self.assertIn("permissions: {}", pre_jobs)
        self.assertNotIn("pages: write", pre_jobs)
        self.assertNotIn("id-token: write", pre_jobs)
        self.assertRegex(validate, r"(?m)^    permissions:\n      contents: read$")
        self.assertNotIn("pages: write", validate)
        self.assertNotIn("id-token: write", validate)
        self.assertRegex(
            deploy,
            r"(?m)^    permissions:\n      pages: write\n      id-token: write$",
        )

    def test_workflows_use_the_closed_manifest_validator(self) -> None:
        missing: list[str] = []
        prohibited: list[str] = []
        for workflow in _workflows():
            text = workflow.read_text(encoding="utf-8")
            if "python scripts/validate_manifest.py" not in text:
                missing.append(str(workflow.relative_to(REPOSITORY_ROOT)))
            if "shasum -a 256 -c MANIFEST.sha256" in text:
                prohibited.append(str(workflow.relative_to(REPOSITORY_ROOT)))
        self.assertEqual(
            [], missing, "Manifest validator absent from: " + ", ".join(missing)
        )
        self.assertEqual(
            [],
            prohibited,
            "Coverage-blind manifest checks remain in: " + ", ".join(prohibited),
        )

    def test_container_job_builds_without_publishing_and_smokes_fail_closed(
        self,
    ) -> None:
        workflow = (WORKFLOW_ROOT / "ci.yml").read_text(encoding="utf-8")
        self.assertIn("container-build:", workflow)
        self.assertIn("runs-on: ubuntu-24.04", workflow)
        self.assertIn("docker build --pull", workflow)
        self.assertIn("ADF_IMAGE_REVISION=${GITHUB_SHA}", workflow)
        self.assertIn("python3 scripts/validate_manifest.py", workflow)
        self.assertIn("docker image inspect", workflow)
        self.assertIn("docker run --rm", workflow)
        self.assertIn("Validate packaged policy and schema", workflow)
        self.assertIn("Run bounded storage-fault campaigns in the image", workflow)
        self.assertIn("tests.test_stage_a_sigkill_campaign", workflow)
        self.assertIn("tests.test_stage_a_storage_failure_campaign", workflow)
        self.assertIn("tests.container_stage_a_storage_fault", workflow)
        self.assertIn("ADF_CONTAINER_STORAGE_CAMPAIGN=1", workflow)
        self.assertIn("Run external container-kill campaign", workflow)
        self.assertIn("tests.test_stage_a_container_external_kill", workflow)
        self.assertIn("ADF_CONTAINER_EXTERNAL_KILL_CAMPAIGN=1", workflow)
        self.assertIn(
            "--tmpfs /audit-volume:rw,noexec,nosuid,nodev,size=1m,"
            "uid=10001,gid=10001,mode=0700",
            workflow,
        )
        self.assertIn(
            '--volume "${GITHUB_WORKSPACE}/tests:/opt/adf/tests:ro"', workflow
        )
        for restriction in (
            "--network=none",
            "--read-only",
            "--tmpfs /tmp:rw,noexec,nosuid,nodev,size=16m",
            "--user 10001:10001",
        ):
            self.assertIn(restriction, workflow)
        for publishing_command in (
            "docker push",
            "build-push-action",
            "login-action",
            "cosign sign",
        ):
            self.assertNotIn(publishing_command, workflow)


if __name__ == "__main__":
    unittest.main()
