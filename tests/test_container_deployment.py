from __future__ import annotations

import json
import re
import shutil
import subprocess
import textwrap
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
KUBERNETES_ROOT = ROOT / "deploy" / "kubernetes"
BASE = KUBERNETES_ROOT / "base"
BOOTSTRAP = KUBERNETES_ROOT / "bootstrap"
SHA256_IMAGE = re.compile(r"^[a-z0-9./_:-]+@sha256:[0-9a-f]{64}$")
ZERO_IMAGE = "registry.invalid/ai-decision-firewall/stage-a@sha256:" + ("0" * 64)


def _read(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def _images(text: str) -> list[str]:
    return [
        line.split("image:", 1)[1].strip()
        for line in text.splitlines()
        if line.lstrip().startswith("image:")
    ]


def _config_json() -> dict[str, object]:
    lines = _read(BASE / "configmap.yaml").splitlines()
    marker = lines.index("  service.json: |")
    payload = "\n".join(
        line[4:] for line in lines[marker + 1 :] if line.startswith("    ")
    )
    return json.loads(textwrap.dedent(payload))


def _render(directory: Path) -> str:
    kubectl = shutil.which("kubectl")
    if kubectl is None:
        raise unittest.SkipTest(
            "kubectl is unavailable; static source checks still ran"
        )
    completed = subprocess.run(
        [kubectl, "kustomize", str(directory)],
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
        timeout=20,
    )
    if completed.returncode != 0:
        raise AssertionError(completed.stderr or completed.stdout)
    return completed.stdout


class ContainerBuildTests(unittest.TestCase):
    def test_base_image_and_runtime_dependencies_are_closed(self) -> None:
        dockerfile = _read(ROOT / "Dockerfile")
        bases = re.findall(r"(?m)^FROM (\S+) AS \S+$", dockerfile)
        self.assertEqual(2, len(bases))
        self.assertEqual(1, len(set(bases)))
        for base in bases:
            self.assertRegex(base, SHA256_IMAGE)
            self.assertIn("python:3.12.13-slim-bookworm@sha256:", base)
            self.assertNotEqual("0" * 64, base.rsplit(":", 1)[1])
        self.assertNotIn("ARG PYTHON_BASE", dockerfile)
        for flag in (
            "--no-cache-dir",
            "--no-compile",
            "--no-deps",
            "--only-binary=:all:",
            "--require-hashes",
        ):
            self.assertIn(flag, dockerfile)
        self.assertNotIn("apt-get", dockerfile)
        self.assertNotIn(" curl ", dockerfile)
        self.assertNotIn(" wget ", dockerfile)
        self.assertNotRegex(dockerfile, r"(?m)^ADD\s")
        self.assertIn(
            "COPY contracts/v0.3.0/phase3-policy.schema.json "
            "/opt/adf/contracts/v0.3.0/phase3-policy.schema.json",
            dockerfile,
        )
        self.assertIn(
            "COPY contracts/v0.3.0/decision-request.schema.json "
            "/opt/adf/contracts/v0.3.0/decision-request.schema.json",
            dockerfile,
        )

    def test_final_image_is_nonroot_and_has_no_network_exposure(self) -> None:
        dockerfile = _read(ROOT / "Dockerfile")
        self.assertIn("USER 10001:10001", dockerfile)
        self.assertIn("RUN mkdir -p /etc/adf", dockerfile)
        self.assertIn("PYTHONDONTWRITEBYTECODE=1", dockerfile)
        self.assertIn("HEALTHCHECK NONE", dockerfile)
        self.assertIn('ENTRYPOINT ["python", "/opt/adf/run_service.py"]', dockerfile)
        self.assertIn('"serve"', dockerfile)
        self.assertIn('"127.0.0.1"', dockerfile)
        self.assertIn('"--workers", "1"', dockerfile)
        self.assertIn('"--require-existing"', dockerfile)
        self.assertNotRegex(dockerfile, r"(?m)^EXPOSE\s")

    def test_privileged_storage_lab_is_separate_and_explicitly_gated(self) -> None:
        lab = _read(ROOT / "tests" / "Dockerfile.stage-a-storage-lab")
        runner = _read(ROOT / "scripts" / "run_stage_a_block_device_campaign.py")
        self.assertIn("ARG ADF_BASE_IMAGE", lab)
        self.assertIn("dmsetup=2:1.02.185-2", lab)
        self.assertIn("e2fsprogs", lab)
        self.assertIn("util-linux", lab)
        self.assertNotIn("COPY ", lab)
        self.assertIn("--allow-privileged-lab", runner)
        self.assertIn('"--privileged"', runner)
        self.assertIn('"--network=none"', runner)
        self.assertIn("ADF_CONTAINER_BLOCK_DEVICE_CAMPAIGN=1", runner)
        self.assertIn("/lab:rw,nosuid,nodev,size=256m", runner)
        self.assertNotIn("/dev/sd", runner)
        self.assertNotIn("/dev/nvme", runner)

    def test_build_context_is_allowlisted(self) -> None:
        ordered_rows = [
            row.strip()
            for row in _read(ROOT / ".dockerignore").splitlines()
            if row.strip()
        ]
        rows = set(ordered_rows)
        self.assertIn("*", rows)
        for required in (
            "!Dockerfile",
            "!requirements.lock",
            "!run_service.py",
            "!src/**",
            "!config/phase3_policy.json",
            "!contracts/v0.3.0/decision-request.schema.json",
            "!contracts/v0.3.0/phase3-policy.schema.json",
            "!artifacts/supply-chain/runtime.cdx.json",
        ):
            self.assertIn(required, rows)
        for ignored in (
            "src/**/__pycache__/",
            "src/**/*.py[cod]",
            "src/**/.DS_Store",
        ):
            self.assertIn(ignored, rows)
            self.assertGreater(
                ordered_rows.index(ignored), ordered_rows.index("!src/**")
            )


class KubernetesDeploymentTests(unittest.TestCase):
    def test_base_resource_set_renders_without_network_endpoint(self) -> None:
        rendered = _render(BASE)
        kinds = re.findall(r"(?m)^kind: (\S+)$", rendered)
        self.assertCountEqual(
            kinds,
            [
                "Namespace",
                "ServiceAccount",
                "ConfigMap",
                "PersistentVolumeClaim",
                "Deployment",
                "PodDisruptionBudget",
                "NetworkPolicy",
            ],
        )
        self.assertNotIn("kind: Service\n", rendered)
        self.assertNotIn("kind: Ingress\n", rendered)
        self.assertNotIn("containerPort:", rendered)
        self.assertNotIn("hostPort:", rendered)
        self.assertTrue(_images(rendered))
        self.assertEqual({ZERO_IMAGE}, set(_images(rendered)))

    def test_workload_is_single_writer_recreate_and_rwop(self) -> None:
        deployment = _read(BASE / "deployment.yaml")
        claim = _read(BASE / "persistentvolumeclaim.yaml")
        disruption = _read(BASE / "poddisruptionbudget.yaml")
        self.assertRegex(deployment, r"(?m)^  replicas: 1$")
        self.assertRegex(deployment, r"(?ms)^  strategy:\n    type: Recreate$")
        self.assertIn("ReadWriteOncePod", claim)
        self.assertNotRegex(claim, r"(?m)^\s+- ReadWriteOnce$")
        self.assertRegex(disruption, r"(?m)^  minAvailable: 1$")
        self.assertNotIn("maxUnavailable", disruption)

    def test_pods_and_containers_use_restricted_security_contexts(self) -> None:
        manifests = (
            _read(BASE / "deployment.yaml"),
            _read(BOOTSTRAP / "job.yaml"),
        )
        for required in (
            "automountServiceAccountToken: false",
            "enableServiceLinks: false",
            "hostIPC: false",
            "hostNetwork: false",
            "hostPID: false",
            "runAsNonRoot: true",
            "runAsUser: 10001",
            "runAsGroup: 10001",
            "fsGroup: 10001",
            "fsGroupChangePolicy: OnRootMismatch",
            "type: RuntimeDefault",
            "allowPrivilegeEscalation: false",
            "privileged: false",
            "readOnlyRootFilesystem: true",
        ):
            for manifest in manifests:
                self.assertIn(required, manifest)
        for manifest in manifests:
            self.assertGreaterEqual(manifest.count("readOnlyRootFilesystem: true"), 2)
            self.assertGreaterEqual(manifest.count("- ALL"), 2)
            self.assertGreaterEqual(manifest.count("ephemeral-storage:"), 4)
            self.assertNotIn("hostPath:", manifest)

    def test_runtime_is_loopback_only_and_probe_paths_are_distinct(self) -> None:
        deployment = _read(BASE / "deployment.yaml")
        self.assertIn("- 127.0.0.1", deployment)
        self.assertIn('- --workers\n            - "1"', deployment)
        self.assertIn("- --require-existing", deployment)
        self.assertIn("startupProbe:", deployment)
        self.assertIn("readinessProbe:", deployment)
        self.assertIn("livenessProbe:", deployment)
        self.assertGreaterEqual(deployment.count("http://127.0.0.1:8080/livez"), 2)
        self.assertEqual(1, deployment.count("http://127.0.0.1:8080/readyz"))
        self.assertNotIn("0.0.0.0", deployment)

    def test_network_policy_is_closed_in_both_directions(self) -> None:
        policy = _read(BASE / "networkpolicy.yaml")
        self.assertIn("podSelector: {}", policy)
        self.assertIn("- Ingress", policy)
        self.assertIn("- Egress", policy)
        self.assertNotRegex(policy, r"(?m)^  ingress:")
        self.assertNotRegex(policy, r"(?m)^  egress:")

    def test_config_is_synthetic_only_and_contains_no_secret_value(self) -> None:
        config = _config_json()
        self.assertEqual(
            {
                "schema_version",
                "runtime_profile",
                "policy_path",
                "state_directory",
                "signing_key_file",
                "evidence_key_files",
                "principals",
                "store_busy_timeout_ms",
            },
            set(config),
        )
        self.assertEqual("STAGE_A_SYNTHETIC_ONLY", config["runtime_profile"])
        self.assertEqual("/var/lib/adf-volume/state", config["state_directory"])
        policy = json.loads(_read(ROOT / "config" / "phase3_policy.json"))
        trusted_sources = set(policy["evidence"]["trusted_sources"])
        self.assertEqual(
            trusted_sources,
            set(dict(config["evidence_key_files"])),
        )
        serialized = json.dumps(config, sort_keys=True)
        self.assertNotIn("http://", serialized)
        self.assertNotIn("https://", serialized)
        self.assertNotIn("connector", serialized.lower())
        self.assertNotIn("live_action", serialized.lower())
        for value in [
            config["signing_key_file"],
            *dict(config["evidence_key_files"]).values(),
        ]:
            self.assertTrue(str(value).startswith("/var/run/adf/staged/secrets/"))
        principals = list(config["principals"])
        self.assertEqual(1, len(principals))
        self.assertTrue(
            str(principals[0]["credential_file"]).startswith(
                "/var/run/adf/staged/secrets/"
            )
        )
        self.assertTrue(
            str(principals[0]["principal"]["identity_source"]).startswith("synthetic_")
        )
        self.assertNotIn("kind: Secret", _read(BASE / "configmap.yaml"))

    def test_projected_secret_keys_exactly_match_closed_config(self) -> None:
        expected = {
            "authorization-signing.key",
            "CMDB_PRIMARY.key",
            "CTI_PRIMARY.key",
            "EDR_PRIMARY.key",
            "IDP_PRIMARY.key",
            "NETWORK_PRIMARY.key",
            "SOC_AGENT_01.credential",
        }
        for manifest in (
            _read(BASE / "deployment.yaml"),
            _read(BOOTSTRAP / "job.yaml"),
        ):
            keys = set(re.findall(r"(?m)^\s+- key: (\S+)$", manifest))
            paths = set(re.findall(r"(?m)^\s+path: (\S+)$", manifest))
            self.assertEqual(expected, keys - {"service.json"})
            self.assertEqual(expected, paths - {"service.json"})
            self.assertNotIn("secretKeyRef:", manifest)
            self.assertNotIn("envFrom:", manifest)

    def test_immutable_config_is_mounted_as_a_real_single_file(self) -> None:
        deployment = _read(BASE / "deployment.yaml")
        bootstrap = _read(BOOTSTRAP / "job.yaml")
        for manifest in (deployment, bootstrap):
            self.assertEqual(2, manifest.count("mountPath: /etc/adf/service.json"))
            self.assertEqual(2, manifest.count("subPath: service.json"))
            self.assertNotIn("mountPath: /etc/adf\n", manifest)

    def test_projected_secrets_are_staged_to_bounded_tmpfs(self) -> None:
        deployment = _read(BASE / "deployment.yaml")
        self.assertIn("name: stage-runtime-secrets", deployment)
        self.assertIn("- stage-secrets", deployment)
        self.assertIn("secretName: adf-stage-a-runtime-secrets-v1", deployment)
        self.assertIn("mountPath: /var/run/adf/projected", deployment)
        self.assertIn("- /var/run/adf/staged/secrets", deployment)
        self.assertIn("mountPath: /var/run/adf/staged", deployment)
        self.assertRegex(
            deployment,
            r"(?ms)- name: runtime-secrets\n          emptyDir:\n            medium: Memory\n            sizeLimit: 1Mi",
        )
        self.assertRegex(
            deployment,
            r"(?ms)mountPath: /var/run/adf/staged\n              readOnly: true",
        )
        self.assertNotIn("mountPath: /var/run/adf/staged/secrets", deployment)

    def test_owner_private_state_is_a_child_of_the_pvc_mount(self) -> None:
        deployment = _read(BASE / "deployment.yaml")
        config = _config_json()
        self.assertEqual("/var/lib/adf-volume/state", config["state_directory"])
        self.assertIn("mountPath: /var/lib/adf-volume", deployment)
        self.assertNotIn("mountPath: /var/lib/adf\n", deployment)

    def test_bootstrap_is_separate_bounded_one_shot_job(self) -> None:
        rendered = _render(BOOTSTRAP)
        kinds = re.findall(r"(?m)^kind: (\S+)$", rendered)
        self.assertIn("Job", kinds)
        self.assertNotIn("Deployment", kinds)
        self.assertNotIn("PodDisruptionBudget", kinds)
        self.assertNotIn("Service", kinds)
        self.assertNotIn("Ingress", kinds)
        self.assertIn("backoffLimit: 0", rendered)
        self.assertIn("- initialize", rendered)
        self.assertIn("- --expect-empty", rendered)
        self.assertNotIn("restartPolicy: Always", rendered)
        self.assertIn("restartPolicy: Never", rendered)
        self.assertEqual({ZERO_IMAGE}, set(_images(rendered)))

    def test_repository_contains_no_deployable_inline_secret_or_floating_image(
        self,
    ) -> None:
        yaml_files = sorted(KUBERNETES_ROOT.rglob("*.yaml"))
        self.assertTrue(yaml_files)
        for path in yaml_files:
            text = _read(path)
            self.assertNotIn("\t", text, path)
            self.assertFalse(
                any(line.rstrip() != line for line in text.splitlines()), path
            )
            self.assertNotIn("kind: Secret", text, path)
            for image in _images(text):
                self.assertRegex(image, SHA256_IMAGE, path)
                self.assertNotIn(":latest", image, path)


if __name__ == "__main__":
    unittest.main()
