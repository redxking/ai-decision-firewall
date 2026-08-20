# Supply-chain control boundary

## Implemented project-controlled controls

The production-development candidate carries two generated dependency locks:

- `requirements.lock` closes the runtime graph to exact versions and accepted
  SHA-256 distribution hashes;
- `requirements-docs.lock` does the same for the documentation toolchain.

The lock validator consumes the complete accepted pip-compile grammar. It
rejects an option, include, URL, local path, marker, editable requirement,
unparsed line, unterminated continuation, duplicate package, duplicate hash, or
package without a SHA-256 hash. Direct runtime requirements must exactly match
the dependency declarations in `pyproject.toml`, must be present in the runtime
lock, and every direct locked version must satisfy its declared closed numeric
range. Documentation requirements receive the same presence and version-range
check against the documentation lock.

CI and the release-triggered Pages validation job install with both
`--require-hashes` and `--only-binary=:all:`. This prohibits an unreviewed sdist
build and fails if the lock has no accepted wheel for the runner. Checkout does
not retain repository credentials. Test execution treats warnings as failures.
Pages write and OIDC permissions exist only on the deployment job; validation
has read-only repository access.

The CI source also defines a separate, non-publishing container job. It verifies
the repository manifest before building the digest-pinned Dockerfile, binds the
OCI revision label to the exact workflow SHA, inspects the configured non-root
user and entry point, and smoke-runs the image with no network, a read-only root
filesystem, a bounded temporary filesystem, and UID/GID `10001:10001`. The job
has no registry login, push, signing, release, package, or deployment authority.
This is a configured verification mechanism until an exact-candidate workflow
run is observed and retained.

Every external GitHub Action reference is pinned to a full 40-character commit
identifier. The repository manifest validator obtains the tracked inventory
from Git, requires exactly one sorted canonical entry for every tracked regular
file except the manifest itself, rejects missing, extra, duplicate, escaping,
symbolic-link, or multiply linked paths, and verifies every recorded SHA-256
digest. This closes the prior failure mode where a file and its manifest line
could be removed together without failing a coverage-blind hash check.

`artifacts/supply-chain/runtime.cdx.json` is a CycloneDX 1.6 component inventory
generated with the reproducible-output marker. Validation uses bounded strict
JSON decoding, rejects duplicate members and non-finite values, enforces a
closed document/component/dependency shape, and requires:

- exact project identity from `pyproject.toml`;
- one canonical component for every runtime lock entry and no others;
- exact package version, purl, and unique component reference;
- an exact, sorted distribution-hash set equal to the lock; and
- exact root edges for the direct runtime dependencies.

The SBOM's component rows do not establish a complete transitive dependency
relationship graph. The generator toolchain itself is not locked by this
runtime graph, so the marker and deterministic ordering checks are not evidence
of an independently reproduced byte-identical SBOM.

## Verification commands

```text
python scripts/validate_supply_chain.py
python scripts/validate_manifest.py
python -m pip install --require-hashes --only-binary=:all: -r requirements.lock
PYTHONWARNINGS=error PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src:. python -m unittest tests.test_supply_chain_artifacts tests.test_workflow_supply_chain
```

Lock, SBOM, workflow, and manifest validation are network-free. Installation
requires access to an approved package index containing a compatible binary
distribution whose digest is already present in the lock. Do not remove
`--only-binary=:all:` or `--require-hashes` to work around an installation
failure.

## Explicit limitations

These controls reduce dependency drift, hidden lock directives, manifest
omissions, GitHub Action tag movement, validation-job authority, and source-build
execution. They do not establish that a pinned upstream commit, accepted wheel,
package index, runner, or build host is trustworthy. The SBOM and manifest are
project-generated and unsigned. No completed vulnerability disposition,
hermetic or independently reproduced build, signed provenance, release
signature, transparency-log entry, trusted builder, isolated build network,
private package mirror, or independent verification is claimed. The Python/pip
bootstrap and the package used to generate the SBOM remain outside the runtime
lock. The non-publishing CI container job is not a vulnerability scan, signed
artifact, provenance attestation, reproducibility result, or evidence that the
runner or upstream image is trustworthy.

The production gate remains `BLOCKED`. These mechanisms do not supply
release-owner acceptance, platform-owner acceptance, deployment authority,
managed key custody, operational effectiveness, or an approved release.
