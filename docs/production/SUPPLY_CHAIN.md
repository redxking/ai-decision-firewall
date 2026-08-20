# Supply-chain control boundary

## Implemented project-controlled controls

The production-development candidate carries two generated dependency locks:

- `requirements.lock` closes the runtime graph to exact versions and accepted
  SHA-256 distribution hashes;
- `requirements-docs.lock` does the same for the documentation toolchain.

CI and the release-triggered Pages validation workflow install the runtime graph
with `pip --require-hashes`. Every external GitHub Action reference in both
workflows is pinned to a full 40-character commit identifier. The test suite
rejects a reintroduced tag, branch, short SHA, missing hash, missing direct
dependency, SBOM/lock mismatch, incomplete SBOM root edge, duplicate component,
or project identity mismatch.

`artifacts/supply-chain/runtime.cdx.json` is a reproducible CycloneDX 1.6 JSON
inventory generated from the runtime lock. Its component set is required to
equal the lock exactly, and its root component is required to bind the direct
runtime dependencies declared by `requirements.txt`.

## Verification commands

```text
python scripts/validate_supply_chain.py
python -m pip install --require-hashes -r requirements.lock
python -m unittest tests.test_supply_chain_artifacts tests.test_workflow_supply_chain
```

The lock and SBOM validation is network-free. Installation requires access to
an approved package index containing a distribution whose digest is already in
the lock.

## Explicit limitations

These controls reduce dependency drift and GitHub Action tag-movement risk.
They do not establish that a pinned upstream commit, package-index artifact,
runner, or build host is trustworthy. The SBOM is project-generated and
unsigned. No vulnerability disposition, hermetic or reproducible cross-platform
build, signed provenance, release signature, transparency-log entry, trusted
builder, isolated build network, private package mirror, or independent
verification is claimed.

The production gate therefore remains `BLOCKED`. These artifacts do not supply
release-owner acceptance, platform-owner acceptance, deployment authority,
managed key custody, or operational effectiveness.
