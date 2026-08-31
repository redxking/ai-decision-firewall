# Reproducibility boundary

**Status:** Working design control; no new campaign evidence  
**Date:** 2026-08-15  
**Scope:** Synthetic Phase 1 model construction, Phase 2 artifact consumption,
published Phase 3 `0.3.0-alpha.1` synthetic demonstrations/corpus, and the
Phase 3.1 synthetic-only model-evaluation mechanism

## Decision

The repository distinguishes three different claims that were previously easy to conflate:

1. **Frozen-artifact replay:** a Phase 2 run consumes the exact model, policy, contract, and input bytes named by their digests. This is the authoritative campaign boundary.
2. **Within-environment regeneration:** a deterministic-regeneration claim may be made only after the builder environment is frozen, recorded, independently repeated, and validated. No such builder claim is established by this document.
3. **Cross-environment retraining:** retraining is not presently claimed to reproduce byte-identical floating-point model parameters across every permitted Python, NumPy, BLAS, processor, or operating-system combination.

The ordinary `python run_poc.py` path permits repository writes only beneath `data/local/**` and `outputs/local/**`; explicitly supplied paths outside the repository remain possible. `--allow-tracked-artifact-overwrite` expands the repository allowance only to `data/**` and `outputs/baseline/**` for an approved freeze workflow. Other repository locations, case-variant repository aliases, symlink redirects, and overlapping data/output trees are rejected. Preflight enumerates every generated data and output leaf, including `run_manifest.json`, and rejects existing symlinks, nonregular files, or multiply linked leaves. The local run manifest SHA-256-binds the other seven generated outputs. Fourteen focused safety tests pass for this bounded behavior.

These checks are local operator interlocks, not an OS sandbox, mount boundary, TOCTOU/race guarantee, comprehensive hardlink defense, or confinement of direct calls to lower-level writer functions. The explicit flag is not evidence that approval occurred.

The Phase 3 demo and corpus runners separately require an absent or empty output
directory. They refuse to clobber a nonempty destination. The demo uses fresh
runtime-only synthetic HMAC/signing keys and therefore does not claim
byte-identical volatile identifiers, signatures, audit hashes, or timestamps
across runs. Its required semantic decisions/effects and lifecycle invariants
are reproducible. The corpus freezes time, scenario IDs, expectations, and
deterministic synthetic runtime key material so its bounded summary is stable;
the output deliberately omits reusable authority/signatures and keys. The
published semantic observations are 57/57 focused tests, two demonstration
acceptance checks PASS, 46/46 corpus scenarios, and 288/288 full repository
tests for exact Commit `423685d105be813056617db738297eba83d3d9d0`; exact-commit
CI and Dependency Graph checks passed.

These are application-level output and determinism controls, not OS/process
confinement, external custody, production key handling, a published evidence
package, or an operational repeatability claim.

## Rationale

The training path uses NumPy mean, standard-deviation, and matrix reductions and serializes binary floating-point parameters at full precision. Different permitted runtimes can produce last-bit coefficient differences. Those differences may leave rounded decisions unchanged while still changing the model SHA-256 digest. Digest enforcement must reject that drift; it must not normalize it away after a campaign is frozen.

## Required freeze workflow

A future model replacement must:

1. freeze the training source, input bytes, seed, dependency resolution, interpreter, platform, and numeric serialization rule;
2. train once in the designated builder and independently repeat the build before accepting the bytes;
3. compare model parameters, decisions, threshold margins, and safety invariants—not only aggregate metrics;
4. assign a new model version and digest rather than overwrite prior evidence silently;
5. update dependent campaign plans only after the new model is intentionally accepted;
6. freeze implementation before running any evidence campaign; and
7. retain the prior model and evidence records as historical artifacts.

If portable byte-for-byte model rebuilding becomes a requirement, the project must first define and validate a canonical numeric algorithm and serialization precision across the supported environment matrix. Quantizing existing bytes after training is not sufficient by itself because it can conceal decision-boundary changes.

## Current nonclaim

The tracked synthetic data, campaign-bound model, and `outputs/baseline/**` are
at their committed Phase 2.5 bytes. Ordinary local execution is designed not to
alter them. Phase 3 runtime fixtures do not replace or validate that model or
dataset. This document does not establish portable byte-identical retraining,
independently attest artifact custody, approve a replacement model, update any
frozen plan, create `P2-CE-005` evidence, elevate Phase 3 observations beyond
simulation-only CE-1 implementation conformance, or authorize the Phase 3.1
candidate to use historical data or promote a model.
