# Source provenance

> **Version boundary.** This record documents the initial v0.1 archive import;
> the current repository includes later normal Git development. Exact Phase 2.5
> Commit `854b15c56397a81de6326b719d3d7d1dc847608f` is published on `main` and its
> exact-commit CI/Dependency Graph checks passed. The tracked data, model, and
> baseline outputs remain at their committed bytes. Phase 3 `0.3.0-alpha.1` is
> an uncommitted local candidate and therefore has no final commit-bound provenance or CI
> claim. `P2-CE-005` was not executed and remains CE-0 `NOT_EVALUATED`.

The repository was initialized from `AI_Decision_Firewall_POC_v0.1.zip`.

- Source archive SHA-256: `16ae3d013c4d2b8fbdc46caba93300d04ec634be85b571d353ce6efb3ac4160e`
- Archive inspection: 80 entries, approximately 16 MB uncompressed, with no absolute paths, traversal paths, or symbolic-link entries detected
- Imported v0.1 integrity check: all 68 entries in the archive's original `MANIFEST.sha256` verified before public-release edits

The request referenced the archive at `/mnt/data/AI_Decision_Firewall_POC_v0.1.zip`, but that path was not present when this work ran. A matching-name local copy was used. Because the referenced object was unavailable, this record does not claim byte-for-byte parity with that unavailable path.

The initial public-release edits updated documentation, distribution markings, ignore rules, and the repository integrity manifest. Subsequent Phase 2 development added code, contracts, schemas, synthetic fixtures, evidence records, tests, and technical documentation through normal Git history. Release-specific evidence records bind the exact commits and artifacts they evaluate; they do not retroactively change the v0.1 archive result.

`MANIFEST.sha256` is a repository snapshot, not the original archive manifest,
a signature, or an external trust anchor. The manifest committed in exact Phase
2.5 Commit `854b15c` applies only to that Git tree. The local Phase 3 files are
new project-authored code, contracts, policy, tests, documentation, demos, and
synthetic corpus fixtures layered on that commit; they are not derived from an
external operational dataset or vendor connector. Their final manifest and
provenance boundary remain pending candidate freeze.

Phase 3 evidence attestations are runtime synthetic HMAC controls, not source
provenance for this repository and not an independent source trust anchor. No
local edit, test/demo/corpus run, manifest regeneration, document render,
package commit, or CI result by itself establishes a tagged release, an
evidence package, source truth, or external assurance.
