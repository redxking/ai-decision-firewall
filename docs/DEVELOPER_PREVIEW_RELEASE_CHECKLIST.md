# `v0.4.0-alpha.2` Developer Preview Release Checklist

**Target:** 2026-08-22

**Scope:** offline synthetic Stage A developer preview

**Production gate:** `BLOCKED`

**Release authority conveyed:** none

This checklist governs a public GitHub prerelease for developers to evaluate
the synthetic mechanism. It does not approve live data, external integrations,
operational decisions, containment actions, or production deployment.

## Candidate acceptance

- [ ] Clean-clone locked install succeeds on supported Python 3.11 and 3.12.
- [ ] `run_preview.py demo` succeeds from a clean clone.
- [ ] The workstation case records a synthetic adapter receipt and ends
  `COMPLETED_VERIFIED`.
- [ ] The Tier 0 domain-controller case ends `DENIED_NO_EFFECT` with no adapter
  receipt.
- [ ] Restart plus `status` remains `READY` and reports a valid audit chain.
- [ ] Generated-request submission succeeds; changed synthetic-only markers or
  signed evidence fail closed without a new lifecycle.
- [ ] Reset refuses unmarked/unexpected directories and removes only an exact
  marked preview directory after explicit confirmation.
- [ ] Full warning-fatal test suite, supply-chain validation, tracked-file
  manifest validation, and restricted container preview all pass.
- [ ] Pull-request CI and exact merged-`main` CI pass on the candidate bytes.
- [ ] Candidate commit, manifest digest, test counts, CI run, known limitations,
  and production `BLOCKED` state are recorded in release notes.
- [ ] The annotated version tag names the exact verified merged commit.
- [ ] GitHub Release is marked as a prerelease and contains no binaries,
  credentials, databases, raw audit logs, or production claims.

## Stop conditions

Do not tag or publish if any acceptance item above is incomplete, if the source
tree is dirty, if the candidate differs from the exact CI-tested commit, if
manifest coverage or digest validation fails, or if any test observes a live
connector, external target, unbounded network exposure, duplicate synthetic
effect, audit discontinuity, unauthorized authority issuance, or unsafe reset.

## Post-release intake

Use GitHub issues for synthetic reproductions only. Require the source commit,
platform, Python version, command, sanitized output, and whether restart/status
remained ready. Reject operational data, credentials, private databases, or
unreviewed audit logs. Security-sensitive reports follow `SECURITY.md` rather
than a public issue.
