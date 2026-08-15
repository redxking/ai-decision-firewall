# POC Test Suite

Run from the repository root:

```bash
PYTHONPATH=src python -m unittest discover -s tests -v
```

The 147-test suite focuses on safety and evidence invariants rather than synthetic classifier accuracy. It covers the original abstention, break-glass, human-authority, authorization, label-separation, and audit-tamper controls plus the Phase 2 read-only execution boundary, replay contracts, path confinement, canonical-context consistency, frozen input snapshots, descriptor-bound historical output, in-memory historical decision processing, temporal normalization, post-decision adjudication decoding, deterministic artifacts, exact eight-stage decision/audit binding, Gate B campaign evidence, typed/source-authorized features, separate reference projection, strict evidence-number handling, exact authorization-state rejection, zero token/broker/effect assertions, and the three current narrow claim-evidence records.

Phase 2.1 qualification coverage includes:

- the predeclared seven-record campaign with three accepted and four quarantined records;
- exact reasons for invalid JSON, a missing field, an invalid timestamp, and canonical-context mismatch;
- `input = accepted + quarantined`, exact rejection projection, and one decision per accepted case;
- source-file, physical-line, nonblank-ordinal, and raw-line-digest binding;
- byte-deterministic qualification and rejection artifacts;
- closed-schema and representation tests that prevent rejected payload and raw validator-text disclosure;
- fatal whole-call behavior for source-read faults, encoding, line-size, record-count, JSON-nesting, version, label, duplicate-ID, source-integrity, and unmapped-validator failures;
- forged, substituted, empty-acceptance, or incomplete qualification results rejected in validate-only and run paths before engine invocation;
- deterministic fixture-generation checks against pinned reviewed-source digests; and
- fail-closed protection against symlinked target directories, hard-linked target files, and source read/hash inconsistency.

These are synthetic control tests with `historical_case_count=0`. They do not measure historical acceptance, historical efficacy, operational performance, agentic alignment, or live-shadow readiness.

Phase 2.2 Gate B coverage includes:

- closed-schema and runtime agreement for approval states, exact roles, controls, review, counts, bindings, path syntax, and resource ceilings;
- rejection of missing, DRAFT, expired, malformed, mismatched, nonhistorical, or unsafe packages before any case or adjudication open, hash, count, decode, or parse;
- confined nonsymlink Gate B inputs under ignored `local/gate_b/` and descriptor-bound, owner-only historical outputs under ignored `outputs/replay/<run>/`, including ancestor-relocation and run-directory-substitution negative controls;
- frozen manifest, model, policy, mapping, and protocol bytes with mutation and symlink-swap detection;
- sanitized failures that do not echo private paths, digests, operating-system errors, unexpected field names, or injected values;
- missing private paths and qualification schemas fail through bounded validate-only and run errors, while duplicate JSON object members are rejected rather than accepted with last-member-wins behavior;
- post-qualification window and exact-decimal quarantine thresholds that stop before normalization or engine invocation;
- staged authorization expiry prevents completion, and unrecognized audit record types fail the replay evidence boundary;
- a path-free historical runner interface containing only in-memory accepted cases, model bytes, policy bytes, and the read-only execution mode, with adjudication bytes withheld until decision and audit closure; and
- zero authorization attempts, tokens, broker calls, action results, or operational effects for the fixed test-only package.

These tests establish implementation and negative-control coverage in the current checkout. No real Gate B approval or historical evidence bundle exists, so they do not establish organizational authority, privacy effectiveness, custody validity, or historical performance.

Phase 2.3 audit-conformance coverage additionally rejects:

- any missing, duplicate, or reordered stage from the exact per-case sequence `CASE_RECEIVED`, `EVIDENCE_ASSESSED`, `MODEL_ASSESSED`, `POLICY_PROPOSED`, `INDEPENDENTLY_VERIFIED`, `EXECUTION_SUPPRESSED`, `AUTHORIZATION_EVALUATED`, and `DECISION_FINALIZED`;
- extra row or payload fields, noninteger or discontinuous sequence values, and malformed, timezone-naive, or decreasing timestamps;
- forged code-owned suppression values and counterfactual action lists that differ from the exact frozen policy; and
- mismatched decision identifiers or hashes, unknown record types, and duplicate JSON object members.

That coverage is CE-1 implementation-conformance evidence only. It cross-checks the presented audit, decisions, and policy actions; it does not independently recompute source-to-decision/model/policy correctness, establish externally trusted time or custody, or prevent wholesale replacement of the self-custodied chain.

The `P2-CE-003` controlled-behavior tests validate the closed campaign plan, schema, profile, result rows, summary, and exact evidence record. The published result contains two complete repetitions of 16 fixed synthetic scenarios (32/32 project-controlled expected-outcome matches), including two validate-only passes, 28 structural pre-payload blocks, and two post-qualification/pre-engine threshold blocks. The two sanitized result ledgers are byte-identical. During the 28 structural-block harness invocations, no governed payload-role open/read attempt was observed by the declared `Path`/`os.open` hooks; across all 32 attempts, no engine, authorization, broker, or target-effect boundary was reached and no completed run manifest, decision artifact, or audit artifact was observed.

Negative claim-evidence tests reject extra or reordered results, missing attempts, outcome drift, nonzero boundary counters, source-binding changes, duplicate JSON members, and authorization-canary disclosure. The result remains a SELF automated project-controlled synthetic check. It includes no real approval or actual historical data, and it does not establish independent/statistical trials, external preregistration, OS-level nonaccess/non-egress, target-side proof, exhaustive coverage, a bounded failure rate, efficacy, live safety, or alignment/misalignment behavior.

Phase 2.4 feature-assurance coverage additionally verifies:

- exact JSON Boolean handling and source authorization for all modeled Boolean attributes;
- finite integral `failed_logins` values in `0..1,000,000`, including accepted `10.0` and rejected Boolean, string, fractional, non-finite, negative, and over-bound forms;
- mandatory exact equality of `asset_id`, `privilege_level`, `break_glass`, and `asset_criticality` across the case and every asset-inventory event;
- opaque-attribute feature-projection invariance and event-order metamorphic behavior;
- rejection of non-finite JSON numbers anywhere in an accepted case and exact Boolean/network-only handling of decision-driving `source_conflict`, which is outside reference feature recomputation; under `QUARANTINE_RECORD`, wrong source is `SEMANTICS / UNAUTHORIZED_DECISION_SIGNAL` and wrong type is `SEMANTICS / INVALID_BOOLEAN`;
- exact normalized-case digest binding: SHA-256 over UTF-8 canonical JSON generated with sorted keys, compact separators, `ensure_ascii=True`, `allow_nan=False`, and no trailing newline;
- a separately implemented standard-library-only projector for all 20 feature values and feature-to-event traces;
- exact/unique case-set and normalized-case hash binding;
- closed metadata-only assurance rows, duplicate-member-aware persisted JSONL validation, and run-manifest/metrics count and digest bindings;
- failure before evaluator loading, qualification/rejection publication, comparisons, metrics, or completed run-manifest finalization; and
- coherent feature-value, feature-trace, source-context, decision-hash, and fully rechained-audit forgeries that pass the legacy validators but are rejected by the reference projector.

On a reference mismatch, earlier raw/normalized/deterministic decisions and audit artifacts may remain and are intentionally incomplete; no `reference_feature_assurance.jsonl`, metrics, or completed run manifest exists. These tests are CE-1 implementation-conformance evidence for the current checkout. They do not prove source truth, evidence quality, model probability, policy/disposition or verifier correctness, external custody, external independence, exhaustive coverage, a bounded failure rate, production readiness, or alignment/misalignment/sabotage robustness.

The committed `P2-CE-001` and `P2-CE-002` bundles were generated before alpha.5 and contain no reference-assurance artifact. Their original version-bound claims remain validated as recorded and were not retroactively upgraded; newly generated alpha.5 replay evidence must include the artifact.

The frozen `P2-CE-004` plan calls for two 16-attempt synthetic repetitions, each containing eight clean matches, four qualification quarantines, and four reference-projector blocks, with zero retries or exclusions. No valid published result ledger, observed 32-attempt denominator, repeatability evidence, claim-evidence record, Commit-B release result, or GitHub CI conclusion exists. A prior unpublished package was invalidated after its frozen validator failed a non-finite-JSON negative control and is excluded from claim evidence.
