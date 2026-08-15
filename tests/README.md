# POC Test Suite

Run from the repository root:

```bash
PYTHONPATH=src python -m unittest discover -s tests -v
```

The 101-test suite focuses on safety and evidence invariants rather than synthetic classifier accuracy. It covers the original abstention, break-glass, human-authority, authorization, label-separation, and audit-tamper controls plus the Phase 2 read-only execution boundary, replay contracts, path confinement, canonical-context consistency, frozen input snapshots, descriptor-bound historical output, in-memory historical decision processing, temporal normalization, post-decision adjudication decoding, deterministic artifacts, exact eight-stage decision/audit binding, Gate B campaign evidence, exact authorization-state rejection, zero token/broker/effect assertions, and the three narrow claim-evidence records.

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
