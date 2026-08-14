# Phase 2.1 Record Qualification and Quarantine Control

## Objective and claim boundary

Phase 2.1 adds a bounded qualification boundary in front of the read-only replay engine. After the existing configuration, manifest, governance, path, size, digest, and declared-count gates pass, the qualifier assigns every nonblank case record exactly one outcome:

- `ACCEPTED`: the record satisfied the canonical case contract and may enter the read-only replay pipeline; or
- `QUARANTINED`: a record-local defect was classified by code and the record may not reach the decision engine.

Qualification prevents a malformed record from silently disappearing while other independently valid case records are evaluated. It does not repair input, infer missing values, establish that accepted evidence is true, or establish that rejected evidence is malicious. It also does not turn a structurally valid sample into a representative one.

The implemented boundary is deliberately narrow: it qualifies the manifest role `cases` only. Adjudications remain a separate, whole-file evaluator input loaded after read-only decisions close. The schemas permit no live mode or action authority.

This document is the CE-1 implementation contract. The committed `P2-CE-002` run meets the fixed synthetic campaign criteria below and supports only CE-2 wording such as “record accounting and quarantine behavior were observed under the named synthetic fixture and implementation.” It cannot support claims of historical data quality, operational performance, production readiness, or safeguard effectiveness.

## Normative artifacts

- [`replay-qualification.schema.json`](../../contracts/v0.2.0/replay-qualification.schema.json) defines one metadata-only ledger record for each nonblank source case record.
- [`replay-rejection.schema.json`](../../contracts/v0.2.0/replay-rejection.schema.json) restricts that contract to the `QUARANTINED` subset.
- [`qualification-expectations.schema.json`](../../contracts/v0.2.0/qualification-expectations.schema.json) constrains the metadata-only totals and per-record outcomes fixed before a synthetic campaign.
- The Python implementation owns error classification, line accounting, and cross-record invariants. JSON Schema validates record shape and allowed status/code combinations; it cannot prove file completeness or source-byte correspondence by itself.

“Must” and “shall” in this document denote release requirements, not observations about an untested environment.

## Metadata-only ledger

Each qualification record contains exactly these fields:

| Field | Meaning |
|---|---|
| `schema_version` | Contract version, fixed to `0.2.0` |
| `qualification_run_id` | Deterministic, opaque, non-sensitive identifier for the frozen qualification attempt |
| `dataset_id` | Opaque, non-sensitive identifier matching the governed dataset manifest |
| `source_role` | Fixed to `cases` for Phase 2.1 |
| `source_file_sha256` | SHA-256 of the complete frozen source case file |
| `physical_line_number` | One-based source line number, including intervening blank lines |
| `nonblank_record_number` | One-based ordinal among nonblank source lines |
| `raw_line_sha256` | SHA-256 of the exact source-record bytes, excluding only a terminal LF or CRLF delimiter |
| `status` | `ACCEPTED` or `QUARANTINED` |
| `error_category` | Empty for accepted records; otherwise one code-owned category |
| `error_code` | Empty for accepted records; otherwise one code-owned stable reason |

All whitespace other than the terminal line delimiter remains part of `raw_line_sha256`. The one-MiB encoded-line bound is evaluated separately over the complete physical-line bytes, including a terminal LF or CRLF. A physical line is blank only when the delimiter-stripped byte string is empty after Python `bytes.strip()` semantics. Blank lines therefore affect `physical_line_number` but do not receive a ledger entry and do not increment `nonblank_record_number`.

The key `(source_role, source_file_sha256, physical_line_number, nonblank_record_number, raw_line_sha256)` identifies a source occurrence without copying its content. The hash is a traceability and integrity value, not proof that the source assertion is accurate and not an anonymization mechanism.

## Code-owned outcome taxonomy

Input data cannot propose, override, or supply a qualification outcome. The qualifier maps typed failures to the vocabulary below. It emits one code: the first failure reached in the versioned validation order. Raw exception text, input fragments, and validator stack traces are not rejection fields. If a validator failure has no reviewed mapping, the run fails with `INTERNAL / UNKNOWN_VALIDATION_FAILURE`; it may not fall through to a generic quarantine reason.

### Record-local quarantine outcomes

These failures are bounded to one source record and may produce a `QUARANTINED` ledger record:

| Error category | Stable error code | Qualification meaning |
|---|---|---|
| `RESOURCE_LIMIT` | `EVENT_COUNT_EXCEEDED` | The case exceeds the event-count bound |
| `RESOURCE_LIMIT` | `UNTRUSTED_TEXT_TOO_LONG` | An untrusted-text value exceeds its bound |
| `RESOURCE_LIMIT` | `ATTRIBUTES_TOO_LARGE` | An event attributes object exceeds its serialized-size bound |
| `SYNTAX` | `INVALID_JSON` | The record is not syntactically valid JSON |
| `STRUCTURE` | `RECORD_NOT_OBJECT` | The decoded JSON value is not an object |
| `STRUCTURE` | `MISSING_REQUIRED_FIELD` | A required canonical field is absent |
| `STRUCTURE` | `UNEXPECTED_FIELD` | A field outside the closed canonical contract is present |
| `SEMANTICS` | `INVALID_IDENTIFIER` | A constrained identifier is invalid |
| `SEMANTICS` | `INVALID_TIMESTAMP` | A timestamp is malformed, timezone-naive, or otherwise invalid |
| `SEMANTICS` | `INVALID_BOOLEAN` | A required Boolean is not exactly a Boolean |
| `SEMANTICS` | `INVALID_TYPE` | An ordinary contract value has the wrong JSON type |
| `SEMANTICS` | `INVALID_ENUM_VALUE` | An ordinary enumerated value is not allowed |
| `SEMANTICS` | `EMPTY_REQUIRED_COLLECTION` | A required list or object is empty |
| `SEMANTICS` | `NUMERIC_OUT_OF_RANGE` | A required numeric value is nonfinite or outside its allowed interval |
| `SEMANTICS` | `CASE_EVENT_ID_MISMATCH` | An event refers to a different parent case |
| `SEMANTICS` | `EVENT_TIME_ORDER_INVALID` | Event timing violates a required semantic relationship |
| `SEMANTICS` | `DUPLICATE_ENTITY_REFERENCE` | An event repeats an entity reference where the canonical contract requires uniqueness |
| `SEMANTICS` | `CANONICAL_CONTEXT_MISSING` | Required canonical asset-inventory context is absent |
| `SEMANTICS` | `CANONICAL_CONTEXT_MISMATCH` | Canonical break-glass or asset-criticality context disagrees with the case |

An accepted record must carry `error_category: ""` and `error_code: ""`. A quarantined record must carry one exact category/code pair permitted by the schema. Accepted records and quarantine records remain in source nonblank order.

### Fatal outcomes

A failure is fatal when it prevents the system from proving the source universe, trustworthy input bytes, governance boundary, deterministic classification, or complete accounting. A fatal result returns no `QualificationResult`; the engine shall receive no subset from that qualification call.

| Fatal condition | Code-owned behavior |
|---|---|
| Invalid replay configuration, manifest, governance attestation, confined path, file availability, declared file-size bound, or declared record count | Existing typed configuration/manifest validation fails before qualification; no per-record ledger is finalized |
| The verified snapshot cannot be opened or reread by the qualifier | `INTERNAL / SOURCE_READ_FAILURE`; abort without copying an operating-system error into the public exception |
| Frozen source bytes do not match the manifest/source digest | `INTERNAL / SOURCE_DIGEST_MISMATCH`; abort the qualification call |
| Nonblank input exceeds the 100,000-record bound | `RESOURCE_LIMIT / RECORD_COUNT_EXCEEDED`; abort rather than publish a truncated ledger |
| A source line is not valid UTF-8 | `ENCODING / INVALID_UTF8`; abort because the bounded canonical JSONL source cannot be decoded as declared |
| A source line exceeds the encoded line-size bound | `RESOURCE_LIMIT / LINE_TOO_LARGE`; abort rather than continue across an untrusted record boundary |
| A JSON value exceeds 128 object/array nesting levels | `RESOURCE_LIMIT / JSON_NESTING_DEPTH_EXCEEDED`; abort before parser recursion behavior can become interpreter-dependent |
| A record declares a contract version other than `0.2.0` | `STRUCTURE / UNSUPPORTED_SCHEMA_VERSION`; abort because one qualification call may not mix contract semantics |
| A runtime record contains an adjudication, outcome, scenario, label, or equivalent forbidden key | `POLICY / RUNTIME_LABEL_LEAKAGE`; abort because the runtime/evaluator separation boundary has been contaminated |
| Duplicate `case_id` across records or duplicate `event_id` within or across accepted candidates | `DUPLICATE / DUPLICATE_CASE_ID` or `DUPLICATE / DUPLICATE_EVENT_ID`; abort because “first accepted” would make validity depend on attacker-controlled order |
| A contract-validator failure lacks an explicit reviewed mapping | `INTERNAL / UNKNOWN_VALIDATION_FAILURE`; abort rather than relabel it as a harmless rejection |
| Snapshot mutation, ledger/rejection write failure, schema failure, accounting mismatch, or finalization failure | Fail the run and withhold a completed-run marker; partial files are diagnostic evidence, not a valid result |

No percentage of acceptable records can override a fatal condition. Operators shall correct or re-authorize the source and start a new qualification run; they shall not manually delete the offending line from a frozen dataset and reuse the prior source identity.

## Exact accounting invariants

For one frozen case file, define:

- `P`: number of physical source lines, including blank lines;
- `N`: number of nonblank source records;
- `A`: number of `ACCEPTED` ledger records;
- `Q`: number of `QUARANTINED` ledger records;
- `L`: number of records in the qualification ledger;
- `R`: number of records in the rejection artifact; and
- `D`: the manifest-declared case-file record count.

A completed qualification must satisfy every invariant below exactly:

1. `D = N`.
2. `N = A + Q`.
3. `L = N`.
4. `R = Q`.
5. Every nonblank source record has exactly one ledger record, and no blank line has one.
6. Ledger `nonblank_record_number` values are exactly the contiguous sequence `1..N`; `physical_line_number` values are unique, strictly increasing, and no greater than `P`.
7. Every ledger record carries the same governed `dataset_id`, `source_role`, `source_file_sha256`, and `qualification_run_id` for that artifact.
8. Every `raw_line_sha256` recomputes from the identified frozen source bytes under the line-delimiter rule above.
9. The rejection artifact is exactly the ordered projection of ledger records whose status is `QUARANTINED`; it contains neither an accepted record nor a missing quarantined record.
10. Accepted and quarantined source occurrences are disjoint.
11. The accepted-case artifact, if emitted, contains exactly `A` contract-valid records in their original nonblank order.
12. If a read-only replay follows qualification, its input-case count and decision count are both `A`; no quarantined source occurrence may be cited by a decision.

An implementation must validate the two JSON Schemas and these cross-record invariants before it labels a qualification artifact complete. A valid JSONL file with too few ledger rows is not a valid qualification result.

## Privacy, custody, and publication rules

The metadata-only design reduces accidental payload duplication; it does not make a historical ledger public or non-sensitive.

- Qualification and rejection records shall never contain raw-line content, parsed record objects, payload excerpts, subject/account/asset/event identifiers, source filenames or absolute paths, analyst rationale, exception messages, prompts, stack traces, or model-generated explanations.
- `qualification_run_id` and `dataset_id` must be opaque values that reveal no person, organization, incident, host, tenant, date, or mission name.
- `source_file_sha256` and `raw_line_sha256` are stable linkable fingerprints. For historical data they inherit the source dataset's access, retention, sharing, and deletion controls and may constitute sensitive or personal data in context.
- The accepted payload artifact, when needed for replay, remains inside the approved processing boundary. It is not embedded in the metadata ledger or rejection artifact.
- Historical qualification artifacts require least-privilege access, encryption in transit and at rest, tenant separation, access logging, approved retention, deletion verification, and incident handling. Hashing does not replace de-identification.
- A public repository or public evidence package shall contain synthetic records only. Historical ledgers, rejection artifacts, accepted payloads, source digests, and record hashes shall not be committed even if direct identifiers were removed.
- Aggregate publication must apply the approved disclosure review and small-cell rules. Error counts can reveal source or collection weaknesses even without payload text.

## Survivorship-bias controls and claim limits

Qualification changes the evaluated population. Any performance computed on accepted records is conditional on survival through this filter and may be optimistic if malformed, incomplete, adversarial, older, or poorly mapped records are disproportionately quarantined.

Every evaluation report must therefore place `N`, `A`, `Q`, the complete error-code distribution, and any fatal attempts adjacent to decision results. Data-quality accounting uses `N` as its denominator. A model-performance denominator may use accepted, adjudicated records only when named explicitly, but it may not hide the intake and quarantine counts.

The following inferences are prohibited:

- `ACCEPTED` does not mean benign, uncompromised, complete, decision-grade, representative, or factually correct.
- `QUARANTINED` does not mean malicious, compromised, low-risk, irrelevant, or safe to delete.
- High acceptance on a designed synthetic fixture does not estimate acceptance on historical or live-shadow data.
- Accuracy, calibration, or agreement on the accepted subset does not describe the complete source population.
- Excluding malformed or policy-conflicting records does not demonstrate robustness to those records.
- A zero count in one error category is `0/n` under the exact tested input, not proof that the failure cannot occur.
- Aggregate acceptance cannot conceal a catastrophic or concentrated rejection class. Concentration by time, source, system, population, or consequence must be assessed under the approved private-data protocol.

Synthetic, historical, and live-shadow qualification results must remain separate. A change in schema, adapter, validator ordering, source mapping, policy, model, or dataset requires a new evidence record and revalidation.

## Phase 2.1 synthetic campaign acceptance criteria

The mixed-quality synthetic campaign is acceptable only if all of the following are observed under the committed source, harness, configuration, schemas, and code revision:

1. The frozen fixture has exactly seven nonblank case records: three predeclared valid controls followed by four independently defective records.
2. Rows 1–3 are accepted. Rows 4–7 are quarantined with exactly one each of `SYNTAX / INVALID_JSON`, `STRUCTURE / MISSING_REQUIRED_FIELD`, `SEMANTICS / INVALID_TIMESTAMP`, and `SEMANTICS / CANONICAL_CONTEXT_MISMATCH`.
3. The fixture expectation artifact is fixed before the evaluated run, validates against `qualification-expectations.schema.json`, and contains metadata only; it is not passed to the qualifier or engine.
4. All accounting invariants above pass: `N=7`, `A=3`, `Q=4`, `L=7`, and `R=4`.
5. Each ledger record reproduces its source-file and raw-line digest; the rejection artifact equals the ordered quarantined projection.
6. All accepted records pass the canonical case validator. No rejected record or expected outcome field reaches the decision engine.
7. Repeated clean runs produce byte-identical qualification and rejection artifacts. `qualification_run_id` is deterministic for the frozen fixture; no volatility exclusion is permitted.
8. Negative tests prove that missing ledger rows, changed source bytes, a wrong line number or digest, accepted records with error values, quarantined records with empty or mismatched error values, an extra payload-like field, and an unknown validator error fail closed.
9. Duplicate case and event identifiers are tested as fatal whole-qualification conditions rather than order-dependent quarantine.
10. The downstream read-only controls remain exact: zero authorization tokens, zero broker invocations, zero action results, zero operational effects, no action-capable credentials, and no live connector.
11. The evidence package records raw counts, exact system and harness versions, test budget, failures, deviations, artifact hashes, reviewer scope, limitations, and prohibited inferences under the project claim-evidence contract.

Passing these criteria establishes bounded synthetic record-accounting behavior only. It does not demonstrate historical acceptance rate, source completeness, adjudication quality, model efficacy, production throughput, privacy compliance, adversarial robustness, monitor effectiveness, or safe autonomy.

## No-live-action boundary

Qualification is an ingestion-control function, not an operational response function. It shall not issue authorization tokens, call an action broker, instantiate an operational target, invoke a vendor or network connector, create tickets, notify an operator queue, change identity state, or write to a monitored system.

The complete case file must be qualified and its accounting verified before any accepted subset enters `HISTORICAL_REPLAY` or `SHADOW_READ_ONLY`. Both modes keep `live_actions_enabled=false`; counterfactual recommendations remain non-executable and post-action verification remains `NOT_APPLICABLE`. A quarantine or fatal outcome cannot itself become an operational action request.

Any later controlled-action experiment belongs to a separately authorized phase with a deployment-specific threat model, non-production target, rollback and independent readback, action-scoped credentials, statistical release criteria, independent review, and an authorizing-official decision.

## Gate for the first historical pilot

Synthetic acceptance does not authorize historical processing. Before the first historical qualification attempt, Gate B in the Phase 2 validation plan must be approved and extended with a signed pilot protocol that establishes:

1. data owner, mission owner, security, privacy/legal, and records-management authority for the exact source, purpose, population, time window, environment, and personnel;
2. documented de-identification and re-identification-risk testing, including handling for pseudonymous identifiers, free text, rare events, and linkable hashes;
3. a frozen source snapshot, independent custody record, expected source-file digest and count, source-to-canonical mapping, collection-completeness assessment, and deletion/incident procedures;
4. read-only identities, no action credentials, no live or write-capable connector, egress restrictions, process/tenant separation, monitoring, a data-collection kill switch, and tested containment;
5. a predeclared sample-selection and temporal-holdout design that preserves the full intake universe and does not select only records likely to validate;
6. predeclared maximum overall and category-specific quarantine thresholds, fatal stop conditions, escalation owners, and a rule that thresholds cannot be relaxed after viewing performance;
7. an adjudication protocol with qualified reviewers, uncertainty and disagreement treatment, evaluator/runtime separation, and safeguards against hindsight and label leakage;
8. a restricted evidence plan that reports intake, acceptance, quarantine, exclusions, failures, source strata, uncertainty assumptions, and representative failure classes without publishing source-level metadata;
9. independent review of the implementation, schemas, mapping, privacy controls, accounting evidence, and claim wording; and
10. claim ownership, expiry, pause/revocation authority, revalidation triggers, and a regression-test requirement for any incident or discovered classifier gap.

The first pilot remains historical, offline, and read-only. It may support only the claim class justified by the recorded evidence. It does not authorize a live feed, operational recommendation workflow, or action.

## Research-derived rationale

This control applies the project's existing [`CLAIM_EVIDENCE_STANDARD.md`](CLAIM_EVIDENCE_STANDARD.md) and [`RESEARCH_COVERAGE_REGISTER.md`](RESEARCH_COVERAGE_REGISTER.md):

- Anthropic's agentic-misalignment and sabotage work motivates preserving negative controls, failures, monitor limitations, and the distinction between a deliberately elicited synthetic behavior and real-world prevalence. This deterministic qualifier is not an agent-alignment evaluation.
- OpenAI's trustworthy-evaluation guidance motivates binding claims to the exact source, system, harness, budget, counts, exclusions, validity checks, artifacts, and review. Quarantined records are part of the evaluated intake and cannot be erased from reporting.
- OpenAI's benchmark-validity, hallucination, and grader work motivates separate accounting for accepted, quarantined, correct, incorrect, and abstained outcomes rather than collapsing them into one success rate.
- OpenAI's preparedness, agent-governance, prompt-injection, long-horizon, and evaluation-environment research motivates least privilege, code-owned authority, explicit stop conditions, incident-derived regression tests, and treating the replay environment itself as a security boundary.

These sources shape test obligations and claim limits; they do not certify this implementation or transfer their reported results to it.
