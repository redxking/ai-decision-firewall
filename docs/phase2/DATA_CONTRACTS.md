# Phase 2 Data Contracts

> **Release boundary.** `0.2.0-alpha.5` / Phase 2.4 is the prior published evidence baseline. The Phase 2.5 receipt and campaign-plan contracts were present at predecessor untagged `0.2.0-alpha.6` design-freeze Commit `08ce203c`, with historical commit-bound CI and Dependency Graph success. This package candidate adds bounded controls and packaging outside that predecessor commit; its Phase 2.5 technical suite passed 222/222, the separate public-site module passed 9/9, and the combined repository aggregate passed 231/231. The site module is outside these contract and Phase 2.5 evidence claims. The candidate includes a generated-and-verified integrity manifest and inspected final-source status renders. Package publication and GitHub CI on the exact published package commit remain external gates; no tag or release/evidence package exists. Contract presence, a design freeze, or green implementation tests do not establish a completed replay or an observed `P2-CE-005` result.

## Contract objective and status

Phase 2 defines a narrow, versioned boundary between an untrusted local evidence snapshot and the v0.1 decision engine. It accepts canonical JSONL, validates integrity and record counts, and decodes separately stored adjudications only after decision processing and read-only safety checks finish. Phase 2.1 qualifies bounded case records into accepted and quarantined sets with exact metadata-only accounting. Phase 2.2 adds a separate Gate B authority, custody, and binding contract before historical payload access. Phase 2.4 adds exact type/source authorization for modeled attributes, exact four-field inventory binding, and a closed reference-feature-assurance record. Phase 2.5 adds a closed source-to-decision semantic receipt across the evidence, model, policy, verifier, and read-only final surfaces.

The implemented contract version is `0.2.0`. The executable Python validation in `src/adf_poc/replay/contracts.py` is the runtime authority; the schemas under `contracts/v0.2.0/` document and independently constrain the same public shape. Unknown fields are rejected rather than silently ignored. These starter contracts do not certify source semantics, legal authority, de-identification effectiveness, or production fitness.

The datasets under `data/phase2_starter/` and `data/phase2_qualification/` are synthetic. Both manifests declare `data_origin: SYNTHETIC_FIXTURE` and `historical_case_count: 0`. The qualification fixture contains seven nonblank case records with predeclared metadata-only outcomes: three accepted and four quarantined. No historical record, production identifier, real incident narrative, raw vendor export, or live telemetry is included.

## Contract artifacts

- `contracts/v0.2.0/replay-manifest.schema.json`
- `contracts/v0.2.0/replay-case.schema.json`
- `contracts/v0.2.0/replay-adjudication.schema.json`
- `contracts/v0.2.0/replay-qualification.schema.json`
- `contracts/v0.2.0/replay-rejection.schema.json`
- `contracts/v0.2.0/qualification-expectations.schema.json`
- `contracts/v0.2.0/evaluation-evidence.schema.json`
- `contracts/v0.2.0/gate-b-authorization.schema.json`
- `contracts/v0.2.0/reference-feature-assurance.schema.json`
- `contracts/v0.2.0/feature-assurance-ce2-campaign.schema.json`
- `contracts/v0.2.0/examples/phase2-feature-assurance-ce2-evidence-record.json`
- `contracts/v0.2.0/examples/gate-b-authorization-draft.json`
- `contracts/v0.2.0/examples/phase2-starter-evidence-record.json`
- `contracts/v0.2.0/README.md`
- `src/adf_poc/replay/contracts.py`
- `src/adf_poc/replay/qualification.py`
- `src/adf_poc/replay/gate_b.py`
- `src/adf_poc/feature_contract.py`
- `src/adf_poc/replay/reference_features.py`
- `src/adf_poc/replay/adapters.py`

## Replay configuration and record-failure policy

The optional `record_failure_policy` configuration field is code-owned:

| Value | Implemented behavior |
|---|---|
| `FAIL_DATASET` | Default. Parse and validate the case file as one unit; any case-record error aborts before engine invocation. |
| `QUARANTINE_RECORD` | Qualify the `cases` role record by record, but only in offline `HISTORICAL_REPLAY`. Reviewed record-local defects are quarantined; fatal conditions abort the complete qualification call. |

`QUARANTINE_RECORD` with `SHADOW_READ_ONLY` is rejected during configuration loading. There is no unreviewed policy value and no configuration option to downgrade a fatal condition. Both policies retain `live_actions_enabled: false`, `zero_effects_required: true`, confined local paths, and the same decision-to-effect suppression boundary.

The optional `gate_b_authorization` configuration field is forbidden for nonhistorical input and mandatory for `HISTORICAL_DEIDENTIFIED`. It must be a confined nonsymlink path under ignored `local/gate_b/`. Historical output must be a new run-specific directory under ignored `outputs/replay/`. The runtime creates it owner-only and keeps all snapshot and artifact operations bound to retained directory descriptors; it does not use the display path as write authority. No real historical configuration or approval package is committed.

## Replay manifest

The manifest is the dataset's integrity and governance index. It uses these exact top-level fields:

| Field | Implemented meaning |
|---|---|
| `schema_version` | Must equal `0.2.0` |
| `dataset_id` | Nonempty constrained identifier |
| `data_origin` | `SYNTHETIC_FIXTURE`, `HISTORICAL_DEIDENTIFIED`, or `SHADOW_TELEMETRY_DEIDENTIFIED` |
| `historical_case_count` | Nonnegative integer; zero for synthetic and shadow origins; for historical origin, equal to the declared cases-file count |
| `intended_mode` | `HISTORICAL_REPLAY` or `SHADOW_READ_ONLY` |
| `created_at` | ISO-8601 timestamp with an explicit UTC offset |
| `attestations` | Exact governance-attestation object defined below |
| `files` | Nonempty array of exact file entries |

Configuration and manifest mode names are uppercase identifiers. The harness maps them to the code-owned lowercase `ExecutionMode` values `historical_replay` and `shadow_read_only`; final decision records use the lowercase values.

Each file entry has exactly:

| Field | Implemented rule |
|---|---|
| `role` | `cases` or `adjudications`; each role appears at most once |
| `path` | Nonempty manifest-relative path confined beneath the manifest directory |
| `sha256` | Lowercase 64-character SHA-256 digest |
| `record_count` | Nonnegative count of nonblank JSONL source records, whether or not each record later parses or qualifies |
| `adapter` | `canonical_jsonl_v0.2` |

A cases file is always required. `HISTORICAL_REPLAY` also requires a physically separate, single-link adjudications file; case and adjudication file identities cannot alias. For synthetic input, the loader verifies the complete declaration before decisions. For historical origin, it first reads only manifest control bytes and completes Gate B. It then freezes both sources, qualifies the frozen case bytes, and keeps exact adjudication bytes in harness-owned memory. The runner receives only accepted case objects plus bound model and policy bytes. The adjudication file is not placed beside or passed to the runner; it is materialized through the retained output descriptor only after decisions and boundary-audit checks close. Snapshot digests and counts are rechecked before final artifacts.

Under `FAIL_DATASET`, the case adapter decodes and semantically validates every snapshotted case as one unit. Under `QUARANTINE_RECORD`, the qualifier first verifies the frozen source digest and accounts for every nonblank source occurrence; only accepted cases proceed. Evaluator-only adjudication bytes are integrity-frozen before decisions but deliberately neither exposed as a runner input nor decoded until read-only decisions and boundary-audit validation close. Digest, count, path, governance, or fatal qualification failures abort before the engine runs.

The manifest is not an independent trust anchor. A party able to replace the files can also replace the manifest and recompute its digests. Approved historical work therefore requires an externally controlled manifest digest, approval record, and chain of custody.

## Replay-case record

The implemented case contract is a flat canonical record, not an outer source envelope. It has exactly these fields:

```json
{
  "schema_version": "0.2.0",
  "case_id": "case-synthetic-000001",
  "opened_at": "2026-08-01T00:00:00+00:00",
  "subject_id": "subject-synthetic-000001",
  "privilege_level": "privileged",
  "break_glass": false,
  "asset_id": "asset-synthetic-000001",
  "asset_criticality": 0.5,
  "events": [
    {
      "event_id": "evt-synthetic-000001",
      "case_id": "case-synthetic-000001",
      "source_type": "asset_inventory",
      "source_instance": "fixture.asset_inventory",
      "observed_at": "2026-08-01T00:00:00+00:00",
      "collected_at": "2026-08-01T00:00:01+00:00",
      "integrity": "verified",
      "provenance_id": "fixture-provenance-000001",
      "trust_score": 1.0,
      "entity_refs": ["asset-synthetic-000001"],
      "attributes": {
        "asset_id": "asset-synthetic-000001",
        "privilege_level": "privileged",
        "break_glass": false,
        "asset_criticality": 0.5
      },
      "untrusted_text": "",
      "contains_instructional_content": false
    }
  ]
}
```

The example is structurally representative; the committed fixture is the evidence for the actual starter values.

## Structural and semantic validation

Before an accepted case reaches the engine, the validator enforces all of the following. Under `FAIL_DATASET`, any violation aborts the complete case set. Under `QUARANTINE_RECORD`, reviewed ordinary record-local violations are represented by one sanitized quarantined outcome; the fatal classes defined below still abort the complete qualification call.

1. `schema_version` is exactly `0.2.0` and no undeclared case or event fields exist.
2. Case and event identifiers match the constrained identifier syntax; case IDs and event IDs are unique across the cases file.
3. Every event `case_id` equals its parent case ID.
4. `trust_score` and `asset_criticality` are finite numbers in `[0,1]`; booleans are not accepted as numbers.
5. `opened_at`, `observed_at`, and `collected_at` are ISO-8601 values with explicit UTC offsets.
6. `collected_at` is not earlier than `observed_at`. The starter defines no clock-skew tolerance.
7. Event integrity is `verified`, `unverified`, or `failed`; entity references are unique within the event; and the required text, provenance, attributes, and instructional-content types are present.
8. Each case has at least one `asset_inventory` event and passes the cross-field checks below.
9. Runtime records contain no prohibited label, adjudication, scenario, expected-disposition, or compromise-outcome key at any nesting depth.
10. Every modeled attribute has its exact code-owned JSON type/range and appears only under an authorized `source_type`; unrecognized attributes remain opaque to the feature projector.
11. Every JSON numeric value anywhere in an accepted case is finite before engine invocation, including values inside otherwise opaque attributes.
12. The separate decision-driving evidence attribute `source_conflict` is an exact JSON Boolean authorized only for `network`; it is not one of the 20 model features.

Invalid values are rejected rather than coerced, apart from deterministic normalization of accepted timestamps and numeric representations after validation.

## Canonical-context cross-field validation

V0.1 consumes top-level canonical context directly. Phase 2.4 therefore treats every `asset_inventory` event as a mandatory consistency check:

- its attributes must contain `asset_id`, `privilege_level`, `break_glass`, and `asset_criticality`;
- all four values must have the required type and exactly equal the corresponding top-level value;
- multiple inventory events must each agree; disagreement is not resolved through majority voting.

A conflict prevents that case from reaching model or policy evaluation. It aborts the case set under `FAIL_DATASET` and is quarantined as `SEMANTICS / CANONICAL_CONTEXT_MISMATCH` under `QUARANTINE_RECORD`. The implementation does not infer a missing critical value or choose a permissive default.

## Modeled-signal type and source contract

The runtime recognizes 17 Boolean modeled attributes plus the `failed_logins` count. A modeled Boolean is accepted only as a JSON Boolean and only from these source roles:

| Source type | Authorized modeled Boolean attributes |
|---|---|
| `identity` | `new_device`, `impossible_travel`, `mfa_fatigue`, `token_reuse`, `after_hours`, `strong_mfa`, `oauth_grant` |
| `endpoint` | `credential_dumping`, `unusual_admin_action`, `edr_malware`, `device_noncompliant` |
| `network` | `threat_ip`, `lateral_movement`, `known_vpn` |
| `threat_intel` | `threat_ip` |
| `user_context` | `approved_travel` |
| `change_management` | `maintenance_window`, `service_account_baseline` |

`failed_logins` is authorized only for `identity` and must be a finite integral JSON number in `0..1,000,000`. The runtime accepts an integral JSON floating representation such as `10.0`, but rejects strings, Booleans, fractions, non-finite values, negatives, and over-bound values. A modeled key under any other source is not treated as harmless opaque context; it fails closed.

Unrecognized attributes that are not model or explicitly governed evidence inputs remain bounded opaque context and cannot change the 20-feature values or traces. `source_conflict` is governed separately because it can change evidence-quality assessment and therefore the downstream disposition despite not entering the model vector. Under `QUARANTINE_RECORD`, a `source_conflict` assertion outside `network` is classified as `SEMANTICS / UNAUTHORIZED_DECISION_SIGNAL`; a non-Boolean network assertion is classified as `SEMANTICS / INVALID_BOOLEAN`. The reference feature projector does not recompute that evidence path.

This contract limits which structured assertions can drive the model or evidence assessment. It does not authenticate a source, validate vendor semantics, establish collection completeness, or make an assertion true.

## Qualification, rejection, and expectation records

The qualification ledger is deliberately metadata-only. Each nonblank case-source occurrence produces exactly one record with these closed fields:

- contract version, deterministic `qualification_run_id`, governed `dataset_id`, and `source_role: cases`;
- complete `source_file_sha256`;
- one-based physical line and nonblank-record numbers;
- `raw_line_sha256`, computed over exact source-record bytes after removing only a terminal LF or CRLF;
- `status` equal to `ACCEPTED` or `QUARANTINED`; and
- code-owned `error_category` and `error_code`, both exactly empty for an accepted record.

The one-MiB encoded-line limit is evaluated over the complete physical line including its delimiter. The raw-line digest excludes that delimiter and retains all other whitespace. Blank physical lines affect later physical-line numbers but do not receive ledger records.

`replay-rejection.schema.json` restricts the same closed shape to the `QUARANTINED` subset. `qualification-expectations.schema.json` independently constrains the predeclared synthetic expectation file: closed campaign totals and ordered metadata-only expected records with the same status/category/code rules and source digest. JSON Schema constrains individual shapes; the harness and tests enforce the cross-record invariants:

1. manifest nonblank count = ledger count;
2. input = accepted + quarantined;
3. rejection artifact = exact ordered quarantined ledger projection;
4. ledger source identity and every physical/nonblank ordinal and raw-line digest match the frozen file;
5. accepted count = normalized case count = decision count; and
6. one deterministic run ID binds the complete ledger.

The ledger and rejection artifact cannot contain raw payload, parsed source values, payload identifiers, file paths, exception text, or a free-form message. Source and raw-line hashes remain linkable and sensitive for historical data; they are not anonymization. See [`RECORD_QUALIFICATION.md`](RECORD_QUALIFICATION.md) for the complete taxonomy, privacy rules, survivorship-bias limits, and pilot gate.

The synthetic expectation artifact is evaluator-only test control data. It is loaded by tests, not by the qualifier or decision engine, and it is not historical ground truth.

`scripts/generate_phase2_qualification_fixture.py --check` verifies that the committed fixture still matches deterministic generation from fixed, digest-reviewed starter controls. Generation is confined to an exact target set; source bytes are read once for both parsing and digest verification, and write mode rejects path escape, symbolic-link redirection, hard-linked targets, and unreviewed directory entries. These controls protect fixture reproducibility; they do not establish independent source custody.

## Temporal ordering and diagnostics

Valid out-of-order arrival is distinct from invalid time. After validation, the normalizer converts timestamps to UTC and sorts events by this exact stable key:

1. `observed_at`;
2. `collected_at`;
3. `source_type`;
4. `source_instance`;
5. `event_id`.

When the input order changes, the starter preserves a case-specific `EVENT_ORDER_NORMALIZED` warning. `normalization_diagnostics.json` reports the case and event counts, mapping-warning count, temporal-reordering count, total warning count, and warning records. Normalization does not invent evidence, rewrite source assertions, or conceal the ordering anomaly.

## Reference feature-assurance record

After decision serialization and complete eight-stage audit validation, the harness invokes the separately implemented in-process reference projector. It recomputes the exact 20 feature values and their event traces from normalized cases and compares them with each decision's `model_assessment` and traceability copy. Exact and unique case sets are required, and records are ordered by case identifier.

For a successful match, `reference_feature_assurance.jsonl` contains exactly one closed row per case:

- `schema_version`;
- `case_id`;
- `normalized_case_sha256`;
- `expected_projection_sha256`;
- `observed_projection_sha256`; and
- `matched`, which can only be `true`.

`normalized_case_sha256` is SHA-256 over the UTF-8 bytes of `json.dumps(normalized_case, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False)` with no trailing newline. Every JSON number has already passed the accepted-case finite-number check before this canonical serialization and digest operation.

The artifact contains no raw case, attribute, feature value, feature trace, source path, or free-form exception. Duplicate JSON object members are rejected when the persisted JSONL is read back; last-member-wins parsing is not accepted. Metrics report cases checked, matched, mismatched, and completeness; the run manifest hash/count-binds the artifact and checked/matched counts.

If a projection, trace, normalized-case binding, or case-set check fails, the projector raises a stable code-owned exception and emits no assurance artifact. The harness then emits no qualification/rejection artifacts, adjudication comparison, metrics, or completed run manifest. Raw, normalized, and deterministic decisions plus audit output may already exist from earlier stages and are incomplete evidence, not a completed replay result.

The reference implementation is separate from the production feature calculation but runs in the same Python process and project against the same normalized case bytes. Its agreement supports only a bounded implementation-conformance claim; it does not recompute `source_conflict`, evidence quality, model probability, policy/disposition correctness, or verifier behavior and is not proof of source truth, external custody, or independent replication.

## Source-to-decision assurance record

After the feature projector succeeds in memory, the Phase 2.5 reference path parses the exact frozen normalized-case and raw-decision JSONL plus the exact model and policy JSON. It rejects invalid encoding, duplicate object members, non-finite values, malformed or nonclosed structures, invalid model/policy ranges, invalid timestamps or identifiers, duplicate cases or decisions, and unequal case sets.

The reference parser applies code-owned ceilings: 64 MiB per model or policy document; 512 MiB per JSONL input; one MiB per physical JSONL line; 100,000 nonblank records; nesting depth 128; 10,000 events per case; 16,384 untrusted-text characters per event; 256 KiB per event `attributes` object or model `training_metadata`; and at most 256 `limitations` entries with 64 KiB total canonical size. A bound failure stops the reference path. These ceilings limit parser exposure and do not establish production capacity or availability.

The implementation separately reconstructs and compares these semantic stages in exact order:

1. `EVIDENCE`;
2. `MODEL`;
3. `POLICY`;
4. `VERIFIER`; and
5. `FINAL_SURFACE`.

Evidence provenance, integrity, freshness, and source-trust aggregates use ordered `math.fsum(values) / event_count` in both implementations. The model calculation iterates the frozen 20-feature order, accumulates contributions with `math.fsum`, adds the intercept, clamps the sigmoid input to `[-30, 30]`, and preserves the defined rounding and factor ordering. These are explicit algorithmic consistency rules, not blanket cross-platform reproducibility claims.

For a successful match, `source_to_decision_assurance.jsonl` contains exactly one closed row per case. It binds the case, execution mode, normalized-case/model/policy sources, expected and observed digests for each stage, and the ordered complete path; `read_only` and `matched` can only be `true`. Raw evidence, model values, policy content, verifier details, source paths, and free-form errors are prohibited.

The receipt binds the deterministic semantic surface rather than volatile `decision_id`, `created_at`, `latency_ms`, or `decision_record_hash` instance fields. The completed run manifest separately co-binds the exact raw decision and eight-stage audit bytes and their counts. A receipt can therefore be identical across semantically equivalent runs and is neither a complete run record nor independent custody evidence.

On a stage or binding mismatch, the harness writes neither reference receipt and stops before qualification/rejection publication, adjudication decoding, comparison, metrics, or completed-run finalization. Earlier normalized cases, diagnostics, raw/deterministic decisions, and audit may remain and are incomplete. Later failures can leave more artifacts or a manifest written before final revalidation; only successful harness return establishes completion. The nonempty output directory is not reusable.

For both ordinary and descriptor-bound historical output, every deterministic artifact is strict-parsed, structurally compared, and exact-digest frozen immediately after write: normalized cases, normalization diagnostics, deterministic decisions, both reference receipts, qualification accounting and rejections when enabled, adjudication comparison, and replay metrics. Volatile raw engine decisions and replay audit are exact-frozen separately. The complete set is rechecked before manifest construction, after construction, and after manifest write and is included in the manifest digest map. The manifest itself is not self-hashed.

The reference implementation is same-process, same-project, and project-controlled. Agreement does not establish source truth, outcome correctness, policy fitness, efficacy, historical/live performance, external custody, or organizational independence. `P2-CE-005` remains CE-0 `NOT_EVALUATED`; its plan and schema are not campaign evidence.

## Governance and de-identification gates

The implemented `attestations` object has exactly these fields:

| Field | Implemented rule |
|---|---|
| `approved_for_replay` | Must be true for every Phase 2 replay or shadow input |
| `approval_reference` | Nonempty reference; the software checks presence, not external validity |
| `deidentified` | Must be true for every Phase 2 input |
| `deidentification_method` | Nonempty description |
| `direct_identifiers_present` | Must be false |
| `attested_by` | Constrained nonempty identifier |
| `attested_at` | ISO-8601 timestamp with explicit UTC offset |

The synthetic fixture uses a synthetic-by-construction attestation. This is metadata about how the fixture was produced, not evidence that a historical de-identification process was applied.

The manifest gate is necessary but insufficient for historical use. Before a historical payload is accessed, the closed Gate B package must be top-level `APPROVED`; contain exactly one approval each from `DATA_OWNER`, `MISSION_OWNER`, `SECURITY`, `PRIVACY_LEGAL`, and `RECORDS_MANAGEMENT`; contain an approved review whose asserted reviewer identity differs from every asserted approver identity; require `window_end <= custody.frozen_at <= valid_from`; and bind the exact dataset manifest, contract, adapter, model, policy, source mapping, adjudication protocol, and pilot protocol. Critical controls, validity, complete-intake/sample counts, custody references, temporal holdout, and frozen thresholds must also pass. Purpose, population, identity, independence, and authority are external assertions; the runtime checks their bounded structural representation, not their truth or legal sufficiency.

This is a two-stage gate. Structural authority, binding, time, path, resource, and declared-count checks occur before any historical payload access. After authorized case qualification—but still before normalization or engine invocation—the harness checks accepted-case `opened_at` values and observed overall/category quarantine rates against the frozen window and thresholds. A manifest, schema, or nonempty reference cannot by itself prove authority, identity, a signature, effective de-identification, or custody truth.

The public repository remains synthetic-only. Actual Gate B files and protocol/mapping artifacts belong under ignored `local/gate_b/`; historical output belongs under ignored owner-only `outputs/replay/<run>/`. Pseudonymous values and hashes may still be sensitive or linkable.

## Label and adjudication separation

Runtime case validation recursively rejects keys including `adjudication`, `adjudicated_disposition`, `compromised`, `expected_disposition`, `ground_truth`, `is_malicious`, `label`, `malicious`, `outcome_label`, and `scenario`. This is a structural leakage guard, not proof that free text or correlated features contain no hindsight.

Adjudications reside in a separate JSONL file. The harness integrity-freezes their exact bytes outside the runner inputs, runs the engine against accepted case/model/policy inputs, validates read-only decisions and finalization audit bindings, completes reference feature assurance, and only then materializes and decodes the adjudication snapshot. This is a harness-enforced interface boundary, not an OS sandbox against arbitrary same-process introspection. Each adjudication has exactly:

- `schema_version` equal to `0.2.0`;
- unique `adjudication_id` and a `case_id` that resolves to an accepted case;
- `adjudicated_at` with an explicit UTC offset and a constrained `adjudicator_role`;
- `adjudicated_disposition` equal to `NO_ACTION`, `INVESTIGATE`, `CONTAIN_REVERSIBLE`, or `ESCALATE_HUMAN`;
- Boolean `compromised`, confidence in `[0,1]`, and a nonempty unique list of `rationale_codes`.

Only one adjudication per case is accepted by this starter. These records are evaluator outcomes with stated confidence; they are not automatically ground truth and they do not establish inter-analyst agreement.

## Path confinement and input surface

Configuration paths are repository-relative and resolved beneath the supplied repository root. Manifest file paths are relative to—and resolved beneath—the manifest directory. Absolute paths, parent traversal, and symlink resolution outside the allowed root fail closed. Gate B authorization and bound protocols additionally require the ignored `local/gate_b/` root and reject symlink components; historical output requires ignored `outputs/replay/<run>/`. Declared inputs must exist as files.

The canonical adapter does not fetch URLs, call vendor APIs, expand archives, execute plugins, or discover inputs with wildcards. This is an offline local-snapshot interface, not a live connector.

## Bounded parsing

The starter fails closed on inputs that exceed these code-owned limits:

| Limit | Maximum |
|---|---:|
| Declared file size | 512 MiB |
| Configuration or manifest document | 1 MiB |
| Gate B authorization or manifest-control JSON nesting | 128 levels |
| Each Gate B mapping or protocol artifact | 2 MiB |
| Gate B model or policy input | 64 MiB |
| Nonblank records per JSONL file | 100,000 |
| Records per descriptor-bound historical JSONL output artifact | 1,000,000 |
| Encoded JSONL physical-line size, including LF or CRLF | 1 MiB |
| JSON object/array nesting depth during qualification | 128 levels |
| Events per case | 10,000 |
| `untrusted_text` length per event | 16,384 characters |
| Serialized `attributes` size per event | 256 KiB |

These are defensive parser bounds, not demonstrated throughput or production capacity. A future adapter requires its own decompression, expansion, and source-rate limits; the starter accepts no archives or streams.

## Failure behavior and accounting boundary

`FAIL_DATASET` validates the declared cases as one unit. Manifest, digest, count, path, governance, case-JSONL, structural, case-semantic, or snapshot-copy failure aborts before the decision engine is invoked.

`QUARANTINE_RECORD` is a bounded exception for reviewed case-local defects. Invalid JSON, ordinary missing/extra fields, invalid timestamps/types/enums/ranges, case/event mismatch, and canonical-context defects can be quarantined with stable metadata-only codes. Source-read failure, invalid source encoding, an oversized physical line, excessive JSON nesting, an unsupported case-contract version, runtime-label contamination, duplicate case/event identifiers, record-count overflow, source-digest mismatch, or an unmapped validator failure is fatal for the complete qualification call. A fatal result returns no accepted subset.

The seven-record campaign demonstrates `7 = 3 accepted + 4 quarantined` and three downstream decisions. The four reasons are exactly one each of `SYNTAX / INVALID_JSON`, `STRUCTURE / MISSING_REQUIRED_FIELD`, `SEMANTICS / INVALID_TIMESTAMP`, and `SEMANTICS / CANONICAL_CONTEXT_MISMATCH`. These results are synthetic test evidence, not estimates of historical source quality or model efficacy.

Modeled-signal type, range, source-authority, and inventory-context failures occur before production feature extraction. Under `FAIL_DATASET` they abort the case set; under the reviewed offline qualification policy, record-local defects use stable codes including `INVALID_BOOLEAN`, `INVALID_TYPE`, and `UNAUTHORIZED_MODELED_SIGNAL`. A reference-projection mismatch occurs later, after decision and audit validation, and aborts before completed evaluation artifacts as described above.

Adjudication JSON and semantics are intentionally evaluated later. Duplicate JSON object members, malformed content, or an inconsistent adjudication abort the evaluation after read-only decisions and their boundary audit exist, but before comparison metrics or a completed run manifest are emitted. This ordering preserves runtime/evaluator separation; the nonempty output-directory guard preserves the partial evidence rather than silently overwriting it.

For both included fixtures, historical efficacy, historical calibration, and historical acceptance rates are unavailable because `historical_case_count=0`. Unavailable adjudication metrics are represented as `null`; they must not be described as measured zero performance. Model measures computed on accepted cases are conditional on qualification and cannot be generalized to the complete source population without explicit missingness and survivorship-bias analysis.

The fixed `P2-CE-004` campaign binds corrected implementation Commit `53e409d6ffa4af98ea892bc1a81302bf30870693` to two complete deterministic same-process repetitions of 16 synthetic attempts. All 32 observations matched the project-controlled expectations with zero retries, exclusions, failures, or deviations: 16 clean matches, eight qualification quarantines, and eight reference-projection blocks. The two sanitized ledgers are byte-identical. This is SELF-reviewed CE-2 evidence only; it does not establish historical/live behavior, source truth, full decision correctness, independent assurance, exhaustive coverage, or a bounded failure rate.
