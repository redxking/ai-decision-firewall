# Phase 2 Data Contracts

## Contract objective and status

Phase 2 defines a narrow, versioned boundary between an untrusted local evidence snapshot and the v0.1 decision engine. It accepts canonical JSONL, validates integrity and record counts, and decodes separately stored adjudications only after decision processing and read-only safety checks finish. Phase 2.1 qualifies bounded case records into accepted and quarantined sets with exact metadata-only accounting. Phase 2.2 adds a separate Gate B authority, custody, and binding contract before historical payload access.

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
- `contracts/v0.2.0/examples/gate-b-authorization-draft.json`
- `contracts/v0.2.0/examples/phase2-starter-evidence-record.json`
- `contracts/v0.2.0/README.md`
- `src/adf_poc/replay/contracts.py`
- `src/adf_poc/replay/qualification.py`
- `src/adf_poc/replay/gate_b.py`
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

Invalid values are rejected rather than coerced, apart from deterministic normalization of accepted timestamps and numeric representations after validation.

## Canonical-context cross-field validation

V0.1 consumes top-level `break_glass`, `asset_id`, and `asset_criticality` directly. Phase 2 therefore treats every `asset_inventory` event as an authoritative consistency check:

- its attributes must contain `break_glass` and `asset_criticality`;
- those values must equal the top-level values, with zero relative tolerance and `1e-12` absolute tolerance for criticality;
- `attributes.asset_id`, when present, must equal the top-level `asset_id`;
- multiple inventory events must each agree; disagreement is not resolved through majority voting.

A conflict prevents that case from reaching model or policy evaluation. It aborts the case set under `FAIL_DATASET` and is quarantined as `SEMANTICS / CANONICAL_CONTEXT_MISMATCH` under `QUARANTINE_RECORD`. The implementation does not infer a missing critical value or choose a permissive default.

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

Adjudications reside in a separate JSONL file. The harness integrity-freezes their exact bytes outside the runner inputs, runs the engine against accepted case/model/policy inputs, validates read-only decisions and finalization audit bindings, and only then materializes and decodes the adjudication snapshot. This is a harness-enforced interface boundary, not an OS sandbox against arbitrary same-process introspection. Each adjudication has exactly:

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

Adjudication JSON and semantics are intentionally evaluated later. Duplicate JSON object members, malformed content, or an inconsistent adjudication abort the evaluation after read-only decisions and their boundary audit exist, but before comparison metrics or a completed run manifest are emitted. This ordering preserves runtime/evaluator separation; the nonempty output-directory guard preserves the partial evidence rather than silently overwriting it.

For both included fixtures, historical efficacy, historical calibration, and historical acceptance rates are unavailable because `historical_case_count=0`. Unavailable adjudication metrics are represented as `null`; they must not be described as measured zero performance. Model measures computed on accepted cases are conditional on qualification and cannot be generalized to the complete source population without explicit missingness and survivorship-bias analysis.
