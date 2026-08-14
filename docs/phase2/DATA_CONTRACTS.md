# Phase 2 Data Contracts

## Contract objective and status

Phase 2 defines a narrow, versioned boundary between an untrusted local evidence snapshot and the v0.1 decision engine. The starter accepts canonical JSONL, validates integrity and record counts across the complete declaration, converts a fully validated case set to the v0.1 `IdentityCase` shape, and decodes separately stored adjudications only after decision processing and read-only safety checks finish.

The implemented contract version is `0.2.0`. The executable Python validation in `src/adf_poc/replay/contracts.py` is the runtime authority; the schemas under `contracts/v0.2.0/` document and independently constrain the same public shape. Unknown fields are rejected rather than silently ignored. These starter contracts do not certify source semantics, legal authority, de-identification effectiveness, or production fitness.

The included dataset under `data/phase2_starter/` is synthetic. Its manifest declares `data_origin: SYNTHETIC_FIXTURE` and `historical_case_count: 0`. No historical record, production identifier, real incident narrative, raw vendor export, or live telemetry is included.

## Contract artifacts

- `contracts/v0.2.0/replay-manifest.schema.json`
- `contracts/v0.2.0/replay-case.schema.json`
- `contracts/v0.2.0/replay-adjudication.schema.json`
- `contracts/v0.2.0/evaluation-evidence.schema.json`
- `contracts/v0.2.0/examples/phase2-starter-evidence-record.json`
- `contracts/v0.2.0/README.md`
- `src/adf_poc/replay/contracts.py`
- `src/adf_poc/replay/adapters.py`

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
| `record_count` | Nonnegative count of nonblank JSONL object records |
| `adapter` | `canonical_jsonl_v0.2` |

A cases file is always required. `HISTORICAL_REPLAY` also requires a physically separate adjudications file. Before any decision processing, the loader resolves every path, verifies that it is a file inside the manifest directory, recomputes every declared digest, enforces file and line bounds, and compares the count of nonblank records with the declaration. The harness then copies the exact configuration, manifest, model, policy, cases, and adjudications into a new run-owned input snapshot; verifies every copied digest and declared count; and loads only from that snapshot. It verifies the snapshot again after engine execution and before final artifacts are produced. The case adapter decodes and semantically validates every snapshotted case before engine invocation. Evaluator-only adjudication bytes are snapshotted, integrity-checked, and counted at this stage but deliberately not decoded until read-only decisions and boundary-audit validation have closed. Any digest, count, path, governance, or case-contract mismatch aborts before the engine runs.

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

Before an accepted case reaches the engine, the validator enforces all of the following:

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

A conflict rejects the dataset before model or policy evaluation. The starter does not infer a missing critical value or choose a permissive default.

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

The manifest gate is necessary but insufficient for historical use. Before a historical dataset is created or processed, external Gate B approval must establish the data owner, authorized purpose, source scope, privacy/legal and mission review, de-identification method and validation, access, retention, deletion, incident response, source mapping, and custody. The public repository must remain synthetic-only. Pseudonymous values may still be sensitive or linkable.

## Label and adjudication separation

Runtime case validation recursively rejects keys including `adjudication`, `adjudicated_disposition`, `compromised`, `expected_disposition`, `ground_truth`, `is_malicious`, `label`, `malicious`, `outcome_label`, and `scenario`. This is a structural leakage guard, not proof that free text or correlated features contain no hindsight.

Adjudications reside in a separate JSONL file. The harness runs the engine against the frozen case/model/policy inputs, validates read-only decisions and their finalization audit bindings, and closes decision processing before decoding the frozen adjudication snapshot. Each adjudication has exactly:

- `schema_version` equal to `0.2.0`;
- unique `adjudication_id` and a `case_id` that resolves to an accepted case;
- `adjudicated_at` with an explicit UTC offset and a constrained `adjudicator_role`;
- `adjudicated_disposition` equal to `NO_ACTION`, `INVESTIGATE`, `CONTAIN_REVERSIBLE`, or `ESCALATE_HUMAN`;
- Boolean `compromised`, confidence in `[0,1]`, and a nonempty unique list of `rationale_codes`.

Only one adjudication per case is accepted by this starter. These records are evaluator outcomes with stated confidence; they are not automatically ground truth and they do not establish inter-analyst agreement.

## Path confinement and input surface

Configuration paths are repository-relative and resolved beneath the supplied repository root. Manifest file paths are relative to—and resolved beneath—the manifest directory. Absolute paths, parent traversal, and symlink resolution outside the allowed root fail closed. Declared inputs must exist as files.

The canonical adapter does not fetch URLs, call vendor APIs, expand archives, execute plugins, or discover inputs with wildcards. This is an offline local-snapshot interface, not a live connector.

## Bounded parsing

The starter fails closed on inputs that exceed these code-owned limits:

| Limit | Maximum |
|---|---:|
| Declared file size | 512 MiB |
| Configuration or manifest document | 1 MiB |
| Nonblank records per JSONL file | 100,000 |
| Encoded JSONL line size | 1 MiB |
| Events per case | 10,000 |
| `untrusted_text` length per event | 16,384 characters |
| Serialized `attributes` size per event | 256 KiB |

These are defensive parser bounds, not demonstrated throughput or production capacity. A future adapter requires its own decompression, expansion, and source-rate limits; the starter accepts no archives or streams.

## Failure behavior and accounting limitation

The implemented starter validates the declared cases as a unit. Manifest, digest, count, path, governance, case-JSONL, structural, case-semantic, or snapshot-copy failure aborts before the decision engine is invoked; the exception carries the specific failure reason. A snapshot digest or count change detected during the run aborts finalization. A malformed case is not silently dropped and valid cases from the same file are not processed after that failure.

Adjudication JSON and semantics are intentionally evaluated later. A malformed or inconsistent adjudication aborts the evaluation after read-only decisions and their boundary audit exist, but before comparison metrics or a completed run manifest are emitted. This ordering preserves runtime/evaluator separation; the nonempty output-directory guard preserves the partial evidence rather than silently overwriting it.

Per-record reject-and-continue processing, a `rejections.jsonl` artifact, and the accounting invariant `input_records = accepted_records + rejected_records` are traced planned capabilities, not current starter claims. They require an explicit policy for safe partial-dataset acceptance before implementation.

For the included fixture, historical efficacy and historical calibration are unavailable because `historical_case_count=0`. Unavailable adjudication metrics are represented as `null`; they must not be described as measured zero performance.
