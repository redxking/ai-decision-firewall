# ADR 006: Require a machine-readable Gate B preflight before historical payload access

**Status:** Accepted for the Phase 2.2 preflight; no historical pilot is approved by this decision

## Context

The synthetic Phase 2 and Phase 2.1 results establish bounded controlled behavior only. They do not establish authority to process historical data, effective de-identification, source custody, adjudication validity, or historical performance. A replay manifest attestation is also insufficient: a dataset producer must not be able to self-assert the legal, mission, privacy, security, records-management, custody, and claim authorities needed for a historical pilot.

Gate B therefore needs both human-governed evidence and a fail-closed machine preflight. The machine-readable record must bind the exact dataset manifest, model, policy, contract, adapter, source mapping, adjudication protocol, pilot protocol, controls, custody record, sampling plan, stop conditions, independent review, and claim lifecycle. It must do so without turning the public repository into a historical-data or approval repository.

## Decision

Historical, de-identified data may be considered only for `HISTORICAL_REPLAY` with `live_actions_enabled=false`, `record_failure_policy=QUARANTINE_RECORD`, and a Gate B document that passes all preflight checks. The public contract is [`gate-b-authorization.schema.json`](../../contracts/v0.2.0/gate-b-authorization.schema.json). A conforming record is necessary but not sufficient.

The runtime shall accept only top-level `status=APPROVED`. It shall require one current approval from each of `DATA_OWNER`, `MISSION_OWNER`, `SECURITY`, `PRIVACY_LEGAL`, and `RECORDS_MANAGEMENT`, plus an `APPROVED` review whose asserted reviewer identifier differs from all asserted approver identifiers. Approval references remain external evidence references; identifier inequality does not authenticate identity, independence, or authority.

The authorization document shall bind:

- the exact `dataset_id` and manifest SHA-256;
- contract version and adapter plus model and policy SHA-256 values;
- exactly one confined, regular, non-symlink artifact for each role: `SOURCE_MAPPING`, `ADJUDICATION_PROTOCOL`, and `PILOT_PROTOCOL`;
- the approved purpose, population, source window, authorization validity interval, and claim expiry;
- de-identification, re-identification-risk, isolation, no-live-feed, no-action-credential, no-write-connector, no-egress, label-separation, complete-intake, restricted-hash, retention/deletion, incident-response, and kill-switch controls;
- external snapshot custody, sample and temporal-holdout design, fatal and quarantine stop conditions, evaluator separation, indeterminate outcomes, disagreement handling, independent review, and claim pause/revocation/revalidation ownership.

The semantic preflight shall additionally require:

- `expires_at` to equal `claim_control.expires_at`, `valid_from <= current_utc < expires_at`, and every approval, review, predeclaration, and custody-freeze timestamp to be no later than `valid_from`;
- `window_start < window_end <= custody.frozen_at <= valid_from < expires_at`, and a nonempty temporal holdout to fall wholly within the approved window;
- `sample_count` to equal both the manifest's declared cases count and `historical_case_count`, with `sample_count <= full_intake_count`;
- approval roles, artifact roles, and category thresholds to be unique;
- the manifest identity and digest, model and policy digests, adapter, and contract version to match the frozen runtime inputs;
- all critical Boolean controls to have the fail-closed values defined by the contract; and
- every bound artifact path to use ignored `local/gate_b/`, remain confined with no symlink component, stay within its code-owned size ceiling, and match the declared SHA-256.

The runtime rechecks the recorded validity interval before payload access, before and after the decision runner, and before final evidence completion. This detects local time-based expiry at those processing boundaries; it does not authenticate an external revocation channel or provide a one-time-use ledger.

After authorized case qualification, but before normalization or engine invocation, the runtime shall separately require every observed quarantine category to have a predeclared threshold, overall and category rates to remain at or below those thresholds, and accepted case `opened_at` values to fall within the approved half-open source window. These outcome-dependent checks cannot occur before payload access.

### Payload-access order

For a manifest declaring historical, de-identified origin, the runtime may read only configuration and manifest control bytes, the Gate B package, the model and policy, and the bound source-mapping, adjudication-protocol, and pilot-protocol control artifacts until preflight passes. It must not open, hash, count, decode, parse, qualify, normalize, or adjudicate the cases or adjudications files first. Any missing, malformed, stale, inconsistent, unapproved, unbound, or inaccessible preflight input terminates the run before historical payload access.

This ordering is a security and privacy invariant, not an optimization. A failed authorization check must not leak source existence, size, record count, line digests, parse behavior, or labels through preliminary processing.

Historical output is confined to a new ignored run-specific `outputs/replay/<run>/` directory with owner-only access. Snapshot and artifact I/O is bound to retained directory descriptors with no-follow, exclusive-create semantics and binding checks before and after operations. The historical decision runner receives in-memory accepted cases, model bytes, policy bytes, and the read-only mode—not filesystem or evaluator-label paths. This is an application-level boundary, not protection against another process operating under the same user identity. Control JSON is limited to one MiB and 128 nesting levels; each mapping/protocol artifact is limited to two MiB; and model and policy inputs are each limited to 64 MiB.

### Non-authorizing drafts

`status=DRAFT` exists only so a proposed package can be assembled and schema-checked. It is never an approval claim and shall always be rejected by the historical runtime preflight. The committed example uses expired placeholder dates, zero placeholder digests, pending roles, and unverified references. Copying, editing, signing, hashing, or validating that example does not authorize processing.

## What machine validation establishes

Machine validation can establish internal structure, permitted values, required-role presence, internal consistency, path confinement, and byte-level binding to the exact artifacts visible to the validator.

It does **not** establish legal authority, approver identity, signature authenticity, effective de-identification, truth of custody assertions, or historical efficacy. Those are externally governed facts requiring authenticated approval systems, competent review, protected custody evidence, empirical validation, and appropriately bounded evaluation results. A schema-valid or preflight-valid package must never be described as independent certification of any of them.

## Security and evidence handling

The authorization snapshot, approver identifiers, approval and review references, custody references, source-system references, incident references, and linkable digests may be sensitive even when no direct identifiers are present. They remain in the restricted pilot evidence boundary and are excluded from public evidence summaries. The runtime summary may retain only a bounded opaque `authorization_id` for trace correlation; it must encode no sensitive identity or source meaning. Public summaries may report sanitized control status, aggregate intake/accounting, bounded results, limitations, and nonclaims.

No actual historical cases, adjudications, authorization record, approval evidence, custody record, source mapping, source-specific protocol, endpoint, credential, direct identifier, pseudonymous identifier, or linkable historical digest may be committed to the public repository. The repository contains schemas and explicitly non-authorizing templates only.

## Consequences

- Historical payload access fails closed before payload bytes are touched when authority or binding is absent.
- Human approval and external custody remain distinct from machine conformance.
- Results can be traced to a frozen configuration without making the repository the system of record for sensitive approvals or data.
- Gate B permits only bounded, offline, read-only historical replay within the approved scope and time. The runtime has no one-time authorization-consumption ledger; single-use enforcement, if required, must be externally anchored. It does not authorize a live feed, live shadow deployment, operational recommendation workflow, action credential, write-capable integration, or operational action.
- Any change to the source, manifest, mapping, contract, adapter, model, policy, controls, sampling, adjudication, personnel authority, claim, or incident state triggers pause and revalidation.

## Alternatives considered

**Manifest attestations only.** Rejected because dataset authors could self-assert approvals and because the manifest does not bind the complete authority, custody, sampling, adjudication, and claim package.

**Process historical files and validate authorization before the engine.** Rejected because opening or measuring the payload before approval violates the data-access boundary and can disclose sensitive metadata.

**Store signed approvals and historical digests in the public repository.** Rejected because approval references, custody records, source identity, and linkable hashes may themselves be sensitive. The public repository is not the authoritative approval or custody system.

**Treat schema validity as authorization.** Rejected because structural conformance cannot prove authority, identity, signatures, de-identification effectiveness, custody truth, or outcome validity.
