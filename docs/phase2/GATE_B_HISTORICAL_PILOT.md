# Gate B historical-pilot preflight

Gate B is the authorization and evidence boundary for the first small, de-identified historical replay. It remains offline and read-only. It does not authorize a live feed, shadow-feed deployment, operational recommendation workflow, action credential, write-capable connector, or operational action.

The public repository contains the contract and blank templates needed to design the package. It must not contain actual historical data, adjudications, approval records, source-specific mappings, custody records, identities, signatures, endpoints, or linkable historical digests.

## Gate outcome

Gate B has only two executable outcomes:

- `APPROVED`: the exact package passes machine preflight and the runtime may open the bound historical payload for an in-scope `HISTORICAL_REPLAY` run with live actions disabled.
- anything else: stop before historical payload access.

`DRAFT`, `REJECTED`, `REVOKED`, and `EXPIRED` are non-authorizing. A schema-valid DRAFT remains a draft.

## Required package

The restricted Gate B package consists of:

1. a machine-readable authorization record conforming to [`gate-b-authorization.schema.json`](../../contracts/v0.2.0/gate-b-authorization.schema.json);
2. an externally held manifest and frozen source snapshot whose identity and manifest digest match the authorization record;
3. a frozen source mapping, adjudication protocol, and pilot protocol, each bound by confined relative path and SHA-256;
4. a frozen contract version, contract adapter, model, and policy;
5. external approval, review, custody, de-identification, retention/deletion, incident-response, isolation, and kill-switch evidence; and
6. a predeclared sampling, holdout, stop-condition, adjudication, and claim-control plan.

Use the public templates only as starting points:

- [`GATE_B_PILOT_PROTOCOL_TEMPLATE.md`](templates/GATE_B_PILOT_PROTOCOL_TEMPLATE.md)
- [`SOURCE_MAPPING_TEMPLATE.csv`](templates/SOURCE_MAPPING_TEMPLATE.csv)
- [`ADJUDICATION_PROTOCOL_TEMPLATE.md`](templates/ADJUDICATION_PROTOCOL_TEMPLATE.md)
- [`gate-b-authorization-draft.json`](../../contracts/v0.2.0/examples/gate-b-authorization-draft.json)

Every committed template is `NOT APPROVED` and contains no historical data. Complete operational packages belong in an approved restricted system, not this repository.

Within a restricted working copy, authorization and bound control artifacts must be placed under ignored `local/gate_b/`; historical output must use a new ignored run-specific `outputs/replay/<run>/` directory with owner-only access. The runtime retains directory descriptors for snapshots and artifacts, rejects changed path bindings, and never gives the historical decision runner a filesystem path. This blocks path-redirection failures inside the application boundary; it is not an operating-system isolation control against another process running as the same user. The runtime does not implement a one-time authorization-consumption ledger. If single-use approval is required, that control must be externally anchored and checked before each run; otherwise an unchanged package may be reused only within its recorded scope and validity interval.

## Required authority

The authorization record contains exactly one approval for each role:

| Role | Required decision | Scope of accountability |
|---|---|---|
| `DATA_OWNER` | `APPROVED` | Exact dataset, purpose, population, time window, access, and use |
| `MISSION_OWNER` | `APPROVED` | Mission need, operational boundary, acceptable consequences, and claim use |
| `SECURITY` | `APPROVED` | Isolation, identities, connectors, egress, monitoring, kill switch, and incident response |
| `PRIVACY_LEGAL` | `APPROVED` | Lawful use, de-identification, re-identification risk, jurisdiction, and disclosure boundary |
| `RECORDS_MANAGEMENT` | `APPROVED` | Custody, retention, deletion, evidence preservation, and disposition |

An independent reviewer must separately record `APPROVED`, and the asserted `reviewer_id` must differ from every asserted approval identity. `approver_id`, `approval_reference`, `reviewer_id`, and `review_reference` are pointers into authenticated external systems. String inequality and nonempty values are structural checks, not proof of identity, independence, authority, or signature authenticity.

## Machine-readable record

The top-level fields are fixed:

`schema_version`, `authorization_id`, `status`, `dataset_id`, `dataset_manifest_sha256`, `approved_purpose`, `population_scope`, `window_start`, `window_end`, `valid_from`, `expires_at`, `approvals`, `artifact_bindings`, `controls`, `custody`, `sampling`, `stop_conditions`, `adjudication`, `independent_review`, and `claim_control`.

The closed nested records require:

- `approvals[]`: `role`, `status`, `approver_id`, `approval_reference`, `approved_at`;
- `artifact_bindings`: `contract_version`, `contract_adapter`, `model_sha256`, `policy_sha256`, and `artifacts[]` with `role`, confined relative `path`, and `sha256`;
- `controls`: the de-identification assessment reference; direct-identifier and re-identification-review states; offline/no-live-feed/no-action-credential/no-write-connector/no-egress states; runtime-label separation; complete-intake reporting; restricted hash handling; and retention/deletion, incident-response, isolation, and kill-switch references;
- `custody`: snapshot, custody-record, and external-manifest-digest references, freeze time, and custodian identifier;
- `sampling`: protocol reference, predeclaration time, temporal-holdout interval, complete-intake and sample counts, selection method, and frozen state;
- `stop_conditions`: overall and category quarantine ceilings, fatal/unknown stop behavior, frozen thresholds, and escalation owner;
- `adjudication`: protocol reference, minimum reviewers, runtime separation, hidden labels until decision, permitted indeterminate outcomes, and disagreement resolution;
- `independent_review`: status, reviewer identifier, review reference, and review time; and
- `claim_control`: claim owner, pause authority, revocation authority, matching expiry, and revalidation triggers.

Exactly one artifact is required for each role: `SOURCE_MAPPING`, `ADJUDICATION_PROTOCOL`, and `PILOT_PROTOCOL`.

## Fail-closed preflight sequence

For `HISTORICAL_DEIDENTIFIED` origin, the runtime sequence is mandatory:

1. Read configuration and the manifest control bytes needed to identify the proposed dataset and control files.
2. Resolve the Gate B path under repository/path-confinement rules and read the authorization snapshot.
3. Validate the closed schema and require top-level `status=APPROVED`.
4. Verify all five unique approval roles, a differently identified approved reviewer, the validity interval, `window_end <= custody.frozen_at <= valid_from`, bounded presence of purpose and population assertions, source window, and matching claim expiry. The truth and authorized meaning of purpose/population, identity, and reviewer independence remain external governance facts.
5. Bind the dataset ID and manifest digest; then bind contract, adapter, model, policy, and the three required artifacts.
6. Resolve each bound artifact without symlink traversal and compare its bytes to the declared SHA-256.
7. Verify critical controls, custody references, frozen sampling, temporal holdout, complete-intake denominator, predeclared thresholds, fatal behavior, adjudication separation, and claim revalidation controls.
8. Cross-check `sample_count = manifest cases record_count = historical_case_count`, `sample_count <= full_intake_count`, nonempty holdout containment in the approved window, unique known category thresholds, approval/review/predeclaration/freeze times no later than `valid_from`, and configuration requirements: `HISTORICAL_REPLAY`, `QUARANTINE_RECORD`, and live actions disabled.
9. Only after every structural, authority, binding, time, resource, path, and declared-count check passes may the runtime open, hash, count, decode, parse, or qualify case/adjudication payloads.
10. After case qualification, but before normalization or engine invocation, verify every accepted `opened_at` value against the approved half-open window and every observed overall/category quarantine rate against its frozen threshold. Any unknown observed category or threshold breach stops the run.
11. Recheck the current half-open authorization interval immediately before the runner, after the runner returns, and before final evidence completion. Expiry or revocation requires a stopped run; it cannot be converted into a completed manifest by finishing work that began while authorization was current.

Before step 9, the runtime may read only configuration, manifest control bytes, the Gate B package, model and policy, and the bound pilot-protocol, source-mapping, and adjudication-protocol controls. Pre-reading a case or label file to discover its size, count, digest, encoding, or validity violates Gate B even if the run later aborts.

Any unknown preflight condition, missing evidence, mismatch, stale approval, zero/placeholder binding, path escape, symlink, category duplication, declared-count inconsistency, or control deviation fails closed before payload access. Outcome-dependent window and quarantine checks necessarily run after authorized qualification and still fail closed before the engine.

Control JSON is limited to one MiB and 128 nesting levels. Each mapping/protocol artifact is limited to two MiB; the bound model and policy are each limited to 64 MiB. These are code-owned POC resource ceilings, not demonstrated production capacities.

## Preparation workflow

### 1. Define scope before acquiring data

Record the exact purpose, source systems, population, inclusion/exclusion rules, jurisdiction, source window, maximum intake, authorized personnel, and prohibited uses. Define the claim that could be supported and the claims that remain prohibited. Do not acquire or stage historical bytes merely to estimate the scope.

### 2. Complete privacy, security, and custody design

Document removal of direct identifiers and test residual re-identification risk from pseudonymous identifiers, free text, rare events, timestamps, combinations of attributes, and hashes. Define restricted storage, access logging, isolation, egress denial, no-action/no-write configuration, retention, deletion verification, incident handling, and the data-collection kill switch.

Freeze the source snapshot and custody record outside the mutable replay directory. Keep the authoritative manifest digest in an independent system. References and digests are evidence pointers, not anonymization.

### 3. Freeze mapping and configuration

Complete the source mapping for every available, missing, derived, normalized, or excluded field. Record source completeness, timestamp semantics, enumeration mappings, canonical-context assumptions, null treatment, and known loss. Freeze the contract, adapter, model, policy, mapping, and three protocol artifacts before outcomes are visible.

### 4. Predeclare sampling and holdout

Preserve the complete intake universe. Record `full_intake_count` independently of accepted records and set `sample_count` no higher than that denominator. Define selection strata and exclusions before labels or results are visible. Place the temporal holdout wholly inside the approved source window, and prohibit threshold or sample changes after outcomes are observed.

The pilot evidence must report intake, accepted, quarantined, fatal, excluded, adjudicated, indeterminate, and missing-label counts together. Decision metrics calculated on accepted cases never replace the complete-intake denominator.

### 5. Predeclare stop conditions

Set a maximum overall quarantine rate and a unique ceiling for every category in scope. Stop on any fatal validator condition and on any unknown failure. Also stop on authority expiry/revocation, manifest or artifact mismatch, custody loss, isolation or egress failure, label exposure, source drift, count inconsistency, incident, or evidence-accounting failure.

A threshold breach, an observed quarantine category without a predeclared threshold, or an accepted case outside the approved half-open source window pauses the pilot and escalates to the named owner. It does not justify deleting rejected records, relaxing thresholds, changing the sample, or continuing only with accepted cases.

### 6. Approve adjudication before replay

Use at least two qualified reviewers. Keep runtime evidence and evaluator labels physically and procedurally separate; hide labels until the runtime decision is final. Permit an explicit indeterminate outcome. Predeclare disagreement resolution, conflict-of-interest handling, hindsight-bias controls, and when a case must remain unresolved rather than forced into consensus.

### 7. Obtain approvals and independent review

Each required role approves the same immutable package. The independent review covers the implementation, schema, mapping, de-identification evidence, custody, sampling, stop rules, adjudication protocol, read-only architecture, and claim wording. Any changed byte invalidates the associated binding and requires revalidation.

### 8. Execute, review, and dispose

Run only inside the approved isolated environment and validity interval. The implementation rechecks the recorded interval at major processing boundaries, but an external authority remains responsible for communicating revocation and enforcing any stronger real-time or single-use control. Monitor stop conditions throughout the run. Preserve restricted evidence under the custody and retention plan, investigate deviations, validate deletion when due, and generate sanitized public summaries only after independent claim review.

## Claim and publication boundary

Gate B approval authorizes data processing within a bounded pilot; it does not predetermine a favorable result. Historical replay may establish only the claim class supported by the completed evidence record. It cannot establish production readiness, safe autonomy, alignment, future incident prevention, absence of rare failures, monitor effectiveness, live-shadow safety, or action safety.

The authorization snapshot and its approval, review, custody, source, incident, and hash references may be sensitive and are excluded from public evidence summaries. A bounded opaque `authorization_id` may appear in the runtime's aggregate preflight summary for trace correlation only; it must not encode a person, system, incident, source, or other sensitive identifier. Do not publish record-level source metadata, linkable line or source digests, rare-event combinations, personnel identifiers, source-system identifiers, or representative failures that could enable re-identification.

Machine validation proves internal structure and binding only. It does not prove legal authority, identity, signature authenticity, effective de-identification, custody truth, or historical efficacy.

## Revalidation and revocation

Pause before further payload access when any of the following occurs:

- authorization or claim expiry, revocation, rejected review, or changed personnel authority;
- any source, manifest, mapping, contract, adapter, model, policy, artifact, control, sampling, holdout, adjudication, or claim change;
- an incident, custody break, control failure, source drift, newly discovered privacy risk, classifier gap, label leak, or unknown failure; or
- a proposed expansion in source, population, time window, environment, personnel, purpose, publication, or claim.

Resume only with a newly frozen and independently reviewed package whose approvals and bindings cover the change. Gate B never rolls forward automatically.
