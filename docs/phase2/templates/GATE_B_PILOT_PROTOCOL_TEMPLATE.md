# Gate B pilot protocol template

> **NOT APPROVED — TEMPLATE ONLY — NO HISTORICAL DATA**
>
> This file is not an authorization, approval record, custody record, signature, or completed protocol. Do not place real names, signatures, endpoints, source-system identifiers, approval-system identifiers, historical digests, record samples, or historical data in the public repository. Complete and retain an operational copy only in the approved restricted evidence system.
>
> Repository status at template review: exact Phase 2.5 Commit
> `854b15c56397a81de6326b719d3d7d1dc847608f` is published on `main` and its
> exact-commit CI/Dependency Graph checks passed. Its package boundary includes
> 222/222 technical tests and separate 9/9 site tests; site tests are outside
> Phase 2.5/pilot evidence. Publication does not make the commit an approved
> pilot baseline. No Gate B package or tag/evidence package exists.
> `P2-CE-005` was not executed and remains CE-0 `NOT_EVALUATED`; it supplies no
> pilot evidence or authority.

## Document control

| Field | Required value |
|---|---|
| Protocol status | `DRAFT / NOT APPROVED` |
| Protocol reference | `[RESTRICTED-REFERENCE-NOT-SET]` |
| Authorization ID | `[DRAFT-AUTHORIZATION-ID]` |
| Dataset ID | `[PLACEHOLDER-DATASET-ID]` |
| Dataset manifest SHA-256 | `[64-HEX-DIGEST-RESTRICTED-NOT-SET]` |
| Approved purpose | `[EXACT-PURPOSE-NOT-APPROVED]` |
| Population scope | `[EXACT-SOURCES-POPULATION-INCLUSIONS-EXCLUSIONS-JURISDICTION-NOT-APPROVED]` |
| Source window | `[WINDOW-START]` through `[WINDOW-END]` |
| Authorization validity | `[VALID-FROM]` through `[EXPIRES-AT]` |
| Execution mode | `HISTORICAL_REPLAY` |
| Manifest origin | `HISTORICAL_DEIDENTIFIED` |
| Record-failure policy | `QUARANTINE_RECORD` |
| Live actions | `false` |
| Approved repository release/commit | `[EXACT-CLEAN-PUBLISHED-RELEASE-AND-40-HEX-COMMIT — NOT SET]` |
| Release-required assurance profile | `[ALPHA.5: REFERENCE_FEATURE / FINAL ALPHA.6: REFERENCE_FEATURE + SOURCE_TO_DECISION / OTHER RELEASE-SPECIFIC PROFILE — NOT APPROVED]` |
| Contract version and adapter | `0.2.0 / [FROZEN-ADAPTER]` |
| Model SHA-256 | `[64-HEX-DIGEST-RESTRICTED-NOT-SET]` |
| Policy SHA-256 | `[64-HEX-DIGEST-RESTRICTED-NOT-SET]` |
| Predeclared at | `[TIMESTAMP-BEFORE-OUTCOME-ACCESS]` |

## Authority and sign-off record

All roles must approve the same frozen package. Use stable identifiers and authenticated external references in the restricted authorization record; do not copy names or signatures into this template.

| Role | Approver ID | Status | External approval reference | Approved at | Exact scope/conditions |
|---|---|---|---|---|---|
| `DATA_OWNER` | `[NOT-ASSIGNED]` | `PENDING` | `[NOT-AN-APPROVAL]` | `[NULL]` | Exact data, purpose, population, window, access, and use |
| `MISSION_OWNER` | `[NOT-ASSIGNED]` | `PENDING` | `[NOT-AN-APPROVAL]` | `[NULL]` | Mission need, boundary, consequences, and claim use |
| `SECURITY` | `[NOT-ASSIGNED]` | `PENDING` | `[NOT-AN-APPROVAL]` | `[NULL]` | Isolation, egress, identity, connector, monitoring, kill-switch, and incident controls |
| `PRIVACY_LEGAL` | `[NOT-ASSIGNED]` | `PENDING` | `[NOT-AN-APPROVAL]` | `[NULL]` | Lawful use, de-identification, re-identification risk, jurisdiction, and disclosure |
| `RECORDS_MANAGEMENT` | `[NOT-ASSIGNED]` | `PENDING` | `[NOT-AN-APPROVAL]` | `[NULL]` | Custody, retention, deletion, evidence preservation, and disposition |

- Independent review status: `PENDING / NOT APPROVED`
- Independent reviewer ID: `[NOT-ASSIGNED]`
- External review reference: `[NOT-A-REVIEW]`
- Reviewed at: `[NULL]`

## Bound artifacts

Use repository-relative confined paths for the restricted execution package. Resolve each path without symlink traversal and bind the exact file bytes.

| Required role | Confined relative path | SHA-256 | Frozen/reviewed at |
|---|---|---|---|
| `SOURCE_MAPPING` | `[RESTRICTED-PATH-NOT-SET]` | `[64-HEX-DIGEST-NOT-SET]` | `[NOT-FROZEN]` |
| `ADJUDICATION_PROTOCOL` | `[RESTRICTED-PATH-NOT-SET]` | `[64-HEX-DIGEST-NOT-SET]` | `[NOT-FROZEN]` |
| `PILOT_PROTOCOL` | `[RESTRICTED-PATH-NOT-SET]` | `[64-HEX-DIGEST-NOT-SET]` | `[NOT-FROZEN]` |

## Scope and prohibited use

Approved purpose: `[NOT APPROVED — describe one bounded evaluation purpose]`

Population definition: `[NOT APPROVED — enumerate source systems, tenant or organizational boundary, inclusion criteria, exclusion criteria, jurisdiction, maximum intake, source time window, personnel access, and known coverage gaps]`

Prohibited uses: `[live monitoring; operational recommendations; action; employment, legal, disciplinary, or access decisions; production claims; reuse outside the stated purpose; other restrictions]`

Explicit nonclaims: `[historical efficacy; production readiness; safe autonomy; alignment; privacy compliance; complete source coverage; zero residual risk; live-shadow safety; action safety]`

## Source completeness and provenance

- Collection authority and source provenance reference: `[RESTRICTED-REFERENCE-NOT-SET]`
- Complete intake universe definition: `[NOT-DEFINED]`
- Expected full-intake count and independent derivation: `[0 / NOT-DERIVED]`
- Manifest cases count and `historical_case_count` equality check: `[NOT-VERIFIED]`
- Source-availability and outage assessment: `[NOT-COMPLETED]`
- Missing-field, missing-source, delay, retry, duplication, and truncation assessment: `[NOT-COMPLETED]`
- Source-to-canonical mapping reference: `[NOT-FROZEN]`
- Canonical-context assumptions and ambiguity handling: `[NOT-APPROVED]`
- Known transformations, exclusions, and information loss: `[NOT-ASSESSED]`
- Completeness evidence owner and external reference: `[NOT-ASSIGNED / NOT-SET]`

Preserve `full_intake_count` separately from accepted, quarantined, excluded, adjudicated, and scored subsets. No post-outcome filtering may redefine the intake denominator.

## De-identification and privacy controls

- De-identification assessment reference: `[NOT-VERIFIED]`
- Direct identifiers removed: `false / NOT VERIFIED`
- Re-identification risk reviewed: `false / NOT VERIFIED`
- Pseudonymous identifier treatment: `[NOT-DEFINED]`
- Free-text treatment and inspection method: `[NOT-DEFINED]`
- Rare-event, timestamp, attribute-combination, and linkage-risk tests: `[NOT-DEFINED]`
- Source and raw-line hash handling: `[RESTRICTED / NOT-DESIGNED]`
- Data minimization justification: `[NOT-COMPLETED]`
- Disclosure-review method for aggregate and representative-failure reporting: `[NOT-COMPLETED]`
- Residual risks and accepted-risk authority: `[NOT-ASSESSED / NOT-ASSIGNED]`

De-identification must be tested; removal of obvious names is not sufficient. Hashes and pseudonymous values remain linkable and are not anonymization.

## Environment and read-only controls

| Control | Required approved state | Evidence reference |
|---|---:|---|
| `offline_only` | `true` | `[NOT-VERIFIED]` |
| `live_feed_connected` | `false` | `[NOT-VERIFIED]` |
| `action_credentials_present` | `false` | `[NOT-VERIFIED]` |
| `write_capable_connectors_present` | `false` | `[NOT-VERIFIED]` |
| `network_egress_disabled` | `true` | `[NOT-VERIFIED]` |
| `runtime_labels_separated` | `true` | `[NOT-VERIFIED]` |
| `complete_intake_reporting` | `true` | `[NOT-VERIFIED]` |
| `restricted_hash_handling` | `true` | `[NOT-VERIFIED]` |
| release-required reference checks enabled | `true` | `[NOT-VERIFIED]` |
| successful final harness return required | `true` | `[NOT-VERIFIED]` |

- Isolation boundary and test reference: `[NOT-SET]`
- Read-only identity and permission review: `[NOT-COMPLETED]`
- Monitoring and tamper-evidence plan: `[NOT-COMPLETED]`
- Data-collection kill-switch reference and last test: `[NOT-SET / NOT-TESTED]`
- Containment and recovery procedure: `[NOT-COMPLETED]`

## Custody, retention, deletion, and incident response

- Frozen snapshot reference: `[NO-HISTORICAL-SNAPSHOT]`
- Frozen at: `[NOT-FROZEN]`
- Custodian ID: `[NOT-ASSIGNED]`
- Custody record reference: `[NO-CUSTODY-RECORD]`
- External manifest-digest reference: `[NO-EXTERNAL-DIGEST]`
- Approved storage boundary and access-control reference: `[NOT-APPROVED]`
- Access-log retention and reviewer: `[NOT-DEFINED]`
- Retention period and legal/mission basis: `[NOT-APPROVED]`
- Deletion trigger, method, scope, verifier, and evidence reference: `[NOT-DEFINED]`
- Evidence-preservation exception process: `[NOT-DEFINED]`
- Incident-response reference, notification roles, and response times: `[NOT-APPROVED]`
- Conditions requiring immediate isolation, preservation, pause, or deletion: `[NOT-DEFINED]`

## Sampling and temporal holdout

- Sampling protocol reference: `[NOT-APPROVED]`
- Predeclared at: `[BEFORE-OUTCOME-ACCESS / NOT-SET]`
- Full intake count: `0 / NOT ESTABLISHED`
- Planned sample count: `0 / NOT ESTABLISHED`
- Selection method and reproducible seed/reference: `[NOT-DEFINED]`
- Source strata and minimum representation: `[NOT-DEFINED]`
- Predeclared exclusions with independent counts: `[NOT-DEFINED]`
- Temporal holdout start/end: `[NOT-DEFINED / MUST BE WITHIN APPROVED WINDOW]`
- Labels and outcomes hidden during selection: `[NOT-VERIFIED]`
- Selection frozen: `false`
- Hindsight, survivorship, spectrum, and availability-bias controls: `[NOT-DEFINED]`

## Predeclared stop conditions

Overall maximum quarantine rate: `[0.0–1.0 / NOT FROZEN]`

| Category | Maximum rate | Denominator | Status |
|---|---:|---|---|
| `ENCODING` | `[NOT-SET]` | complete intake | `NOT FROZEN` |
| `RESOURCE_LIMIT` | `[NOT-SET]` | complete intake | `NOT FROZEN` |
| `SYNTAX` | `[NOT-SET]` | complete intake | `NOT FROZEN` |
| `STRUCTURE` | `[NOT-SET]` | complete intake | `NOT FROZEN` |
| `SEMANTICS` | `[NOT-SET]` | complete intake | `NOT FROZEN` |
| `POLICY` | `[NOT-SET]` | complete intake | `NOT FROZEN` |
| `DUPLICATE` | `[NOT-SET]` | complete intake | `NOT FROZEN` |

- Stop on any fatal condition: `true`
- Stop on unknown failure: `true`
- Thresholds frozen before outcome access: `false / NOT FROZEN`
- Escalation owner ID: `[NOT-ASSIGNED]`
- Pause authority ID: `[NOT-ASSIGNED]`
- Required response to threshold breach: `[STOP; preserve evidence; do not relax threshold or filter denominator; investigate; independently review; reauthorize before resumption]`
- Required response to an unlisted observed quarantine category or an accepted case outside the approved half-open window: `[STOP; preserve evidence; investigate; reauthorize before resumption]`
- Additional stops: `[authority expiry/revocation, binding mismatch, custody break, source drift, egress/isolation failure, label leakage, incident, evidence-accounting failure, reference-assurance mismatch/incompleteness, late artifact mutation, failed finalization, unsuccessful harness return]`

## Adjudication plan

- Protocol reference: `[NOT-APPROVED]`
- Minimum independent reviewers: `2`
- Reviewer qualification and conflict criteria: `[NOT-DEFINED]`
- Runtime/evaluator separation: `true / NOT VERIFIED`
- Labels hidden until runtime decision is final: `true / NOT VERIFIED`
- Indeterminate outcome allowed: `true`
- Evidence available to reviewers and prohibited hindsight information: `[NOT-DEFINED]`
- Initial independent review method: `[NOT-DEFINED]`
- Disagreement-resolution method and tie-breaker authority: `[NOT-APPROVED]`
- Rule against forced consensus: `[NOT-DEFINED]`
- Label amendment, audit, and versioning method: `[NOT-DEFINED]`

## Payload-access order

For historical, de-identified origin, the runtime may read only configuration, manifest control bytes, the Gate B package, model and policy, and the bound source-mapping, adjudication-protocol, and pilot-protocol controls until preflight passes. It must not open, hash, count, decode, parse, qualify, normalize, or adjudicate cases or adjudications first. Any preflight failure stops before payload access.

Restricted authorization and control artifacts must reside under ignored `local/gate_b/`; historical output must use an ignored run-specific `outputs/replay/<run>/` directory with owner-only access. Gate B control JSON is limited to one MiB and 128 nesting levels, each mapping/protocol artifact to two MiB, and each bound model/policy file to 64 MiB. After authorized qualification, but before normalization or engine invocation, accepted-case window and observed quarantine-rate/category gates must pass.

After read-only decision and exact eight-stage audit validation, execute every reference-assurance check required by the frozen release before adjudication decoding or result finalization. A replay against the prior alpha.5 baseline requires the Phase 2.4 feature-assurance receipt. A replay against published Phase 2.5 Commit `854b15c` requires both feature and source-to-decision assurance; neither receipt may be published when the latter check fails. Publication does not itself approve this template or a historical pilot. Any receipt mismatch, incomplete case set, malformed binding, or late artifact mutation stops the run. A metrics or manifest file left by a failed return is incomplete diagnostic material, not completion evidence.

## Evidence and claim plan

- Claim owner ID: `[NOT-ASSIGNED]`
- Pause authority ID: `[NOT-ASSIGNED]`
- Revocation authority ID: `[NOT-ASSIGNED]`
- Claim expiry matching authorization expiry: `[NOT-SET]`
- Revalidation triggers: `[every source/baseline/control/protocol/authority/claim change; any incident, classifier gap, label leak, custody break, or control failure]`
- Required raw counts: `[full intake, accepted, quarantined by category/code, fatal, excluded, adjudicated, indeterminate, agreement/disagreement, correct, incorrect, abstained]`
- Required uncertainty and denominator statements: `[NOT-DEFINED]`
- Representative failure disclosure review: `[NOT-DEFINED]`
- Public-summary sanitization owner and review reference: `[NOT-ASSIGNED / NOT-SET]`
- Release-required assurance artifacts and expected case counts: `[NOT-DEFINED / RELEASE-SPECIFIC]`
- Evidence of successful harness return after final binding checks: `[NOT-DEFINED]`
- Incomplete-run quarantine and non-reuse procedure: `[NOT-DEFINED]`

The authorization snapshot and approval/reference fields may be sensitive and must be excluded from public evidence summaries. A bounded opaque `authorization_id` may appear in a restricted aggregate trace summary only when it encodes no person, source, incident, system, or other sensitive fact. Machine validation proves internal structure and binding only; it does not prove legal authority, identity, signature authenticity, effective de-identification, custody truth, or historical efficacy.

## Final preflight declaration

This template remains `NOT APPROVED`. A restricted operational copy may be marked ready only after every placeholder is replaced, every control is evidenced, an exact clean released commit and its required assurance profile are frozen, the complete package is hashed, all five roles and the independent reviewer approve it in authenticated external systems, semantic cross-checks pass, and the runtime rejects all non-`APPROVED` states before historical payload access. Approval to begin processing does not predetermine a successful run: completion additionally requires every release-specific reference check, final binding check, and a successful harness return. Published Phase 2.5 Commit `854b15c`, published simulation-only Phase 3 Commit `423685d`, the Phase 3.1 synthetic model-evaluation candidate, and the `P2-CE-005` plan do not satisfy those external approval conditions.
