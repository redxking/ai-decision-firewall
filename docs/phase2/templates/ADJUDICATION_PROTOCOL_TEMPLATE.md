# Gate B adjudication protocol template

> **NOT APPROVED — TEMPLATE ONLY — NO HISTORICAL DATA OR LABELS**
>
> Do not add real identities, signatures, endpoints, record examples, source metadata, adjudications, or historical data to the public repository. Complete the operational protocol in the approved restricted evidence system and bind its exact bytes through the `ADJUDICATION_PROTOCOL` artifact role.

## Document control

| Field | Required value |
|---|---|
| Protocol status | `DRAFT / NOT APPROVED` |
| Protocol reference | `[RESTRICTED-REFERENCE-NOT-SET]` |
| Authorization ID | `[DRAFT-AUTHORIZATION-ID]` |
| Dataset ID | `[PLACEHOLDER-DATASET-ID]` |
| Approved source window | `[NOT-APPROVED]` |
| Predeclared at | `[BEFORE-LABEL-OR-RUNTIME-OUTCOME-ACCESS]` |
| Protocol owner ID | `[NOT-ASSIGNED]` |
| Minimum reviewers | `2` |
| Runtime/evaluator separation | `true / NOT VERIFIED` |
| Labels hidden until decision finalization | `true / NOT VERIFIED` |
| Indeterminate outcome allowed | `true` |

## Adjudication objective and boundary

Decision question: `[DEFINE THE EXACT OUTCOME OR DISPOSITION QUESTION]`

Unit of adjudication: `[CASE / TIME-BOUNDED INCIDENT / OTHER PREDECLARED UNIT]`

Permitted evidence: `[ENUMERATE SOURCES AND TIME CUT-OFF AVAILABLE TO REVIEWERS]`

Prohibited evidence: `[RUNTIME DECISION BEFORE INITIAL LABEL; POST-WINDOW OUTCOMES; UNAPPROVED SOURCES; IDENTITY OR OPERATIONAL CONSEQUENCES OUTSIDE SCOPE]`

The adjudication is an evaluator label under a stated protocol. It is not automatically ground truth and must not be described as such without independent outcome validation.

## Reviewer qualification and independence

- Required expertise and minimum experience: `[NOT-DEFINED]`
- Required training/calibration exercise: `[NOT-DEFINED]`
- Conflict-of-interest disclosure and recusal rule: `[NOT-DEFINED]`
- Organizational/functional independence requirement: `[NOT-DEFINED]`
- Reviewer identifiers and authenticated assignment references: `[RESTRICTED / NOT-ASSIGNED]`
- Minimum independent initial reviews per case: `2`
- Prohibition on reviewer discussion before initial labels are frozen: `[NOT-DEFINED]`

## Label taxonomy

| Outcome | Operational definition | Minimum evidence | Disqualifying ambiguity |
|---|---|---|---|
| `[OUTCOME-A]` | `[NOT-DEFINED]` | `[NOT-DEFINED]` | `[NOT-DEFINED]` |
| `[OUTCOME-B]` | `[NOT-DEFINED]` | `[NOT-DEFINED]` | `[NOT-DEFINED]` |
| `INDETERMINATE` | Evidence is insufficient, conflicting, unavailable, or outside the approved window | Documented uncertainty reason | Must not be forced into another class |

Define any expected-disposition taxonomy separately from compromise/outcome labels. Do not collapse detection, decision appropriateness, evidence sufficiency, authorization, and remediation completeness into one label.

## Evidence packet and label isolation

- Approved evidence fields and redactions: `[NOT-DEFINED]`
- Evidence-window cut-off: `[NOT-DEFINED]`
- Canonical-context source and ambiguity rule: `[NOT-DEFINED]`
- Missing-source and degraded-telemetry presentation: `[NOT-DEFINED]`
- Runtime decision storage boundary: `[SEPARATE / NOT-VERIFIED]`
- Adjudication-label storage boundary: `[SEPARATE / NOT-VERIFIED]`
- Access-control and audit-log reference: `[NOT-SET]`
- Method proving labels remain hidden until runtime decision finalization: `[NOT-TESTED]`
- Response to suspected label leakage: `[STOP; preserve evidence; invalidate affected run; investigate; reauthorize before reuse]`

## Independent initial review

Each reviewer records, before discussion:

- outcome label or `INDETERMINATE`;
- expected disposition, if separately in scope;
- evidence references within the approved packet;
- confidence or evidence-sufficiency category under a predeclared scale;
- missing or conflicting evidence;
- assumptions and contextual dependencies; and
- reason codes from the frozen taxonomy.

Free-form notes may contain sensitive source context and remain restricted. They are never runtime input.

## Disagreement resolution

Disagreement definition: `[ANY LABEL DIFFERENCE / PREDECLARED FIELD-SPECIFIC RULE]`

Resolution sequence:

1. Freeze and retain both initial independent labels.
2. Classify the disagreement source: evidence absence, interpretation, taxonomy ambiguity, source conflict, temporal ambiguity, context assumption, or reviewer error.
3. Permit a documented reviewer conference only after initial labels are immutable.
4. If disagreement remains, apply `[QUALIFIED TIE-BREAKER / PANEL / REMAIN INDETERMINATE]` under the predeclared rule.
5. Never force consensus solely to increase agreement or produce a scoreable label.
6. Retain initial labels, final label, reason, participants, timestamps, and protocol version.

Report initial raw agreement, disagreement counts by cause, indeterminate counts, resolved and unresolved counts, and any agreement statistic only with its assumptions and denominator.

## Bias controls

- Temporal/hindsight control: reviewers see only evidence available by `[APPROVED CUT-OFF]`.
- Selection control: reviewers do not choose cases and do not receive accept/quarantine or model-score strata unless explicitly required and analyzed.
- Survivorship control: adjudication counts remain linked to complete intake, including quarantined and excluded records.
- Expectancy control: runtime outputs, model version performance, target rates, and other reviewers' labels remain hidden during initial review.
- Taxonomy control: ambiguous definitions discovered after outcomes trigger pause and revalidation rather than retrospective relabeling without an audit trail.
- Representative-failure control: examples selected for reporting undergo privacy and selection-bias review.

## Quality control and amendment

- Duplicate, inconsistent, or impossible label checks: `[NOT-DEFINED]`
- Reviewer-drift monitoring: `[NOT-DEFINED]`
- Blind re-review sample: `[NOT-DEFINED]`
- Protocol-deviation classification and escalation: `[NOT-DEFINED]`
- Label correction authority and evidence standard: `[NOT-DEFINED]`
- Versioning rule: no silent overwrite; preserve original, amended value, reason, authorizer, and timestamp.
- Incident-derived regression requirement: `[NOT-DEFINED]`

## Stop conditions

Stop adjudication and preserve restricted evidence on label leakage, unauthorized source access, identity/custody failure, protocol drift, reviewer conflict, material taxonomy defect, unexplained count mismatch, evidence-window breach, privacy incident, unknown failure, or authorization expiry/revocation.

The escalation owner, pause authority, resumption criteria, and incident-response reference are: `[NOT-ASSIGNED / NOT-APPROVED]`.

## Evidence and claim limits

Required reporting includes complete intake, accepted, quarantined, excluded, adjudicated, indeterminate, reviewer-agreement, disagreement, resolved, unresolved, and missing-label counts. Metrics calculated only on adjudicated or accepted cases must retain those denominators and exclusions adjacent to the result.

The authorization snapshot, approval/reference fields, reviewer identifiers, source references, and record-level reasons may be sensitive and are excluded from public evidence summaries. A bounded opaque `authorization_id` may appear in a restricted aggregate trace summary only when it encodes no person, source, incident, system, or other sensitive fact. Machine validation proves internal structure and binding only; it does not prove legal authority, identity, signature authenticity, effective de-identification, custody truth, label truth, or historical efficacy.

This template remains `NOT APPROVED`. No sign-off block in this public file can authorize historical processing.
