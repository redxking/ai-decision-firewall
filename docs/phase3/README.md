# Phase 3 simulation-only operational MVP

## Current state

Phase 3 is a working **local `0.3.0-alpha.1` candidate** for an operational
decision-control path over synthetic requests, evidence, identities, targets,
and effects. It is not yet a committed or published Phase 3 baseline, and its
exact commit and exact-commit CI remain pending. Local observations are CE-1
implementation-conformance evidence only. They do not establish live
containment, operational efficacy or calibration, production safety, or
external independence.

The candidate accepts a raw versioned decision request plus an opaque
invocation credential. A firewall-owned resolver maps that credential to a
signed `ResolvedPrincipal`; no request-supplied identity, role, or authority can
create the principal. The firewall then assesses target-bound HMAC-attested
synthetic evidence and action consequence, applies deterministic machine
policy, and returns one of:

- `ALLOW`
- `DENY`
- `ESCALATE`
- `ALLOW_CONSTRAINED`

Only `ALLOW` and `ALLOW_CONSTRAINED` can produce an authorization. The
authorization is short lived, exact-scope, and single use. The broker can act
only on the in-memory `NETWORK_ISOLATE` simulation target, and a separate
read-only observer determines the post-action verification status.

## Reproduce the local observations

Run the two raw-request demonstrations into a new directory:

```bash
demo_dir="$(mktemp -d /tmp/adf-phase3-demo.XXXXXX)"
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src python3 run_phase3.py \
  --output-dir "$demo_dir"
```

Expected semantic results:

| Demonstration | Decision | Authorization/effect | Verification |
|---|---|---|---|
| High-risk `DOMAIN_CONTROLLER_01` isolation, AI confidence `0.96`, stale and conflicting evidence, insufficient Tier-0 authority | `ESCALATE` | None; target unchanged | Not applicable |
| Authorized `WORKSTATION_042` isolation with fresh corroborated evidence | `ALLOW` | One synthetic broker attempt | `VERIFIED` by read-only target observation |

Run the deterministic 46-scenario adversarial corpus:

```bash
corpus_dir="$(mktemp -d /tmp/adf-phase3-corpus.XXXXXX)"
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src python3 run_phase3_corpus.py \
  --output-dir "$corpus_dir"
```

Run focused Phase 3 tests:

```bash
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src python3 -m unittest \
  tests.test_phase3_contracts \
  tests.test_phase3_decision_path \
  tests.test_phase3_authorization_boundary \
  tests.test_phase3_adversarial \
  tests.test_phase3_end_to_end \
  tests.test_phase3_corpus \
  tests.test_phase3_release_blockers -v
```

As of 2026-08-15, the current local candidate passed **57/57 focused Phase 3
tests**, both demonstration acceptance checks reported **PASS**, and the corpus
reported **46/46** passing scenarios. The complete repository suite passed
**288/288** locally. These are checkout-local observations, not exact-commit CI
evidence.

Both command-line writers require an absent or empty destination and refuse to
clobber a nonempty directory. Their outputs are local diagnostic artifacts,
not a release or evidence package.

## Control flow

1. Strictly decode and validate raw JSON against the closed v0.3.0 request
   contract; reject duplicate members, non-finite numbers, unsafe sizes/depth,
   unknown fields, bad times, and unsupported versions.
2. Resolve the opaque invocation credential at a firewall-owned trusted
   boundary, verify the signed `ResolvedPrincipal`, and compare its trusted
   attributes with the request's agent claims. Self-asserted roles and
   authority do not grant access.
3. Resolve source reliability, target criticality/dependencies/current state,
   action bounds, policy identity, and time from firewall-owned context.
4. Verify runtime HMAC attestations over synthetic evidence, including source,
   provenance, content, semantic assertions, time, and subject target; then
   assess freshness, relevance, corroboration, conflicts, and missing sources.
5. Evaluate authority and consequence, including reversibility, blast radius,
   downtime, mission/safety/availability impact, dependencies, and cascading
   effects.
6. Apply validated external policy and produce a structured decision with
   stable reason codes. Agent recommendation and confidence remain
   non-authoritative inputs.
7. Recheck the decision in the functionally separate deterministic verifier.
8. For an allowed decision, sign an exact-scope authorization and invoke the
   mandatory simulation broker. For any non-allow decision, record the
   nonexecuting lifecycle and leave target state unchanged.
9. Observe target state through a separate read-only interface and classify the
   result as `VERIFIED`, `FAILED`, `PARTIAL`, `UNEXPECTED_EFFECT`, or
   `ROLLBACK_REQUIRED`.
10. Record a correlated hash-linked lifecycle and update in-process metrics.

See [Architecture](ARCHITECTURE.md), [Security and Safety Case](SECURITY_AND_SAFETY_CASE.md),
[Test and Evaluation Plan](TEST_AND_EVALUATION_PLAN.md), and the
[Requirements Traceability Matrix](REQUIREMENTS_TRACEABILITY.csv).

## Hard boundaries

- `synthetic_simulation` is the only Phase 3 execution mode. There is no live,
  vendor, network, IAM, cloud, Kubernetes, or OT/ICS connector.
- The broker's private capability and the target's private mutation method are
  application-level Python boundaries, not OS/process isolation, a reference
  monitor, or protection against arbitrary same-process code execution.
- Authorization consumption uses an in-memory process-local ledger. It is not
  durable, distributed, crash consistent, or suitable for multi-node replay
  prevention.
- Source attestations use HMAC keys supplied at runtime for synthetic fixtures.
  They are not enterprise device identity, PKI, HSM-backed provenance, or
  independent source custody. Keys are not stored in the policy file.
- Human approval resolves a separate opaque credential to a trusted human,
  validates one exact escalated scope, and creates a signed single-use receipt
  that permits reevaluation only. It cannot mint an action token or execute
  through the broker.
- The decision and target verifiers are functionally separate deterministic
  components within the same project and process. They are not external or
  organizationally independent assurance.
- The audit is self-custodied and hash linked. It is not externally anchored,
  WORM protected, or resistant to complete authorized replacement.

## Evidence status

| Item | Current status | Claim boundary |
|---|---|---|
| Phase 2.5 exact Commit `854b15c56397a81de6326b719d3d7d1dc847608f` | Published on `main`; exact-commit CI and Dependency Graph green | Phase 2.5 implementation/package status only |
| `P2-CE-005` | CE-0 `NOT_EVALUATED`; not executed or published | Plan only; no campaign observation or CE-2 result |
| Phase 3 code, tests, demonstrations, and corpus | Local candidate; exact commit and CI pending | CE-1 implementation conformance and local synthetic observations only |
| Live/operational behavior | Not evaluated | No operational efficacy, production safety, or authority claim |

## Safety findings closed during candidate review

Adversarial review found and closed release-blocking defects across the
consequence, evidence, identity, policy, authorization/approval, failure, and
audit boundaries. The closed classes include cascading-dependency enforcement;
signed evidence subject-target binding; opaque credential resolution and trust
material domain separation; exact-type and deep-immutable security objects;
machine-enforced rule uniqueness, evidence floors, zero-conflict automation,
severe-consequence floors, and Tier-0 domain-controller treatment; request,
token, verifier-receipt, and approval-receipt replay/atomicity controls; and
fail-closed identifier, clock, dependency, and post-effect lifecycle handling.
Post-effect prewrite append failures are accounted through one honest
`POST_EFFECT_ACCOUNTING_FAILURE`, a `ROLLBACK_REQUIRED` result, and exactly-once
decision/verification-failure metrics; no automated rollback is claimed.
Focused negative regressions cover these classes. Their closure is CE-1 local
implementation evidence, not proof that the remaining attack surface is defect
free.

## Next gates

1. Complete documentation/diagram and package reconciliation while preserving
   the executable/test bytes behind the settled local results; rerun if those
   bytes change.
2. Freeze one exact Phase 3 commit and regenerate integrity/package artifacts.
3. Publish only with explicit authorization and require exact-commit CI.
4. Keep all future live-data, test-tenant, and operational progression behind
   separate data-governance, threat-model, architecture, safety, change-control,
   rollback, key-management, and authorizing-official gates.
