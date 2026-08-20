# Phase 4 Disposable Container Lab Evidence Record

**Record date:** 2026-08-20

**Evidence class:** project-controlled local engineering observation

**Production authorization:** `BLOCKED`

**Action authorization:** `NOT_AUTHORIZED`

**Observed effect:** `NO_EFFECT`

## Claim boundary

This record documents one successful disposable Docker campaign against a
mutable pre-commit worktree candidate. It is not exact-commit release evidence,
independent validation, target-owner acceptance, live-action evidence, or image
provenance. The local image ID binds only the bytes present in the local Docker
engine for this observation.

## Observed campaign

| Field | Observed value |
|---|---|
| Lab ID | `102030405068` |
| Local image ID | `sha256:28f717fa772a964d1b8f58450b5001979596c61d436b710274ad9e3b461aa2c3` |
| Schema version | `0.4.0` |
| Application containers inspected | `5` |
| Initializers inspected | `5` |
| Docker bridge | Internal, fixed `172.31.254.0/28` |
| Beacon reachability | `true` |
| Synthetic management reachability | `true` |
| Receipt | `NO_EFFECT`; `effect_possible=false` |
| Message correlation | `true` |
| Authorization integration | `false` |
| Live actions possible | `false` |
| Cleanup | `true` |

The campaign initially exposed two implementation defects and failed closed
with complete cleanup: Docker reports added capabilities as `CAP_CHOWN`, and
Linux may report peer PID zero across PID namespaces while retaining UID/GID.
The harness now normalizes the inspected capability spelling and accepts only
the kernel's zero PID sentinel while continuing to require the exact peer UID.
The volume initializer was also kept at the single added `CHOWN` capability by
setting mode before transferring ownership rather than widening privileges.

## Security controls observed

- exact immutable local image-ID input and post-create image validation;
- no privileged containers, host bind mounts, Docker socket, published ports,
  or external Docker route;
- all application capabilities dropped, read-only roots,
  `no-new-privileges`, owner-private IPC material, and resource limits;
- distinct executor and observer keys and volumes;
- networkless control client;
- exact internal-network membership and subnet validation; and
- exact recorded-resource cleanup rather than broad label or prefix deletion.

## Nonclaims and open evidence

No target state changed. The observed listeners and facts are code-owned and
synthetic. This record does not establish resistance to hostile same-UID peers,
container-runtime compromise, network-namespace mutation, post-effect crash
recovery, rollback, distributed fencing, production transport, supply-chain
provenance, image signing/scanning, external evidence custody, or operational
effectiveness. ADR-017's adversarial and kill matrices remain open.

## Subsequent process-kill evidence

The next bounded test slice adds two real `SIGKILL` cases around the pre-effect
executor journal. Post-reservation loss leaves exactly one durable reservation;
an exact retry is fenced as recovery-required and performs zero target reads.
Post-completion loss leaves one reservation and one durable `NO_EFFECT`
completion; restart returns the exact stored receipt and performs zero target
reads. These repository-controlled process tests do not extend this record's
container, independence, production, or action claims.
