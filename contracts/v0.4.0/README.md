# Version 0.4.0 isolated-lab contracts

These contracts define the first process-isolated, non-production adapter-lab
message boundary proposed by ADR-017. They do not authorize a live connector,
production target, external network, or operational action.

- `lab-execution-command.schema.json` accepts only `NETWORK_ISOLATE` for the
  code-owned `LAB_ENDPOINT_001` target and fixed lab network profile.
- `lab-executor-receipt.schema.json` records the executor's bounded command
  outcome. It is acknowledgement evidence, not independent effect proof.
- `lab-observation-request.schema.json` carries only the exact correlation
  fields needed to request a fresh read. It uses the observer channel and
  cannot be accepted by the executor.
- `lab-observation.schema.json` records independently keyed target-side facts.
  It cannot authorize or invoke execution.

The code-owned validator in `adf_poc.lab_contracts` adds strict duplicate-safe
JSON parsing, size/depth limits, offset-aware time checks, cross-field outcome
rules, canonical SHA-256 bindings, domain-separated HMAC authentication, and
executor/observer key-separation checks. `adf_poc.lab_transport` adds an
explicit opt-in Linux-only `SOCK_SEQPACKET` transport with one-packet framing,
bounded deadlines, exact `SO_PEERCRED` UID checks, owner-private `0700`/`0600`
filesystem checks, inode binding, and non-destructive cleanup on replacement.
`adf_poc.lab_services` composes those boundaries into explicitly enabled
executor and observer handlers. The executor uses a create-once, owner-private,
append-only reservation/completion journal: exact completed duplicates return
the original receipt, conflicting reuse fails closed, and an unfinished
reservation requires reconciliation instead of retry. The observer authenticates
a separate observation request and performs a fresh code-owned read for every
response. The executor now verifies exact target boot identity, ruleset
prestate, and management reachability before an explicitly gated internal
mutation port. The shipped node does not supply or enable that port and
therefore still returns `NO_EFFECT`; no kernel mutation is reachable in this
increment. A mutation-port exception is durably classified `AMBIGUOUS`, while
loss after effect entry leaves the reservation fenced against retry. The fixed
kernel driver, executable reconciliation/rollback, and its full kill matrix
remain outside this increment.
