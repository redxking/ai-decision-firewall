# Version 0.4.0 isolated-lab contracts

These contracts define the first process-isolated, non-production adapter-lab
message boundary proposed by ADR-017. They do not authorize a live connector,
production target, external network, or operational action.

- `lab-execution-command.schema.json` accepts only `NETWORK_ISOLATE` for the
  code-owned `LAB_ENDPOINT_001` target and fixed lab network profile.
- `lab-executor-receipt.schema.json` records the executor's bounded command
  outcome. It is acknowledgement evidence, not independent effect proof.
- `lab-observation.schema.json` records independently keyed target-side facts.
  It cannot authorize or invoke execution.

The code-owned validator in `adf_poc.lab_contracts` adds strict duplicate-safe
JSON parsing, size/depth limits, offset-aware time checks, cross-field outcome
rules, canonical SHA-256 bindings, domain-separated HMAC authentication, and
executor/observer key-separation checks. Sockets, peer credentials, executor
mutation, and container orchestration are deliberately outside this increment.
