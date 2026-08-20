# Stage A Synthetic Developer Preview

## Purpose and release boundary

This preview gives developers a playable path through the durable Stage A
decision boundary. It is an offline synthetic evaluation surface, not a
production deployment, security product, or authorization to connect the
firewall to operational systems. It contains no live connector and opens no
network listener.

The preview exercises the actual Stage A mechanism: a trusted synthetic caller,
signed synthetic evidence, deterministic policy and verification, durable
control and adapter stores, sanitized result lookup, and a hash-chained JSONL
audit. Reported synthetic adapter state is same-project evidence; it is not
independently custodied proof of an external effect.

## Run it

Install the hash-locked dependencies as described in the repository README,
then run:

```bash
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src:. python3 run_preview.py demo
```

Expected high-level behavior:

- `workstation` is evaluated as a bounded synthetic containment case and may
  produce a verified synthetic effect;
- `domain-controller` is a Tier 0 case and is denied or held for human
  escalation without an effect; and
- `integrity.audit_chain_valid` is `true` and readiness is `READY`.

Exact reason codes are the authoritative explanation. Do not infer production
quality, detection performance, or operational efficacy from these two
designed scenarios.

Use a different owner-private state directory when desired:

```bash
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src:. python3 run_preview.py demo \
  --root /absolute/path/to/private-preview
```

The state survives process restart. `status` reconstructs the service against
the existing stores and verifies the audit chain. `scenario` appends another
unique synthetic lifecycle:

```bash
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src:. python3 run_preview.py status
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src:. python3 run_preview.py scenario workstation
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src:. python3 run_preview.py \
  scenario domain-controller
```

Generate an inspectable, currently signed request and submit it separately:

```bash
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src:. python3 run_preview.py \
  generate workstation --output /tmp/adf-preview-request.json
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src:. python3 run_preview.py \
  submit --file /tmp/adf-preview-request.json
```

The generated request contains synthetic data only and no credential. Changing
signed evidence, its provenance, or the required synthetic-only markers should
fail closed. Generate a fresh file instead of retrying a request whose outcome
is uncertain; exact duplicate submissions return the already durable sanitized
result and do not issue new authority.

Reset is deliberately gated and refuses an unmarked or unexpectedly shaped
directory:

```bash
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src:. python3 run_preview.py reset \
  --confirm-synthetic-preview
```

For an isolated one-shot container evaluation, run
`./scripts/run_preview_container.sh`. The wrapper builds locally, disables
networking for the running preview, drops Linux capabilities, enables
no-new-privileges, uses a read-only root filesystem, and places preview state
in ephemeral tmpfs. It does
not publish or pull an ADF application image. The digest-pinned Python base and
locked dependency wheels remain external supply-chain inputs governed by the
repository build controls.

## What to test and report

Useful preview feedback includes:

1. the platform, Python version, and exact source commit;
2. the command and scenario used;
3. the sanitized output, excluding the `secrets` directory;
4. whether a restart followed by `status` remained `READY` with a valid audit
   chain; and
5. confusing reason codes, unsafe defaults, reproducibility failures, or
   unexpected state transitions.

Never attach `service.json`, files under `secrets`, raw databases, or an audit
log from anything except this generated synthetic preview. Open an issue only
after confirming the reproduction contains no operational data or credential.

## Known limitations

- synthetic scenarios and synthetic adapter only;
- single-host cooperative locking and one active writer;
- no production transport, independent evidence custody, trusted time, HA,
  DR, external identity provider, or live policy administration;
- no validated outcome or detection-performance claim; and
- production readiness remains `BLOCKED` pending the documented independent
  owner, infrastructure, security, and operational evidence gates.
