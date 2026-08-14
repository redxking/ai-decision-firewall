# POC Test Suite

Run from the repository root:

```bash
PYTHONPATH=src python -m unittest discover -s tests -v
```

The tests focus on safety invariants rather than synthetic classifier accuracy: poisoned evidence must force abstention, break-glass identities cannot be autonomously contained, human-only actions cannot pass the verifier, the action broker rejects missing authorization, labels are separated from runtime inputs, and audit tampering is detected.
