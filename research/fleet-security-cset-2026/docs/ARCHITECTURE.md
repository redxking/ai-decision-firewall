# Architecture

The harness has four logical layers:

1. Scenario/configuration: population, topology, workload, adversary, policy.
2. Synthetic execution: deterministic seeded discrete-step simulation.
3. Security measurement: authorization-integrity loss, compromise propagation, blast radius, containment, qualified throughput.
4. Evidence: raw CSV, summary CSV, environment manifest, and SHA-256 result digest.

Communication topology and authorization/privilege are deliberately modeled separately. The ability to exchange information is not equivalent to authority to perform a protected action.

The v0.1 simulator is intentionally minimal. It validates the experiment design and data pipeline before integration with real LLM/tool agents. A real adapter must preserve the external policy-enforcement boundary and event semantics: principal -> proposed action -> authorization decision -> execution -> observed effect.
