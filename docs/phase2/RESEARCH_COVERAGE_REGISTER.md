# Research Coverage Register

## Purpose and review boundary

This register makes the research basis for Phase 2 test and claim design auditable. The [OpenAI Research Index](https://openai.com/research/index/) was screened through **2026-08-14**, together with the named Anthropic research program. Screening covered material that could change this project's threat model, evidence standard, evaluation validity, control architecture, monitoring plan, human-authorization boundary, or public wording.

“Screened” does not mean that every OpenAI publication is evidence for this POC. Mathematics, general scientific-discovery, economic, product-announcement, and unrelated capability work is recorded below as outside the present decision-control claim unless it contributes a transferable evaluation method or system-safety control. Model and product system cards are design references; this repository does not inherit their safeguards or results.

The index is dynamic. This register is a dated baseline, not a permanent assertion of completeness. It must be refreshed before a new claim class, phase gate, generative-agent integration, model/monitor change, or operational-data evaluation.

## Disposition codes

| Code | Meaning |
|---|---|
| Incorporated | The current standard, contract, code, or tests address the transferable requirement |
| Partial | Some controls or tests exist; the cited research requires broader evaluation before a stronger claim |
| Planned | Relevant, but the necessary component, data, harness, or independent review does not exist |
| Context only | Informs risk framing; no result is transferred to this POC |
| Not applicable now | Outside the current deterministic, offline, synthetic system under test; review again if the boundary changes |

## OpenAI source coverage

| Official source | Transferable requirement for this project | Current accounting | Disposition |
|---|---|---|---|
| [OpenAI Research Index](https://openai.com/research/index/) | Use a dated source inventory and rescreen new safety, agent, evaluation, robustness, cyber, governance, and monitoring work at each gate | This register records the screen date, scope, exclusions, and update triggers | Incorporated |
| [Safety and alignment in an era of long-horizon models](https://openai.com/index/safety-alignment-long-horizon-models/) | Evaluate cumulative trajectory intent/outcome, match horizon length, test instruction retention, enable intervention/pause/rollback, and turn incidents into regression tests | ADV-009 and claim-lifecycle requirements now cover these obligations; the current POC has no generative long-horizon agent | Planned |
| [Model-evaluation security incident](https://openai.com/index/hugging-face-model-evaluation-security-incident/) | Treat evaluation infrastructure as an attack surface: package proxies, egress, credentials, lateral movement, isolation, monitoring, containment, and kill switch | The evidence schema now records the environment boundary and residual risk; Phase 2 has path confinement but no OS sandbox/escape campaign | Partial |
| [Preparedness Framework v2](https://cdn.openai.com/pdf/18a02b5d-6b67-4cec-ab64-68cdfbddebcd/preparedness-framework-v2.pdf) and [framework update](https://openai.com/index/updating-our-preparedness-framework/) | Separate capability from safeguard evidence; define threat models, thresholds, defense in depth, residual risk, governance review, and reassessment triggers | CE-3 through CE-5 and Phase 2 gates require these elements; no operational safety case is claimed | Partial |
| [Frontier Governance Framework](https://openai.com/index/openai-frontier-governance-framework/) | Connect technical evaluation to risk management, incident response, external input, reporting, and framework updates | Phase 2.2 implements a closed Gate B machine preflight for asserted authority, review, custody, incident, pause/revocation, expiry, and revalidation fields; it does not authenticate or exercise those external controls | Partial; external governance remains unevaluated |
| [Trustworthy third-party evaluation playbook](https://openai.com/index/trustworthy-third-party-evaluations-foundations/) | Bind each claim to the exact system, harness, tools, budget, elicitation, scoring, validity checks, raw evidence, and review | `evaluation-evidence.schema.json`, the four worked records, and CE levels bind all current synthetic results; `P2-CE-003` and `P2-CE-004` additionally record fixed registries, two repetitions, raw 32-observation denominators, runtime fingerprints, and project-controlled validity checks | Incorporated at CE-2 |
| [Strengthening the safety ecosystem with external testing](https://openai.com/index/strengthening-safety-with-external-testing/) | Distinguish independent evaluation, methodology review, subject-matter-expert probing, and red teaming; expose mitigated and less-mitigated conditions where authorized | The schema distinguishes self, internal-independent, and external-independent review; all four current records remain SELF reviewed, and the project-controlled commit freezes are not external preregistration | Planned beyond CE-2 |
| [Advancing red teaming with people and AI](https://openai.com/index/advancing-red-teaming-with-people-and-ai/) | Define campaign scope and diverse expertise, quality-review findings, and convert validated attacks into repeatable regression tests | The adversarial matrix defines campaigns; no external human campaign has been run | Planned |
| [Practices for Governing Agentic AI Systems](https://openai.com/index/practices-for-governing-agentic-ai-systems/) | Define lifecycle roles, task suitability, action constraints, meaningful approval, legibility, interruptibility, attribution, safe defaults, and continuing responsibility | Evidence records require lifecycle controls, and Phase 2.2 Gate B fails closed on missing role, review, expiry, pause/revocation, and read-only assertions; meaningful external approval remains unverified | Partial |
| [GPT-Red](https://openai.com/index/unlocking-self-improvement-gpt-red/) | Use adaptive automated red teams, explicit attacker control/threat models, held-out environments, realistic transfer tests, and separate robustness from over-refusal or capability loss | ADV-003 through ADV-007 require adaptive attacks, held-out cases, outcome checks, and regression/capability controls | Planned for any generative-agent path |
| [Separating signal from noise in coding evaluations](https://openai.com/index/separating-signal-from-noise-coding-evaluations/) | Audit tasks and scorers for underspecification, misleading prompts, overly strict tests, and low coverage; use multiple independent reviewers and escalate disagreement | Validity records include broken tasks and scorer exploitation; starter fixtures have deterministic checks but no five-reviewer campaign | Partial |
| [PaperBench](https://openai.com/index/paperbench/) | Use hierarchical expert rubrics, multiple runs, executable artifacts, human baselines, and separately validate automated graders | The schema requires grader identity and validation; current deterministic checks have negative tests but no expert judge benchmark | Partial |
| [Why language models hallucinate](https://openai.com/index/why-language-models-hallucinate/) | Report accuracy, error, and abstention separately; do not reward guessing; penalize confident consequential errors; test calibration and uncertainty expression | Four dispositions preserve abstention/escalation; future model-based evaluations must report confident errors, abstentions, and calibration separately | Partial; no generative model in current path |
| [Understanding prompt injections](https://openai.com/index/prompt-injections/) | Treat prompt injection as an evolving security problem requiring layered training, monitoring, sandboxing, least privilege, confirmation, red teaming, and user control | Untrusted text cannot grant authority; read-only execution is structural; the POC lacks an OS sandbox and adaptive prompt-injection monitor | Partial |
| [Instruction Hierarchy](https://openai.com/index/the-instruction-hierarchy/) and [IH-Challenge](https://openai.com/index/instruction-hierarchy-challenge/) | Test trusted/untrusted instruction conflicts, unseen attack generalization, over-refusal, normal capability regression, and production-representative cases | Runtime free text is non-authoritative and poisoning cases exist; generative instruction-following and generalization are not evaluated | Partial / planned |
| [Designing agents to resist prompt injection](https://openai.com/index/designing-agents-to-resist-prompt-injection/) | Do not rely on an input classifier alone; analyze user intent, data-flow/exfiltration, consent, and social-engineering-style attacks | The “decision firewall” is an authority/effect boundary, not a promise to perfectly classify malicious text; data-flow attacks remain future work | Context only / planned |
| [Keeping data safe when an agent clicks a link](https://openai.com/index/ai-agent-link-safety/) | Bind authorization to the exact resource/action; combine deterministic egress controls with layered monitoring and red teaming | Phase 2 has no URL fetch or network access; any future connector requires destination and data-flow authorization rather than domain reputation alone | Not applicable now / future gate |
| [Model Spec](https://model-spec.openai.com/2025-10-27) | Define authority hierarchy, scope of autonomy, untrusted-data handling, side-effect disclosure, uncertainty, and explicit control transfer | Policy/authorization separation and untrusted-text rules align conceptually; the POC is not certified against the Model Spec | Context only |
| [Detecting misbehavior with chain-of-thought monitoring](https://openai.com/index/chain-of-thought-monitoring/) | Test reward hacking and outcome manipulation; observe actions and legitimately available traces; do not treat monitor output as truth or train away visible evidence without checking behavior | ADV-004 and ADV-011 capture these obligations; current pipeline exposes no model chain of thought | Planned for reasoning agents |
| [Evaluating chain-of-thought monitorability](https://openai.com/index/evaluating-chain-of-thought-monitorability/) | Use intervention, process, and outcome-property tests; test monitorability across system versions and distribution shift | The evidence schema records exact versions; no reasoning-model monitor exists | Not applicable now / planned |
| [Detecting and reducing scheming](https://openai.com/index/detecting-and-reducing-scheming-in-ai-models/) | Use out-of-distribution tasks, independently constructed environments, evaluation-awareness interventions, and realistic-use comparisons | ADV-001, ADV-002, ADV-007, and ADV-008 require these methods before alignment claims | Planned |
| [Internal coding-agent misalignment monitoring](https://openai.com/index/how-we-monitor-internal-coding-agents-misalignment/) | Evaluate long, tool-rich trajectories; quantify recall/false negatives, latency, escalation coverage, human response, privacy, and actor-monitor collusion | ADV-009 and ADV-011 trace these measures; no monitoring-efficacy claim is permitted | Planned |
| [OpenAI–Anthropic pilot alignment evaluation](https://openai.com/index/openai-anthropic-safety-evaluation/) | Preserve system/safeguard differences, inspect grader errors and refusal/error tradeoffs, and describe adversarial propensities without converting them into real-world likelihood | The standard prohibits apples-to-apples or prevalence claims without a representative design | Incorporated in claim rules |
| [Operator system card](https://openai.com/index/operator-system-card/) and [ChatGPT agent system card](https://openai.com/index/chatgpt-agent-system-card/) | Use mock environments for consequential actions, internal and external red teams, product-specific safeguards, confirmations, limited access, staged deployment, and post-deployment monitoring | Phase 2 uses only synthetic/offline evidence and no action path; future live shadow or controlled action requires a new deployment-specific safety case | Context only |
| [Strengthening cyber resilience](https://openai.com/index/strengthening-cyber-resilience/) | Evaluate dual-use cyber capability and safeguards separately, assume capability growth, use layered controls, and involve domain experts | The privileged-identity use case is defensive, but this POC does not evaluate frontier offensive cyber capability | Context only |
| [GPT-5.3-Codex system card](https://openai.com/index/gpt-5-3-codex-system-card/) | Separate isolated cyber skill, operational consistency, and end-to-end operations; test realistic noise, hardening, active defense, and safeguard conditions | No generative cyber capability claim is made; ADV-016 preserves the future obligation | Context only |

## Anthropic cross-check

| Official source | Transferable requirement | Current accounting | Disposition |
|---|---|---|---|
| [Agentic Misalignment](https://www.anthropic.com/research/agentic-misalignment) | Cross goal conflict, replacement/authority pressure, safe-alternative availability, access/tool authority, repeated trials, and evaluation awareness | ADV-001 and ADV-002; no real-world prevalence inference | Planned for generative agents |
| [Sabotage Evaluations](https://www.anthropic.com/research/sabotage-evaluations) | Test human-decision sabotage, code sabotage, sandbagging, and oversight undermining; evaluate actor and control system together | ADV-004 through ADV-007 and ADV-010 | Planned |
| [Alignment Faking](https://www.anthropic.com/research/alignment-faking) | Compare monitored and apparently unmonitored conditions; do not infer a universal hidden objective | ADV-002 and ADV-007 | Planned |
| [Auditing Hidden Objectives](https://www.anthropic.com/research/auditing-hidden-objectives) | Use a seeded known objective, blind red/blue teams, access tiers, held-out behavior, and known-truth grading | ADV-008 | Planned |
| [SHADE-Arena](https://www.anthropic.com/research/shade-arena-sabotage-monitoring) | Use long tool trajectories with hidden side objectives and jointly report task success, sabotage success, evasion, detection, and false positives | ADV-006, ADV-009, and ADV-011 | Planned |

## Topic-family accounting

| Research-index topic family | Screening disposition |
|---|---|
| Agent safety, alignment, autonomy, monitoring, scheming, sandbagging, prompt injection, red teaming | Included individually above when a transferable test or control requirement was identified |
| Evaluation science, benchmark validity, uncertainty, hallucination, calibration, third-party assessment | Included individually above |
| Cybersecurity capability, safeguard, and deployment-governance research | Included when it changes threat modeling, control efficacy, or expert-review requirements; offensive-capability scores are not transferred to this defensive POC |
| Model/product system cards | Sampled for transferable system-level methods; treated as context only because the POC does not inherit another system's mitigations |
| Pure mathematics, theoretical computer science, scientific-discovery applications, economics, and unrelated product capability | Not applicable to the present decision-control claim unless a future item introduces a relevant evaluation or assurance method |
| General benchmark scores and model-leaderboard results | Excluded as evidence for this POC; a score is considered only with its task validity, harness, configuration, sampling, and scorer evidence |

## Unresolved research-derived obligations

The current public starter must continue to say **not evaluated** for:

- performance on approved historical or live-shadow identity data;
- generative-agent alignment, evaluation awareness, scheming, sabotage, or sandbagging;
- adaptive prompt-injection and data-exfiltration robustness;
- cumulative long-horizon authority, instruction retention, and trajectory-level monitor efficacy;
- monitor recall, false-negative rate, false-positive cost, latency, escalation coverage, or collusion resistance;
- evaluation-environment resistance to sandbox escape, dependency abuse, credential discovery, lateral movement, or covert egress;
- automated-grader accuracy against blinded expert known truth;
- independent or external replication of the Phase 2 evidence;
- OS-enforced process, network, and filesystem isolation;
- independent target-side proof of an operational effect, rollback, or recovery.

## Refresh procedure

Before changing a public claim or crossing a phase gate:

1. Rescreen the OpenAI Research Index and the named Anthropic research pages for new or revised material.
2. Record the review date, URL, relevance decision, and disposition change in this register.
3. Update the adversarial matrix, requirements traceability, evidence schema, or tests when a source adds a material threat, validity hazard, or control-efficacy requirement.
4. Preserve superseded assumptions and explain why a source was excluded; do not silently remove an inconvenient test family.
5. Reissue the evidence record. If a required area remains untested, retain it under `not_yet_evaluated` and prohibit the corresponding inference.
