# Synthetic Data Card

## Dataset identity

**Name:** ADF Synthetic Privileged Identity Dataset  
**Version:** 0.1.0  
**Generator seed:** 20260814  
**Default partitions:** 800 training cases and 400 test cases

## Intended use

The dataset exists to exercise architecture, policy, safety, auditability, and test automation before real telemetry is available. It is suitable for software testing, interface development, requirements validation, and failure-mode analysis. It is not suitable for estimating real-world attack prevalence, detection efficacy, analyst workload, or production risk.

## Data separation

Case input files contain only case metadata and evidence events. Ground-truth files contain scenario, compromise label, expected disposition, and rationale. Runtime engine code receives only the case file. The evaluator joins decisions with labels after execution.

## Evidence sources represented

- Identity provider
- Endpoint detection and response
- Network analytics
- Threat intelligence
- Asset inventory / CMDB
- Change management
- Workforce travel context
- Free-text ticket content

Each event includes event identity, case identity, source type and instance, observation and collection times, integrity status, provenance identifier, source trust, entity references, structured attributes, and optional untrusted text.

## Scenario catalog

Malicious scenarios include stolen privileged tokens, password spray followed by success, credential dumping with lateral movement, and malicious OAuth consent. Benign scenarios include approved travel, VPN geolocation artifacts, approved maintenance, known service-account batch activity, and a break-glass drill. Ambiguous or adversarial scenarios include sensor conflict, telemetry gaps, and prompt-injection content embedded in a ticket.

## Generation limitations

The generator encodes the engineering team's current assumptions. Feature relationships, base rates, event correlations, source reliability, attack timing, and contextual evidence are simplified. The model is trained and tested on partitions from the same generator family, so apparent discrimination is optimistic. Real data will exhibit unmodeled vendor differences, missing fields, semantic drift, adversarial adaptation, human process variation, and class imbalance.

## Required evolution

Version 0.2 should add de-identified historical replay cases, vendor-specific schema adapters, analyst disagreement labels, uncertain ground truth, delayed evidence arrival, duplicate and out-of-order events, multi-identity campaigns, and sector-specific mission criticality.
