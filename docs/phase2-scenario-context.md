# Phase 2: Advanced SOC Scenario Context

The scenario layer gives an analyst a structured way to record what type of investigation may be relevant without declaring that the scenario is confirmed.

Supported scenario contexts:

- Credential Attack
- Malware
- Command and Control
- Exfiltration
- Phishing
- Impersonation
- Social Engineering
- Insider Threat
- AI-Assisted Attack

Each scenario has explicit evidence requirements. Examples:

- **Command and Control:** network evidence, destination context, and endpoint/process correlation.
- **Exfiltration:** source/destination evidence, transfer scope or volume, data classification, and authorization.
- **Impersonation:** the identity claim, independent identity verification, and authentication/authorization context.
- **Insider Threat:** account ownership, expected activity baseline, and independent evidence of intent or policy violation.
- **AI-Assisted Attack:** an AI-related indicator plus supporting content/identity/telemetry evidence and independent corroboration.

## Classification boundary

`indicator_present` means that an investigation indicator exists. `classification_established` is a stronger state and requires an indicator. Neither field by itself proves actor intent, compromise, or an incident.

Missing scenario evidence is returned as explicit gaps so the analyst knows what to collect next.

This is deliberately a context and investigation model rather than an offensive attack generator. It supports evidence-led triage for common SOC scenarios while preserving uncertainty.
