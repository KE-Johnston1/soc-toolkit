# SOC Toolkit

A defensive Python toolkit for turning synthetic security logs into structured observations, detection signals, evidence correlation, analyst assessment, risk context, escalation recommendations, and controlled response decisions.

## Analyst workflow

```text
Log input
  ↓
Normalisation
  ↓
Detection signal
  ↓
Evidence correlation
  ↓
Analyst assessment
  ↓
Risk context
  ↓
Escalation recommendation
  ↓
Response decision
  ↓
Case lifecycle / decision trail
  ↓
Closure and lessons learned
```

The project deliberately separates **detection**, **assessment**, **risk**, **escalation**, and **response**. A rule firing is an investigation lead, not proof of brute force, compromise, malicious intent, or an incident.

## Current capabilities

- Structured `LogEvent` model with IP, port, protocol, timestamp, account, and evidence-source validation
- SSH authentication parsing without inventing missing year/timezone information
- Evidence-aware repeated authentication detection with configurable threshold and time window
- Cross-source correlation with explicit temporal-correlation handling
- Analyst assessment states: `Expected`, `Requires Investigation`, `Insufficient Evidence`, and `Security Concern`
- Evidence items with source, observation, confidence, and relationship (`direct`, `corroborating`, `contradicting`)
- Explicit evidence-gap tracking and recommended next actions
- Organisational risk context covering asset criticality, account privilege, data sensitivity, likelihood, business/financial impact, CVE relevance, CVSS severity, and legal/privacy considerations
- Evidence-based escalation recommendations with separate specialist and stakeholder routing
- Controlled response actions: monitor, investigate, escalate, contain, remediate, recover, and close
- Case lifecycle with validated status transitions and an auditable analyst decision trail
- Unit tests across validation, parsing, detection, correlation, assessment, risk, escalation, response, and case management

## Analyst principles

Missing context is recorded as an evidence gap rather than silently inferred. Contradictory evidence prevents an `Expected` closure until it is resolved.

Risk is organisational context, not a compromise verdict. CVSS describes vulnerability severity; it does not prove exploitation or automatically determine organisational risk. Financial impact is labelled by basis rather than presented as invented precision.

Escalation is evidence-based. Severity alone does not determine escalation. Privileged accounts, multiple affected accounts, malware, persistence, command-and-control, potential exfiltration, recurring related alerts, or possible sensitive-data/legal implications can justify additional review depending on the evidence.

Response is controlled rather than automatic. `Insufficient Evidence` leads to investigation, not closure. Containment requires explicit authorisation and a safe execution condition. Closure requires an `Expected` assessment, no remaining evidence gaps, and a documented closure rationale.

## Examples

Run the structured analyst assessment:

```bash
python main.py --module assessment
```

Run a response recommendation:

```bash
python main.py --module response
```

Run a case-lifecycle demonstration:

```bash
python main.py --module case
```

Run the test suite:

```bash
python -m unittest discover -s tests -v
```

See [`docs/risk-and-escalation.md`](docs/risk-and-escalation.md) and [`docs/response-and-case-management.md`](docs/response-and-case-management.md) for the decision models.

## Project structure

```text
soc_toolkit/
├── assessment.py             # Evidence-first analyst assessment
├── case_management.py       # Controlled case lifecycle and decision trail
├── escalation.py             # Evidence-based escalation recommendations
├── models.py                 # Validated structured event model
├── response.py               # Controlled response decisions
└── risk.py                   # Organisational risk context

detections/
└── authentication.py         # Repeated SSH authentication detection

parsers/
├── auth_parser.py
├── firewall_parser.py
├── web_parser.py
└── log_parser.py

tests/
├── test_models_and_auth.py
├── test_assessment.py
├── test_risk_escalation.py
└── test_response_case_management.py
```

Additional legacy modules and sample logs remain in the repository while the refactor is completed.

## Safety and scope

This repository is an educational defensive-security project using synthetic/sample log data. It does not perform live scanning, exploitation, credential attacks, packet capture, or automated containment. Results should be treated as analyst hypotheses and evidence summaries, not authoritative incident conclusions. Legal/privacy fields are workflow referral indicators, not legal advice or breach determinations.

## Author

Created by Karen Johnston — cybersecurity portfolio focused on evidence-based detection, investigation, and defensive tooling.
