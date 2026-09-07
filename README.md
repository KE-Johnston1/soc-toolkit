# SOC Toolkit

A defensive Python toolkit for turning synthetic security logs into structured observations, detection signals, evidence correlation, analyst assessments, risk context, and escalation recommendations.

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
```

The project deliberately separates **detection**, **assessment**, **risk**, and **escalation**. A rule firing is an investigation lead, not proof of brute force, compromise, malicious intent, or an incident.

## Current capabilities

- Structured `LogEvent` model with IP, port, protocol, timestamp, account, and evidence-source validation
- SSH authentication parsing without inventing missing year/timezone information
- Evidence-aware repeated authentication detection with configurable threshold and time window
- Cross-source correlation with explicit temporal-correlation handling
- Analyst assessment states: `Expected`, `Requires Investigation`, `Insufficient Evidence`, and `Security Concern`
- Evidence items with source, observation, confidence, and relationship (`direct`, `corroborating`, `contradicting`)
- Explicit evidence-gap tracking and recommended next actions
- Organisational risk context covering asset criticality, account privilege, data sensitivity, likelihood, business/financial impact, CVE relevance, CVSS severity, and legal/privacy considerations
- Evidence-based escalation levels from monitoring through Tier 2, Incident Response, and Management/Legal/Privacy referral
- Unit tests for validation, parsing, detection, correlation, assessment, risk, and escalation

## Analyst assessment principles

The assessment layer asks what is actually established before closing a case. Relevant checks include ownership, authorisation, expected activity/baseline, exact timing, network evidence, endpoint/post-event evidence, maintenance/deployment/change/security-testing context, privileged post-authentication activity, and contradictory evidence.

Missing context is recorded as an evidence gap rather than silently inferred. Contradictory evidence prevents an `Expected` closure until it is resolved.

## Risk and escalation principles

Risk is organisational context, not a compromise verdict. Unknown values remain unknown, and financial impact is labelled by basis (`Observed`, `Derived`, `Estimated`, or `Unknown`). CVSS describes vulnerability severity; it does not prove exploitation or automatically determine organisational risk.

Escalation is also evidence-based. Severity alone does not determine escalation. A privileged account may justify Tier 2 review even when compromise is unconfirmed; malware, persistence, command-and-control, or potential exfiltration evidence may justify Incident Response review; possible sensitive-data or regulatory implications may justify Management/Legal/Privacy referral.

## Examples

Run the structured analyst assessment against the synthetic authentication log:

```bash
python main.py --module assessment
```

Run the test suite:

```bash
python -m unittest discover -s tests -v
```

See [`docs/risk-and-escalation.md`](docs/risk-and-escalation.md) for the decision model and escalation criteria.

## Project structure

```text
soc_toolkit/
├── __init__.py
├── assessment.py             # Evidence-first analyst assessment
├── escalation.py             # Escalation recommendation engine
├── models.py                 # Validated structured event model
└── risk.py                    # Organisational risk context

detections/
└── authentication.py         # Repeated SSH authentication detection

parsers/
├── auth_parser.py            # Structured SSH authentication parser
├── firewall_parser.py        # Synthetic firewall parser
├── web_parser.py             # Synthetic web parser
└── log_parser.py             # Compatibility wrapper

tests/
├── test_models_and_auth.py
├── test_assessment.py
└── test_risk_escalation.py
```

Additional legacy modules and sample logs remain in the repository while the refactor is completed.

## Safety and scope

This repository is an educational defensive-security project using synthetic/sample log data. It does not perform live scanning, exploitation, credential attacks, packet capture, or automated containment. Results should be treated as analyst hypotheses and evidence summaries, not authoritative incident conclusions. Legal/privacy fields are referral indicators, not legal advice or breach determinations.

## Author

Created by Karen Johnston — cybersecurity portfolio focused on evidence-based detection, investigation, and defensive tooling.
