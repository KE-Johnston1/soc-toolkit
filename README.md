# SOC Toolkit

A defensive Python toolkit for turning synthetic security logs into structured observations, detection signals, evidence correlation, and analyst assessments.

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
Recommended action
```

The project deliberately separates **detection** from **assessment**. A rule firing is an investigation lead, not proof of brute force, compromise, malicious intent, or an incident.

## Current capabilities

- Structured `LogEvent` model with IP, port, protocol, timestamp, account, and evidence-source validation
- SSH authentication parsing without inventing missing year/timezone information
- Evidence-aware repeated authentication detection with configurable threshold and time window
- Cross-source correlation with explicit temporal-correlation handling
- Analyst assessment states: `Expected`, `Requires Investigation`, `Insufficient Evidence`, and `Security Concern`
- Evidence items with source, observation, confidence, and relationship (`direct`, `corroborating`, `contradicting`)
- Explicit evidence-gap tracking and recommended next actions
- Unit tests for validation, parsing, detection, correlation, and analyst assessment
- Legacy parser entry points retained while the toolkit is being migrated to the structured workflow

## Analyst assessment principles

The assessment layer asks what is actually established before closing a case. Relevant checks include:

- asset or account ownership
- authorisation for the activity
- expected activity or baseline
- exact timing
- network evidence
- endpoint/post-event evidence
- maintenance, deployment, change, or security-testing context
- post-authentication activity for privileged accounts
- contradictory evidence

Missing context is recorded as an evidence gap rather than silently inferred. Contradictory evidence prevents an `Expected` closure until it is resolved.

## Example

Run the structured analyst assessment against the synthetic authentication log:

```bash
python main.py --module assessment
```

The command reports the detection rule, current assessment, confidence, classification, recommended action, rationale, and remaining evidence gaps.

## Project structure

```text
soc_toolkit/
├── assessment.py             # Evidence-first analyst assessment
├── models.py                 # Validated structured event model
detections/
└── authentication.py         # Repeated SSH authentication detection
parsers/
├── auth_parser.py            # Structured SSH authentication parser
├── firewall_parser.py        # Synthetic firewall parser
├── web_parser.py             # Synthetic web parser
└── log_parser.py             # Compatibility wrapper

tests/
├── test_models_and_auth.py
└── test_assessment.py
```

Additional legacy modules and sample logs remain in the repository while the refactor is completed.

## Safety and scope

This repository is an educational defensive-security project using synthetic/sample log data. It does not perform live scanning, exploitation, credential attacks, packet capture, or automated containment. Results should be treated as analyst hypotheses and evidence summaries, not authoritative incident conclusions.

## Development

Run the test suite with:

```bash
python -m unittest discover -s tests -v
```

## Author

Created by Karen Johnston — cybersecurity portfolio focused on evidence-based detection, investigation, and defensive tooling.
