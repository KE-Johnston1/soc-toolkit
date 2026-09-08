# SOC Toolkit

A defensive Python toolkit for turning synthetic security logs into structured observations, detection signals, evidence correlation, analyst assessment, competing hypotheses, risk context, escalation recommendations, controlled response decisions, and auditable case handling.

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
Competing hypotheses
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

The project deliberately separates **detection**, **correlation**, **hypotheses**, **assessment**, **risk**, **escalation**, and **response**. A rule firing is an investigation lead, not proof of brute force, compromise, malicious intent, or an incident.

## End-to-end case demonstration

The `pipeline` module composes the existing decision layers around one synthetic SSH authentication scenario. It demonstrates how an analyst can move from a detection signal to cross-source evidence, competing hypotheses, evidence-backed assessment, organisational risk context, escalation recommendation, controlled response, and case status without inventing missing evidence.

Run it with:

```bash
python main.py --module pipeline
```

The demonstration intentionally leaves ownership, authorization, timing, network, endpoint, and change/testing verification incomplete. The resulting case therefore remains investigative rather than being presented as a confirmed compromise.

## Phase 1: multi-source investigation case

The Phase 1 case pack at `cases/CASE-MULTI-001/` contains alert metadata plus authentication, firewall, and web evidence. The case-pack loader normalises the supported logs into structured `LogEvent` objects and the correlation layer checks whether the same source appears across multiple evidence sources within a configured time window.

The case also carries five explicit competing hypotheses: legitimate administration, credential attack, possible account compromise, misconfigured/automated service, and unknown/novel activity. Evidence is linked to hypotheses as supporting or challenging context; supporting evidence is not treated as proof.

Run the Phase 1 tests with:

```bash
python -m unittest tests.test_case_loader tests.test_hypothesis_case -v
```

See [`docs/phase1-multisource-case.md`](docs/phase1-multisource-case.md) and [`docs/phase1-completion-checklist.md`](docs/phase1-completion-checklist.md) for the evidence flow, hypothesis model, completion criteria, and current limitations. Correlation is supporting evidence only; a shared source IP does not establish attribution or malicious intent.

## Current capabilities

- Structured `LogEvent` model with IP, port, protocol, timestamp, account, and evidence-source validation
- SSH authentication parsing without inventing missing year/timezone information
- Structured synthetic firewall and web event parsing
- Reproducible multi-source case packs with alert metadata and evidence files
- Evidence-aware repeated authentication detection with configurable threshold and time window
- Cross-source correlation with explicit temporal-correlation handling
- Explicit competing hypotheses with supporting/challenging evidence and uncertainty-aware status
- Analyst assessment states: `Expected`, `Requires Investigation`, `Insufficient Evidence`, and `Security Concern`
- Evidence items with source, observation, confidence, and relationship (`direct`, `corroborating`, `contradicting`)
- Explicit evidence gap tracking and recommended next actions
- Organisational risk context covering asset criticality, account privilege, data sensitivity, likelihood, business/financial impact, CVE relevance, CVSS severity, and legal/privacy considerations
- Evidence-based escalation recommendations with separate specialist and stakeholder routing
- Controlled response actions: monitor, investigate, escalate, contain, remediate, recover, and close
- Case lifecycle with validated status transitions and an auditable analyst decision trail
- End-to-end synthetic case pipeline combining the decision layers into one reproducible analyst workflow
- Unit tests across validation, parsing, detection, correlation, hypotheses, assessment, risk, escalation, response, case management, and pipeline behaviour
- CodeQL analysis workflow for Python

## Analyst principles

Missing context is recorded as an evidence gap rather than silently inferred. Contradictory evidence prevents an `Expected` closure until it is resolved.

Hypotheses are competing explanations, not conclusions. A hypothesis can be supported, challenged, or unresolved while the overall analyst assessment remains appropriately cautious.

Risk is organisational context, not a compromise verdict. CVSS describes vulnerability severity; it does not prove exploitation or automatically determine organisational risk. Financial impact is labelled by basis rather than presented as invented precision.

Escalation is evidence-based. Severity alone does not determine escalation. Privileged accounts, multiple affected accounts, malware, persistence, command and control, potential exfiltration, recurring related alerts, or possible sensitive-data/legal implications can justify additional review depending on the evidence.

Response is controlled rather than automatic. `Insufficient Evidence` leads to investigation, not closure. Containment requires explicit authorisation and a safe execution condition. Closure requires an `Expected` assessment, no remaining evidence gaps, and a documented closure rationale.

## Examples

Run the structured analyst assessment:

```bash
python main.py --module assessment
```

Run the end-to-end case pipeline:

```bash
python main.py --module pipeline
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

See [`docs/risk-and-escalation.md`](docs/risk-and-escalation.md), [`docs/response-and-case-management.md`](docs/response-and-case-management.md), [`docs/phase1-multisource-case.md`](docs/phase1-multisource-case.md), and [`docs/phase1-completion-checklist.md`](docs/phase1-completion-checklist.md) for the decision models.

## Project structure

```text
soc_toolkit/
├── assessment.py             # Evidence-first analyst assessment
├── case_loader.py            # Reproducible synthetic case-pack loader
├── case_management.py        # Controlled case lifecycle and decision trail
├── correlation.py            # Cross-source temporal correlation
├── escalation.py             # Evidence-based escalation recommendations
├── hypotheses.py             # Competing hypothesis tracking
├── models.py                 # Validated structured event model
├── pipeline.py               # End-to-end synthetic case workflow
├── response.py               # Controlled response decisions
└── risk.py                   # Organisational risk context

detections/
└── authentication.py         # Repeated SSH authentication detection

parsers/
├── auth_parser.py
├── firewall_events.py
├── firewall_parser.py
├── log_parser.py
└── web_events.py

cases/
└── CASE-MULTI-001/           # Reproducible auth/firewall/web case pack
    ├── alert.json
    ├── auth.log
    ├── firewall.log
    └── web.log

tests/
├── test_case_loader.py
├── test_hypotheses.py
├── test_hypothesis_case.py
├── test_models_and_auth.py
├── test_assessment.py
├── test_risk_escalation.py
├── test_response_case_management.py
└── test_pipeline.py
```

Additional legacy modules and sample logs remain in the repository while the refactor is completed.

## Safety and scope

This repository is an educational defensive security project using synthetic/sample log data. It does not perform live scanning, exploitation, credential attacks, packet capture, or automated containment. Results should be treated as analyst hypotheses and evidence summaries, not authoritative incident conclusions. Legal/privacy fields are workflow referral indicators, not legal advice or breach determinations.

## Author

Created by Karen Johnston — cybersecurity portfolio focused on evidence-based detection, investigation, and defensive tooling.
