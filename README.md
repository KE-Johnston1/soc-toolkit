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
Evidence provenance
  ↓
Cross-source correlation
  ↓
Competing hypotheses
  ↓
Analyst assessment
  ↓
Vulnerability / impact / attribution context
  ↓
Scenario-specific evidence requirements
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

The project deliberately separates **detection**, **correlation**, **evidence provenance**, **hypotheses**, **assessment**, **risk**, **escalation**, and **response**. A rule firing is an investigation lead, not proof of brute force, compromise, malicious intent, or an incident.

## Phase 2: evidence and investigation context

Phase 2 makes evidence provenance explicit and adds structured context around vulnerability relevance, business impact, financial impact, legal/privacy considerations, attribution, and advanced SOC investigation scenarios.

`Soc_toolkit/evidence.py` distinguishes `observed`, `correlated`, `inferred`, `hypothesis`, and `unknown` evidence. The pipeline exposes typed `EvidenceRecord` objects and an `EvidenceSummary`, so direct observations remain distinguishable from relationships and analyst reasoning.

`Soc_toolkit/investigation_context.py` adds CVE/CVSS context, impact and financial basis, legal/privacy referral context, attribution uncertainty, and `ScenarioContext`. The scenario model covers credential attacks, malware, command and control, exfiltration, phishing, impersonation, social engineering, insider threat, and AI-assisted attacks. Each scenario has explicit evidence requirements rather than an automatic malicious verdict.

The pipeline exposes vulnerability relevance and evidence gaps without declaring exploitation, actor identity, financial loss, or a legal breach where those facts are not established.

**Phase 2 is complete.** See [`docs/phase2-completion-checklist.md`](docs/phase2-completion-checklist.md) for the validated scope and controls.

See [`docs/phase2-evidence-context.md`](docs/phase2-evidence-context.md), [`docs/phase2-risk-context.md`](docs/phase2-risk-context.md), and [`docs/phase2-scenario-context.md`](docs/phase2-scenario-context.md).

## End-to-end case demonstration

The `pipeline` module composes the existing decision layers around one synthetic SSH authentication scenario. It demonstrates how an analyst can move from a detection signal to cross-source evidence, competing hypotheses, evidence-backed assessment, organisational risk context, escalation recommendation, controlled response, and case status without inventing missing evidence.

Run it with:

```bash
python main.py --module pipeline
```

The demonstration intentionally leaves ownership, authorization, timing, network, endpoint, and change/testing verification incomplete. The resulting case therefore remains investigative rather than being presented as a confirmed compromise.

## Current capabilities

- Structured `LogEvent` model with IP, port, protocol, timestamp, account, and evidence-source validation
- SSH authentication parsing without inventing missing year/timezone information
- Structured synthetic firewall and web event parsing
- Reproducible multi-source case packs with alert metadata and evidence files
- Typed evidence provenance: `observed`, `correlated`, `inferred`, `hypothesis`, `unknown`
- Evidence summaries showing direct observation and timestamp coverage
- Evidence-aware repeated authentication detection with configurable threshold and time window
- Cross-source correlation with explicit temporal-correlation handling
- Explicit competing hypotheses with supporting/challenging evidence and uncertainty-aware status
- Analyst assessment states: `Expected`, `Requires Investigation`, `Insufficient Evidence`, and `Security Concern`
- Explicit evidence gap tracking and recommended next actions
- CVE/CVSS context that separates vulnerability relevance from exploitation and organisational risk
- Business, operational, data-sensitivity, and financial-impact context with explicit value basis
- Legal/privacy workflow referral indicators without legal or breach determinations
- Attribution context that separates source IP from verified actor identity and preserves proxy/NAT uncertainty
- Scenario-specific evidence requirements for credential attack, malware, C2, exfiltration, phishing, impersonation, social engineering, insider threat, and AI-assisted attack investigations
- Organisational risk context covering asset criticality, account privilege, data sensitivity, likelihood, and business/financial impact
- Evidence-based escalation recommendations with separate specialist and stakeholder routing
- Controlled response actions: monitor, investigate, escalate, contain, remediate, recover, and close
- Case lifecycle with validated status transitions and an auditable analyst decision trail
- End-to-end synthetic case pipeline combining the decision layers into one reproducible analyst workflow
- Unit tests across validation, parsing, detection, correlation, evidence, hypotheses, assessment, risk, escalation, response, case management, investigation context, scenario context, and pipeline behaviour
- CodeQL analysis workflow for Python

## Analyst principles

Missing context is recorded as an evidence gap rather than silently inferred. Contradictory evidence prevents an `Expected` closure until it is resolved.

Evidence provenance is explicit. `observed` means directly represented by a source; `correlated` means a relationship between observations; `inferred` and `hypothesis` describe analyst reasoning; `unknown` records facts that remain unestablished.

A CVE reference is not proof of exploitation. CVSS describes vulnerability severity, while organisational risk depends on the affected asset, exposure, likelihood, impact, and available evidence.

Potential impact is not observed impact. Estimated financial values are labelled by basis, and unknown costs remain unknown.

A source IP is not necessarily an individual actor. Attribution requires identity evidence and should preserve NAT, proxy, shared infrastructure, and other ambiguity.

Scenario labels are investigation contexts, not verdicts. For example, unusual periodic outbound traffic can justify a C2 investigation without proving C2, and an AI-assisted attack indicator requires independent corroboration before classification is established.

Legal/privacy fields identify when specialist referral may be appropriate; they do not establish that a legal breach occurred and are not legal advice.

Hypotheses are competing explanations, not conclusions. A hypothesis can be supported, challenged, or unresolved while the overall analyst assessment remains appropriately cautious.

Escalation is evidence-based. Severity alone does not determine escalation. Privileged accounts, multiple affected accounts, malware, persistence, command and control, potential exfiltration, recurring related alerts, or possible sensitive-data/legal implications can justify additional review depending on the evidence.

Response is controlled rather than automatic. `Insufficient Evidence` leads to investigation, not closure. Containment requires explicit authorisation and a safe execution condition. Closure requires an `Expected` assessment, no remaining evidence gaps, and a documented closure rationale.

## Examples

Run the end-to-end case pipeline:

```bash
python main.py --module pipeline
```

Run the test suite:

```bash
python -m unittest discover -s tests -v
```

See [`docs/risk-and-escalation.md`](docs/risk-and-escalation.md), [`docs/response-and-case-management.md`](docs/response-and-case-management.md), [`docs/phase1-multisource-case.md`](docs/phase1-multisource-case.md), [`docs/phase1-completion-checklist.md`](docs/phase1-completion-checklist.md), [`docs/phase2-evidence-context.md`](docs/phase2-evidence-context.md), [`docs/phase2-risk-context.md`](docs/phase2-risk-context.md), [`docs/phase2-scenario-context.md`](docs/phase2-scenario-context.md), and [`docs/phase2-completion-checklist.md`](docs/phase2-completion-checklist.md) for the decision and evidence models.

## Project structure

```text
soc_toolkit/
├── assessment.py             # Evidence-first analyst assessment
├── case_loader.py            # Reproducible synthetic case-pack loader
├── case_management.py        # Controlled case lifecycle and decision trail
├── correlation.py             # Cross-source temporal correlation
├── escalation.py             # Evidence-based escalation recommendations
├── evidence.py               # Typed evidence provenance
├── hypotheses.py             # Competing hypothesis tracking
├── hypothesis_case.py        # Case-specific hypothesis construction
├── investigation_context.py  # CVE, impact, legal/privacy, attribution, scenario context
├── models.py                 # Validated structured event model
├── pipeline.py               # End-to-end synthetic case workflow
├── response.py               # Controlled response decisions
├── risk.py                   # Organisational risk context
└── scenario_context.py       # Advanced SOC scenario evidence requirements

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
├── test_evidence.py
├── test_investigation_context.py
├── test_scenario_context.py
└── test_pipeline.py
```

Additional legacy modules and sample logs remain in the repository while the refactor is completed.

## Safety and scope

This repository is an educational defensive security project using synthetic/sample log data. It does not perform live scanning, exploitation, credential attacks, packet capture, or automated containment. Results should be treated as analyst hypotheses and evidence summaries, not authoritative incident conclusions. Legal/privacy fields are workflow referral indicators, not legal advice or breach determinations.

## Author

Created by Karen Johnston — cybersecurity portfolio focused on evidence-based detection, investigation, and defensive tooling.
