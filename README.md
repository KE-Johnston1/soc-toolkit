# SOC Toolkit

A defensive Python toolkit for turning synthetic security logs into structured observations, detection signals, evidence correlation, analyst assessment, competing hypotheses, risk context, escalation recommendations, controlled response decisions, auditable case handling, scenario reporting, and operational-quality checks.

## Analyst workflow

```text
Log input → Normalisation → Detection signal → Evidence provenance
→ Cross-source correlation → Competing hypotheses → Analyst assessment
→ Vulnerability / impact / attribution context → Scenario evidence requirements
→ Risk → Escalation → Response → Case lifecycle / decision trail
→ Closure / lessons learned → Quality validation
```

The project deliberately separates detection from judgement. A rule firing is an investigation lead, not proof of brute force, compromise, malicious intent, attribution, legal breach, or an incident.

## Phase status

- **Phase 1 — Complete:** reproducible multi-source case, structured normalisation, detection, correlation, hypotheses, assessment, risk, escalation, response, case lifecycle.
- **Phase 2 — Complete:** typed evidence provenance, vulnerability/CVE/CVSS context, business/financial impact, legal/privacy referral context, attribution uncertainty, and advanced scenario evidence requirements.
- **Phase 3 — Complete:** reproducible scenario case packs and analyst reports covering phishing/impersonation, network/C2/exfiltration investigation, and privileged-account/insider-context investigation.
- **Phase 4 — Complete:** detection-quality checks, scenario validation, descriptive case metrics, regression coverage, documentation/audit refresh, and explicit limits on synthetic quality metrics.
- **Phase 5 — Complete:** employment-readiness hardening, security/contributor guidance, dependency-update automation, current GitHub Actions runtimes, and final repository audit controls.

## Phase 3 scenario cases

### CASE-PHISH-001 — Suspected Executive Impersonation / Phishing

A synthetic mail investigation involving display-name impersonation, header evidence, and a user report. The case remains **Requires Investigation** because sender identity, account compromise, and user impact require verification.

### CASE-NET-001 — Periodic Outbound Traffic / Potential C2 and Data Transfer

A synthetic network investigation involving periodic outbound connections and a subsequent transfer. The case is **Requires Investigation** with **High provisional risk** and **Tier 2** escalation; periodic traffic and transfer volume are not treated as proof of C2 or exfiltration.

### CASE-INSIDER-001 — Privileged Account Activity Requiring Context

A synthetic identity investigation where unusual privileged authentication overlaps a maintenance window. The case remains **Insufficient Evidence** because ownership, authorisation, source-device identity, and endpoint evidence are unresolved. The scenario does not automatically attribute activity to an insider.

Each case contains a machine-readable `scenario.json` and an analyst-facing `analyst-report.md` with timeline, evidence matrix, hypotheses, assessment, risk, escalation, response, closure and lessons learned.

## Phase 4 operational-quality controls

The toolkit now includes controls for the quality of the synthetic investigation corpus:

- labelled true-positive, false-positive, true-negative and false-negative detection checks
- precision and recall when their denominators exist
- tuning notes that encourage context/telemetry review before changing thresholds
- structural validation of scenario packs
- descriptive case-collection metrics for assessment, escalation, response, closure readiness and unresolved cases
- regression tests for quality and data validation

These are **training-data quality controls**, not production SOC performance claims.

## Evidence-first principles

- **Observed:** directly represented by supplied evidence.
- **Correlated:** a relationship between observations.
- **Inferred:** an interpretation supported by observations.
- **Hypothesis:** a possible explanation requiring validation.
- **Unknown:** not established by available evidence.

A source IP is not automatically an actor identity. A CVE reference is not proof of exploitation. CVSS severity is not the same as organisational risk. Potential impact is not observed impact. Estimated financial values must retain their basis. Legal/privacy fields indicate when specialist referral may be appropriate; they are not legal advice or breach determinations.

Scenario labels are investigation contexts rather than verdicts. Phishing, impersonation, insider threat, C2, exfiltration and AI-assisted attack indicators require appropriate corroboration.

Containment is controlled: it requires explicit authorisation and a safe execution condition. Closure requires an `Expected` assessment, no unresolved evidence gaps, and a documented rationale.

## Running the toolkit

Run the flagship synthetic pipeline:

```bash
python main.py --module pipeline
```

Validate and summarise the Phase 3 scenario cases:

```bash
python main.py --module scenarios
```

Run Phase 4 quality controls:

```bash
python main.py --module quality
```

Run the full test suite:

```bash
python -m unittest discover -s tests -v
```

## Project structure

```text
soc_toolkit/
├── assessment.py
├── case_loader.py
├── case_management.py
├── case_metrics.py
├── correlation.py
├── escalation.py
├── evidence.py
├── hypotheses.py
├── hypothesis_case.py
├── investigation_context.py
├── models.py
├── pipeline.py
├── quality.py
├── reporting.py
├── response.py
├── risk.py
├── scenario_cases.py
└── scenario_validation.py

detections/
└── authentication.py

parsers/
├── auth_parser.py
├── firewall_events.py
├── firewall_parser.py
├── log_parser.py
└── web_events.py

cases/
├── CASE-MULTI-001/
├── CASE-PHISH-001/
├── CASE-NET-001/
└── CASE-INSIDER-001/

tests/
└── unit and integration coverage for parsing, evidence, hypotheses,
    assessment, risk, escalation, response, case management, context,
    scenarios, reporting, quality, validation, and the end-to-end pipeline
```

## Quality and security

The repository includes Python 3.11/3.12/3.13 CI and CodeQL analysis. GitHub Actions uses current Node 24-compatible action versions. Dependabot checks GitHub Actions and Python dependencies monthly. Synthetic case data is designed to be reproducible and auditable. Generated report output is not committed as source data. Phase 4 quality metrics describe only the supplied synthetic checks.

## Safety and scope

This is an educational defensive security project. It does not perform live scanning, exploitation, credential attacks, packet capture, real-world phishing or impersonation operations, persistence, target command execution, or automated containment. Results are analyst-support outputs bounded by the supplied evidence.

## Audit

See [`AUDIT.md`](AUDIT.md) for the repository audit history and Phase 5 employment-readiness disposition. See [`docs/phase4-operational-maturity.md`](docs/phase4-operational-maturity.md) and [`docs/phase5-employment-readiness.md`](docs/phase5-employment-readiness.md) for the quality controls, limitations and final hardening work.

## Author

Created by Karen Johnston — cybersecurity portfolio focused on evidence-based detection, investigation, and defensive tooling.
