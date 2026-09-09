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

The project deliberately separates detection from judgement. A rule firing is an investigation lead, not proof of brute force, compromise, malicious intent, legal breach, or attribution.

## Phase status

- **Phase 1 — Complete:** reproducible multi-source case, structured normalisation, detection, correlation, hypotheses, assessment, risk, escalation, response, case lifecycle.
- **Phase 2 — Complete:** typed evidence provenance, vulnerability/CVE/CVSS context, business/financial impact, legal/privacy referral context, attribution uncertainty, and advanced scenario evidence requirements.
- **Phase 3 — Complete:** reproducible scenario case packs and analyst reports covering phishing/impersonation, network/C2/exfiltration investigation, and privileged-account/insider-context investigation.
- **Phase 4 — Complete:** detection-quality checks, scenario validation, descriptive case metrics, regression coverage, documentation/audit refresh, and explicit limits on synthetic quality metrics.
- **Phase 5 — Complete:** employment-readiness hardening, security/contributor guidance, dependency-update automation, current GitHub Actions runtimes, and final repository audit controls.
- **Security audit hardening — Complete:** password-spraying detection coverage, immutable GitHub Actions references, and an explicit security-audit record.
- **Detection engineering layer — Complete:** MITRE ATT&CK mappings, portable Sigma rules, Microsoft Sentinel KQL, Splunk SPL, false-positive guidance, and regression checks for the detection catalogue.

## Detection engineering

The authentication analytics are represented consistently across multiple detection-engineering formats:

```text
Python analytic
     ↓
Sigma specification
     ↓
Microsoft Sentinel KQL / Splunk SPL
     ↓
MITRE ATT&CK mapping
     ↓
Positive + negative validation
     ↓
Analyst triage and case handling
```

The flagship `AUTH-REPEAT-001` analytic evaluates both repeated failures against one account and source-wide failures across multiple accounts. The second view is designed to surface password-spraying investigation leads that a per-account threshold can miss.

### ATT&CK coverage

| Rule | Behaviour | ATT&CK |
|---|---|---|
| `AUTH-BASE-001` | Failed SSH authentication | T1110 |
| `AUTH-REPEAT-001` | Repeated failures against one account | T1110.001 Password Guessing |
| `AUTH-REPEAT-001` | Repeated failures across multiple accounts | T1110.003 Password Spraying |

Portable rules and SIEM query examples live under [`detections/`](detections/) and are documented in [`docs/detection-engineering.md`](docs/detection-engineering.md).

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
├── authentication.py
├── README.md
├── sigma/
│   ├── ssh_auth_failures.yml
│   ├── ssh_repeated_auth_failures.yml
│   └── ssh_password_spray_correlation.yml
└── queries/
    ├── microsoft-sentinel/
    │   └── ssh-password-spray.kql
    └── splunk/
        └── ssh-password-spray.spl

cases/
├── CASE-MULTI-001/
├── CASE-PHISH-001/
├── CASE-NET-001/
└── CASE-INSIDER-001/

tests/
└── unit and integration coverage for parsing, evidence, hypotheses,
    assessment, risk, escalation, response, case management, context,
    scenarios, reporting, quality, validation, detection engineering,
    and the end-to-end pipeline
```

## Quality and security

The repository includes Python 3.11/3.12/3.13 CI and CodeQL analysis. GitHub Actions uses current Node 24-compatible action versions and the security-hardening branch pins those action references to immutable commit SHAs. Dependabot checks GitHub Actions and Python dependencies monthly. Synthetic case data is designed to be reproducible and auditable. Generated report output is not committed as source data.

See [`SECURITY.md`](SECURITY.md) for the reporting policy and [`AUDIT.md`](AUDIT.md) for the repository audit history. The security-hardening review is documented in [`docs/security-audit.md`](docs/security-audit.md) once merged.

## Safety and scope

This is an educational defensive security project. It does not perform live scanning, exploitation, credential attacks, packet capture, real-world phishing or impersonation operations, persistence, target command execution, or automated containment. Results are analyst-support outputs bounded by the supplied evidence.

## Audit

See [`AUDIT.md`](AUDIT.md) for the repository audit history and Phase 5 employment-readiness disposition. See [`docs/phase4-operational-maturity.md`](docs/phase4-operational-maturity.md) and [`docs/phase5-employment-readiness.md`](docs/phase5-employment-readiness.md) for the quality controls, limitations and hardening work.

## Author

Created by Karen Johnston — cybersecurity portfolio focused on evidence-based detection, investigation, and defensive tooling.
