# SOC Toolkit Repository Audit

**Audit status:** Phase 5 post-merge audit completed; security-hardening follow-up in review  
**Repository:** `KE-Johnston1/soc-toolkit`  
**Phase 4 baseline:** `4bc8b93b0ec4ca70635ba44a807e02ec5d2199b0`  
**Phase 5 merge:** `3ea7d9a9ae6d981c0397d7b34b7c2cc8e3fe9aee`  
**Current main audit commit:** `0a3eea2a743f4d4958f0a0e8ddbe7f2df3fe5157`  
**Audit date:** 2026-09-09

## Scope

Reviewed the completed Phase 1–5 implementation for code/project maturity, detection coverage, evidence handling, documentation accuracy, repository hygiene, security/contributor guidance, CI/CodeQL configuration, dependency-update hygiene, compatibility items and defensive safety boundaries. A focused security-hardening review was then performed against the authentication detector and GitHub Actions supply-chain configuration.

## Final disposition

| Area | Result | Disposition |
|---|---|---|
| Phase 1–4 workflow | Integrated | Retain |
| Phase 5 employment hardening | Integrated | Retain |
| Evidence-first model | Consistent across pipeline, scenarios and reporting | Verified |
| Scenario validation | Required fields and non-empty evidence/hypotheses/lessons enforced | Verified |
| Quality metrics | Synthetic-corpus controls with bounded interpretation | Verified |
| README | Matches current capabilities and phase status | Verified on hardening branch |
| Generated output | `.gitignore` retains only `output/.gitkeep` | Verified |
| Legacy CLI/parser compatibility | Intentionally retained | Documented compatibility item |
| SECURITY.md | Added and merged | Resolved |
| CONTRIBUTING.md | Added and merged | Resolved |
| Dependabot | Added for GitHub Actions and Python | Resolved |
| GitHub Actions | Current major versions | Verified |
| GitHub Actions immutability | Mutable tags replaced with reviewed commit SHAs on hardening branch | In review |
| CodeQL | Supported v4 | Verified |
| Licence | MIT, 2026 | Verified |
| Open issues / pull requests | None at Phase 5 audit start | Verified |
| Safety boundary | Defensive synthetic scope preserved | Verified |
| Latest main CI | Test and CodeQL runs passed | Verified |
| Password-spraying detection | Source-wide multi-account coverage added on hardening branch | In review |

## Security findings

### SEC-001 — Password-spraying detection coverage

The original authentication detector grouped failures by `(source_ip, account)`. That detects repeated failures against one account but can miss password spraying, where one source distributes attempts across multiple usernames.

**Remediation:** the hardening branch evaluates both per-account repetition and source-wide repetition across multiple accounts. A regression test covers the multi-account pattern using synthetic data.

This remains a detection lead rather than a verdict: ownership, authorization, successful authentication and endpoint context still require analyst validation.

### SEC-002 — GitHub Actions supply-chain hardening

The original workflows referenced mutable major-version tags. The hardening branch pins the reviewed action releases to full commit SHAs while keeping version comments for maintainability.

Workflow permissions remain explicitly read-only except the CodeQL `security-events: write` permission required to publish analysis results, and checkout credentials remain disabled.

### SEC-003 — Dependency transparency

The runtime implementation currently uses Python standard-library functionality and has no third-party runtime dependency manifest. This is not a confirmed vulnerability, but adding packaging metadata and explicit development dependencies would improve reproducibility and supply-chain visibility if external tooling is introduced.

### SEC-004 — Legacy compatibility surface

Historical parser modules remain because the CLI retains legacy entry points. The newer case-pipeline and scenario layers are authoritative. Legacy code should not be expanded without regression coverage and can be retired in a deliberate compatibility-breaking change.

### SEC-005 — GitHub account-level security settings

Repository files cannot prove whether secret scanning, push protection and Dependabot alerts are enabled. These should be verified in GitHub repository settings before using the project as a security portfolio.

## Recruitment / employment-readiness assessment

The project demonstrates more than a simple log parser: it shows detection engineering, evidence provenance, competing hypotheses, analyst assessment, risk, escalation, controlled response, case lifecycle, scenario validation, regression testing, CodeQL and repository security practices.

The highest-value next additions for employment are:

1. **MITRE ATT&CK mappings** for every production-style detection and scenario, including technique, data source, analytic rationale and known false positives.
2. **Sigma-style detection rules and test fixtures** so the project demonstrates portable detection engineering rather than only Python implementation.
3. **A small SIEM query pack** with equivalent analytics in KQL and Splunk SPL, documented against the same synthetic scenarios.
4. **A threat model** covering trust boundaries, assets, assumptions, abuse cases and mitigations.
5. **A recruiter-facing demo**: one command, one case, one analyst report, one decision trail, and a short architecture diagram.
6. **Packaging metadata** (`pyproject.toml`) and reproducible developer tooling if third-party dependencies are introduced.
7. **A measurable detection-engineering roadmap** showing rule objective, telemetry requirement, test cases, expected false positives and tuning decisions.

The project should continue to be explicit that its evidence is synthetic and that quality metrics are corpus-validation metrics rather than production SOC KPIs.

## CI verification record

The latest `main` commit `0a3eea2a743f4d4958f0a0e8ddbe7f2df3fe5157` had successful Test and CodeQL workflow runs on 2026-09-09. The security-hardening branch changes detection behaviour and workflow references, so fresh Test and CodeQL runs are required before merge.

## Safety boundary

The project remains a defensive educational toolkit using synthetic data. It does not perform live exploitation, credential attacks, packet capture, persistence, target command execution or automated containment.

## Post-merge conclusion

**Phase 5 hardening is accepted on `main`.** The security-hardening follow-up is a targeted improvement, not evidence of a critical unresolved vulnerability. Merge it only after the new regression test and CodeQL checks pass.
