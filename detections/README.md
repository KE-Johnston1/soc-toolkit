# Detection Engineering Catalogue

This directory contains the portable detection layer for SOC Toolkit.

| Rule | Python | Sigma | KQL | SPL | ATT&CK |
|---|---|---|---|---|---|
| AUTH-BASE-001 | Authentication model | `sigma/ssh_auth_failures.yml` | Adapter pattern in KQL | Adapter pattern in SPL | T1110 |
| AUTH-REPEAT-001 | `authentication.py` | `sigma/ssh_repeated_auth_failures.yml` + correlation | `queries/microsoft-sentinel/ssh-password-spray.kql` | `queries/splunk/ssh-password-spray.spl` | T1110.001 / T1110.003 |

## How to use this directory

1. Start with the Python analytic and its tests.
2. Review the Sigma rule as the portable analytic specification.
3. Adapt KQL or SPL field names to the target SIEM schema.
4. Validate with positive, negative, and known-benign events.
5. Record false-positive tuning decisions.
6. Map resulting alerts to an investigation case rather than treating an alert as proof of compromise.

## Quality bar

Every production-ready analytic should document:

- unique rule ID;
- detection objective;
- ATT&CK technique/sub-technique;
- required telemetry;
- time window and threshold;
- expected false positives;
- analyst validation steps;
- evidence gaps;
- positive and negative tests;
- query portability assumptions;
- tuning history.
