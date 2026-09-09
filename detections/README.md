# Detection Engineering Catalogue

This directory contains the portable detection layer for SOC Toolkit.

| Rule | Python | Sigma | KQL | SPL | ATT&CK |
|---|---|---|---|---|---|
| AUTH-BASE-001 | Authentication model | `sigma/ssh_auth_failures.yml` | Adapter pattern | Adapter pattern | T1110 |
| AUTH-REPEAT-001 | `authentication.py` | `sigma/ssh_repeated_auth_failures.yml` + correlation | `queries/microsoft-sentinel/ssh-password-spray.kql` | `queries/splunk/ssh-password-spray.spl` | T1110.001 / T1110.003 |
| SOC-EXEC-001 | Reference specification | `sigma/suspicious_powershell.yml` | `queries/microsoft-sentinel/suspicious-powershell.kql` | `queries/splunk/suspicious-powershell.spl` | T1059.001 |
| SOC-ID-001 | Reference specification | `sigma/privileged_login_context.yml` | `queries/microsoft-sentinel/privileged-login-context.kql` | `queries/splunk/privileged-login-context.spl` | T1078 |
| SOC-NET-001 | Reference specification | `sigma/network_beaconing.yml` | `queries/microsoft-sentinel/network-beaconing.kql` | `queries/splunk/network-beaconing.spl` | T1071 |

## Portfolio scope

The three `SOC-*` rules are deliberately labelled **experimental/reference examples**. They demonstrate the structure of a portable detection but are not claimed to be production-ready analytics. Real deployments require environment-specific schemas, baselines, thresholds, testing, and tuning.

## How to use this directory

1. Start with the detection objective and ATT&CK mapping.
2. Review the Sigma rule as the portable analytic specification.
3. Adapt KQL or SPL field names to the target SIEM schema.
4. Validate with positive, negative, and known-benign events.
5. Record false-positive tuning decisions.
6. Correlate alerts with additional evidence before making an incident assessment.

## Quality bar

Every mature analytic should document:

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
