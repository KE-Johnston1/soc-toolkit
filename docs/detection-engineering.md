# Detection Engineering Layer

SOC Toolkit now includes a portable detection-engineering layer around its evidence-aware Python analytics.

## Detection lifecycle

```text
Synthetic telemetry
      ↓
Normalisation
      ↓
Python analytic
      ↓
Sigma detection
      ↓
SIEM query (KQL / SPL)
      ↓
MITRE ATT&CK mapping
      ↓
Positive / negative validation
      ↓
False-positive review
      ↓
Analyst triage
      ↓
Case / escalation decision
```

The same analytic intent is represented in Python, Sigma, Microsoft Sentinel KQL and Splunk SPL. Field names in the SIEM examples are deliberately documented as adapter points because production schemas vary by connector and CIM/data model.

## ATT&CK coverage

| Rule | Behaviour | ATT&CK | Analyst use |
|---|---|---|---|
| AUTH-BASE-001 | Failed SSH authentication | T1110 Credential Access / Brute Force family | Base telemetry |
| AUTH-REPEAT-001 | Repeated failures against one account | T1110.001 Password Guessing | Brute-force investigation lead |
| AUTH-REPEAT-001 | Repeated failures from one source across multiple accounts | T1110.003 Password Spraying | Password-spraying investigation lead |

ATT&CK technique mappings describe the behaviour represented by the analytic; they are not conclusions about attacker identity or intent.

## Detection specification

**AUTH-REPEAT-001**

- Protocol/service: SSH
- Event: authentication failure
- Window: 5 minutes
- Threshold: 5 or more failures
- Single-account view: repeated failures against the same account
- Source-wide view: failures from one source across multiple accounts
- Default assessment: `Requires Investigation`
- Default confidence: `Medium` when timestamps are trustworthy; `Low` when only a count is supported

### Required analyst validation

1. Confirm the source IP and whether it is expected infrastructure.
2. Confirm timestamps and time synchronisation.
3. Identify distinct target accounts.
4. Search for successful authentication from the same source.
5. Review endpoint activity after any successful authentication.
6. Check whether the activity overlaps approved testing, scanners, automation, or maintenance.
7. Preserve evidence and record the reasoning for escalation or closure.

## False-positive strategy

Do not lower a threshold solely to increase alert volume. First inspect context and telemetry quality. Candidate benign sources include vulnerability scanners, shared NAT/proxy infrastructure, misconfigured automation, password rotation activity, and approved penetration testing.

## Query portability

The KQL and SPL examples are reference implementations. A production deployment should:

- map source/account fields to the organisation's schema;
- use the organisation's approved index/table scope;
- preserve UTC/time-zone semantics;
- exclude known authorised scanners only through governed allow-lists;
- test against representative positive and negative datasets;
- measure precision/recall only where labelled data supports it.

## Safety boundary

These detections are defensive analytics. SOC Toolkit does not perform live credential attacks, scanning, exploitation, or automated containment.
