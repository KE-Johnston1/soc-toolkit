# CASE-INSIDER-001 — Privileged Account Activity Requiring Context

## Executive summary
A synthetic identity alert shows privileged authentication from an unusual source during a maintenance window. The timing provides a plausible legitimate explanation, but the responsible engineer, source device, authorisation, and endpoint activity are not verified.

## Timeline
| Time | Source | Observation | Confidence |
|---|---|---|---|
| T0 | Identity provider | Privileged account authenticated from an unusual source | High |
| T0 | Change management | Maintenance window overlaps the event | Medium |
| T0 | Endpoint telemetry | No post-authentication evidence supplied | Low / Unknown |

## Evidence matrix
| ID | Type | Relationship | Finding |
|---|---|---|---|
| E-201 | Observed | Neutral | Privileged authentication from an unusual baseline source |
| E-202 | Correlated | Challenges | Maintenance window overlaps the authentication timestamp |
| E-203 | Unknown | Neutral | Endpoint process evidence is absent |

## Competing hypotheses
1. Authorised maintenance by a privileged administrator.
2. Compromised privileged account.
3. Shared or proxy source obscuring the endpoint.
4. Misconfigured automation.
5. Potential insider activity requiring verification.

## Analyst assessment
**Insufficient Evidence — Low confidence.** The case contains a plausible change-related explanation and an anomalous authentication observation, but neither is sufficient to establish actor identity or malicious intent.

## Risk / escalation / response
- **Risk:** High provisional risk because privileged access can have significant organisational impact; compromise is not established.
- **Escalation:** Monitor pending evidence collection.
- **Response:** Investigate ownership, authorisation, change-ticket details, source-device identity, authentication history, and endpoint/post-authentication telemetry.

## Closure
Not ready. Ownership, authorisation, change context, endpoint activity, and account-compromise indicators remain unresolved.

## Lessons learned
- Privileged authentication anomalies require context before insider attribution.
- Change-ticket and endpoint evidence should be correlated before closure.

> Synthetic training case; no real insider activity is performed.
