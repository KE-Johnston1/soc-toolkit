# CASE-PHISH-001 — Suspected Executive Impersonation / Phishing

## Executive summary
A synthetic email alert indicates possible executive impersonation. Header and user-report evidence supports investigation, but sender compromise and user impact are not established.

## Timeline
| Time | Source | Observation | Confidence |
|---|---|---|---|
| T0 | Mail gateway | Urgent finance-themed message using an executive display name | High |
| T0 | Email headers | Reply-to identity differs from expected corporate domain | High |
| T+1 | User report | Recipient reported the message as suspicious | Medium |

## Evidence matrix
| ID | Type | Relationship | Finding |
|---|---|---|---|
| E-001 | Observed | Neutral | Executive display name and urgent payment-related request |
| E-002 | Observed | Supports | Reply-to identity differs from expected sender domain |
| E-003 | Observed | Supports | Recipient reported the message before completing the action |

## Competing hypotheses
1. Legitimate delegated external communication.
2. Executive impersonation / BEC attempt.
3. Compromised legitimate sender account.
4. Unknown mail-routing or identity anomaly.

## Analyst assessment
**Requires Investigation — Medium confidence.** The evidence supports validating sender identity and message provenance but does not prove impersonation or compromise.

## Risk / escalation / response
- **Risk:** Medium, based on potential financial/social-engineering impact; actual loss is not established.
- **Escalation:** SOC Investigation.
- **Response:** Preserve relevant message/header evidence and investigate sender identity, recipient interaction, authentication impact, and message disposition.

## Closure
Not ready. Sender identity, user interaction, authentication impact, and disposition require verification.

## Lessons learned
- Verify identity independently before classifying impersonation.
- Preserve headers and message metadata where policy permits.

> Synthetic training case; no real phishing activity is performed.
