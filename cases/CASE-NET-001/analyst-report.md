# CASE-NET-001 — Periodic Outbound Traffic and Potential Data Transfer

## Executive summary
Synthetic firewall, DNS, and flow evidence shows repeated outbound communication to a rare external destination followed by a transfer. This warrants Tier 2 investigation, but the evidence does not prove C2 or exfiltration.

## Timeline
| Time | Source | Observation | Confidence |
|---|---|---|---|
| T0..T+N | Firewall | Repeated outbound connections at regular intervals | High |
| T0..T+N | DNS | Destination is outside the synthetic allow-list | Medium |
| T+N | Flow summary | Transfer follows the connection pattern; data type is unknown | Medium |

## Evidence matrix
| ID | Type | Relationship | Finding |
|---|---|---|---|
| E-101 | Observed | Neutral | Periodic outbound connections to rare destination |
| E-102 | Correlated | Supports | Destination is not in synthetic allow-list |
| E-103 | Observed | Supports | Transfer follows connection pattern, data type unknown |

## Competing hypotheses
1. Approved application telemetry.
2. Compromised endpoint communicating externally.
3. Potential C2 beaconing.
4. Potential unauthorised data transfer.
5. Unknown application behaviour.

## Analyst assessment
**Requires Investigation — Medium confidence.** Correlated network behaviour raises a security question, but attribution, process ownership, data type, authorisation, and baseline remain incomplete.

## Risk / escalation / response
- **Risk:** High provisional organisational risk because a potentially sensitive outbound transfer could have material impact; actual impact is unknown.
- **Escalation:** Tier 2.
- **Response:** Correlate endpoint process/network ownership, destination reputation, transfer volume/type, approved application behaviour, and change context.

## Closure
Not ready. Destination ownership, process attribution, transfer purpose, volume baseline, and data classification require validation.

## Lessons learned
- Periodic traffic is a C2 investigation signal, not proof of C2.
- Transfer volume alone cannot establish exfiltration.

> Synthetic training case; no live network activity is performed.
