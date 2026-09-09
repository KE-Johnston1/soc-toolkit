# Portfolio Demonstration — End-to-End Investigation

This walkthrough is designed to show how an entry-level analyst can move from a detection lead to an evidence-based assessment.

## Scenario
Use `CASE-NET-001` as the primary example. Synthetic firewall, DNS, and flow evidence shows repeated outbound communication to a rare external destination followed by a transfer.

## 1. Detection lead
`SOC-NET-001` identifies repeated outbound connections that warrant investigation.

**Important:** periodic traffic is not automatically C2.

## 2. Evidence collection
Review:
- firewall observations
- DNS context
- flow/transfer information
- endpoint process ownership
- approved application/change context

## 3. Competing hypotheses
1. Approved application telemetry.
2. Compromised endpoint communicating externally.
3. Potential C2 beaconing.
4. Potential unauthorised data transfer.
5. Unknown application behaviour.

## 4. Analyst assessment
The supplied synthetic case remains **Requires Investigation — Medium confidence** because destination ownership, process attribution, transfer purpose, and baseline context remain incomplete.

## 5. Response recommendation
Do not automatically block the destination from this evidence alone. Correlate endpoint ownership, destination reputation, transfer volume/type, approved application behaviour, and change context first. Escalate when corroborating evidence supports compromise or material impact.

## 6. Lessons learned
- A detection is an investigation lead, not a verdict.
- Multiple independent observations should increase confidence.
- Evidence gaps should be documented explicitly.
- Detection tuning should follow context review rather than simply lowering thresholds.

## What this demonstrates
- alert triage
- evidence handling
- competing hypotheses
- confidence-aware assessment
- risk and escalation thinking
- controlled response recommendations
- defensive limits and safe scope

> All evidence in this walkthrough is synthetic. No live network activity is performed.
