# End-to-End SOC Case Walkthrough

The pipeline demonstrates a synthetic SSH authentication alert moving through the toolkit's decision layers.

## Case

`CASE-SSH-001` is built from the repository's sample authentication log. The detection layer looks for repeated SSH authentication failures within its configured threshold and time window.

The case is deliberately configured with incomplete ownership, authorization, timing, network, endpoint, and change/testing verification.

## Analyst path

1. **Detection** — repeated SSH failures create a detection signal.
2. **Assessment** — incomplete ownership and authorization keep the assessment at `Insufficient Evidence`.
3. **Risk** — asset criticality, privileged-account context, likelihood, and business impact can describe potential organisational exposure without asserting compromise.
4. **Escalation** — insufficient evidence is routed to `Monitor` rather than being treated as an incident automatically.
5. **Response** — the response recommendation is `Investigate` because disruptive action is not justified by the available evidence.
6. **Case management** — the case moves to `Investigating` and records the decision rationale in its trail.
7. **Closure** — closure is not ready while evidence gaps remain.

## Why this matters

The pipeline is intentionally conservative. A high-severity alert, privileged account, or repeated authentication pattern can justify deeper investigation, but those indicators do not independently establish attribution, compromise, malicious intent, or business impact.

A stronger synthetic evidence set can be supplied to exercise specialist escalation and authorised containment paths. Containment remains gated by explicit authorization and a safe execution condition.

## Scope

All data used by this demonstration is synthetic or repository sample data. The pipeline performs no live log collection, scanning, exploitation, credential attacks, or automated containment.
