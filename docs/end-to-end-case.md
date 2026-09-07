# End-to-End SOC Case Walkthrough

The pipeline composes the toolkit's existing decision layers around a synthetic SSH authentication scenario.

## Analyst path

`Log input → Detection signal → Evidence correlation → Assessment → Risk → Escalation → Response → Case lifecycle → Closure`

For `CASE-SSH-001`, repeated SSH failures create a detection signal. Ownership and authorization are intentionally incomplete, so the analyst assessment remains `Insufficient Evidence`. Risk context can still describe potential organisational exposure, but it does not establish compromise. The escalation layer therefore recommends monitoring rather than automatic incident declaration, and the response layer recommends investigation.

The case lifecycle records the move to `Investigating` and preserves the rationale in a decision trail. Closure is not ready while evidence gaps remain.

## Stronger evidence path

The pipeline can also be supplied with stronger synthetic evidence, such as malware evidence plus an Incident Response escalation and explicit safe containment authorization. This demonstrates the control boundary between **recommendation** and **action**: the toolkit only selects `Contain` when the response layer receives both authorization and a safe execution condition.

## Analyst principles

- Detection is a signal, not a compromise verdict.
- Missing ownership, authorization, timing, network, endpoint, or change context is an evidence gap.
- CVSS severity and organisational risk are separate concepts.
- Severity alone does not determine escalation.
- Financial impact is not presented with false precision.
- Legal/privacy fields are referral indicators, not legal conclusions.
- Disruptive response requires explicit authorization and safety validation.
- Closure requires an `Expected` assessment, no remaining evidence gaps, and a documented rationale.

## Scope

All data used by this demonstration is synthetic or repository sample data. The pipeline performs no live log collection, scanning, exploitation, credential attacks, packet capture, or automated containment.
