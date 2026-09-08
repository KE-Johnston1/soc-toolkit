# End-to-End SOC Case Walkthrough

The pipeline composes the toolkit's decision layers around a dedicated synthetic SSH authentication fixture.

## Analyst path

`Log input → Detection signal → Evidence correlation → Assessment → Risk → Escalation → Response → Case lifecycle → Closure`

For `CASE-SSH-001`, five SSH authentication failures from the same source/account occur within a verified five-minute window, creating a detection signal. Ownership and authorization are intentionally incomplete, so the analyst assessment remains `Insufficient Evidence`. Risk context can describe potential organisational exposure, but it does not establish compromise. The escalation layer therefore recommends monitoring rather than automatic incident declaration, and the response layer recommends investigation.

The case lifecycle records the move to `Investigating` and preserves the rationale in a decision trail. Closure is not ready while evidence gaps remain.

## Stronger evidence path

A second synthetic test supplies complete contextual verification plus explicit stronger security evidence, Incident Response escalation, and authorised safe containment conditions. The assessment remains evidence-aware rather than being converted into a generic "confirmed compromise" label. The response layer selects `Contain` only when the escalation context and both authorization and safety conditions are present.

## Analyst principles

- Detection is a signal, not a compromise verdict.
- Missing ownership, authorization, timing, network, endpoint, or change context is an evidence gap.
- Strong security evidence must be represented explicitly rather than inferred from severity.
- CVSS severity and organisational risk are separate concepts.
- Severity alone does not determine escalation.
- Financial impact is not presented with false precision.
- Legal/privacy fields are referral indicators, not legal conclusions.
- Disruptive response requires explicit authorization and safety validation.
- Closure requires an `Expected` assessment, no remaining evidence gaps, and a documented rationale.

## Scope

All data used by this demonstration is synthetic or repository sample data. The pipeline performs no live log collection, scanning, exploitation, credential attacks, packet capture, or automated containment.
