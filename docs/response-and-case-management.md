# Response and Case Management

Response is deliberately separated from detection, assessment, risk, and escalation.

## Response actions

The response layer can recommend:

- `Monitor` — no disruptive response condition is established.
- `Investigate` — collect missing evidence and reassess.
- `Escalate` — route an unresolved case to the recommended specialist level.
- `Contain` — only when containment is explicitly authorised and assessed as safe.
- `Remediate` — perform an authorised corrective action.
- `Recover` — proceed when documented recovery conditions are ready.
- `Close` — only after closure criteria, evidence, and rationale are complete.

A detection signal alone never authorises containment.

## Case lifecycle

`Open → Investigating → Escalated → Contained → Remediation → Recovery → Closed`

The implementation permits only defined transitions rather than arbitrary status changes. A case cannot be closed unless the analyst assessment is `Expected`, evidence gaps are cleared, and a closure rationale is documented.

## Analyst decision trail

Each transition records:

- timestamp
- stage
- action
- actor role
- observation
- rationale
- confidence
- evidence source

This makes the case lifecycle auditable and keeps the reasoning visible rather than reducing the workflow to a final status label.

## Safety and uncertainty

`Insufficient Evidence` results in investigation, not automatic containment or closure. `Requires Investigation` remains unresolved until supporting context is collected. Incident-response escalation can recommend containment only when authorisation and safe execution are both explicit.

The toolkit is a defensive educational project using synthetic/sample data. It does not perform live scanning, exploitation, credential attacks, packet capture, or automated response.
