# Risk and Escalation Workflow

## Purpose

Risk and escalation are separate from detection and analyst assessment. The toolkit uses them to answer two different questions:

1. **Risk:** If the investigated activity matters to the organisation, how significant could the impact be?
2. **Escalation:** Who should review the case next, based on evidence and operational context?

Neither decision is a declaration that a compromise or incident has been confirmed.

## Risk context

The risk layer can record:

- asset criticality
- account privilege
- data sensitivity
- likelihood
- business impact
- financial impact
- financial value basis: Unknown, Observed, Derived, or Estimated
- possible legal/regulatory consideration
- CVE relevance
- CVSS severity
- confidence

Unknown values remain unknown. CVSS severity is vulnerability severity, not organisational risk and not evidence that exploitation occurred.

## Escalation levels

| Level | Purpose |
|---|---|
| `No Escalation` | Current evidence supports closure or routine handling. |
| `Monitor` | Context is incomplete and the safest next step is continued observation/evidence collection. |
| `SOC Investigation` | The alert remains unresolved and requires continued analyst investigation. |
| `Tier 2` | Escalation-relevant context warrants deeper security investigation. |
| `Incident Response` | Stronger independent security evidence supports specialist response review. |
| `Management/Legal/Privacy` | Business, sensitive-data, legal, privacy, or compliance considerations may require stakeholder referral. |

Severity alone does not determine escalation.

## Escalation triggers

Examples include:

- privileged account involvement
- multiple affected accounts
- established malicious-infrastructure evidence
- malware or persistence evidence
- command-and-control evidence
- potential exfiltration evidence
- sensitive data involvement
- recurring related alerts
- unsafe or specialist containment requirements
- possible legal/privacy implications

A trigger is a reason to review or escalate. It is not, by itself, proof of malicious intent.

## Example

A repeated authentication detection involving a privileged account can remain `Requires Investigation` while ownership, authorisation, post-authentication activity, and change context are verified. The escalation engine may recommend `Tier 2` because the account privilege increases the need for deeper review. That recommendation does not establish account compromise.

If independent endpoint evidence establishes malware or persistence, the recommendation can move to `Incident Response`.

If sensitive data or possible regulatory implications are identified, the case can be referred to `Management/Legal/Privacy`. This is a referral recommendation, not legal advice or a confirmed breach determination.
