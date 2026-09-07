# Risk and Escalation Workflow

Risk and escalation are separate from detection and analyst assessment.

## Risk context

The risk layer records asset criticality, account privilege, data sensitivity, likelihood, business impact, financial impact, financial-value basis, possible legal/regulatory consideration, CVE relevance, CVSS severity, and confidence.

Unknown values remain unknown. Financial values are labelled `Observed`, `Derived`, `Estimated`, or `Unknown`. CVSS describes vulnerability severity; it does not prove exploitation or automatically determine organisational risk.

Risk is organisational context, not a compromise verdict.

## Escalation levels

| Level | Purpose |
|---|---|
| `No Escalation` | Evidence supports routine handling or closure. |
| `Monitor` | Context remains incomplete and evidence collection continues. |
| `SOC Investigation` | The alert remains unresolved and needs analyst investigation. |
| `Tier 2` | Escalation-relevant context warrants deeper security investigation. |
| `Incident Response` | Stronger independent security evidence supports specialist response review. |
| `Management/Legal/Privacy` | Business, sensitive-data, legal, privacy, or compliance considerations may require stakeholder referral. |

Severity alone does not determine escalation.

## Example triggers

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

A trigger is a reason to review or escalate, not proof of malicious intent.

## Example reasoning

A repeated authentication detection involving a privileged account can remain `Requires Investigation` while ownership, authorisation, post-authentication activity, and change context are verified. The escalation engine may recommend `Tier 2` because account privilege increases the need for deeper review. That recommendation does not establish compromise.

If independent evidence establishes malware or persistence, `Incident Response` review may be appropriate. If sensitive data or possible regulatory implications are identified, `Management/Legal/Privacy` referral may be appropriate. These are workflow recommendations, not legal advice or breach determinations.
