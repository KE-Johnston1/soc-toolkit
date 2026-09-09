# Phase 2: Investigation Risk Context

This increment adds structured investigation context around four areas that are often confused with security conclusions: vulnerability relevance, business/financial impact, legal/privacy considerations, and attribution.

## Vulnerability context

`VulnerabilityContext` records product, version, CVE identifier, applicability, CVSS severity, and whether exploitation evidence exists.

The model deliberately distinguishes:

- CVSS severity from organisational risk
- vulnerability applicability from exploitation
- a CVE reference from proof that the affected product/version exists
- exploitation evidence from a vulnerability being present

A case can therefore be `Potentially Relevant - Exploitation Not Established` without claiming exploitation.

## Business and financial impact

`ImpactContext` records operational impact, business impact, data sensitivity, and financial impact. A financial value is optional, but if supplied it must have an explicit basis: `Observed`, `Derived`, or `Estimated`.

This prevents a precise-looking monetary figure from being presented as fact when it is only an estimate.

## Legal and privacy context

`LegalPrivacyContext` records whether a legal/privacy consideration exists, what data category or jurisdiction may be relevant, whether the evidence is established, and whether referral is required.

These fields are workflow controls only. They do not determine that a breach occurred and do not provide legal advice.

## Attribution

`AttributionContext` separates a source IP from an individual or organisation. It records whether identity has been verified and whether NAT, proxying, shared infrastructure, or other source ambiguity is possible.

A network source can therefore support investigation without being treated as proof of actor identity.

## Pipeline integration

The end-to-end pipeline exposes `InvestigationContext`, vulnerability relevance, and vulnerability evidence gaps in its case summary. Vulnerability context is also passed into the existing risk model without replacing the existing assessment controls.

## Analyst safeguards

The model keeps the following boundaries explicit:

- suspicious activity is not automatically malicious activity
- a CVE is not proof of exploitation
- CVSS is not organisational risk
- potential impact is not observed impact
- an estimated cost is not an observed loss
- a source IP is not necessarily an individual actor
- legal/privacy consideration is not a confirmed breach

The next Phase 2 increment can use these context objects for scenario-specific investigations such as C2, exfiltration, phishing, impersonation, insider threat, and AI-assisted social engineering while retaining the same evidence-first controls.
