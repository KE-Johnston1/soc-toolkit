# Phase 2: Evidence Context and Provenance

Phase 2 extends the Phase 1 investigation workflow by making evidence provenance explicit. The goal is to help an analyst distinguish what was directly observed from what was correlated, inferred, proposed as a hypothesis, or still unknown.

## Evidence levels

| Level | Meaning |
| --- | --- |
| `observed` | Directly represented by a parsed evidence source. |
| `correlated` | A relationship identified between multiple observations. |
| `inferred` | An analyst inference derived from available evidence. |
| `hypothesis` | A possible explanation that remains subject to testing. |
| `unknown` | A material fact that has not been established. |

Evidence level is separate from confidence. A high-confidence observation is still an observation; it does not become proof of intent or compromise.

## Case implementation

`CASE-MULTI-001` now exposes typed evidence records through the end-to-end pipeline. Parsed authentication, firewall, and web events are represented as `observed` records. Cross-source relationships are represented separately as `correlated` records.

Each record can preserve:

- evidence identifier
- evidence source
- observation text
- evidence provenance level
- confidence
- relationship to an investigation question
- timestamp when the source provides one
- affected asset and account when available
- analyst notes

The pipeline also returns an `EvidenceSummary` so the analyst can see how much evidence is direct versus derived and whether timestamps are represented.

## Analyst safeguards

- Correlation is not attribution.
- Inference is not observation.
- A hypothesis is not an established fact.
- Unknown information remains visible instead of being guessed.
- CVSS severity remains distinct from organisational risk.
- Legal/privacy indicators remain referral points rather than legal conclusions.

## Phase 2 boundary

This increment establishes the evidence vocabulary and provenance layer. Later Phase 2 work can attach explicit evidence relationships to CVE/CVSS review, business impact, attribution, command-and-control, exfiltration, social engineering, impersonation, insider-threat, and AI-related investigations without changing the evidence-first decision model.
