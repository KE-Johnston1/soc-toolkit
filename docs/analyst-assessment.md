# Analyst Assessment Workflow

## Purpose

The assessment layer sits after detection and correlation. Its purpose is to answer:

> What does the available evidence support right now, and what still needs to be verified?

It does not convert a detection into a compromise verdict automatically.

## Assessment states

| State | Meaning |
|---|---|
| `Expected` | Relevant context and evidence checks are complete and support authorised expected activity. |
| `Requires Investigation` | The detection remains relevant, but contextual checks or corroborating evidence are incomplete, or evidence conflicts. |
| `Insufficient Evidence` | Key identity, ownership, or authorisation facts are not established. |
| `Security Concern` | Reserved for a later stage when independent evidence supports a stronger security conclusion. The current input model does not manufacture this state. |

## Evidence model

Each `EvidenceItem` records:

- `source` — where the observation came from
- `observation` — what was actually observed
- `confidence` — Low, Medium, or High
- `relationship` — direct, corroborating, or contradicting
- `notes` — optional analyst context

This keeps observed facts separate from inference.

## Context checks

The current assessment input can explicitly represent whether the analyst has verified:

1. asset or account ownership
2. authorisation
3. expected activity or baseline
4. exact timing against expected use
5. network evidence
6. endpoint/post-event evidence
7. maintenance, deployment, change, or security-testing context
8. privileged post-authentication activity
9. contradictory evidence

A missing check becomes an evidence gap. It is not silently treated as negative evidence.

## Example reasoning

A repeated SSH-authentication detection may be genuine and still remain `Insufficient Evidence` if ownership and authorisation are unknown. If ownership and authorisation are verified but change context or endpoint review is incomplete, the case remains `Requires Investigation`.

If all relevant checks are complete and support approved administration, the assessment can become `Expected` and recommend closure if the applicable playbook permits.

If evidence conflicts, the case remains `Requires Investigation` until the contradiction is resolved.

## What this layer does not claim

- repeated failures do not automatically prove brute force
- a successful login does not automatically prove account compromise
- a suspicious IP does not automatically identify an attacker
- severity does not by itself determine escalation
- missing context does not prove that activity was unauthorised

The next planned layer is a separate escalation/risk decision so that assessment, risk, and response remain distinct and testable.
