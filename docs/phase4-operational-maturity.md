# Phase 4 — Operational SOC Maturity

Phase 4 strengthens the toolkit as an analyst-support project rather than adding offensive capability.

## Controls

### Detection quality and tuning

`SOC Toolkit` can evaluate labelled synthetic detection checks as true/false positive and true/false negative outcomes. Precision and recall are reported when denominators exist. Tuning notes direct the analyst to inspect context, scope and telemetry before changing a threshold.

These metrics describe the supplied synthetic checks only; they are not production detection-performance claims.

### Scenario validation

Every scenario pack can be structurally checked for required assessment, risk, escalation, response, evidence and hypothesis fields. Validation is a data-quality control, not proof that the scenario conclusion is correct.

### Case metrics

Case collections can be summarised by assessment, escalation and response, with counts for closure-ready and unresolved cases. Metrics are descriptive and should not be used as unsupported SOC performance KPIs.

### Analyst quality

The project preserves the distinctions between observed evidence, correlation, inference, hypotheses and unknowns. A scenario label does not establish compromise, attribution, insider activity, C2, exfiltration, legal breach or financial loss.

## Audit disposition

The Phase 4 baseline audit identified documentation drift in `AUDIT.md` and the need for explicit operational-quality controls. The audit was updated to the current main baseline, stale Phase 3 wording was retained only as historical context, and the new quality/validation controls were added with regression tests.

Legacy parser modules remain intentionally supported because the CLI still exposes their entry points. They are not used as the basis for Phase 3 scenario conclusions.

## Safety

All examples remain synthetic and defensive. No live scanning, credential attacks, exploitation, packet capture, real-world phishing/impersonation, target command execution or automated containment is introduced.
