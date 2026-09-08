# Phase 1 Completion Checklist

Phase 1 is complete when the reproducible multi-source case demonstrates the following chain:

- [x] Alert metadata is stored separately from evidence.
- [x] Authentication, firewall, and web evidence are normalised into structured events.
- [x] Repeated authentication failures produce a detection signal without a compromise verdict.
- [x] Cross-source correlation records evidence-source relationships and temporal correlation.
- [x] Competing hypotheses are explicit and separate from analyst assessment.
- [x] Supporting evidence is not treated as proof.
- [x] Missing ownership, authorization, timing, endpoint, change/testing, and post-authentication context remains visible to the assessment layer.
- [x] Risk and escalation remain separate from compromise confirmation.
- [x] Response decisions require appropriate authorization and safety checks for disruptive actions.
- [x] Case lifecycle records an auditable decision trail.
- [x] Tests cover the integrated multi-source case and hypothesis layer.
- [x] The multi-source fixture contains enough authentication-failure evidence to exercise the configured detection threshold.

The next phase should add richer evidence modelling and investigation context rather than bypassing these controls with more aggressive detection claims.
