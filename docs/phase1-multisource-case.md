# Phase 1: Multi-source investigation case

This phase starts the move from a single-log demonstration to a reproducible SOC case pack.

## Case pack

`cases/CASE-MULTI-001/` contains:

- `alert.json` — alert metadata and initial analyst framing
- `auth.log` — SSH authentication observations
- `firewall.log` — firewall observations
- `web.log` — web request observations

The logs are synthetic and intentionally use the same source IP so that cross-source correlation can be demonstrated without claiming attribution.

## Evidence flow

```text
Case pack
   ↓
Parser normalisation
   ↓
Structured LogEvent objects
   ↓
Cross-source correlation
   ↓
Temporal relationship + evidence sources
   ↓
Analyst assessment (later phase)
```

Correlation answers a narrow question: **does the same source appear across multiple evidence sources within the configured time window?**

It does not answer whether the source is malicious, whether an account was compromised, or whether an incident is confirmed.

## Current Phase 1 implementation

- Reproducible case directory
- Structured firewall event parser
- Structured web event parser
- Existing structured authentication parser reused
- Cross-source correlation by source IP
- Configurable temporal correlation window
- Unit tests proving all three evidence sources are loaded and correlated

## Deliberate limitations

The current correlation model uses source IP as the common relationship key. It should be treated as supporting evidence rather than attribution. NAT, shared infrastructure, proxies, and other legitimate causes can produce the same source IP.

The next Phase 1 step is to connect the case-pack loader and correlation result directly into the end-to-end case pipeline, followed by richer evidence objects and hypothesis tracking.
