# SOC Toolkit Repository Audit

**Audit status:** Initial structural and code audit  
**Repository:** `KE-Johnston1/soc-toolkit`  
**Branch:** `main`  
**Audit date:** 2026-09-07

## Executive Summary

The repository is currently a small Python proof-of-concept rather than an employment-ready SOC toolkit. It contains useful starting ideas—authentication-log parsing, firewall parsing, web-log parsing, cross-log IP correlation, and a mock IP reputation list—but has significant quality, correctness, maintainability, and security-engineering gaps.

The existing implementation should be treated as a refactor-and-validation project before additional SOC capabilities are added.

## Findings

### High priority

1. **No automated test suite is present.** No visible `tests/` directory or CI workflow exists, so detection behaviour is not regression-tested.
2. **Generated Python bytecode is committed.** `parsers/__pycache__/ip_reputation.cpython-312.pyc` should not be version-controlled.
3. **The project structure is inconsistent.** `main.py` imports modules from `parsers/`, while duplicate empty root-level `log_parser.py` and `web_parser.py` files also exist.
4. **Detection logic is overly simplistic.** The authentication parser labels matching failed-password entries as an SSH brute-force pattern without a configurable time window, threshold policy, source context, account context, or analyst-confidence model.
5. **Parser input paths are hard-coded.** Parsers read fixed paths such as `logs/auth.log`, limiting reuse and making isolated testing harder.

### Medium priority

6. **Parsers print results directly instead of returning structured data.** This makes correlation, testing, reporting, and reuse harder.
7. **Error handling is narrow.** Missing files are handled, but malformed input, permissions, encoding, and unexpected parsing failures are not clearly handled.
8. **IP extraction uses regular expressions without explicit IP validation.** A matching string is not necessarily a valid IPv4 address.
9. **Correlation is based mainly on IP presence.** It does not correlate exact timestamps, users, event types, ports, direction, or other context.
10. **Firewall detection is too broad.** The firewall parser treats any line containing `port 22` as an SSH-related block.
11. **Mock threat intelligence is presented too definitively.** The IP reputation module should clearly identify local training data and should never imply that an IP absent from the list is benign.
12. **README maturity exceeds the current implementation.** The documentation does not adequately describe limitations, data structures, testing, or analyst-confidence boundaries.

### Cleanup

13. Remove or clearly justify empty duplicate root-level modules.
14. Review committed generated `output/log_report.txt`; generated reports should normally be reproducible rather than source data.
15. Establish a clear Python package/module layout and consistent imports.
16. Refresh the MIT licence copyright year to 2026.
17. Add a project-specific `.gitignore`.

## Security / Analyst Design Assessment

The strongest direction is to evolve this into a defensive analyst-support toolkit rather than a collection of simplistic pattern-matching scripts.

Future outputs should distinguish:

- **Observed:** directly present in supplied evidence.
- **Correlated:** supported by multiple independent records.
- **Inferred:** reasonable interpretation of observed evidence.
- **Hypothesis:** possible explanation requiring validation.
- **Unknown:** evidence is insufficient to determine the answer.

A detection should not automatically equal compromise, malicious activity, or incident confirmation.

## Recommended Target Workflow

`Input → Normalisation → Detection → Correlation → Evidence/Context → Analyst Assessment → Recommended Action → Report`

Engineering goals:

- structured parser results
- explicit input paths
- deterministic functions suitable for unit testing
- validated timestamps/IPs/ports where applicable
- configurable detection thresholds
- evidence confidence
- false-positive handling
- separation between detection and analyst assessment
- reproducible synthetic data
- safe, explicit CLI arguments
- automated tests
- CI
- CodeQL
- dependency/update hygiene
- security policy and contribution guidance

## Audit Conclusion

**Current state: functional proof-of-concept, not employment-ready.**

The existing code is salvageable. The next implementation stage should establish repository hygiene and automated quality controls, then refactor and test the core parsers before adding advanced SOC functionality.
