# Security Policy

## Scope

SOC Toolkit is a defensive educational cybersecurity portfolio project. It uses synthetic logs, synthetic case packs and controlled investigation logic. It is not intended to process production credentials, customer data, private incident records or other sensitive operational information.

## Reporting a security issue

If you identify a security issue in the repository, please report it privately through GitHub's security reporting mechanism where available rather than publishing exploit details in a public issue.

Please include:

- affected file or component;
- reproducible steps or a minimal proof of concept;
- expected and observed behaviour;
- security impact;
- any relevant version or commit information.

Do not include real credentials, private logs, personal data or other sensitive information in a report.

## Project safety boundary

The project intentionally does not provide live exploitation, credential attacks, persistence, packet capture, target command execution or automated containment. Contributions should preserve this defensive and educational scope.

## Supported baseline

The `main` branch is the supported development baseline. Pull requests should include appropriate tests for behavioural changes and should not weaken evidence validation merely to make a test pass.
