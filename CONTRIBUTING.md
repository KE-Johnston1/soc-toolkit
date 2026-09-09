# Contributing

## Development approach

SOC Toolkit is an evidence-first defensive training project. Contributions should improve reproducibility, analyst reasoning, maintainability or validation without turning detections into unsupported conclusions.

## Before opening a pull request

Run:

```bash
python -m unittest discover -s tests -v
```

For scenario or quality changes, also run the relevant CLI module locally where practical.

## Evidence and detection rules

- A detection is an investigation lead, not proof of compromise.
- Preserve distinctions between observed, correlated, inferred, hypothesis and unknown information.
- Do not invent timestamps, attribution, authorization, business impact or financial precision.
- Do not weaken validation or tests simply to make CI pass; correct stale fixtures or implementation defects instead.
- Synthetic data should remain reproducible and clearly separated from real-world sensitive information.

## Pull requests

Explain the behavioural change, tests added or updated, evidence assumptions, and any remaining limitations. Security-sensitive changes should also be reviewed against `SECURITY.md`.
