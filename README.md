# SOC Toolkit

A hands-on cybersecurity toolkit for threat detection and log analysis, built for clarity, modularity, and real-world scenarios.

## Overview

This project includes:

- Log parsing and anomaly detection  
- Signature matching for known attacker behaviours  
- CLI wrappers for modular execution  
- Sample outputs and documentation for educational and portfolio use

## Modules

| Component            | Description                                      |
|----------------------|--------------------------------------------------|
| `log_parser.py`      | Parses logs and extracts relevant entries        |
| `anomaly_detector.py`| Flags unusual activity based on frequency        |
| `signature_matcher.py`| Matches patterns against known attacker tools  |
| `cli_wrapper.py`     | Unified command-line interface                   |
| `samples/`           | Sample logs and visual outputs                   |

## Usage

Run the CLI wrapper:
python cli_wrapper.py

Optional flags:
- `--parse` → Run log parser  
- `--detect` → Run anomaly detector  
- `--match` → Run signature matcher  
- `--save` → Save output to file

## Status

Actively maintained. Additional modules and case studies in development.

## Ethical Notice

This toolkit is intended for educational and defensive purposes only.  
It must not be used to monitor or interfere with systems without explicit permission.

## Author

Created by [Karen Johnston](https://github.com/KE-Johnston1) — entry-level cybersecurity analyst focused on ethical detection tooling and modular documentation.
