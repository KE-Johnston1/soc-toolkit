SOC Toolkit: Modular Threat Detection & Log Analysis
A hands-on cybersecurity toolkit built for clarity, modularity, and real-world scenarios. This CLI-powered tool parses logs, detects threats, correlates activity, and checks IP reputation designed to support entry level SOC workflows and showcase practical detection logic.

Why I Built This
I created this toolkit to sharpen my threat detection skills and build something I could confidently share with recruiters, peers, and learners alike. I wanted a project that reflects how I think: clear, modular, and scenario-driven. Every module is designed to be testable, readable, and grounded in real-world logic—because I believe cybersecurity should be accessible, transparent, and empowering.

Project Structure
soc-toolkit/
├── logs/           # Sample log files (auth, firewall, web)
├── output/         # Saved reports from each module
├── parsers/        # Modular detection scripts
├── main.py         # CLI controller with interactive mode
└── README.md       # Project overview and usage
How to Use

Run a Module via CLI

python main.py --module log
python main.py --module firewall
python main.py --module web
python main.py --module correlate
python main.py --module reputation

Or Use Interactive Mode
python main.py
Then select a module by number.

Modules Overview
Module	Description
log	Detects SSH brute force attempts from auth.log
firewall	Flags blocked SSH traffic in firewall.log
web	Detects suspicious /admin access in web.log
correlate	Cross-references IPs across all logs for multi-vector threats
reputation	Flags known bad IPs using mock threat intelligence

Output Saving
Each module can optionally save results to the output/ folder. Example:
python parsers/log_parser.py
# → output/log_report.txt created

Project Highlights
Regex-based detection for flexible log parsing

Modular CLI architecture with interactive mode

Realistic log samples and scenario-driven logic

Threat correlation and reputation analysis

Clean output formatting and optional report saving
