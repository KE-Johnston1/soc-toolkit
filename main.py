import argparse

def run_module(module):
    if module == "log":
        from parsers import log_parser
        log_parser.parse_auth_log()

    elif module == "firewall":
        from parsers import firewall_parser
        firewall_parser.parse_firewall_log()

    elif module == "web":
        from parsers import web_parser
        web_parser.parse_web_log()

    elif module == "correlate":
        from parsers import correlate_logs
        correlate_logs.correlate_logs()

    elif module == "reputation":
        from parsers import ip_reputation
        ip_reputation.check_ip_reputation()

    else:
        print("[!] Invalid module name")
        print("    Use: log, firewall, web, correlate, reputation")

def main():
    parser = argparse.ArgumentParser(description="SOC Toolkit CLI")
    parser.add_argument("--module", type=str, help="Module to run: log, firewall, web, correlate, reputation")
    args = parser.parse_args()

    if args.module:
        run_module(args.module)
    else:
        print("Select a module to run:")
        print("  1. log")
        print("  2. firewall")
        print("  3. web")
        print("  4. correlate")
        print("  5. reputation")
        choice = input("Enter number (1–5): ").strip()

        options = {
            "1": "log",
            "2": "firewall",
            "3": "web",
            "4": "correlate",
            "5": "reputation"
        }

        selected = options.get(choice)
        if selected:
            run_module(selected)
        else:
            print("[!] Invalid selection")

if __name__ == "__main__":
    main()


