import re

def parse_auth_log(save=False):
    output = []
    try:
        with open("logs/auth.log", "r") as file:
            lines = file.readlines()
            pattern = r"Failed password.*from (\d+\.\d+\.\d+\.\d+)"
            matches = [re.search(pattern, line) for line in lines]
            failed_ips = [match.group(1) for match in matches if match]

            if failed_ips:
                output.append("[!] SSH brute force pattern detected:")
                for ip in set(failed_ips):
                    count = failed_ips.count(ip)
                    output.append(f"    {ip} failed login {count} times")
            else:
                output.append("[✓] No brute force activity detected")
    except FileNotFoundError:
        output.append("[!] auth.log not found")

    for line in output:
        print(line)

    if save:
        with open("output/log_report.txt", "w") as f:
            for line in output:
                f.write(line + "\n")

if __name__ == "__main__":
    parse_auth_log(save=True)
