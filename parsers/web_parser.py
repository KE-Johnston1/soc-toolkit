import re

def parse_web_log():
    try:
        with open("logs/web.log", "r") as file:
            lines = file.readlines()
            pattern = r"GET /admin from (\d+\.\d+\.\d+\.\d+)"
            matches = [re.search(pattern, line) for line in lines]
            suspicious_ips = [match.group(1) for match in matches if match]

            if suspicious_ips:
                print("[!] Suspicious access to /admin detected:")
                for ip in set(suspicious_ips):
                    count = suspicious_ips.count(ip)
                    print(f"    {ip} accessed /admin {count} times")
            else:
                print("[✓] No suspicious web activity detected")
    except FileNotFoundError:
        print("[!] web.log not found")

if __name__ == "__main__":
    parse_web_log()
