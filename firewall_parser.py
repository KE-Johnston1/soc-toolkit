import re

def parse_firewall_log():
    try:
        with open("logs/firewall.log", "r") as file:
            lines = file.readlines()
            pattern = r"Blocked connection from (\d+\.\d+\.\d+\.\d+) to port 22"
            matches = [re.search(pattern, line) for line in lines]
            blocked_ips = [match.group(1) for match in matches if match]

            if blocked_ips:
                print("[!] Firewall blocked SSH brute force attempts:")
                for ip in set(blocked_ips):
                    count = blocked_ips.count(ip)
                    print(f"    {ip} blocked {count} times")
            else:
                print("[✓] No SSH-related blocks detected")
    except FileNotFoundError:
        print("[!] firewall.log not found")

if __name__ == "__main__":
    parse_firewall_log()
