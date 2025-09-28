import re

# Hardcoded list of known bad IPs (mock threat intel)
known_bad_ips = {
    "192.168.1.101": "SSH brute force",
    "203.0.113.45": "Firewall evasion",
    "198.51.100.23": "Reconnaissance"
}

def extract_ips(filename, pattern):
    try:
        with open(filename, "r") as file:
            lines = file.readlines()
            matches = [re.search(pattern, line) for line in lines]
            return [match.group(1) for match in matches if match]
    except FileNotFoundError:
        print(f"[!] {filename} not found")
        return []

def check_ip_reputation():
    print("[+] Checking IP reputation across logs...")
    auth_ips = extract_ips("logs/auth.log", r"Failed password.*from (\d+\.\d+\.\d+\.\d+)")
    firewall_ips = extract_ips("logs/firewall.log", r"Blocked connection from (\d+\.\d+\.\d+\.\d+)")
    web_ips = extract_ips("logs/web.log", r"GET /admin from (\d+\.\d+\.\d+\.\d+)")

    all_ips = set(auth_ips + firewall_ips + web_ips)

    for ip in all_ips:
        if ip in known_bad_ips:
            print(f"[⚠] {ip} flagged: {known_bad_ips[ip]}")
        else:
            print(f"[✓] {ip} not found in threat intel")

    print("[✓] Reputation check complete")

if __name__ == "__main__":
    check_ip_reputation()
