def parse_firewall_log():
    try:
        with open("logs/firewall.log", "r") as file:
            lines = file.readlines()
            blocked_ssh = [line for line in lines if "port 22" in line]
            if blocked_ssh:
                print("[!] Firewall blocked SSH brute force attempts:")
                for line in blocked_ssh:
                    print("    " + line.strip())
            else:
                print("[✓] No SSH-related blocks detected")
    except FileNotFoundError:
        print("[!] firewall.log not found")

if __name__ == "__main__":
    parse_firewall_log()

