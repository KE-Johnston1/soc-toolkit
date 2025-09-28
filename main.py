import subprocess

def run_module():
    print("[+] Running correlate_logs.py...")
    subprocess.run(["python", "parsers/correlate_logs.py"])

if __name__ == "__main__":
    run_module()

