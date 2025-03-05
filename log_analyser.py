import re
from collections import defaultdict

# Path to the authentication log file
LOG_FILE = "/var/log/auth.log"  # Change this path if needed
THRESHOLD = 5  # Number of failed attempts to trigger an alert

def parse_log(file_path):
    """ Reads auth.log and extracts failed login attempts with IP addresses. """
    failed_attempts = defaultdict(int)
    ip_pattern = re.compile(r"Failed password for .* from (\d+\.\d+\.\d+\.\d+)")

    try:
        with open(file_path, "r") as log_file:
            for line in log_file:
                match = ip_pattern.search(line)
                if match:
                    ip = match.group(1)
                    failed_attempts[ip] += 1
        return failed_attempts
    except FileNotFoundError:
        print(f"Error: Log file {file_path} not found.")
        return {}

def detect_brute_force(failed_attempts, threshold):
    """ Detects IPs with failed attempts exceeding the threshold. """
    suspicious_ips = {ip: count for ip, count in failed_attempts.items() if count >= threshold}
    return suspicious_ips

if __name__ == "__main__":
    print("[*] Scanning authentication logs...")
    
    failed_logins = parse_log(LOG_FILE)
    
    if not failed_logins:
        print("[!] No failed login attempts found.")
    else:
        print(f"[*] Found {len(failed_logins)} unique IPs with failed attempts.")

        suspicious_ips = detect_brute_force(failed_logins, THRESHOLD)
        
        if suspicious_ips:
            print("\n[ALERT] Possible Brute Force Attack Detected!")
            for ip, count in suspicious_ips.items():
                print(f" -> {ip} attempted {count} times!")
        else:
            print("[*] No suspicious activity detected.")
