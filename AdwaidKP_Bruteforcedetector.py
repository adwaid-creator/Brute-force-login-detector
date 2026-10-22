import csv
import random
from collections import defaultdict
from datetime import datetime, timedelta

LOG_FILE = "login_logs.csv"
MAX_FAILS = 5          # failed attempts allowed...
WINDOW_SECONDS = 60    # ...within this many seconds
FMT = "%Y-%m-%d %H:%M:%S"


def generate_sample_logs(filename=LOG_FILE):
    """Create a sample log with normal users and one attacker."""
    random.seed(42)  # same output every run
    start = datetime(2026, 10, 23, 10, 0, 0)
    users = ["admin", "alice", "bob", "carol"]
    normal_ips = ["192.168.1.10", "192.168.1.11", "10.0.0.5"]
    rows = []

    for _ in range(30):  # normal activity
        t = start + timedelta(seconds=random.randint(0, 600))
        status = random.choice(["SUCCESS", "SUCCESS", "SUCCESS", "FAILED"])
        rows.append([t.strftime(FMT), random.choice(normal_ips),
                     random.choice(users), status])

    attacker = "203.0.113.45"  # brute-force attacker
    for i in range(12):
        t = start + timedelta(seconds=120 + i * 3)
        rows.append([t.strftime(FMT), attacker, "admin", "FAILED"])
    t = start + timedelta(seconds=170)
    rows.append([t.strftime(FMT), attacker, "admin", "SUCCESS"])

    rows.sort()
    with open(filename, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["timestamp", "ip", "username", "status"])
        writer.writerows(rows)


def load_logs(filename=LOG_FILE):
    with open(filename, newline="") as f:
        return list(csv.DictReader(f))


def detect_bruteforce(logs):
    fails = defaultdict(list)
    successes = defaultdict(list)
    for row in logs:
        t = datetime.strptime(row["timestamp"], FMT)
        if row["status"] == "FAILED":
            fails[row["ip"]].append(t)
        else:
            successes[row["ip"]].append(t)

    alerts = []
    for ip, times in fails.items():
        times.sort()
        for i in range(len(times)):
            window = [t for t in times[i:]
                      if (t - times[i]).total_seconds() <= WINDOW_SECONDS]
            if len(window) >= MAX_FAILS:
                compromised = any(s > window[-1] for s in successes.get(ip, []))
                alerts.append({"ip": ip, "failed_attempts": len(times),
                               "first_fail": times[0],
                               "possible_compromise": compromised})
                break
    return alerts


def main():
    generate_sample_logs()
    logs = load_logs()
    alerts = detect_bruteforce(logs)

    print("=" * 50)
    print(" BRUTE-FORCE LOGIN ATTEMPT DETECTOR")
    print("=" * 50)
    print(f"Total log entries analysed: {len(logs)}")
    print(f"Rule: {MAX_FAILS}+ failed logins within {WINDOW_SECONDS} seconds\n")

    if not alerts:
        print("No suspicious activity detected.")
    for a in alerts:
        print(f"[ALERT] IP {a['ip']}")
        print(f"   Failed attempts : {a['failed_attempts']}")
        print(f"   First failure   : {a['first_fail']}")
        if a["possible_compromise"]:
            print("   WARNING: successful login after failures. "
                  "Account may be compromised!")
        print()


if __name__ == "__main__":
    main()