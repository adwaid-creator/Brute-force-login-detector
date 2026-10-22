# Brute-Force Login Attempt Detector

A simple cybersecurity project in Python that analyses login logs and detects brute-force attacks.

## Overview
A brute-force attack is when an attacker tries many passwords on an account until one works. This tool reads a log of login attempts, finds IP addresses with too many failed logins in a short time, and raises an alert. It also warns when a successful login follows the failures, which means the account may be compromised.

## Features
- Generates a sample login log (`login_logs.csv`) with normal users and one attacker
- Detects IPs with **5 or more failed logins within 60 seconds**
- Flags a **possible account compromise** if a successful login follows the failures
- Prints a clear summary report
- No machine learning and no external libraries

## Project Structure
| File | Description |
|------|-------------|
| `app.py` | Main code: log generation, detection and report |
| `requirements.txt` | Library requirements (standard library only) |
| `README.md` | Project overview and usage |
| `Project_Report.pdf` | Detailed project report |

## How to Run
1. Install Python 3.8 or higher.
2. Open a terminal in the project folder.
3. Run:
   ```
   python app.py
   ```

## Sample Output
```
==================================================
 BRUTE-FORCE LOGIN ATTEMPT DETECTOR
==================================================
Total log entries analysed: 43
Rule: 5+ failed logins within 60 seconds

[ALERT] IP 203.0.113.45
   Failed attempts : 12
   First failure   : 2026-10-23 10:02:00
   WARNING: successful login after failures. Account may be compromised!
```

## How It Works
1. Read each log entry (timestamp, ip, username, status).
2. Group failed logins by IP address.
3. Slide a 60-second window over each IP's failures.
4. If the window holds 5 or more failures, raise an alert.
5. Check whether a successful login came after the failures.

## Configuration
Change these values at the top of `app.py`:
- `MAX_FAILS` : number of failures that triggers an alert (default 5)
- `WINDOW_SECONDS` : time window in seconds (default 60)

## Domain
Cybersecurity: intrusion and attack detection.

## Future Improvements
- Read real server logs (for example SSH or web logs)
- Automatically block flagged IPs
- Email or SMS alerts
- Dashboard with charts
