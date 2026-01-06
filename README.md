# FUTURE_CS_02


Security Alert Monitoring & Incident Response Report

Internship Track: Cyber Security (CS)
Task: Task 2 – Security Alert Monitoring & Incident Response
Intern Name: Deependra Mishra
Organization: Future Interns
Submission Date:


---

1. Objective

The objective of this task is to monitor simulated security alerts using a SIEM tool, identify suspicious activities, classify incidents, and prepare an incident response report. This task helps in understanding SOC operations, alert triage, and incident handling.


---

2. Scope of Monitoring

The scope of this task includes:

Monitoring system and application logs

Identifying suspicious or malicious events

Classifying alerts based on severity

Preparing an incident response report


The monitoring was performed on simulated log data for learning and analysis purposes.


---

3. Tools Used

SIEM Tool: Elastic Stack (ELK) / Splunk Free Trial

Log Sources: Sample system, authentication, and network logs

Analysis Tools: Kibana dashboards, alert rules



---

4. Methodology

The following steps were followed:

1. Ingested log data into the SIEM platform


2. Configured basic alert rules


3. Monitored dashboards for suspicious patterns


4. Analyzed alerts and correlated events


5. Classified incidents based on impact


6. Documented findings and remediation steps




---

5. Alerts & Incident Analysis

5.1 Brute Force Login Attempt

Description: Multiple failed login attempts were detected from a single IP address in a short time frame.

Severity: High

Impact:

Risk of account compromise

Unauthorized access attempts


Response Actions:

Blocked the malicious IP address

Enabled account lockout policy

Recommended MFA implementation



---

5.2 Suspicious Login from Unknown Location

Description: Successful login detected from an unusual geographic location.

Severity: Medium

Impact:

Possible credential compromise


Response Actions:

Forced password reset

Reviewed recent user activities

Enabled geo-location based alerts



---

5.3 Malware Indicator Alert

Description: Log entry matched a known malware signature.

Severity: High

Impact:

Potential system compromise


Response Actions:

Isolated affected system

Performed malware scan

Updated antivirus signatures



---

6. Incident Classification Summary

Incident Type	Severity	Status

Brute Force Attack	High	Mitigated
Suspicious Login	Medium	Investigated
Malware Alert	High	Resolved



---

7. Recommendations

Implement Multi-Factor Authentication (MFA)

Enable centralized log monitoring

Regularly update SIEM rules

Conduct periodic incident response drills



---

8. Conclusion

This task provided practical exposure to SOC operations, alert monitoring, and incident response procedures. Understanding alert patterns and quick response actions are critical to minimizing security risks.


---

9. Learning Outcomes

Hands-on experience with SIEM tools

Improved log analysis skills

Understanding of incident response lifecycle


FUTURE_CS_02/
│
├── logs.txt
├── siem_alert_monitor.py
├── incident_report.txt
└── README.md
1️⃣ Logs File (logs.txt)
Copy code
Txt
2024-12-01 10:01:23 LOGIN_FAILED user=admin ip=192.168.1.10
2024-12-01 10:01:25 LOGIN_FAILED user=admin ip=192.168.1.10
2024-12-01 10:01:28 LOGIN_FAILED user=admin ip=192.168.1.10
2024-12-01 10:01:30 LOGIN_FAILED user=admin ip=192.168.1.10
2024-12-01 10:02:10 LOGIN_SUCCESS user=john ip=45.33.12.90
2024-12-01 10:05:44 MALWARE_DETECTED trojan.exe host=PC-01
2️⃣ SIEM Alert Monitoring Script
📌 siem_alert_monitor.py
Copy code
Python
from collections import defaultdict

FAILED_LOGIN_THRESHOLD = 3
failed_logins = defaultdict(int)

print("🔍 Starting SIEM Log Analysis...\n")

with open("logs.txt", "r") as file:
    for line in file:
        if "LOGIN_FAILED" in line:
            ip = line.split("ip=")[1].strip()
            failed_logins[ip] += 1

            if failed_logins[ip] >= FAILED_LOGIN_THRESHOLD:
                print(f"🚨 HIGH ALERT: Brute Force detected from IP {ip}")

        elif "LOGIN_SUCCESS" in line:
            ip = line.split("ip=")[1].strip()
            print(f"⚠️ MEDIUM ALERT: Successful login from suspicious IP {ip}")

        elif "MALWARE_DETECTED" in line:
            malware = line.split(" ")[2]
            print(f"🔥 HIGH ALERT: Malware detected -> {malware}")

print("\n✅ Log analysis completed.")
3️⃣ Incident Response Report
📌 incident_report.txt
Copy code
Txt
Incident Response Report – Task 2

1. Brute Force Attack
Severity: High
Action Taken:
- Identified malicious IP
- Recommended IP blocking
- Enabled account lockout

2. Suspicious Login
Severity: Medium
Action Taken:
- Password reset recommended
- Geo-location alert suggested

3. Malware Detection
Severity: High
Action Taken:
- System isolation
- Malware scan performed
- Antivirus updated

Status: Incidents Mitigated
4️⃣ README.md (Very Important for Submission)
Copy code
Md
# Security Alert Monitoring & Incident Response – Task 2

## Description
This project simulates SIEM-based security alert monitoring and incident response using Python.

## Tools Used
- Python
- Sample log files
- SIEM concepts

## Alerts Detected
- Brute Force Attack
- Suspicious Login
- Malware Detection

## How to Run
```bash
python siem_alert_monitor.py
Learning Outcome
Log analysis
Alert classification
Incident response basics
Copy code
