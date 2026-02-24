Real-Time Intrusion Detection & Prevention System

Overview

This project is a real-time intrusion detection and prevention system built in Python.

It monitors web server logs continuously, detects suspicious behavior using sliding-window anomaly detection, assigns risk scores to IP addresses, and simulates automated firewall blocking.

The system includes a live SOC-style dashboard for real-time threat visibility.



Features

- Real-time log monitoring
- Sliding time-window burst detection
- Detection of directory scanning (404 abuse)
- Sensitive endpoint probing detection
- Automated IP blocking simulation
- Live SOC dashboard using Rich
- CSV alert logging for auditing and incident tracking




The system analyzes behavior within a configurable time window:

- Detects rapid request bursts (possible bot activity)
- Identifies excessive unique path requests
- Flags repeated 404 errors (directory scanning)
- Detects repeated access to sensitive endpoints (/admin, /login, /wp-admin)
- Assigns risk scores (Low / Medium / High)
- Automatically blocks high-risk IPs

Running the system on CLI:
-python analyzer.py

Example output when suspicious activity is detected:
-[HIGH ALERT] 203.0.113.10 → ['3 requests in last 5s', 'Repeated access to sensitive paths']
[FIREWALL] 203.0.113.10 blocked successfully

Future Improvements:
-Machine learning-based anomaly detectio
-Real firewall integration
-REST API interface
-Docker containerization
-Alert severity visualization charts

Installation

Clone the repository:

```bash
git clone https://github.com/Taunku/real-time-intrusion-detection.git
cd real-time-intrusion-detection

python
intrusion-detection
cybersecurity
real-time
log-analysis
siem
