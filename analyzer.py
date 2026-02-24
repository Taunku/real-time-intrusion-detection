import re, os, time, json, csv
from collections import defaultdict, deque
from datetime import datetime 
from rich.console import Console
from rich.table import Table


log_file = "sample_logs.txt"
WINDOW_SECONDS = 5
BURST_THRESHOLD = 3
sensitive_paths = ["/admin", "/login", "/wp-admin"]

ip_requests = defaultdict(int)
ip_404 = defaultdict(int)
ip_sensitive_access = defaultdict(int)
ip_timestamps = defaultdict(lambda: deque())
ip_paths = defaultdict(set)
alerted_ips = set()
alerts = []
blocked_ips = set()

ip_data = defaultdict(lambda: {
    "timestamps": deque(),
    "paths": set(),
    "errors_404": 0,
    "risk": "Low" 
})

results = []
"""def main():

    print("\nSuspicious Activity Report:\n")

    for ip in ip_requests:
        total = ip_requests[ip]
        errors_404 = ip_404[ip]
        sensitive = ip_sensitive_access[ip]
        risk = "Low"
        reasons = []
        timestamps = sorted(ip_timestamps[ip])
        unique_paths = set(ip_paths[ip])
        score = 0

        if len(unique_paths) > 10:
            score += 3
            reasons.append("High number of unique paths requested")

        for i in range(len(timestamps) - 2):
            if (timestamps[i + 2] - timestamps[i]).total_seconds() <= 5:
                score += 4
                reasons.append("Rapid request burst detected (it is maybe a bot)")
                break

        if errors_404 >= 5:
            score += 2
            reasons.append("Multiple 404 errors (possible directory scanning)")

        if sensitive >= 2:
            score += 3
            reasons.append("Repeated access to sensitive paths")

        if score >= 6:
            risk = "High"
        elif score >= 3:
            risk = "Medium"

        if risk != "Low":
            results.append({
            "ip": ip,
            "total_requests": total,
            "404_errors": errors_404,
            "sensitive_access_attempts": sensitive,
            "risk_level": risk,
            "score": score,
            "reasons": reasons
        })

        print(f"IP: {ip}")
        print(f"  Risk Level: {risk}")

        for reason in reasons:
            print(f"  {reason}")
        print()

    report = {
        "analysis_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "total_unique_ips": len(ip_requests),
        "results": results
    }
    
    with open("analysis_report.json", "w") as f:
        json.dump(report, f, indent=4)

    print("Analysis complete. Report saved to analysis_report.json")"""

console = Console()
blocked_ips = set()

def display_dashboard(ip_data):
    table = Table(title="Live SOC Dashboard")
    table.add_column("IP")
    table.add_column("Risk Level")
    table.add_column("Recent Requests")
    table.add_column("Unique Paths")
    table.add_column("404 Errors")
    table.add_column("Blocked")

    for ip, data in ip_data.items():
        table.add_row(
            ip,
            data["risk"],
            str(len(data["timestamps"])),
            str(len(data["paths"])),
            str(data["errors_404"]),
            "Yes" if ip in blocked_ips else "No"
        )
    console.clear()
    console.print(table)

def block_ip(ip):
    if ip not in blocked_ips:
        blocked_ips.add(ip)
        print(f"[FIREWALL] {ip} blocked successfully")

def log_alert(ip, risk, reasons):
    os.makedirs("alerts", exist_ok=True)
    with open("alerts/alerts.csv", "a", newline="") as f:
        writer = csv.writer(f)
        writer.writerow([datetime.now(), ip, risk, "; ".join(reasons)])

def process_line(line):
    if not line.strip():
        return
    
    parts = line.split()
    if len(parts) < 9:
        return

    ip = parts[0]
    path = parts[6]
    status_code = parts[-2]

    ip_requests[ip] += 1
    ip_paths[ip].add(path)

    if ip in blocked_ips:
        print(f"[BLOCKED TRAFFIC] Ignoring request from {ip}")
        return

    try:
        raw_timestamp = line.split("[")[1].split("]")[0]
        timestamp_str = raw_timestamp.split()[0]
        timestamp = datetime.strptime(timestamp_str, "%d/%b/%Y:%H:%M:%S")
    except:
        return
    
    timestamps = ip_data[ip]["timestamps"]
    timestamps.append(timestamp)

    while timestamps and (timestamp - timestamps[0]).total_seconds() > WINDOW_SECONDS:
        timestamps.popleft()

    ip_data[ip]["paths"].add(path)
    if status_code == "404":
        ip_data[ip]["errors_404"] += 1
    evaluate_ip(ip)

def evaluate_ip(ip):
    data = ip_data[ip]
    errors_404 = data["errors_404"]
    sensitive_access = sum(1 for p in data["paths"] if any(sp in  p for sp in sensitive_paths))
    timestamps = data["timestamps"]
    unique_paths = data["paths"]

    score = 0
    reasons = []

    if len(timestamps) >= BURST_THRESHOLD:
        score += 4
        reasons.append(f"{len(timestamps)} requests in last {WINDOW_SECONDS}s")

    if len(unique_paths) > 10:
        score += 3
        reasons.append("High number of unique paths requested")

    if errors_404 >= 5:
        score += 2
        reasons.append("Multiple 404 errors")

    sensitive_access = sum(1 for p in data["paths"] if any(sp in p for sp in sensitive_paths))
    if sensitive_access >= 2:
        score += 3
        reasons.append("Repeated access to sensitive paths")

    if score >= 6:
        data["risk"] = "High"
        if ip not in alerted_ips:
            print(f"[HIGH ALERT] {ip} → {reasons}")
            alerted_ips.add(ip)
            block_ip(ip)
            log_alert(ip, "High", reasons)
    elif score >= 3:
        data["risk"] = "Medium"
        if ip not in alerted_ips:
            print(f"[MEDIUM ALERT] {ip} → {reasons}")
            alerted_ips.add(ip)
            log_alert(ip, "Medium", reasons)
    else:
        data["risk"] = "Low"

def monitor_logs():
    print("Starting real-time log monitoring...\n")
    if not os.path.exists(log_file):
        print(f"Log file {log_file} not found!")
        return

    last_refresh = time.time()
    REFRESH_INTERVAL = 2  # seconds

    with open(log_file, "r") as file:
        file.seek(0, os.SEEK_END)

        while True:
            line = file.readline()
            if line:
                process_line(line)

            # Refresh dashboard every REFRESH_INTERVAL seconds
            if time.time() - last_refresh >= REFRESH_INTERVAL:
                display_dashboard(ip_data)
                last_refresh = time.time()

            time.sleep(0.1)  # small sleep to reduce CPU usage

if __name__ == "__main__":
    monitor_logs()