"""Q14 - SIEM pipeline: collect -> normalize -> correlate -> alert."""
import re
from collections import defaultdict

def collect():
    """Stage 1: collect raw events from multiple sources."""
    return [("firewall", "DENY src=203.0.113.50 dst=10.0.0.5 dport=22 t=100"),
            ("windows",  "EventID=4625 user=admin src=203.0.113.50 t=101"),
            ("windows",  "EventID=4625 user=admin src=203.0.113.50 t=102"),
            ("windows",  "EventID=4625 user=admin src=203.0.113.50 t=103"),
            ("linux",    "sshd Failed password for admin from 203.0.113.50 t=104"),
            ("windows",  "EventID=4624 user=admin src=203.0.113.50 t=106")]

def normalize(source, line):
    """Stage 2: map each vendor format into one common schema."""
    ip = re.search(r"(\d{1,3}(?:\.\d{1,3}){3})", line).group(1)
    t = int(re.search(r"\bt=(\d+)", line).group(1))
    if "4624" in line: kind = "login_success"
    elif "4625" in line or "Failed password" in line: kind = "login_failure"
    else: kind = "blocked_connection"
    return {"source": source, "type": kind, "ip": ip, "t": t}

events = [normalize(s, l) for s, l in collect()]
print("Normalized events:")
for e in events: print(" ", e)

# Stage 3: correlate by source IP
by_ip = defaultdict(list)
for e in events: by_ip[e["ip"]].append(e)

# Stage 4: alert
print("\nCorrelation + alerting:")
for ip, ev in by_ip.items():
    fails = sum(e["type"] == "login_failure" for e in ev)
    success = any(e["type"] == "login_success" for e in ev)
    sources = {e["source"] for e in ev}
    if fails >= 3 and success:
        print(f"  *** ALERT [HIGH]: {ip} - {fails} failures then a success across {len(sources)} sources {sorted(sources)}")
        print("      -> possible account compromise via brute force")
