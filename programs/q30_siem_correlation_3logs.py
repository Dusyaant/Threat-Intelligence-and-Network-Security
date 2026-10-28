"""Q30 - Correlate firewall + Windows + VPN logs to detect a distributed brute-force."""
from collections import defaultdict
firewall = [(100, "203.0.113.50", "ALLOW", 3389), (101, "203.0.113.50", "ALLOW", 3389), (140, "203.0.113.50", "ALLOW", 443)]
windows  = [(102, "jsmith", "4625", "203.0.113.50"), (103, "jsmith", "4625", "203.0.113.50"), (105, "jsmith", "4625", "203.0.113.50"), (120, "jsmith", "4624", "203.0.113.50")]
vpn      = [(121, "jsmith", "203.0.113.50", "VPN LOGIN SUCCESS from new country")]
print("Single-log view (nothing alarming alone):")
print("  Firewall : allowed inbound RDP/HTTPS ->", len(firewall), "events")
print("  Windows  : 3 failed + 1 success logon for jsmith (could be a typo-prone user)")
print("  VPN      : 1 successful login (normal)\n")
by_ip = defaultdict(dict)
for t, ip, act, port in firewall:  by_ip[ip]["fw_rdp"] = by_ip[ip].get("fw_rdp", 0) + (port == 3389)
for t, u, ev, ip in windows:       by_ip[ip]["fail"] = by_ip[ip].get("fail", 0) + (ev == "4625"); by_ip[ip]["success"] = by_ip[ip].get("success", False) or ev == "4624"
for t, u, ip, m in vpn:            by_ip[ip]["vpn"] = True
print("Correlated view:")
for ip, d in by_ip.items():
    if d.get("fw_rdp") and d.get("fail", 0) >= 3 and d.get("success") and d.get("vpn"):
        print(f"  *** ALERT [CRITICAL] {ip}: RDP probing (FW) + {d['fail']} failed logons then success (Windows) + VPN login (VPN)")
        print("      => Brute-force followed by account takeover. Recommend: disable jsmith, kill VPN session, block IP.")
