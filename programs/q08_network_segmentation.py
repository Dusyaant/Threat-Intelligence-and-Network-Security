"""Q8 - Network segmentation blocks lateral movement."""
from collections import deque
segments = {"Guest-WiFi": 1, "DMZ": 2, "Corporate": 3, "Database": 5}
hosts = {"guest-laptop": "Guest-WiFi", "web-server": "DMZ", "hr-pc": "Corporate", "db-server": "Database"}
ALLOWED = {("Guest-WiFi", "DMZ"), ("Corporate", "DMZ"), ("Corporate", "Database")}  # permitted flow directions (initiator -> target)
def reachable(start, policy_on):
    seen, q = {start}, deque([start])
    while q:
        h = q.popleft()
        for n, seg in hosts.items():
            if n in seen: continue
            ok = (hosts[h] == seg) or ((hosts[h], seg) in ALLOWED) if policy_on else True
            if ok: seen.add(n); q.append(n)
    return seen - {start}
print("Attacker compromises: guest-laptop (Guest-WiFi, low trust)\n")
flat = reachable("guest-laptop", False)
print("Flat network (no segmentation) can reach :", sorted(flat))
seg = reachable("guest-laptop", True)
print("Segmented network (policy enforced)      :", sorted(seg))
direct = ("Guest-WiFi", "Database") in ALLOWED
print(f"\nDirect Guest-WiFi -> Database allowed? {direct}  => {'ALLOW' if direct else 'BLOCKED by segmentation policy'}")
