"""Q22 - Detect brute-force: repeated failures then success for a user."""
import re
log = """Oct 26 10:00:01 srv sshd[1]: Failed password for admin from 203.0.113.7
Oct 26 10:00:03 srv sshd[1]: Failed password for admin from 203.0.113.7
Oct 26 10:00:05 srv sshd[1]: Failed password for admin from 203.0.113.7
Oct 26 10:00:07 srv sshd[1]: Failed password for admin from 203.0.113.7
Oct 26 10:00:09 srv sshd[1]: Failed password for admin from 203.0.113.7
Oct 26 10:00:12 srv sshd[1]: Accepted password for admin from 203.0.113.7
Oct 26 10:05:00 srv sshd[1]: Accepted password for alice from 10.0.0.8"""
def detect(lines, user, threshold=4):
    fails = 0
    for l in lines:
        m = re.search(r"(Failed|Accepted) password for (\w+) from (\S+)", l)
        if not m or m.group(2) != user: continue
        if m.group(1) == "Failed": fails += 1
        else:
            if fails >= threshold: return f"BRUTE FORCE: {fails} failures then SUCCESS for '{user}' from {m.group(3)} at {l[:15]}"
            fails = 0
    return f"No brute-force pattern for '{user}'"
for u in ("admin", "alice"): print(detect(log.splitlines(), u))
