"""Q28 - Detect DoS from web server logs by abnormal request rate per IP."""
import re, random
from collections import Counter, defaultdict
random.seed(1)
lines = []
for s in range(60):                                   # 60 seconds of normal traffic
    for ip in random.sample(["10.0.0.%d" % i for i in range(1, 9)], 2):
        lines.append(f'{ip} - - [26/Oct/2026:10:00:{s:02d}] "GET /index.html HTTP/1.1" 200 512')
for s in range(20, 30):                               # attacker bursts
    for _ in range(50): lines.append(f'198.51.100.77 - - [26/Oct/2026:10:00:{s:02d}] "GET /search HTTP/1.1" 200 90')
per_ip, per_ip_sec = Counter(), defaultdict(Counter)
for l in lines:
    m = re.match(r'(\S+) .*\[[^:]+:(\d+:\d+:\d+)\]', l)
    per_ip[m.group(1)] += 1; per_ip_sec[m.group(1)][m.group(2)] += 1
THRESHOLD = 20  # requests per second
print(f"Parsed {len(lines)} requests from {len(per_ip)} IPs\n{'IP':<16}{'TOTAL':<8}{'PEAK/SEC':<10}STATUS")
for ip, total in per_ip.most_common():
    peak = max(per_ip_sec[ip].values())
    print(f"{ip:<16}{total:<8}{peak:<10}{'*** POSSIBLE DoS ***' if peak > THRESHOLD else 'normal'}")
