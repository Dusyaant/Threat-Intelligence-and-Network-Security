"""Q7 - ELK roles: Logstash-style parse, Elasticsearch-style index, Kibana-style aggregate."""
import re
from collections import defaultdict, Counter
raw = [
 '192.168.1.10 - - [26/Oct/2026:10:01:02] "GET /index.html HTTP/1.1" 200 512',
 '192.168.1.11 - - [26/Oct/2026:10:01:05] "POST /login HTTP/1.1" 401 128',
 '10.0.0.5 - - [26/Oct/2026:10:01:09] "GET /admin HTTP/1.1" 403 99',
 '192.168.1.11 - - [26/Oct/2026:10:01:12] "POST /login HTTP/1.1" 401 128',
 '192.168.1.10 - - [26/Oct/2026:10:01:20] "GET /about.html HTTP/1.1" 200 740',
]
PAT = re.compile(r'(?P<ip>\S+) - - \[(?P<ts>[^\]]+)\] "(?P<method>\w+) (?P<path>\S+) [^"]+" (?P<status>\d+) (?P<bytes>\d+)')
# 1. Logstash: parse
events = [m.groupdict() for l in raw if (m := PAT.match(l))]
print(f"[Logstash] parsed {len(events)} events. Sample:\n  {events[0]}")
# 2. Elasticsearch: inverted index
index = defaultdict(set)
for i, e in enumerate(events):
    for field in ("ip", "method", "path", "status"):
        index[f"{field}:{e[field]}"].add(i)
print("\n[Elasticsearch] search status:401 ->", [f"doc{i}: {events[i]['path']} from {events[i]['ip']}" for i in sorted(index['status:401'])])
# 3. Kibana: aggregation
print("\n[Kibana] requests per status code:")
for k, v in sorted(Counter(e['status'] for e in events).items()): print(f"  {k}: {'#'*v} ({v})")
print("[Kibana] requests per IP:", dict(Counter(e['ip'] for e in events)))
