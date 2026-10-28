"""Q19 - Splunk-style 'search' filter and 'stats count by field'."""
from collections import Counter
events = [{"host": "web01", "status": 200, "src": "10.0.0.5", "action": "allowed"},
          {"host": "web01", "status": 404, "src": "10.0.0.6", "action": "allowed"},
          {"host": "web02", "status": 500, "src": "10.0.0.5", "action": "error"},
          {"host": "web02", "status": 200, "src": "10.0.0.7", "action": "allowed"},
          {"host": "fw01",  "status": 403, "src": "203.0.113.9", "action": "blocked"},
          {"host": "fw01",  "status": 403, "src": "203.0.113.9", "action": "blocked"},
          {"host": "web01", "status": 200, "src": "10.0.0.5", "action": "allowed"}]
def search(data, **cond): return [e for e in data if all(e.get(k) == v for k, v in cond.items())]
def stats_count_by(data, field): return Counter(e[field] for e in data).most_common()
print("index=main host=web01   ->", len(search(events, host="web01")), "events")
print("index=main action=blocked ->", search(events, action="blocked")[0], "...")
print("\n| stats count by host")
for k, v in stats_count_by(events, "host"): print(f"  {k:<8}{v}")
print("\naction=allowed | stats count by src")
for k, v in stats_count_by(search(events, action="allowed"), "src"): print(f"  {k:<14}{v}")
