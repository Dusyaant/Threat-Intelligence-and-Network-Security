"""Q23 - Signature IDS extended to inline IPS with tuning whitelist."""
SIGS = {"SQL Injection": "' or 1=1", "Directory Traversal": "../../", "XSS": "<script>"}
WHITELIST = {"10.0.0.99"}   # trusted vulnerability scanner
traffic = [("198.51.100.4", "GET /?id=' OR 1=1 --"), ("198.51.100.8", "GET /index.html"),
           ("10.0.0.99", "GET /?q=<script>alert(1)</script>"), ("203.0.113.6", "GET /../../etc/passwd")]
def ids(src, payload):
    return [n for n, s in SIGS.items() if s in payload.lower()]
print("--- IDS mode (detect only) ---")
for src, p in traffic:
    for n in ids(src, p): print(f"ALERT  {n:<20} from {src}")
print("\n--- IPS mode (inline, blocks, whitelist tuning) ---")
for src, p in traffic:
    m = ids(src, p)
    if m and src in WHITELIST: print(f"PASS   {src:<14}matched {m[0]} but source is whitelisted (false positive avoided)")
    elif m: print(f"BLOCK  {src:<14}dropped: {m[0]}")
    else: print(f"PASS   {src:<14}clean")
