"""Q39 - Mini Threat Intelligence Platform: ingest, normalize, correlate IOCs against logs."""
import re
feed = ["IP,185.220.101.7,botnet C2", "domain,Evil-Update.COM,phishing", "hash,D41D8CD98F00B204E9800998ECF8427E,trojan",
        "ip,185.220.101.7,duplicate entry", "URL,hxxp://bad.example/pay,credential harvest"]
def normalize(line):
    typ, val, tag = line.split(",", 2); typ = typ.lower(); val = val.lower().replace("hxxp", "http")
    return (typ, val, tag.strip())
iocs = {}
for l in feed:
    t, v, tag = normalize(l); iocs.setdefault((t, v), tag)
print(f"Ingested {len(feed)} raw lines -> {len(iocs)} unique normalized IOCs")
for (t, v), tag in iocs.items(): print(f"  {t:<7}{v:<40}{tag}")
logs = ["10:01 proxy: 10.0.0.5 GET http://evil-update.com/payload.exe",
        "10:02 fw: 10.0.0.8 -> 8.8.8.8:53 ALLOW",
        "10:03 fw: 10.0.0.9 -> 185.220.101.7:443 ALLOW",
        "10:04 edr: 10.0.0.5 file hash d41d8cd98f00b204e9800998ecf8427e created"]
print("\nCorrelating against internal logs:")
for line in logs:
    for (t, v), tag in iocs.items():
        if v in line.lower(): print(f"  *** ALERT: IOC [{t}] {v} ({tag}) matched -> {line}")
