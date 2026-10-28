"""Q13 - Is it genuine threat intelligence or still raw data?"""
def assess(item):
    checks = {"Context": bool(item.get("context")),
              "Confidence assessment": item.get("confidence") in ("low", "medium", "high"),
              "Actionability": bool(item.get("action"))}
    verdict = "THREAT INTELLIGENCE" if all(checks.values()) else "RAW DATA"
    return verdict, checks
items = [{"data": "185.220.101.7"},
         {"data": "185.220.101.7", "context": "Seen scanning SSH on banks in Q3; linked to botnet X",
          "confidence": "high", "action": "Block at perimeter firewall and hunt SSH logs"},
         {"data": "evil-domain.xyz", "context": "Phishing kit host", "confidence": "medium"}]
for i in items:
    v, c = assess(i)
    print(f"Data: {i['data']:<18} -> {v}")
    for k, ok in c.items(): print(f"    {'[x]' if ok else '[ ]'} {k}")
    print()
