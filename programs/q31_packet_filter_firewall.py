"""Q31 - Packet-filtering firewall: default-deny and rule ordering."""
def decide(rules, pkt):
    for i, (action, proto, port, src) in enumerate(rules, 1):
        if proto in ("any", pkt["proto"]) and port in ("any", pkt["port"]) and (src == "any" or pkt["src"].startswith(src)):
            return action, f"rule {i}"
    return "DENY", "default-deny"
good = [("DENY", "tcp", 22, "203.0.113."), ("ALLOW", "tcp", 22, "10."), ("ALLOW", "tcp", 443, "any")]
bad  = [("ALLOW", "tcp", "any", "any")] + good          # permissive rule placed first
pkts = [{"proto": "tcp", "port": 443, "src": "8.8.8.8"}, {"proto": "tcp", "port": 22, "src": "10.0.0.4"},
        {"proto": "tcp", "port": 22, "src": "203.0.113.9"}, {"proto": "udp", "port": 161, "src": "8.8.4.4"}]
print(f"{'PACKET':<28}{'GOOD ORDER':<22}BAD ORDER (allow-all first)")
for p in pkts:
    a, r = decide(good, p); a2, r2 = decide(bad, p)
    print(f"{p['proto']}/{p['port']} from {p['src']:<14}{a+' ('+r+')':<22}{a2+' ('+r2+')'}")
print("\nUnmatched UDP/161 -> default-deny in the good set. Ordering matters: rule 1 of the bad set lets the attacker in.")
