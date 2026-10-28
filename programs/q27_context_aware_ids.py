"""Q27 - Signature IDS requiring BOTH protocol/port context AND content pattern."""
SIGNATURES = [{"name": "SQLi on web", "proto": "TCP", "ports": {80, 443, 8080}, "pattern": "union select"},
              {"name": "Shellcode on SMB", "proto": "TCP", "ports": {445}, "pattern": "\\x90\\x90\\x90"},
              {"name": "DNS tunnelling", "proto": "UDP", "ports": {53}, "pattern": "base64:"}]
def inspect(pkt, context_aware=True):
    out = []
    for s in SIGNATURES:
        pat = s["pattern"] in pkt["data"].lower()
        ctx = pkt["proto"] == s["proto"] and pkt["dport"] in s["ports"]
        if (pat and ctx) if context_aware else pat: out.append(s["name"])
    return out
packets = [{"proto": "TCP", "dport": 80, "data": "GET /?q=1 UNION SELECT password FROM users"},
           {"proto": "TCP", "dport": 25, "data": "Email body discussing how a UNION SELECT query works"},
           {"proto": "UDP", "dport": 53, "data": "base64:aGVsbG8="}]
print(f"{'PACKET (dport/data)':<55}{'STRING-ONLY':<14}CONTEXT+CONTENT")
for p in packets:
    print(f"{str(p['dport'])+' '+p['data'][:45]:<55}{str(inspect(p, False) or '-'):<14}{inspect(p) or '-'}")
print("\nPacket 2 is a false positive for string-only matching; context-aware IDS ignores it.")
