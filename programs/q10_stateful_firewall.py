"""Q10 - Stateful inspection firewall simulation."""
class StatefulFirewall:
    def __init__(self, inside="10."):
        self.inside, self.state = inside, set()
    def process(self, src, sport, dst, dport, proto="TCP"):
        if src.startswith(self.inside):                      # outbound
            self.state.add((dst, dport, src, sport, proto))  # remember expected reply
            return "ALLOW (outbound, state recorded)"
        if (src, sport, dst, dport, proto) in self.state:    # inbound reply
            return "ALLOW (return traffic matches state table)"
        return "BLOCK (unsolicited inbound)"
fw = StatefulFirewall()
packets = [("10.0.0.5", 50000, "93.184.216.34", 443), ("93.184.216.34", 443, "10.0.0.5", 50000),
           ("203.0.113.9", 4444, "10.0.0.5", 22), ("93.184.216.34", 443, "10.0.0.5", 50001)]
print(f"{'#':<3}{'SRC':<22}{'DST':<22}DECISION")
for i, (s, sp, d, dp) in enumerate(packets, 1):
    print(f"{i:<3}{s+':'+str(sp):<22}{d+':'+str(dp):<22}{fw.process(s, sp, d, dp)}")
print("\nState table:", fw.state)
