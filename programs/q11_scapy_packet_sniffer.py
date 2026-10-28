"""Q11 - Packet sniffing with Scapy (live capture; falls back to crafted packets if no privileges)."""
from scapy.all import sniff, IP, TCP, UDP, ICMP, Ether, conf
import os
print("Scapy default interface:", conf.iface)
def show(pkt): print(" ", pkt.summary())
captured = []
try:
    print("Sniffing 5 packets (timeout 5s)...")
    captured = sniff(count=5, timeout=5, prn=show)
except Exception as e:
    print("Live capture unavailable:", type(e).__name__, e)
if len(captured) == 0:
    print("\nNo live traffic captured in this sandbox -> analysing sample packets built with Scapy:")
    captured = [Ether()/IP(src="192.168.1.10", dst="8.8.8.8")/UDP(sport=53124, dport=53),
                Ether()/IP(src="192.168.1.10", dst="93.184.216.34")/TCP(sport=51000, dport=443, flags="S"),
                Ether()/IP(src="192.168.1.1", dst="192.168.1.10")/ICMP()]
    for p in captured: show(p)
print(f"\nTotal packets summarised: {len(captured)}")
for p in captured:
    if IP in p: print(f"  {p[IP].src:>15} -> {p[IP].dst:<15} proto={p[IP].proto}")
