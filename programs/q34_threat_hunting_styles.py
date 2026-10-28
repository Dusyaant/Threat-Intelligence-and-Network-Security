"""Q34 - Hypothesis-, intelligence- and analytics-based threat hunting."""
import statistics
logs = [{"host": "pc1", "proc": "winword.exe", "child": "powershell.exe", "dst": "198.51.100.23", "bytes": 300},
        {"host": "pc2", "proc": "chrome.exe", "child": None, "dst": "142.250.1.1", "bytes": 2000},
        {"host": "pc3", "proc": "explorer.exe", "child": None, "dst": "10.0.0.1", "bytes": 1500},
        {"host": "pc4", "proc": "chrome.exe", "child": None, "dst": "142.250.1.2", "bytes": 1800},
        {"host": "pc5", "proc": "svchost.exe", "child": None, "dst": "203.0.113.99", "bytes": 950000},
        {"host": "pc6", "proc": "chrome.exe", "child": None, "dst": "142.250.1.3", "bytes": 2200}]
print("1) HYPOTHESIS-BASED: 'Office apps spawning PowerShell indicate macro malware'")
for l in logs:
    if l["proc"] in ("winword.exe", "excel.exe") and l["child"] == "powershell.exe": print("   HIT:", l["host"], l["proc"], "->", l["child"])
print("\n2) INTELLIGENCE-BASED: search for IOCs from a threat feed")
IOCS = {"198.51.100.23", "203.0.113.99"}
for l in logs:
    if l["dst"] in IOCS: print("   HIT:", l["host"], "contacted known-bad IP", l["dst"])
print("\n3) ANALYTICS-BASED: statistical outliers in bytes sent")
vals = [l["bytes"] for l in logs]; mu, sd = statistics.mean(vals), statistics.pstdev(vals)
for l in logs:
    z = (l["bytes"] - mu) / sd
    if z > 1.5: print(f"   HIT: {l['host']} sent {l['bytes']} bytes (z-score {z:.2f}) -> possible exfiltration")
