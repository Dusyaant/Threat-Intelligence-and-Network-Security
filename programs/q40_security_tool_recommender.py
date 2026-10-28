"""Q40 - Keyword-based recommender: security task -> industry tool."""
TOOLS = {"Nmap": ["port scan", "network discovery", "open ports", "host discovery"],
         "Wireshark": ["packet capture", "analyze packets", "network traffic", "protocol analysis"],
         "Metasploit": ["exploit", "penetration test", "payload"],
         "Splunk / ELK": ["log analysis", "siem", "search logs", "dashboard"],
         "Nessus / OpenVAS": ["vulnerability scan", "vulnerability assessment", "cve"],
         "Snort / Suricata": ["intrusion detection", "ids", "ips", "signature"],
         "Burp Suite": ["web application", "sql injection", "xss", "intercept http"],
         "Autopsy / FTK": ["forensic", "disk image", "recover deleted", "evidence"],
         "John the Ripper / Hashcat": ["password cracking", "crack hashes", "password audit"]}
def recommend(task):
    t = task.lower(); s = {k: sum(w in t for w in v) for k, v in TOOLS.items()}
    b = max(s, key=s.get); return b if s[b] else "No match - consult a security engineer"
for t in ["I need to find open ports and do network discovery", "Capture and analyze packets from the network traffic",
          "Run a vulnerability scan to find CVEs on servers", "Test a web application for SQL injection",
          "Perform forensic analysis of a disk image", "Search logs and build a SIEM dashboard"]:
    print(f"{recommend(t):<28}<- {t}")
