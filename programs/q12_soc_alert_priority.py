"""Q12 - Assign P1-P4 priority to a SOC alert."""
RULES = [("P1", ["ransomware", "data exfiltration", "domain controller compromised", "active breach", "root access"]),
         ("P2", ["malware detected", "privilege escalation", "brute force", "c2 beacon", "lateral movement"]),
         ("P3", ["port scan", "failed login", "suspicious email", "policy violation", "phishing report"]),
         ("P4", ["informational", "software update", "scheduled scan", "low risk", "false positive"])]
def triage(text):
    t = text.lower()
    for p, kws in RULES:
        if any(k in t for k in kws): return p
    return "P3"
alerts = ["Ransomware encrypting files on the file server",
          "Brute force attack on VPN gateway from external IP",
          "Port scan from internet host against DMZ",
          "Scheduled scan completed - informational"]
for a in alerts: print(f"{triage(a)}  {a}")
