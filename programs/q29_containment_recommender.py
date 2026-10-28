"""Q29 - Recommend a containment strategy for a described incident."""
STRATEGIES = {"Isolate host from network (quarantine VLAN)": ["ransomware", "malware", "infected", "worm", "lateral"],
              "Disable/reset compromised account & revoke sessions": ["credential", "compromised account", "stolen password", "brute force", "phishing"],
              "Block malicious IPs/domains at firewall, enable rate limiting/CDN": ["ddos", "dos", "flood", "port scan", "c2", "botnet"],
              "Take system offline & patch/virtual-patch": ["vulnerab", "exploit", "zero-day", "unpatched", "web shell"],
              "Revoke access, preserve evidence, involve HR/legal": ["insider", "employee", "data theft by", "usb"],
              "Remove public exposure & rotate keys": ["bucket", "misconfigur", "exposed", "api key leaked", "public"]}
def recommend(t):
    t = t.lower(); s = {k: sum(w in t for w in v) for k, v in STRATEGIES.items()}
    b = max(s, key=s.get); return b if s[b] else "Escalate to incident commander for manual triage"
for inc in ["Ransomware is spreading from an infected workstation laterally to file servers",
            "A user's stolen password was used after a phishing email",
            "Web server hit by a DDoS flood from a botnet",
            "A cloud bucket with customer data is publicly exposed",
            "An employee is copying files to a USB drive before leaving"]:
    print(f"Incident : {inc}\nContain  : {recommend(inc)}\n")
