"""Q20 - Classify an incident into Phishing, DoS/DDoS, Malware or Man-in-the-Middle."""
CATS = {"Phishing": ["phishing", "fake login", "email asking", "spoofed email", "clicked link", "credentials"],
        "DoS/DDoS": ["flood", "overwhelmed", "unavailable", "traffic spike", "botnet requests", "denial", "syn"],
        "Malware": ["malware", "ransomware", "virus", "trojan", "worm", "infected", "encrypted files"],
        "Man-in-the-Middle": ["intercept", "eavesdrop", "arp spoof", "rogue access point", "certificate warning", "ssl strip"]}
def classify(t):
    t = t.lower(); s = {k: sum(w in t for w in v) for k, v in CATS.items()}
    b = max(s, key=s.get); return b if s[b] else "Unknown"
for d in ["Users received a spoofed email with a fake login page asking for credentials.",
          "The website became unavailable after a flood of SYN requests from a botnet.",
          "Files were encrypted and a ransomware note appeared on infected machines.",
          "An attacker on the cafe Wi-Fi used ARP spoofing to intercept traffic; users saw a certificate warning."]:
    print(f"{classify(d):<20}<- {d}")
