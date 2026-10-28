"""Q17 - Map a control description to an ISO/IEC 27001 Annex A control domain (2013 structure)."""
DOMAINS = {"A.5 Information security policies": ["policy", "policies", "management direction"],
 "A.6 Organization of information security": ["roles", "segregation of duties", "mobile device", "teleworking"],
 "A.7 Human resource security": ["background check", "awareness training", "onboarding", "termination", "employee screening"],
 "A.8 Asset management": ["asset inventory", "classification", "media handling", "labelling"],
 "A.9 Access control": ["access", "password", "authentication", "privilege", "mfa"],
 "A.10 Cryptography": ["encrypt", "cryptograph", "key management", "tls"],
 "A.11 Physical and environmental security": ["door", "cctv", "badge", "server room", "physical"],
 "A.12 Operations security": ["backup", "malware", "logging", "patch", "change management"],
 "A.13 Communications security": ["network", "firewall", "vpn", "email transfer"],
 "A.15 Supplier relationships": ["supplier", "vendor", "third party contract"],
 "A.16 Incident management": ["incident", "reporting events", "response procedure"],
 "A.17 Business continuity": ["continuity", "disaster recovery", "redundan"],
 "A.18 Compliance": ["legal", "audit", "regulatory", "privacy law"]}
def map_control(t):
    t = t.lower(); s = {d: sum(k in t for k in kw) for d, kw in DOMAINS.items()}
    b = max(s, key=s.get); return b if s[b] else "Unmapped"
for c in ["Badge readers on the server room door", "Encrypt laptops and manage keys centrally",
          "Multi-factor authentication for admin access", "Nightly backup of databases",
          "Background check during employee onboarding", "Contracts with every supplier include security clauses",
          "Disaster recovery site with redundancy"]:
    print(f"{map_control(c):<45}<- {c}")
