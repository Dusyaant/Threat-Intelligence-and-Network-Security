"""Q15 - Classify an incident narrative into a root-cause category."""
CATS = {"Phishing": ["phishing", "email", "clicked", "credential harvest", "malicious link", "attachment"],
        "Unpatched vulnerability": ["unpatched", "patch", "cve", "outdated version", "known vulnerability", "exploit"],
        "Misconfiguration": ["misconfigur", "open bucket", "default password", "public access", "exposed", "permissive"],
        "Insider threat": ["insider", "disgruntled", "employee copied", "privileged user", "resigning", "abused access"],
        "Supply-chain compromise": ["vendor", "third-party", "supplier", "update server", "dependency", "supply chain"]}
def classify(t):
    t = t.lower(); s = {k: sum(w in t for w in v) for k, v in CATS.items()}
    b = max(s, key=s.get); return (b if s[b] else "Unknown"), s[b]
cases = ["An employee clicked a malicious link in an email and entered credentials on a fake page.",
         "Attackers used a known vulnerability (CVE-2021-44228) on an unpatched server.",
         "A cloud storage bucket was left with public access due to a permissive policy.",
         "A disgruntled employee copied customer data before resigning.",
         "A trojanised update from a third-party vendor reached all customers."]
for c in cases:
    r, n = classify(c); print(f"{r:<26}({n} hits) <- {c}")
