"""Q36 - Identify the likely compliance standard (PCI-DSS, HIPAA, GDPR, SOX)."""
STD = {"PCI-DSS": ["credit card", "cardholder", "payment card", "pan", "cvv", "payment gateway"],
       "HIPAA": ["patient", "health record", "phi", "medical", "hospital", "ehr", "insurance claim"],
       "GDPR": ["eu citizens", "european", "personal data", "data subject", "right to erasure", "consent"],
       "SOX": ["financial reporting", "public company", "audit trail", "general ledger", "earnings", "internal controls"]}
def identify(t):
    t = t.lower(); s = {k: sum(w in t for w in v) for k, v in STD.items()}
    b = max(s, key=s.get); return b if s[b] else "None identified"
for d in ["An e-shop storing cardholder data and processing payment card numbers",
          "A hospital system storing patient health records and insurance claims",
          "A website collecting personal data of EU citizens with a consent banner",
          "Listed company's general ledger and financial reporting system with audit trail"]:
    print(f"{identify(d):<8}<- {d}")
