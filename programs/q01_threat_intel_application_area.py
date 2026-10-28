"""Q1 - Identify the threat-intelligence application area for a business scenario."""
AREAS = {
    "Banking fraud prevention": ["bank", "transaction", "atm", "card", "loan", "wire", "swift"],
    "Healthcare data protection": ["hospital", "patient", "medical", "clinic", "health", "ehr"],
    "E-commerce fraud prevention": ["online store", "checkout", "cart", "e-commerce", "refund", "shopping"],
    "Critical infrastructure protection": ["power grid", "scada", "utility", "water plant", "energy"],
}
def identify(text):
    t = text.lower()
    scores = {a: sum(k in t for k in kws) for a, kws in AREAS.items()}
    best = max(scores, key=scores.get)
    return (best if scores[best] else "General threat intelligence"), scores

scenarios = [
    "A bank notices unusual wire transfers and stolen card numbers being used at ATMs.",
    "A hospital's patient records and medical devices are targeted by ransomware.",
    "An online store sees fake checkout attempts and refund abuse on its shopping cart.",
    "A regional power grid operator finds probing of its SCADA network.",
]
for s in scenarios:
    area, sc = identify(s)
    print(f"Scenario : {s}\nArea     : {area}  (keyword hits: {sc[area]})\n")
