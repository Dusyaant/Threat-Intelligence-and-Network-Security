"""Q5 - Classify a threat intelligence report as Strategic, Tactical or Operational."""
KEYWORDS = {
    "Strategic": ["executive", "board", "ceo", "trend", "geopolitical", "risk landscape", "budget", "long-term", "business impact"],
    "Tactical": ["ttp", "tactics", "techniques", "procedures", "mitre", "detection rule", "soc analyst", "ioc", "signature"],
    "Operational": ["campaign", "attacker infrastructure", "incident responder", "threat hunter", "imminent", "actor motivation", "upcoming attack"],
}
def classify(text):
    t = text.lower()
    scores = {k: sum(w in t for w in v) for k, v in KEYWORDS.items()}
    best = max(scores, key=scores.get)
    return (best if scores[best] else "Unclassified"), scores
samples = [
    "Report on geopolitical trends and business impact for the board and CEO.",
    "List of attacker TTPs mapped to MITRE with detection rules for SOC analysts.",
    "Details of an ongoing campaign and attacker infrastructure for incident responders and threat hunters.",
]
for s in samples:
    label, sc = classify(s)
    print(f"Description: {s}\n  -> {label}  {sc}\n")
