"""Q9 - Tag an activity with its Threat Intelligence Lifecycle stage."""
STAGES = {
    "Direction": ["requirement", "objective", "goal", "scope", "priorit", "stakeholder"],
    "Collection": ["collect", "gather", "feed", "scrape", "honeypot", "osint"],
    "Processing": ["normalize", "parse", "decrypt", "translate", "deduplicate", "format"],
    "Analysis": ["analyze", "correlate", "assess", "attribute", "hypothes", "pattern"],
    "Dissemination": ["share", "distribute", "brief", "publish", "deliver", "report to"],
    "Feedback": ["feedback", "review usefulness", "improve", "stakeholders rated", "refine"],
}
def tag(text):
    t = text.lower(); scores = {s: sum(k in t for k in kw) for s, kw in STAGES.items()}
    b = max(scores, key=scores.get); return b if scores[b] else "Unknown"
acts = ["The team defines intelligence requirements and priorities with stakeholders.",
        "Analysts gather indicators from OSINT sources and a honeypot.",
        "Raw logs are parsed and normalized into a common format.",
        "Analysts correlate indicators and assess attribution of the campaign.",
        "The team publishes a briefing and shares it with the SOC.",
        "Stakeholders give feedback so the team can refine future reports."]
for a in acts: print(f"{tag(a):<14}<- {a}")
