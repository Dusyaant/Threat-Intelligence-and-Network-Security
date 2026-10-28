"""Q33 - Classify an action into an Incident Response lifecycle phase."""
PHASES = {"Preparation": ["policy", "playbook", "train", "tooling", "prepare", "tabletop", "irt"],
          "Identification": ["detect", "alert", "triage", "confirm", "analyze logs", "identify", "report an anomaly"],
          "Containment": ["isolate", "quarantine", "block", "disconnect", "contain", "disable account"],
          "Eradication": ["remove malware", "delete", "patch", "eradicat", "clean", "reimage", "eliminate"],
          "Recovery": ["restore", "recover", "bring back online", "resume", "validate systems", "return to production"],
          "Lessons Learned": ["lessons", "post-incident", "retrospective", "review meeting", "update playbook", "after-action"]}
def phase(t):
    t = t.lower(); s = {k: sum(w in t for w in v) for k, v in PHASES.items()}
    b = max(s, key=s.get); return b if s[b] else "Unknown"
for a in ["Run a tabletop exercise and train the IRT", "Analyst triages the SIEM alert and confirms the intrusion",
          "Isolate the infected host and block the C2 IP", "Remove malware and patch the exploited server",
          "Restore data from backups and return to production", "Hold a post-incident retrospective and update playbook"]:
    print(f"{phase(a):<17}<- {a}")
