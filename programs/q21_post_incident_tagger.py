"""Q21 - Tag improvement areas discussed in a post-incident report."""
AREAS = {"Patch management": ["patch", "update", "vulnerab", "outdated"],
         "Security awareness": ["awareness", "training", "phishing simulation", "educate", "staff"],
         "Monitoring": ["monitor", "siem", "alert", "logging", "detection", "visibility"],
         "Backup strategy": ["backup", "restore", "recovery point", "offline copy", "snapshot"],
         "Access control": ["access", "least privilege", "mfa", "password", "privilege", "permission"]}
report = """Post-incident review: The breach exploited an outdated VPN appliance; we will patch quarterly.
Staff training on phishing will be expanded. Logging gaps delayed detection, so SIEM alerting will be tuned.
Offline backups allowed us to restore within a day. Admin accounts will move to MFA with least privilege."""
text = report.lower()
print("Improvement areas found in report:\n")
for area, kws in AREAS.items():
    hits = [k for k in kws if k in text]
    print(f"  [{'X' if hits else ' '}] {area:<20} matched: {hits}")
