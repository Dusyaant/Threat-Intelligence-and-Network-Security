"""Q32 - Detect violated CIA principles from tagged properties."""
props = [("Data at rest is encrypted", "Confidentiality", True),
         ("Access limited to need-to-know", "Confidentiality", True),
         ("File integrity hashes verified", "Integrity", False),
         ("Changes are logged and signed", "Integrity", True),
         ("Service has redundant failover", "Availability", True),
         ("Backups restore successfully", "Availability", False),
         ("DDoS protection enabled", "Availability", False)]
violated = {}
for desc, principle, status in props:
    print(f"  [{'OK ' if status else 'BAD'}] {principle:<16}{desc}")
    if not status: violated.setdefault(principle, []).append(desc)
print("\nViolated principles:")
for p in ("Confidentiality", "Integrity", "Availability"):
    print(f"  {p:<16}{'VIOLATED -> ' + '; '.join(violated[p]) if p in violated else 'intact'}")
