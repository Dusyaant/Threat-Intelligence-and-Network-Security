"""Q3 - Check a draft security policy for required governance elements."""
import re
REQUIRED = {
    "Scope": r"\bscope\b|applies to",
    "Roles and responsibilities": r"roles?\b.*responsibilit|responsibilit",
    "Enforcement": r"enforce|disciplinary|sanction|non-compliance",
    "Review cycle": r"review (cycle|annually|every)|reviewed (annually|every)|annual review",
    "Approval authority": r"approved by|approval authority|signed off",
}
draft = """
Information Security Policy (Draft v0.3)
1. Purpose: protect company information assets.
2. Scope: This policy applies to all employees, contractors and systems.
3. Roles and Responsibilities: The CISO owns the policy; managers ensure staff compliance.
4. Enforcement: Violations may lead to disciplinary action.
"""
print("Checking draft policy...\n")
missing = []
for element, pattern in REQUIRED.items():
    found = re.search(pattern, draft, re.I | re.S) is not None
    print(f"  [{'PASS' if found else 'MISSING'}] {element}")
    if not found: missing.append(element)
print("\nResult:", "All governance elements present." if not missing else "Missing -> " + ", ".join(missing))
