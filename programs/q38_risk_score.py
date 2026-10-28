"""Q38 - Qualitative risk score = likelihood x impact (1-5 scale)."""
def level(score):
    return "Low" if score <= 5 else "Medium" if score <= 12 else "High" if score <= 19 else "Critical"
def risk(l, i):
    if not (1 <= l <= 5 and 1 <= i <= 5): raise ValueError("ratings must be 1-5")
    s = l * i; return s, level(s)
print(f"{'RISK':<34}{'L':<3}{'I':<3}{'SCORE':<7}LEVEL")
for name, l, i in [("Lost USB with public flyers", 4, 1), ("Phishing against finance team", 4, 3),
                   ("Unpatched internet-facing server", 4, 4), ("Ransomware on production DB", 5, 5),
                   ("Data-centre flood", 1, 5)]:
    s, lv = risk(l, i); print(f"{name:<34}{l:<3}{i:<3}{s:<7}{lv}")
try: risk(6, 2)
except ValueError as e: print("\nInput validation:", e)
