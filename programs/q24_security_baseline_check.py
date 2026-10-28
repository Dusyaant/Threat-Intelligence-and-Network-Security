"""Q24 - Compare current security configuration to a minimum baseline."""
baseline = {"min_password_length": 12, "mfa_enabled": True, "disk_encryption": True,
            "firewall_enabled": True, "patch_age_days_max": 30, "log_retention_days": 90}
current = {"min_password_length": 8, "mfa_enabled": True, "disk_encryption": False,
           "firewall_enabled": True, "patch_age_days_max": 45, "log_retention_days": 90}
def ok(k, req, cur):
    if k == "patch_age_days_max": return cur <= req
    if isinstance(req, bool): return cur == req
    return cur >= req
fails = []
print(f"{'CONTROL':<24}{'REQUIRED':<10}{'CURRENT':<10}RESULT")
for k, req in baseline.items():
    r = ok(k, req, current[k]); print(f"{k:<24}{str(req):<10}{str(current[k]):<10}{'PASS' if r else 'FAIL'}")
    if not r: fails.append(k)
print(f"\nCompliance: {len(baseline)-len(fails)}/{len(baseline)}  Failing controls: {fails}")
