"""Q35 - Audit accounts against role-required permissions (least privilege)."""
ROLE_PERMS = {"Developer": {"read_code", "write_code", "deploy_staging"},
              "HR": {"read_hr", "write_hr"},
              "Auditor": {"read_logs", "read_hr", "read_code"},
              "Admin": {"read_logs", "manage_users", "manage_servers"}}
accounts = {"asha": ("Developer", {"read_code", "write_code", "deploy_staging"}),
            "ravi": ("Developer", {"read_code", "write_code", "deploy_staging", "deploy_prod", "manage_users"}),
            "meena": ("HR", {"read_hr", "write_hr", "read_logs"}),
            "kiran": ("Auditor", {"read_logs", "read_hr"})}
for user, (role, perms) in accounts.items():
    excess, missing = perms - ROLE_PERMS[role], ROLE_PERMS[role] - perms
    status = "EXCESS ACCESS" if excess else "OK"
    print(f"{user:<7}{role:<11}{status}")
    if excess: print(f"        remove -> {sorted(excess)}")
    if missing: print(f"        (note: role permissions not granted -> {sorted(missing)})")
