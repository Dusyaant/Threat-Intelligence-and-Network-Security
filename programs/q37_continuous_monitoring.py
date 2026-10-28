"""Q37 - Continuous monitoring loop over a login-event stream with baseline anomalies."""
import time, itertools
BASELINE = {"hours": range(8, 19), "countries": {"IN"}, "max_failed_per_min": 3}
stream = iter([{"t": "09:10", "user": "asha", "country": "IN", "ok": True},
               {"t": "09:12", "user": "ravi", "country": "IN", "ok": False},
               {"t": "02:41", "user": "asha", "country": "IN", "ok": True},
               {"t": "11:05", "user": "meena", "country": "RU", "ok": True},
               {"t": "11:06", "user": "ravi", "country": "IN", "ok": False},
               {"t": "11:06", "user": "ravi", "country": "IN", "ok": False},
               {"t": "11:06", "user": "ravi", "country": "IN", "ok": False},
               {"t": "11:06", "user": "ravi", "country": "IN", "ok": False}])
fail_counter = {}
print("Monitoring started (baseline: 08-18h, country IN, <=3 fails/min)\n")
for n, e in enumerate(stream, 1):
    anomalies = []
    if int(e["t"][:2]) not in BASELINE["hours"]: anomalies.append("off-hours login")
    if e["country"] not in BASELINE["countries"]: anomalies.append(f"unusual country {e['country']}")
    if not e["ok"]:
        k = (e["user"], e["t"]); fail_counter[k] = fail_counter.get(k, 0) + 1
        if fail_counter[k] > BASELINE["max_failed_per_min"]: anomalies.append("failed-login burst")
    print(f"[tick {n}] {e['t']} {e['user']:<6}{e['country']} {'OK ' if e['ok'] else 'FAIL'} -> " + ("ANOMALY: " + ", ".join(anomalies) if anomalies else "normal"))
    time.sleep(0.05)
