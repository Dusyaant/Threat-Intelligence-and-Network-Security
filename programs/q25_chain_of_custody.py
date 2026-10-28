"""Q25 - Verify hash chain and timestamp order of chain-of-custody records."""
import hashlib
def rec_hash(r): return hashlib.sha256(f"{r['prev']}|{r['ts']}|{r['holder']}|{r['action']}".encode()).hexdigest()
def build(entries):
    chain, prev = [], "0" * 64
    for ts, holder, action in entries:
        r = {"prev": prev, "ts": ts, "holder": holder, "action": action}; r["hash"] = rec_hash(r)
        chain.append(r); prev = r["hash"]
    return chain
def verify(chain):
    prev, last = "0" * 64, -1
    for i, r in enumerate(chain):
        if r["prev"] != prev: return f"BROKEN at record {i}: previous-hash mismatch"
        if rec_hash(r) != r["hash"]: return f"BROKEN at record {i}: record content altered"
        if r["ts"] < last: return f"BROKEN at record {i}: timestamp goes backwards"
        prev, last = r["hash"], r["ts"]
    return "VALID: unbroken hash chain and non-decreasing timestamps"
chain = build([(1000, "Officer Rao", "Seized laptop"), (1200, "Lab Tech Meena", "Imaged disk"), (1500, "Analyst Dev", "Analysis")])
print("Original chain      :", verify(chain))
chain[1]["holder"] = "Unknown Person"
print("After tampering     :", verify(chain))
c2 = build([(1000, "A", "x"), (900, "B", "y")])
print("Out-of-order times  :", verify(c2))
