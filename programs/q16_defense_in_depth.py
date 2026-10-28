"""Q16 - Defense in depth: layered, independent controls."""
import random
random.seed(7)
layers = [("Perimeter firewall", 0.70), ("IDS/IPS", 0.60), ("Endpoint protection", 0.65),
          ("Application security", 0.55), ("Access control / MFA", 0.80), ("Data encryption", 0.50)]
def attack(active):
    for name, p in active:
        if random.random() < p: return f"STOPPED at '{name}'"
    return "BREACHED (passed all layers)"
N = 10000
def success_rate(active):
    return sum("BREACHED" in attack(active) for _ in range(N)) / N
print("One sample attack through every layer:", attack(layers))
print(f"\n{'Configuration':<40}{'Attack success rate'}")
for i in range(1, len(layers) + 1):
    print(f"{str(i)+' layer(s): ' + layers[i-1][0]:<40}{success_rate(layers[:i]):.2%}")
print(f"\nBest single layer ({layers[4][0]}) alone: {success_rate([layers[4]]):.2%} success")
print("Overlapping controls drive risk far lower than any single layer.")
