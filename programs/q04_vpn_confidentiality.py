"""Q4 - VPN confidentiality demo using a toy symmetric stream cipher (SHA-256 keystream XOR)."""
import hashlib
def keystream(key: bytes, n: int) -> bytes:
    out, ctr = b"", 0
    while len(out) < n:
        out += hashlib.sha256(key + ctr.to_bytes(4, "big")).digest(); ctr += 1
    return out[:n]
def crypt(data: bytes, key: bytes) -> bytes:       # XOR cipher: encrypt == decrypt
    return bytes(a ^ b for a, b in zip(data, keystream(key, len(data))))

shared_key = b"corp-vpn-shared-key"
message = b"Payroll file: user=admin pass=S3cret!"
tunnel_data = crypt(message, shared_key)

print("Sender plaintext      :", message.decode())
print("Captured in transit   :", tunnel_data.hex())
print("Attacker (wrong key)  :", crypt(tunnel_data, b"guessed-key").decode(errors="replace")[:40].encode("unicode_escape").decode())
print("Receiver (shared key) :", crypt(tunnel_data, shared_key).decode())
print("\nConclusion: traffic is unreadable without the shared key -> confidentiality.")
