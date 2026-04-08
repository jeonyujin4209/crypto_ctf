#!/usr/bin/env python3
import requests

s = requests.Session()
base = "https://aes.cryptohack.org/oh_snap/send_cmd"

def get_ks_byte(nonce_bytes):
    r = s.get(f"{base}/00/{nonce_bytes.hex()}/").json()
    if "error" in r:
        return bytes.fromhex(r["error"].split(": ")[1])[0]
    return None

# Statistical FMS attack with multiple samples per byte
# nonce = [A, 0xFF, trial] for trial in 0..255
# key = [A, 0xFF, trial, FLAG[0], FLAG[1], ...]
# After KSA steps 0,1,2 (known), step 3 involves FLAG[0], etc.
# Use voting across multiple trials

known_flag = list(b"crypto{")

for target in range(len(known_flag), 50):
    votes = [0] * 256
    A = target + 3  # 3-byte nonce, FLAG[target] at key[3+target]

    for trial in range(256):
        nonce = bytes([A % 256, 0xFF, trial])

        # Partial KSA with known bytes: nonce(3) + known_flag(target)
        S = list(range(256))
        j = 0
        known_key = list(nonce) + known_flag[:target]
        for i in range(len(known_key)):
            j = (j + S[i] + known_key[i]) % 256
            S[i], S[j] = S[j], S[i]

        # Check resolved condition: S[1] < A and S[S[1]] hasn't been touched
        # Simplified: just collect and vote

        out = get_ks_byte(nonce)
        if out is None:
            continue

        # FMS guess for key[A] = key[3+target] = FLAG[target]
        # At KSA step i=3+target: j_new = (j + S[3+target] + key[3+target]) % 256
        # key[3+target] = FLAG[target]
        # Approximate: guess = (S^{-1}[out] - j - S[(3+target)%256]) % 256

        i_pos = (3 + target) % 256
        S_inv = [0] * 256
        for x in range(256):
            S_inv[S[x]] = x

        guess = (S_inv[out] - j - S[i_pos]) % 256
        votes[guess] += 1

    # Pick most voted
    best = max(range(256), key=lambda x: votes[x])
    known_flag.append(best)
    c = chr(best) if 32 <= best <= 126 else f"\\x{best:02x}"
    top3 = sorted(range(256), key=lambda x: -votes[x])[:3]
    top3_str = ", ".join(f"{chr(v) if 32<=v<=126 else hex(v)}:{votes[v]}" for v in top3)
    print(f"  [{target}] {c} ({top3_str})")

    if best == ord("}"):
        break

flag = bytes(known_flag)
print(f"\nOh SNAP: {flag}")
