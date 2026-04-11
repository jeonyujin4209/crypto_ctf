"""
Too Many Errors (Learning With Errors 2) — POC solver

The server's `get_sample` for each call:
  1. Generates deterministic a[0..27] from `self.rand` (state = SEED).
  2. Generates deterministic noise e ∈ {-1,0,1} from the same rand.
  3. Re-seeds `self.rand` with OS entropy.
  4. With 50% probability, replaces ONE entry a[k] with a fresh random value.
  5. Returns (a, b) where b = a·FLAG + e (mod 127).

Key observations:
  • SEED is fixed for the connection. Calling `reset` restores the state.
  • Therefore the "deterministic a" before the replacement is FIXED across
    every (reset → get_sample) sequence — call it a_orig.
  • e is ALSO fixed — call it e_orig — but a_orig and e_orig are unknown to us.
  • Half of all samples come back unchanged (a_used == a_orig). The other
    half differ from a_orig in exactly one coordinate.
  • In all cases, b = a_used · FLAG + e_orig (mod 127). The noise is THE
    SAME across calls.

Recovery:
  1. Reset, then call get_sample many times (~200) without resetting between
     calls. We get many (a_i, b_i) pairs.
  2. The majority (~50%) of a_i are exactly a_orig. Take the mode component-
     wise: the most common value at each coordinate IS a_orig[k].
  3. For each sample (a_i, b_i), look at coordinates where a_i ≠ a_orig.
     - If 0 differences: it's the clean sample → also gives us
       b_orig := a_orig · FLAG + e_orig.
     - If 1 difference at index k:
            b_i  - b_orig
          = (a_i[k] - a_orig[k]) * FLAG[k]   (mod 127)
       so FLAG[k] = (b_i - b_orig) * (a_i[k] - a_orig[k])^(-1) (mod 127).
  4. Collect FLAG[k] for as many k as we observe. With ~200 samples and
     uniform random indices, all 28 coordinates are covered with high
     probability.
"""
import ast
import json
import socket
from collections import Counter

HOST = "socket.cryptohack.org"
PORT = 13390
TIMEOUT = 30
q = 127
N_SAMPLES = 400
FLAG_LEN_GUESS = 28  # FLAG = "crypto{?...?}"; length not directly known


def query(f, payload):
    f.write((json.dumps(payload) + "\n").encode())
    line = f.readline()
    if not line:
        raise ConnectionError("server closed")
    return json.loads(line.decode())


def main():
    sock = socket.create_connection((HOST, PORT))
    sock.settimeout(TIMEOUT)
    f = sock.makefile("rwb", buffering=0)
    f.readline()  # greeting

    print(f"[*] collecting {N_SAMPLES} samples (reset BEFORE each)")
    samples = []
    for i in range(N_SAMPLES):
        query(f, {"option": "reset"})       # state ← SEED, deterministic a/e
        r = query(f, {"option": "get_sample"})
        samples.append((tuple(r["a"]), int(r["b"])))
        if (i + 1) % 50 == 0:
            print(f"    collected {i+1}/{N_SAMPLES}")

    sock.close()

    # The first sample's `a` length tells us FLAG length
    flag_len = len(samples[0][0])
    print(f"[*] FLAG length = {flag_len}")

    # Compute coordinate-wise mode → a_orig
    a_orig = []
    for k in range(flag_len):
        col = Counter(s[0][k] for s in samples)
        a_orig.append(col.most_common(1)[0][0])
    a_orig = tuple(a_orig)
    print(f"[*] a_orig (head): {a_orig[:8]}")

    # Find b_orig: the b of any sample where a == a_orig
    b_orig = None
    clean_count = 0
    for a, b in samples:
        if a == a_orig:
            if b_orig is None:
                b_orig = b
            elif b_orig != b:
                # Multiple "clean" samples with different b — shouldn't happen
                # since e_orig is fixed.
                print(f"[!] inconsistent clean b: {b_orig} vs {b}")
            clean_count += 1
    print(f"[*] clean samples (a == a_orig): {clean_count}/{N_SAMPLES}, b_orig = {b_orig}")
    if b_orig is None:
        raise RuntimeError("never saw a clean sample — increase N_SAMPLES")

    # For each perturbed sample with 1-coord difference, recover FLAG[k]
    flag_recovered = [None] * flag_len
    votes = [Counter() for _ in range(flag_len)]
    for a, b in samples:
        diffs = [k for k in range(flag_len) if a[k] != a_orig[k]]
        if len(diffs) != 1:
            continue
        k = diffs[0]
        delta_a = (a[k] - a_orig[k]) % q
        if delta_a == 0:
            continue
        flag_byte = ((b - b_orig) * pow(delta_a, -1, q)) % q
        votes[k][flag_byte] += 1

    for k in range(flag_len):
        if votes[k]:
            flag_recovered[k] = votes[k].most_common(1)[0][0]

    missing = [k for k in range(flag_len) if flag_recovered[k] is None]
    if missing:
        print(f"[!] missing indices: {missing}")
    else:
        print(f"[+] all {flag_len} bytes recovered")

    flag = bytes(b if b is not None else 0x3f for b in flag_recovered)
    print(f"FLAG: {flag.decode(errors='replace')}")


if __name__ == "__main__":
    main()
