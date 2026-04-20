"""
Maybe Someday (GoogleCTF 2022) — Paillier non-adaptive padding oracle

Vulnerability:
  Paillier additive homomorphism: E(m)*g^delta = E(m+delta mod n).
  Adding delta causes carry from 128-byte secret zone into \x00 separator
  -> unpad fails -> binary oracle. The carry also creates complex byte patterns
  in the remainder, and has_zero_byte test partitions candidates differently
  for different deltas. 20 queries -> ~90% unique fingerprints per round.

Attack:
  secret = sha512(2-byte random).hexdigest().encode() -> 65536 candidates.
  Use all-carry deltas so oracle = has_zero_byte(remainder) for all candidates.
  Precompute fingerprint table. ~88% unique, P(round)~0.91, P(16)~0.22. Retry ~5x.
"""
import hashlib
import random
import sys
from pwn import *

BYTE128 = 256 ** 128

# -------- Precomputation --------
def precompute_candidates():
    """Return {S_int: secret_bytes} and sorted S list."""
    cands = {}
    vals = []
    for i in range(65536):
        secret_bytes = i.to_bytes(2, 'big')
        secret = hashlib.sha512(secret_bytes).hexdigest().encode()
        s = int.from_bytes(secret, 'big')
        cands[s] = secret
        vals.append(s)
    vals_sorted = sorted(set(vals))
    return cands, vals, vals_sorted

def choose_deltas(s_min, s_max, seed=58, n_queries=20):
    """Choose deltas in the all-carry range (carry for ALL candidates)."""
    delta_lo = BYTE128 - s_min       # s_min + delta_lo = BYTE128 -> always carry
    delta_hi = 2 * BYTE128 - s_max   # s_max + delta_hi = 2*BYTE128 -> no double-carry
    rng = random.Random(seed)
    return [rng.randint(delta_lo, delta_hi) for _ in range(n_queries)]

def build_fingerprint_table(vals, deltas, cands):
    """Precompute fingerprint -> [list of secrets] lookup table."""
    fp_map = {}
    for s in vals:
        bits = 0
        for q, d in enumerate(deltas):
            remainder = s + d - BYTE128
            if 0 <= remainder < BYTE128:
                if b'\x00' in remainder.to_bytes(128, 'big'):
                    bits |= (1 << q)
        entry = cands[s]
        fp_map.setdefault(bits, []).append(entry)
    return fp_map

# -------- Server interaction --------
def attempt(cands, vals, fp_table, deltas):
    HOST = "archive.cryptohack.org"
    PORT = 14846

    log.info(f"Connecting to {HOST}:{PORT}...")
    r = remote(HOST, PORT)

    # Receive public key
    line_n = r.recvline().decode().strip()
    line_g = r.recvline().decode().strip()
    n = int(line_n.split('= ')[1])
    g = int(line_g.split('= ')[1])
    n2 = n * n
    log.info(f"n = {n.bit_length()} bits, g = {g.bit_length()} bits")

    for round_num in range(16):
        # Receive c0
        line_c0 = r.recvline().decode().strip()
        c0 = int(line_c0.split('= ')[1])
        log.info(f"Round {round_num+1}/16: c0 received")

        # Compute and send 20 ciphertexts
        for d in deltas:
            c = c0 * pow(g, d, n2) % n2
            r.sendline(str(c).encode())

        # Receive 20 responses
        fp = 0
        for q in range(20):
            resp = r.recvline().decode().strip()
            if '\U0001f600' in resp:  # happy face
                fp |= (1 << q)

        happy_count = bin(fp).count('1')

        # Look up candidates
        if fp in fp_table:
            candidates_list = fp_table[fp]
            if len(candidates_list) == 1:
                guess = candidates_list[0]
                log.info(f"  {happy_count}/20 happy -> unique match!")
            else:
                guess = random.choice(candidates_list)
                log.info(f"  {happy_count}/20 happy -> collision size {len(candidates_list)}, random guess")
        else:
            log.warning(f"  {happy_count}/20 happy -> unknown fingerprint! random guess")
            guess = random.choice(list(cands.values()))

        r.sendline(guess)

        # Check result
        result = r.recvline().decode().strip()

        if '\U0001f4a1' in result:  # bulb = round passed
            log.success(f"  Round {round_num+1} PASSED!")
        elif '\U0001f3c1' in result:  # flag!
            log.success(f"FLAG: {result}")
            r.close()
            return result
        elif '\U0001f44b' in result:  # wave = failed
            log.warning(f"  FAILED at round {round_num+1}")
            r.close()
            return None

    # After 16 rounds, should get flag
    result = r.recvline().decode().strip()
    if '\U0001f3c1' in result:
        log.success(f"FLAG: {result}")
        r.close()
        return result

    r.close()
    return None

def main():
    log.info("Precomputing 65536 candidates...")
    cands, vals, vals_sorted = precompute_candidates()
    s_min, s_max = vals_sorted[0], vals_sorted[-1]

    SEED = 58
    log.info(f"Using seed={SEED}")
    deltas = choose_deltas(s_min, s_max, seed=SEED)

    log.info("Building fingerprint table...")
    fp_table = build_fingerprint_table(vals, deltas, cands)
    unique = sum(1 for v in fp_table.values() if len(v) == 1)
    total = len(vals)
    collision_sizes = [len(v) for v in fp_table.values() if len(v) > 1]
    p_round = (unique + sum(1.0/s for s in collision_sizes)) / total if collision_sizes else unique/total
    log.info(f"Unique: {unique}/{total} ({100*unique/total:.1f}%), P(round)={p_round:.4f}, P(16)={p_round**16:.4f}")

    for attempt_num in range(20):
        log.info(f"=== Attempt {attempt_num+1} ===")
        result = attempt(cands, vals, fp_table, deltas)
        if result:
            log.success(f"Got flag on attempt {attempt_num+1}!")
            return
        log.info("Retrying...")

if __name__ == '__main__':
    main()
