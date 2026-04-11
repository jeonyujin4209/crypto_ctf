"""
Nothing Up My Sleeve (50pts) — Dual EC DRBG backdoor

The server runs the notorious Dual EC DRBG with:
    s_{k+1} = (s_k * P).x
    r_k    = LSB240((s_{k+1} * Q).x)

where P is the casino's fixed P-256 point and Q is CHOSEN BY US. The
classic Dual EC backdoor: if we know the scalar d such that Q = d*P, then
from any output r we can recover ~2^16 high-bit candidates for (s_{k+1}*Q).x,
compute d^{-1} * that point = s_{k+1}*P = s_{k+2}, and predict every
future output.

We simplify by setting Q := P (so d = 1). Then r_k = LSB240(s_{k+2}),
and for each candidate s_{k+2} we verify against the next r via
LSB240((s_{k+2} * P).x) == r_{k+1}.

The 240-bit outputs are converted to base-37 digits (MSB-popped) for the
roulette wheel. We observe TWO full rebase sequences (46 digits each) to
reconstruct n_0 and n_1, brute 2^16 candidates, then predict all future
spins and bet on the exact number (+35 per win) to reach $1000.
"""
import json
import re
import socket
import time
from Crypto.PublicKey.ECC import EccPoint

HOST = "socket.cryptohack.org"
PORT = 13387

# P-256 curve order
P256_N = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551

# Casino's "lucky point" (actually the P-256 base point G)
CASINO_X = 0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296
CASINO_Y = 0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5

P = EccPoint(CASINO_X, CASINO_Y, curve="P-256")

VALUES = list(range(37))


def rebase_to_int(digits, b=37):
    """Inverse of the server's rebase: digits[0] = LSD, digits[-1] = MSD."""
    n = 0
    for d in reversed(digits):
        n = n * b + d
    return n


def digits_from_int(n, b=37):
    """Server's rebase: LSD first, MSD last."""
    if n < b:
        return [n]
    return [n % b] + digits_from_int(n // b, b)


def recv_json(sock, timeout=5.0):
    sock.settimeout(timeout)
    buf = b""
    while not buf.endswith(b"\n"):
        c = sock.recv(4096)
        if not c:
            break
        buf += c
    return json.loads(buf.decode())


def recv_all(sock, timeout=3.0):
    sock.settimeout(timeout)
    buf = b""
    try:
        while True:
            c = sock.recv(4096)
            if not c:
                break
            buf += c
            sock.settimeout(0.5)
    except socket.timeout:
        pass
    return buf.decode()


def send_json(sock, obj):
    sock.send((json.dumps(obj) + "\n").encode())


def recover_n(spins_msb_first, n_digits=46):
    """Given spins (popped MSD-first), reconstruct the 240-bit n."""
    # The server's rebase list is [LSD, LSD+1, ..., MSD]. spin_wheel pops
    # from end = MSD first. So observed sequence is MSD, MSD-1, ..., LSD.
    # Reverse to LSD-first for base conversion.
    lsd_first = list(reversed(spins_msb_first))
    n = 0
    for d in reversed(lsd_first):
        n = n * 37 + d
    return n


def recover_seed_with_prefix(n0, seq1_prefix_msd):
    """Given LSB240(α_2) = n0 and the first few MSD digits of n_1 = LSB240(α_3),
    brute 2^16 candidate high bits for α_2, compute α_3_cand = (α_2*P).x,
    and check whether rebase(LSB240(α_3_cand))[::-1][:k] matches the prefix."""
    p256_p = 0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff
    mask240 = (1 << 240) - 1
    k = len(seq1_prefix_msd)
    tried = 0
    for hi in range(1 << 16):
        s2_cand = (hi << 240) | n0
        if s2_cand >= p256_p or s2_cand == 0:
            continue
        tried += 1
        R = P * s2_cand
        s3_cand = int(R.x)
        n1_cand = s3_cand & mask240
        digits_msb = digits_from_int(n1_cand)[::-1]
        if digits_msb[:k] == seq1_prefix_msd:
            print(f"[+] match at hi={hi}  tried={tried}")
            return s2_cand
    print(f"[DEBUG] tried {tried} valid candidates, none matched")
    return None


def main():
    sock = socket.create_connection((HOST, PORT))
    greeting = recv_all(sock, 2.0)
    print(f"[*] greeting: {greeting!r}")

    # Round 1: send Q = P (same coords as casino's point)
    send_json(sock, {"x": hex(CASINO_X), "y": hex(CASINO_Y)})
    r1 = recv_json(sock)
    print(f"[1] {r1}")

    # Collect first ~92 spins to get at least 2 complete rebase sequences.
    # We need to detect sequence boundaries via "new croupier" msg.
    sequences = [[]]
    next_bet = {"choice": "EVEN"}  # cheap bet
    rounds_consumed = 1

    # The server's "new croupier" message is prepended on the spin that
    # EMPTIED the old sequence (i.e. the LAST spin of the old seq), NOT
    # the first of the new. So we append the spin to the current
    # subsequence first, and if the msg contains "new croupier" we start
    # a fresh subsequence for the NEXT round.

    OBS_SEQS_NEEDED = 5  # observe seq0 fully + some of seq1 for verification
    SPINS_TO_COLLECT = 60
    while rounds_consumed < 1 + SPINS_TO_COLLECT:
        send_json(sock, next_bet)
        r = recv_json(sock)
        rounds_consumed += 1
        spin = r.get("spin")
        msg = r.get("msg", "")
        dollars = r.get("$")
        if spin is None:
            print(f"[!] unexpected: {r}")
            break
        sequences[-1].append(spin)
        if "new croupier" in msg:
            sequences.append([])
        if rounds_consumed % 15 == 0:
            print(f"  [r{rounds_consumed}] ${dollars} sequences={[len(s) for s in sequences]}")
        # Stop once we have seq 0 complete AND at least 5 spins of seq 1
        if len(sequences) >= 2 and len(sequences[1]) >= OBS_SEQS_NEEDED:
            break

    print(f"[*] collected sequences: lengths = {[len(s) for s in sequences]}")

    # seq[0] is complete; seq[1] has OBS_SEQS_NEEDED partial digits.
    seq0 = sequences[0]
    seq1_prefix = sequences[1]
    n0 = recover_n(seq0)
    print(f"[*] n0 = {hex(n0)}  bits={n0.bit_length()}  len={len(seq0)} digits")
    print(f"[*] seq1 prefix (MSDs): {seq1_prefix}")

    # Round-trip check
    rt_n0 = digits_from_int(n0)[::-1]
    assert rt_n0 == seq0, f"round-trip failed: {rt_n0} vs {seq0}"

    # Brute α_2 candidates and verify against seq1 prefix
    s2 = recover_seed_with_prefix(n0, seq1_prefix)
    if s2 is None:
        print("[!] failed to recover seed")
        return
    print(f"[+] recovered α_2 = {hex(s2)}")

    # State trace (with Q=P):
    #   rng.next() call k: state transitions s_{k} -> s_{k+1} = (s_k*P).x,
    #                      returns LSB240((s_{k+1}*Q).x) = LSB240(s_{k+2}).
    #   Seq i in the game is produced by call i; its value is n_i = LSB240(s_{i+2}).
    #   So α_2 (what we recovered) is the state that, when multiplied by P, gives
    #   the (x of) s_3. And n_1 = LSB240(s_3).
    #
    # We already observed all of seq 0 and a prefix of seq 1. We need to
    # predict seq 1's REMAINING spins, then seq 2, seq 3, etc.
    mask240 = (1 << 240) - 1

    # Recompute the full n_1 digits (MSD-first):
    s3 = int((P * s2).x)
    n1_full = s3 & mask240
    seq1_full_msd = digits_from_int(n1_full)[::-1]
    already_in_seq1 = len(seq1_prefix)
    assert seq1_full_msd[:already_in_seq1] == seq1_prefix, "seq1 prefix mismatch"
    seq1_remaining = seq1_full_msd[already_in_seq1:]

    # Predict further sequences:
    # After seq 1 (from call 1), the state becomes s_3. Call 2 takes s_3,
    # computes s_4 = (s_3*P).x, and emits LSB240(s_5) as seq 2. So:
    #   seq k (for k >= 2): output = LSB240(s_{k+2}), state evolves as
    #                         s_{k+1} = (s_k * P).x
    MAX_PREDICT_SEQS = 4  # more than we need
    predicted_seqs = [seq1_remaining]
    state = s3
    for _ in range(MAX_PREDICT_SEQS):
        state = int((P * state).x)  # next state
        n_cand = state & mask240
        predicted_seqs.append(digits_from_int(n_cand)[::-1])
    future_spins = []
    for ps in predicted_seqs:
        future_spins.extend(ps)
    print(f"[*] {len(future_spins)} future spins predicted")

    # Now bet exact numbers and cash in
    for idx, expected in enumerate(future_spins):
        if rounds_consumed >= 124:
            break
        send_json(sock, {"choice": expected})
        r = recv_json(sock)
        rounds_consumed += 1
        spin = r.get("spin")
        dollars = r.get("$")
        if spin != expected:
            print(f"[!] spin mismatch at {rounds_consumed}: expected {expected}, got {spin}")
            break
        if idx % 10 == 0:
            print(f"  [r{rounds_consumed}] bet={expected} spin={spin} ${dollars}")

    # round 125 should return the flag
    send_json(sock, {"choice": "EVEN"})
    final = recv_all(sock, 3.0)
    print(f"[+] final: {final}")
    sock.close()


if __name__ == "__main__":
    main()
