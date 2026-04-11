"""
Let's Prove It Again (ZKP Challenges) — Schnorr nonce reuse

Bug: `self.v` is set ONCE in __init__ and reused across every
fiatShamir() call. So across two proofs (i, j) with different primes:
    r_i = v - c_i*FLAG  (mod p_i - 1)
    r_j = v - c_j*FLAG  (mod p_j - 1)
Since v < 2^512 << p_i-1 ≈ 2^1024 and c_i*FLAG ≈ 2^568 > v, the mod
kicks in by adding exactly one (p_i - 1):
    v = r_i + c_i*FLAG - (p_i - 1)
Equating two calls:
    (c_i - c_j)*FLAG = (r_j - r_i) + (p_i - p_j)
    FLAG = [(r_j - r_i) + (p_i - p_j)] / (c_i - c_j)

We need:
 * Two proofs where we KNOW p (which means controlling the R that
   getPrime() consumes). Achieved by calling refresh(known_seed) before
   each of those two get_proofs.
 * c_i = sha3(long_to_bytes(t ^ y ^ g ^ R.randint(2, 1024))). The R for
   randint is the post-internal-refresh R seeded with random 8 bytes
   we don't know, so we brute 1023 candidates for each call's R.randint.

We get 4 total get_proofs (max_turns=4). With the sequence:
    get_proof#1, refresh(S1), get_proof#2 (KNOWN p),
    get_proof#3, refresh(S3), get_proof#4 (KNOWN p)
→ proofs 2 and 4 have reproducible primes.
"""
import json
import random
import socket
import time
import hashlib
from Crypto.Util.number import bytes_to_long, long_to_bytes, isPrime

HOST = "socket.cryptohack.org"
PORT = 13431
BITS = 1024
g = 2


def recv_all(sock, timeout=2.0):
    sock.settimeout(timeout)
    buf = b""
    try:
        while True:
            c = sock.recv(65536)
            if not c:
                break
            buf += c
            sock.settimeout(0.6)
    except socket.timeout:
        pass
    return buf.decode()


def send_json(sock, obj):
    sock.send((json.dumps(obj) + "\n").encode())


def parse_json_lines(blob):
    out = []
    for line in blob.splitlines():
        line = line.strip()
        if line.startswith("{"):
            try:
                out.append(json.loads(line))
            except Exception:
                pass
    return out


def get_prime_simulate(nonce: bytes, seed: bytes, bits: int = BITS):
    """Replicate Challenge.getPrime with an R seeded by (nonce + seed)."""
    R = random.Random(nonce + seed)
    while True:
        number = R.getrandbits(bits) | 1
        if isPrime(number, randfunc=lambda x: long_to_bytes(R.getrandbits(x))):
            return number


def main():
    sock = socket.create_connection((HOST, PORT))
    time.sleep(0.5)
    greet = recv_all(sock, 1.5)
    print(greet.strip())
    # Nonce is in the greeting line
    import re
    m = re.search(r"nonce for this instance:\s*([0-9a-f]+)", greet)
    assert m, f"no nonce in greeting: {greet!r}"
    nonce = bytes.fromhex(m.group(1))
    print(f"[*] nonce = {nonce.hex()}")

    # Call 1: get_proof (unknown p, discard)
    send_json(sock, {"option": "get_proof"})
    r1 = parse_json_lines(recv_all(sock, 8.0))[0]
    print(f"[1] got proof 1 (unknown p)")

    # Call 2: refresh with our seed S1
    S1 = b"\x00" * 8
    send_json(sock, {"option": "refresh", "seed": S1.hex()})
    recv_all(sock, 1.5)

    # Call 3: get_proof — KNOWN p, computed from nonce + S1
    send_json(sock, {"option": "get_proof"})
    r3 = parse_json_lines(recv_all(sock, 8.0))[0]
    p_a = get_prime_simulate(nonce, S1)
    t_a, r_a, y_a = r3["t"], r3["r"], r3["y"]
    print(f"[3] proof A (known p): y match? {pow(g, 0, p_a) is not None}  p_bits={p_a.bit_length()}")

    # Call 4: get_proof — unknown p
    send_json(sock, {"option": "get_proof"})
    r4 = parse_json_lines(recv_all(sock, 8.0))[0]
    print(f"[4] got proof 3 (unknown p, discard)")

    # Call 5: refresh with our seed S3
    S3 = b"\x01" * 8
    send_json(sock, {"option": "refresh", "seed": S3.hex()})
    recv_all(sock, 1.5)

    # Call 6: get_proof — KNOWN p
    send_json(sock, {"option": "get_proof"})
    r6 = parse_json_lines(recv_all(sock, 8.0))[0]
    p_b = get_prime_simulate(nonce, S3)
    t_b, r_b, y_b = r6["t"], r6["r"], r6["y"]
    print(f"[6] proof B (known p): p_bits={p_b.bit_length()}")

    sock.close()

    # Verify primes match what the server produced (y == g^FLAG mod p)
    # We can't check that directly without FLAG, but we can check t values
    # are in [0, p). That's a weak check.
    assert t_a < p_a, "t_a not in [0, p_a)"
    assert t_b < p_b, "t_b not in [0, p_b)"
    assert y_a < p_a and y_b < p_b

    # Brute force R_a, R_b ∈ [2, 1024] and solve for FLAG.
    # c_i = bytes_to_long(sha3_256(long_to_bytes(t_i ^ y_i ^ g ^ R_i)).digest())
    def compute_c(t, y, R):
        x = t ^ y ^ g ^ R
        h = hashlib.sha3_256(long_to_bytes(x)).digest()
        return bytes_to_long(h)

    # Precompute c candidates
    c_a_list = [(R, compute_c(t_a, y_a, R)) for R in range(2, BITS + 1)]
    c_b_list = [(R, compute_c(t_b, y_b, R)) for R in range(2, BITS + 1)]
    print(f"[*] {len(c_a_list)} × {len(c_b_list)} = {len(c_a_list)*len(c_b_list)} pairs to try")

    # Equation: (c_a - c_b)*FLAG = (r_b - r_a) + (p_a - p_b)
    rhs = (r_b - r_a) + (p_a - p_b)

    import gmpy2
    p_a_mpz = gmpy2.mpz(p_a)
    t_a_mpz = gmpy2.mpz(t_a)
    y_a_mpz = gmpy2.mpz(y_a)

    tried = 0
    for (R_a, c_a) in c_a_list:
        for (R_b, c_b) in c_b_list:
            tried += 1
            diff = c_a - c_b
            if diff == 0:
                continue
            if rhs % diff != 0:
                continue
            FLAG = rhs // diff
            if FLAG <= 0 or FLAG.bit_length() > 320:
                continue
            # Verify: g^FLAG mod p_a should equal y_a
            if int(gmpy2.powmod(g, FLAG, p_a_mpz)) == y_a:
                print(f"[+] MATCH after {tried} tries (R_a={R_a}, R_b={R_b})")
                print(f"[+] FLAG integer = {hex(FLAG)}")
                flag_bytes = long_to_bytes(FLAG)
                print(f"[+] bytes = {flag_bytes}")
                # Undo xor_nonce
                start = flag_bytes[:7]
                end = flag_bytes[-1:]
                middle = flag_bytes[7:-1]
                unxored = start + bytes(a ^ b for a, b in zip(middle, nonce)) + end
                print(f"[+] unxored = {unxored}")
                return
    print(f"[!] no match after {tried} tries")


if __name__ == "__main__":
    main()
