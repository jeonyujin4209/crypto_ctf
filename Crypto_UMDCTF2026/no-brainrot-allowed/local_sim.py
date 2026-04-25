"""Local simulation: same oracle structure, smaller key for fast iteration."""
from Crypto.Util.number import getPrime, bytes_to_long, long_to_bytes
import random

random.seed(0xC0FFEE)

def setup(bits=1024):
    """Mimic the real challenge: n is 1023-bit, hex(n) starts with 0x7."""
    while True:
        p = getPrime(bits // 2)
        q = getPrime(bits // 2)
        n = p * q
        if n.bit_length() != bits - 1:
            continue
        # Want hex(n)[2] >= '7' so brainrot d=256 range [0x67<...>, 0x68<...>) is inside [0,n)
        if hex(n)[2] in '789abcdef':
            break
    e = 65537
    d = pow(e, -1, (p-1)*(q-1))
    return n, e, d

def oracle_real(c, d, n):
    """Same logic as server.py."""
    pt = hex(pow(c, d, n))
    return pt.startswith("0x67")

if __name__ == "__main__":
    n, e, d = setup(1024)
    print(f"n bits: {n.bit_length()}")
    print(f"hex(n) starts: {hex(n)[:8]}")
    print(f"hex(n) digits: {len(hex(n)) - 2}")

    # Sample flag
    flag = b"UMDCTF{this_is_a_test_flag}"
    m = bytes_to_long(flag)
    ct = pow(m, e, n)
    print(f"m bits: {m.bit_length()}")
    print(f"hex(m): {hex(m)[:20]}...")

    # Sanity: oracle on ct should be False (UMDCTF starts with 0x55, not 0x67)
    print(f"oracle(ct) = {oracle_real(ct, d, n)}")

    # Probability of brainrot for random query
    hits = 0
    for _ in range(1000):
        s = random.randrange(2, 1000)
        c = ct * pow(s, e, n) % n
        if oracle_real(c, d, n):
            hits += 1
    print(f"brainrot hits in 1000 random queries: {hits} (~ expected 1000/128 = ~8)")
