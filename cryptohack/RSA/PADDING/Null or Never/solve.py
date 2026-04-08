#!/usr/bin/env python3
"""
Null or Never - CryptoHack RSA PADDING (offline challenge)

e=3, message padded with null bytes to 100 bytes:
  m_padded = FLAG + b'\\x00' * (100 - len(FLAG))
  c = m_padded^3 mod n

Since FLAG is ~44 bytes: m_padded = FLAG_int * 256^(100 - len(FLAG))
Let k = 100 - len(FLAG) (unknown, but we can try values).

c = (FLAG_int * 256^k)^3 mod n
c = FLAG_int^3 * 256^(3k) mod n

So: FLAG_int^3 = c * inverse(256^(3k), n) mod n

If FLAG_int is small enough that FLAG_int^3 < n (or just slightly wraps),
we can recover FLAG_int by computing the integer cube root.

With FLAG ~44 bytes (352 bits) and n 1024 bits:
  FLAG_int^3 ~ 1056 bits > 1024 bits, so there's some wrapping.

Use Coppersmith's method (small roots of polynomials mod n),
or iterate over k*n + c to find perfect cubes.

Alternative: since m_padded = FLAG_int << (8*k), and m_padded < n (1024 bits),
FLAG_int < n / 2^(8*k). For k=56: FLAG_int < n / 2^448 ~ 2^576.
m_padded^3 might wrap: m_padded ~ 2^800, m^3 ~ 2^2400, mod 2^1024 = wraps ~2^1376 times.
Actually m_padded is 100 bytes = 800 bits. m^3 ~ 2400 bits. n ~ 1024 bits.
So c = m^3 mod n with heavy wrapping. Need Coppersmith.

Use SageMath or a Coppersmith implementation.
"""

from Crypto.Util.number import long_to_bytes
from gmpy2 import iroot

# Given values
n = 95341235345618011251857577682324351171197688101180707030749869409235726634345899397258784261937590128088284421816891826202978052640992678267974129629670862991769812330793126662251062120518795878693122854189330426777286315442926939843468730196970939951374889986320771714519309125434348512571864406646232154103
e = 3
c = 63476139027102349822147098087901756023488558030079225358836870725611623045683759473454129221778690683914555720975250395929721681009556415292257804239149809875424000027362678341633901036035522299395660255954384685936351041718040558055860508481512479599089561391846007771856837130233678763953257086620228436828

def coppersmith_short_pad(n, e, c):
    """
    Try to find flag using the structure:
    m = flag * 2^(8*pad_len), c = m^3 mod n
    flag starts with 'crypto{' = 7 bytes known

    For each possible flag length, try Coppersmith or brute cube root.
    """
    # Flag format: crypto{...} so starts with 0x63727970746f7b and ends with 0x7d
    prefix = b"crypto{"
    prefix_int = int.from_bytes(prefix, 'big')

    # Try different flag lengths (typical: 30-60 bytes)
    for flag_len in range(20, 80):
        pad_len = 100 - flag_len
        # m = flag_int * 256^pad_len
        # c = (flag_int * 256^pad_len)^3 mod n
        # c = flag_int^3 * 256^(3*pad_len) mod n
        # flag_int^3 = c * inverse(256^(3*pad_len), n) mod n

        shift = 256 ** (3 * pad_len)
        shift_inv = pow(shift, -1, n)
        flag_cubed_mod_n = (c * shift_inv) % n

        # flag_int is about flag_len * 8 bits
        # flag_int^3 is about 3 * flag_len * 8 bits
        # If 3 * flag_len * 8 <= 1024 (n's bit length), cube root is unique
        # 3 * flag_len * 8 <= 1024 -> flag_len <= 42

        if flag_len <= 42:
            # flag_int^3 < n (no wrapping), just take cube root
            flag_int, exact = iroot(flag_cubed_mod_n, 3)
            flag_int = int(flag_int)
            if exact:
                flag = long_to_bytes(flag_int)
                if flag.startswith(b"crypto{") and flag.endswith(b"}"):
                    return flag
        else:
            # flag_int^3 > n, try flag_int^3 = flag_cubed_mod_n + k*n
            # flag_int < 256^flag_len ~ 2^(8*flag_len)
            # flag_int^3 < 2^(24*flag_len)
            # k < 2^(24*flag_len) / n ~ 2^(24*flag_len - 1024)
            max_k = (2 ** (8 * flag_len * 3)) // n + 1
            # If max_k is too large, skip
            if max_k > 10**8:
                continue
            for k in range(max_k + 1):
                val = flag_cubed_mod_n + k * n
                flag_int, exact = iroot(val, 3)
                flag_int = int(flag_int)
                if exact:
                    flag = long_to_bytes(flag_int)
                    if flag.startswith(b"crypto{") and flag.endswith(b"}"):
                        return flag
    return None

flag = coppersmith_short_pad(n, e, c)
if flag:
    print(f"Flag: {flag.decode()}")
else:
    print("Flag not found with basic approach, trying Coppersmith...")

    # Use SageMath-style Coppersmith if available
    # Alternative: manual brute force with known prefix
    prefix = b"crypto{"
    suffix = b"}"
    prefix_int = int.from_bytes(prefix, 'big')

    for flag_len in range(30, 60):
        pad_len = 100 - flag_len
        # flag = prefix + unknown_middle + suffix
        # unknown_middle is flag_len - 8 bytes
        middle_len = flag_len - len(prefix) - len(suffix)
        if middle_len < 0:
            continue

        # m = flag_int * 256^pad_len
        # flag_int = prefix_int * 256^(middle_len + 1) + middle * 256 + suffix_int
        # This is a univariate polynomial in middle
        # Too complex for brute force if middle_len > 10

        # Try small wrapping counts
        shift = pow(256, 3 * pad_len, n)
        shift_inv = pow(shift, -1, n)
        flag_cubed_mod_n = (c * shift_inv) % n

        max_k = min((2 ** (8 * flag_len * 3)) // n + 1, 10**7)
        for k in range(max_k + 1):
            val = flag_cubed_mod_n + k * n
            flag_int, exact = iroot(val, 3)
            flag_int = int(flag_int)
            if exact:
                flag = long_to_bytes(flag_int)
                if b"crypto{" in flag:
                    print(f"Flag (len={flag_len}): {flag.decode()}")
                    exit()

    print("Try using SageMath Coppersmith method")
