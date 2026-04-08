"""
Solve CryptoHack "Real Eisenstein" using LLL lattice reduction.

The challenge computes: h = sum(ord(c_i) * Decimal(p_i).sqrt()) with prec=100
                        ct = floor(h * 16^64)

The flag is 23 characters: crypto{...15 unknown chars...}
Uses first 23 primes: [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71, 73, 79, 83]

Approach: Construct a lattice where the flag characters form a short vector.
- Approximate sqrt(p_i) * C for large C to get integer S_i values
- Build a knapsack-style lattice with identity scaling N to balance
  the solution vector entries (~47) against the residual (~10^22)
"""
from decimal import Decimal, getcontext
import math
from mpmath import mp, mpf, sqrt as mpsqrt
from flint import fmpz_mat


def solve():
    mp.dps = 300

    PRIMES = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71, 73, 79, 83]
    ct = 1350995397927355657956786955603012410260017344805998076702828160316695004588429433

    n_unk = 15  # positions 7-21
    unknowns = list(range(7, 22))
    known = {0: ord('c'), 1: ord('r'), 2: ord('y'), 3: ord('p'),
             4: ord('t'), 5: ord('o'), 6: ord('{'), 22: ord('}')}
    center = 79

    # C: precision factor for integer approximation of sqrt(p_i)
    # N: identity column scaling (balances solution entries with residual)
    C = 10**100
    N = 10**21

    # Integer approximations of sqrt(p_i) * C
    alpha = [int(mpsqrt(PRIMES[i]) * mpf(C) + mpf(0.5)) for i in unknowns]

    # Target: h_mid = (ct + 0.5) / 16^64 (midpoint of [ct, ct+1) / 16^64)
    h_mid = (mpf(ct) + mpf(0.5)) / mpf(16**64)
    known_part = sum(val * mpsqrt(PRIMES[idx]) for idx, val in known.items())
    h_centered = h_mid - known_part - center * sum(mpsqrt(PRIMES[i]) for i in unknowns)
    T = int(h_centered * mpf(C) + mpf(0.5))

    # Build lattice (n_unk+1) x (n_unk+1)
    # Row i: N*e_i | alpha[i]
    # Last row: 0 | -T
    dim = n_unk + 1
    rows = []
    for i in range(n_unk):
        row = [0] * dim
        row[i] = N
        row[n_unk] = alpha[i]
        rows.append(row)
    last_row = [0] * dim
    last_row[n_unk] = -T
    rows.append(last_row)

    # LLL reduction
    M = fmpz_mat(rows)
    R = M.lll()
    reduced = R.tolist()

    # Search for flag in reduced basis
    for row_data in reduced:
        for sign in [1, -1]:
            chars = []
            valid = True
            for j in range(n_unk):
                v = sign * int(row_data[j])
                if v % N != 0:
                    valid = False
                    break
                c = v // N + center
                if 32 <= c <= 126:
                    chars.append(chr(c))
                else:
                    valid = False
                    break
            if not valid:
                continue

            flag = "crypto{" + "".join(chars) + "}"
            getcontext().prec = 100
            h = Decimal(0.0)
            for idx, ch in enumerate(flag):
                h += ord(ch) * Decimal(PRIMES[idx]).sqrt()
            if math.floor(h * 16**64) == ct:
                print(f"FLAG: {flag}")
                return flag

    print("Flag not found.")
    return None


if __name__ == "__main__":
    flag = solve()
    # Flag: crypto{r34l_t0_23D_m4p}
