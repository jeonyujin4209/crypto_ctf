"""
Real Eisenstein: LLL lattice attack on sum(ord(c)*sqrt(p_i))
Flag has 23 chars (15 unknown), uses first 23 primes.
"""
from decimal import Decimal, getcontext
import math
from sympy import Matrix

getcontext().prec = 100

PRIMES = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71, 73, 79, 83]
ct = 1350995397927355657956786955603012410260017344805998076702828160316695004588429433

known = {0: ord('c'), 1: ord('r'), 2: ord('y'), 3: ord('p'), 4: ord('t'), 5: ord('o'), 6: ord('{'), 22: ord('}')}
unknowns = list(range(7, 22))
n = len(unknowns)

SCALE = Decimal(16**64)
S = [int(Decimal(PRIMES[i]).sqrt() * SCALE + Decimal('0.5')) for i in range(23)]

target = ct - sum(known[i] * S[i] for i in known)
center = 79
target_c = target - center * sum(S[i] for i in unknowns)

rows = []
for j in range(n):
    row = [0] * (n + 1)
    row[j] = 1
    row[n] = S[unknowns[j]]
    rows.append(row)
last_row = [0] * (n + 1)
last_row[n] = -target_c
rows.append(last_row)

R = Matrix(rows).lll()

for i in range(R.rows):
    if abs(int(R[i, n])) < 5000:
        for neg in [False, True]:
            chars = []
            ok = True
            for j in range(n):
                v = -int(R[i, j]) if neg else int(R[i, j])
                c = v + center
                if 32 <= c <= 126:
                    chars.append(chr(c))
                else:
                    ok = False
                    break
            if ok:
                flag = 'crypto{' + ''.join(chars) + '}'
                h = Decimal(0.0)
                for idx, ch in enumerate(flag):
                    h += ord(ch) * Decimal(PRIMES[idx]).sqrt()
                if math.floor(h * 16**64) == ct:
                    print(f'FLAG: {flag}')
# Flag: crypto{r34l_t0_23D_m4p}
