"""
1n_jection (Zh3r0 CTF V2 2021)

The nk2n function is the recursive Cantor pairing:
  nk2n([x])    = x
  nk2n([i,j])  = (i+j)(i+j+1)//2 + j
  nk2n(nk)     = nk2n([nk2n(nk[:ceil(l/2)]), nk2n(nk[floor(l/2):])])

The flag (as a bytes object = list of byte values) is passed in.
We invert by trying different flag lengths until we get valid bytes.
"""
from math import isqrt

TARGET = 2597749519984520018193538914972744028780767067373210633843441892910830749749277631182596420937027368405416666234869030284255514216592219508067528406889067888675964979055810441575553504341722797908073355991646423732420612775191216409926513346494355434293682149298585

def inv_cantor(n):
    # Find w such that w*(w+1)//2 <= n < (w+1)*(w+2)//2
    w = (isqrt(8 * n + 1) - 1) // 2
    t = w * (w + 1) // 2
    j = n - t
    i = w - j
    return i, j

def inv_nk2n(n, l):
    if l == 1:
        return [n]
    if l == 2:
        i, j = inv_cantor(n)
        return [i, j]
    first_l  = l - l // 2   # ceil(l/2)
    second_l = l // 2        # floor(l/2)
    first_val, second_val = inv_cantor(n)
    return inv_nk2n(first_val, first_l) + inv_nk2n(second_val, second_l)

for length in range(1, 150):
    try:
        result = inv_nk2n(TARGET, length)
        if all(0 <= b <= 255 for b in result):
            candidate = bytes(result)
            if b'zh3r0' in candidate or b'flag' in candidate or candidate.isascii():
                print(f"length={length}: {candidate}")
    except Exception:
        pass
