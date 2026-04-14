"""
LLL reduction + Babai nearest-plane CVP, using exact Fraction arithmetic.

Correctness over speed: for small-to-medium lattices (n <= ~30) this is fast
enough for CTFs. For larger lattices use fpylll or Sage.

Interface mirrors the original olll module:
  reduction(basis, delta=0.75) -> LLL-reduced basis (list of lists of ints)
  babai_nearest_plane(reduced, target) -> closest lattice vector to target
"""
from __future__ import annotations

from fractions import Fraction
from typing import List, Sequence


def _gram_schmidt(B: List[List[int]]):
    """Return (Bs, mu, Bsq) for integer basis B using exact Fractions.
      Bs[i]    = i-th GS vector (list of Fractions)
      mu[i][j] = <B[i], Bs[j]> / <Bs[j], Bs[j]>   for j < i
      Bsq[i]   = <Bs[i], Bs[i]>
    """
    n = len(B)
    dim = len(B[0])
    Bs = [[Fraction(x) for x in B[i]] for i in range(n)]
    mu = [[Fraction(0)] * n for _ in range(n)]
    Bsq = [Fraction(0)] * n
    for i in range(n):
        for j in range(i):
            if Bsq[j] == 0:
                continue
            num = sum(Fraction(B[i][d]) * Bs[j][d] for d in range(dim))
            mu[i][j] = num / Bsq[j]
            for d in range(dim):
                Bs[i][d] -= mu[i][j] * Bs[j][d]
        Bsq[i] = sum(Bs[i][d] * Bs[i][d] for d in range(dim))
    return Bs, mu, Bsq


def reduction(basis: Sequence[Sequence[int]], delta: float = 0.75) -> List[List[int]]:
    B = [list(row) for row in basis]
    n = len(B)
    dim = len(B[0])
    delta_f = Fraction(delta).limit_denominator(10 ** 6)

    k = 1
    while k < n:
        _, mu, Bsq = _gram_schmidt(B)
        # Size-reduce B[k] against B[k-1], ..., B[0]
        for j in range(k - 1, -1, -1):
            if abs(mu[k][j]) > Fraction(1, 2):
                q = round(mu[k][j])
                if q != 0:
                    for d in range(dim):
                        B[k][d] -= q * B[j][d]
                    _, mu, Bsq = _gram_schmidt(B)
        # Lovász
        if Bsq[k] >= (delta_f - mu[k][k - 1] ** 2) * Bsq[k - 1]:
            k += 1
        else:
            B[k], B[k - 1] = B[k - 1], B[k]
            k = max(k - 1, 1)
    return B


def babai_nearest_plane(reduced: List[List[int]], target: Sequence[int]) -> List[int]:
    """Babai's nearest-plane CVP approximation. `reduced` must be LLL-reduced."""
    n = len(reduced)
    dim = len(reduced[0])
    Bs, _, Bsq = _gram_schmidt(reduced)
    b = [Fraction(x) for x in target]
    for i in range(n - 1, -1, -1):
        if Bsq[i] == 0:
            continue
        num = sum(b[d] * Bs[i][d] for d in range(dim))
        c = round(num / Bsq[i])
        if c != 0:
            for d in range(dim):
                b[d] -= c * Fraction(reduced[i][d])
    # closest = target - residual; residual b should have integer entries
    return [int(Fraction(target[d]) - b[d]) for d in range(dim)]


if __name__ == "__main__":
    test = [[1, 1, 1], [-1, 0, 2], [3, 5, 6]]
    out = reduction(test, 0.75)
    print("reduction:", out)
    print("shortest norm^2:", min(sum(x * x for x in r) for r in out))
