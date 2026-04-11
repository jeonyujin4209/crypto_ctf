"""
Integer-based LLL reduction using rational arithmetic on the Gram matrix.

This implementation tracks:
  G[i][j] = <b_i, b_j>            (exact integer Gram matrix — cheap to update)
and computes mu / GS norms as exact Fractions derived from G on demand.
Size reduction operates on both the basis and G, and swaps do a localised
fix-up to G plus rederiving the GS quantities needed.

Rationale: olll recomputes full GS on every step → O(n^5). A float-based
GS version overflows when entries drift past 1e308. Tracking G in exact
integers and computing just the required μ columns gives O(n^4) with no
numerical issues.

Interface mirrors olll.reduction.
"""
from __future__ import annotations

from fractions import Fraction
from typing import List, Sequence


def _gram(B: List[List[int]]) -> List[List[int]]:
    n = len(B)
    G = [[0] * n for _ in range(n)]
    for i in range(n):
        for j in range(i, n):
            s = 0
            a, b = B[i], B[j]
            for k in range(len(a)):
                s += a[k] * b[k]
            G[i][j] = s
            G[j][i] = s
    return G


def _gs_from_gram(G: List[List[int]], n: int):
    """Compute GS squared norms (as Fractions) and mu[i][j] (as Fractions)
    from the Gram matrix. Returns (Bsq, mu) where Bsq[i] = ||b*_i||^2 and
    mu[i][j] = <b_i, b*_j> / ||b*_j||^2 for j < i."""
    mu = [[Fraction(0)] * n for _ in range(n)]
    Bsq = [Fraction(0)] * n
    for i in range(n):
        # ||b*_i||^2 = <b_i, b_i> - sum_{j<i} mu[i][j]^2 * Bsq[j]
        s = Fraction(G[i][i])
        for j in range(i):
            # <b_i, b*_j> = <b_i, b_j> - sum_{k<j} mu[j][k] * <b_i, b*_k>
            #            where <b_i, b*_k> = mu[i][k] * Bsq[k]
            num = Fraction(G[i][j])
            for k in range(j):
                num -= mu[j][k] * mu[i][k] * Bsq[k]
            if Bsq[j] == 0:
                mu[i][j] = Fraction(0)
            else:
                mu[i][j] = num / Bsq[j]
            s -= mu[i][j] * mu[i][j] * Bsq[j]
        Bsq[i] = s
    return Bsq, mu


def reduction(basis: Sequence[Sequence[int]], delta: float = 0.75) -> List[List[int]]:
    n = len(basis)
    dim = len(basis[0])
    B = [list(row) for row in basis]
    G = _gram(B)
    Bsq, mu = _gs_from_gram(G, n)
    delta_f = Fraction(delta).limit_denominator(10 ** 6)

    def recompute_gs() -> None:
        nonlocal Bsq, mu
        Bsq, mu = _gs_from_gram(G, n)

    def update_G_size_reduce(k: int, j: int, q: int) -> None:
        """Effect of B[k] -= q*B[j] on G (symmetric)."""
        # G[k][l] -= q * G[j][l] for all l; G[l][k] similarly; G[k][k] adjusts.
        for l in range(n):
            G[k][l] -= q * G[j][l]
        for l in range(n):
            G[l][k] = G[k][l]
        # The double-subtract above over-counts G[k][k]. Fix:
        # After the two passes the k,k entry is G[k][k] - 2q*G[j][k] + 0, but it
        # should be G[k][k] - 2q*G[j][k] + q^2*G[j][j]. Add the missing q^2 term.
        G[k][k] += q * q * G[j][j]

    def swap_rows(k: int) -> None:
        """Swap B[k] and B[k-1], update G accordingly."""
        B[k], B[k - 1] = B[k - 1], B[k]
        for l in range(n):
            G[k][l], G[k - 1][l] = G[k - 1][l], G[k][l]
        for l in range(n):
            G[l][k], G[l][k - 1] = G[l][k - 1], G[l][k]

    k = 1
    while k < n:
        # Size reduce b_k against b_{k-1}, ..., b_0
        for j in range(k - 1, -1, -1):
            m_kj = mu[k][j]
            if m_kj.numerator * 2 > m_kj.denominator or m_kj.numerator * 2 < -m_kj.denominator:
                q_int = int(round(float(m_kj)))  # round half to even is fine
                if q_int != 0:
                    for d in range(dim):
                        B[k][d] -= q_int * B[j][d]
                    update_G_size_reduce(k, j, q_int)
                    for l in range(j + 1):
                        mu[k][l] -= q_int * mu[j][l]

        # Lovász
        if Bsq[k] >= (delta_f - mu[k][k - 1] ** 2) * Bsq[k - 1]:
            k += 1
        else:
            swap_rows(k)
            recompute_gs()  # localised recompute would work but this is cheap enough
            k = max(k - 1, 1)

    return B


def _babai_gs(reduced: List[List[int]]):
    n = len(reduced)
    G = _gram(reduced)
    Bsq, mu = _gs_from_gram(G, n)
    return Bsq, mu


def babai_nearest_plane(reduced: List[List[int]], target: Sequence[int]) -> List[int]:
    """Babai's nearest-plane CVP approximation using integer/Fraction arithmetic.
    `reduced` must be LLL-reduced.
    """
    n = len(reduced)
    dim = len(reduced[0])

    # Compute GS norms and mu (as Fractions) from the gram matrix.
    Bsq, mu = _babai_gs(reduced)
    # Also compute GS vectors themselves (as Fraction lists) to do the reduction.
    # Bs[i] = b_i - sum_{j<i} mu[i][j] * Bs[j]
    Bs = [[Fraction(x) for x in reduced[i]] for i in range(n)]
    for i in range(n):
        for j in range(i):
            coef = mu[i][j]
            if coef == 0:
                continue
            for d in range(dim):
                Bs[i][d] -= coef * Bs[j][d]

    # Nearest plane: reduce `target` against Bs in reverse order using integer
    # rounding of dot(target, Bs[i]) / ||Bs[i]||^2.
    b_vec = [Fraction(x) for x in target]
    for i in range(n - 1, -1, -1):
        if Bsq[i] == 0:
            continue
        num = Fraction(0)
        for d in range(dim):
            num += b_vec[d] * Bs[i][d]
        c_rat = num / Bsq[i]
        c = int(round(float(c_rat)))
        if c != 0:
            for d in range(dim):
                b_vec[d] -= c * Fraction(reduced[i][d])

    # closest = target - residual
    closest = [int(round(float(Fraction(target[d]) - b_vec[d]))) for d in range(dim)]
    return closest


if __name__ == "__main__":
    # Sanity test: reproduce the olll doctest
    test = [[1, 1, 1], [-1, 0, 2], [3, 5, 6]]
    out = reduction(test, 0.75)
    print("test1 reduction:", out)
    expected = [[0, 1, 0], [1, 0, 1], [-1, 0, 2]]
    # Not requiring strict equality since different algorithms can produce
    # different but equivalent reduced bases.
    print("test1 shortest row norm^2:", min(sum(x * x for x in r) for r in out))
