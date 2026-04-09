"""
Missing Modulus: requires live server at socket.cryptohack.org 13412.
SKIPPED (server challenge).

Intended attack: b = A @ S + m*delta + e is computed WITHOUT reducing mod q.
So b has unbounded magnitude depending on A, S entries. But each character
of the flag is in [0, 257), so m*delta is in [0, ~q*256]. Given two encryptions
with known m, we can compute (b1 - b2) = (A1 - A2) @ S + (m1 - m2)*delta + (e1-e2).
Since there's no mod reduction, once we know S exactly we can solve.

Trick: set S to a single entry by exploiting correlations, or use the fact that
A entries are signed uniform so A @ S has sqrt(n)*sigma scale while m*delta is
large enough to extract via rounding after enough queries and averaging.

Requires server interaction.
"""
print("This challenge requires a live server connection. Skipped locally.")
