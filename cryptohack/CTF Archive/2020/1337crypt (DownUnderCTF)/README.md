# 1337crypt (DownUnderCTF) (?pts)
## 2020

## Description
Can you solve my factorisation problem if I give you a hint?Challenge contributed by josephChallenge files:  - output.txt  - 1337crypt.sage

## Files
- `output.txt`
- `1337crypt.sage`

## Solution
`hint = floor(D*sqrt(p) + D*sqrt(q))` where `D = 63^14 ≈ 2^84`.
`hint/D ≈ sqrt(p) + sqrt(q)` → quadratic roots give `sqrt(p)`, `sqrt(q)` → `p_approx = round(sqrt(p)^2)`.
Error in p_approx ≈ `2*sqrt(p)/D ≈ 2^585`. Simple ±5 search fails completely.
**Coppersmith**: `f(x) = p_approx + x`, find small root `|x| < 2^600 < N^{1/4} ≈ 2^668` via `small_roots(beta=0.5)`.
Decrypt: Goldwasser-Micali. `Legendre(c_i, p) = (-1)^(1337+b)`. Since 1337 is odd: bit=1 iff Legendre==+1.

## Flag
`DUCTF{wh0_N33ds_pr3cIsi0n_wh3n_y0u_h4v3_c0pp3rsmiths_M3thod}`
