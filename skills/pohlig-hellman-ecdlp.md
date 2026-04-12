# Pohlig-Hellman ECDLP on Smooth-Order Curves

## When to use
- Private key is small (nbits << curve order bit length)
- Curve order factors into small primes (check with `factor(order)` in Sage)
- Enough smooth factors exist to cover the private key size

## Key steps

### 1. Check order smoothness
```python
# In Sage:
order = G.order()
factor(order)
# Need: product of small factors >= 2^nbits
```

### 2. Pohlig-Hellman per prime factor
```python
for prime, exp in factor(order):
    pe = prime**exp
    e = order // pe
    G_sub = e * G     # subgroup generator of order pe
    A_sub = e * A     # Alice's key projected to subgroup
    d = discrete_log(A_sub, G_sub, ord=pe, operation='+')
    results.append(d)
    moduli.append(pe)
    mul *= pe
    if mul > 2**nbits:  # stop once product covers key space
        break
```

### 3. CRT reconstruction
```python
n_A = crt(results, moduli)  # gives n_A mod M
# If n_A > 2^nbits, try M - n_A (lift_x may give wrong sign)
```

### 4. Verify and decrypt
```python
if ec_mul(G, n_A)[0] == Ax:   # x-coordinate check
    shared = ec_mul(B, n_A)[0]
    key = sha1(str(shared).encode('ascii')).digest()[:16]
```

## Critical pitfalls

### Use the given G, not E.gens()[0]
```python
# WRONG:
G = E.gens()[0]  # Sage picks an arbitrary generator

# CORRECT:
G = E(Gx, Gy)   # use exactly the generator from the challenge
```
If G differs from the challenge G, `discrete_log(A, G)` gives a wrong exponent.

### lift_x gives arbitrary sign
`E.lift_x(x)` returns one of `(x, y)` or `(x, -y)`.
The BSGS result for `-A` gives `M - n_A_true`, not `n_A_true`.
Fix: try both `n_A` and `M - n_A`, verify with `ec_mul(G, n_cand)[0] == Ax`.

### BSGS coverage
For subgroup of order `l`, use `m = isqrt(l) + 1` baby steps.
Store full point tuples (not just x-coord) as keys to avoid false matches.
When checking giant steps, also try `(i*m - baby[neg(gamma)]) % l`.

### Key derivation
Check challenge source for SHA1 vs SHA256:
- Micro Transmissions: `sha1(str(shared_x).encode('ascii')).digest()[:16]`
- Other challenges may use SHA256

## Reference solve (pure Python)
See: `cryptohack/Elliptic Curves/Parameter Choice/Micro Transmissions/solve_final.py`

## Challenge
- CryptoHack: Micro Transmissions (120pts) — Elliptic Curves / Parameter Choice
- Flag: `crypto{d0nt_l3t_n_b3_t00_sm4ll}`
