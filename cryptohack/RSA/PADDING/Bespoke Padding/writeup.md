# Bespoke Padding

## Challenge

Custom RSA padding scheme with e=11:
```
c = (a*m + b)^11 mod N
```
Each request returns different random `a`, `b`, and the ciphertext `c`. The modulus N stays the same across requests.

## Attack: Franklin-Reiter Related Message Attack

When two ciphertexts encrypt messages that are linearly related (m1 = a*m2 + b), the plaintext can be recovered efficiently.

Given two encryptions:
- c1 = (a1*m + b1)^e mod N
- c2 = (a2*m + b2)^e mod N

Both polynomials f1(x) = (a1*x + b1)^e - c1 and f2(x) = (a2*x + b2)^e - c2 have the same root m in Z_N[x].

Therefore `gcd(f1, f2)` in the polynomial ring Z_N[x] yields a linear factor `(x - m)`, directly revealing the message.

### Implementation

1. Request two encryptions of the flag (different a, b each time)
2. Build degree-11 polynomials f1, f2 using the binomial theorem
3. Compute polynomial GCD over Z_N using Euclidean algorithm
4. Extract the root m = -g[0] * g[1]^(-1) mod N

## Key Insight

The custom "bespoke" padding creates a linear relationship between the raw message and the padded value. With small e and access to multiple encryptions of the same message, Franklin-Reiter efficiently recovers the plaintext regardless of the random padding.
