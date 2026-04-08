# Let's Decrypt Again

## Challenge

The server has a fixed SIGNATURE. We must provide a composite public key N (via set_pubkey), receive a random suffix, then make 3 "claims" -- each requiring a valid signature verification for a different message pattern (with the same N but different e values). The 3 claims yield secret shares that XOR together to produce the flag.

For each claim: `pow(SIGNATURE, e_i, N) == bytes_to_long(emsa_pkcs1_v15.encode(msg_i, 96))`

We control N, e_i, and msg_i (within pattern constraints).

## Attack: Smooth prime squared + discrete log

### Key Insight: N = p^2

Choose N = p^2 where p is a smooth prime (~385 bits). This gives:
- N is composite (passes the `isPrime` check)
- N ~ 770 bits > max digest value (~753 bits)
- The group (Z/p^2Z)* has order p*(p-1), which is smooth if p-1 is smooth
- Discrete log mod p^2 is computationally feasible

### Steps:

1. **Get SIGNATURE** from the server
2. **Generate smooth prime p** (~385 bits) where:
   - p-1 is smooth (product of small primes up to ~200)
   - SIGNATURE is a primitive root mod p (so every coprime element has a dlog)
   - SIGNATURE^(p-1) != 1 mod p^2 (primitive root mod p^2 too)
3. **Set pubkey** N = p^2, receive suffix
4. **For each claim pattern**, craft a matching message, compute the EMSA-PKCS1 digest, then:
   - Compute dlog mod p using Pohlig-Hellman (fast because p-1 is smooth)
   - Hensel-lift to get dlog mod p*(p-1) = dlog mod p^2
5. **Submit claims** and XOR the 3 shares

### Hensel Lifting Detail

Given e0 = dlog(digest, SIGNATURE, p):
- Compute h_ratio = digest * SIGNATURE^(-e0) mod p^2. This is 1 mod p.
- Write h_ratio = 1 + s*p and SIGNATURE^(p-1) = 1 + t*p mod p^2
- Then k = s * t^(-1) mod p gives the correction
- Final answer: e = e0 + k*(p-1)

## Patterns

- Pattern 0: `This is a test ... for a fake signature.`
- Pattern 1: `My name is [name] and I own CryptoHack.org`
- Pattern 2: Valid Bitcoin address message (generated using version 0x00 with zero payload)
