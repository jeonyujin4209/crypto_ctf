# Let's Decrypt

## Challenge

The server has a fixed SIGNATURE. To verify, we provide our own msg, N, and e. The server checks:
```
pow(SIGNATURE, e, our_N) == emsa_pkcs1_v15.encode(msg)
```
If msg matches `^I am Mallory.*own CryptoHack.org$`, we get the flag.

## Attack: Control the modulus

Since we control both N and e, we can trivially forge verification:

1. Set `e = 1`, so `pow(SIGNATURE, 1, N) = SIGNATURE mod N`
2. Compute `digest = emsa_pkcs1_v15.encode(our_msg)` as an integer
3. Set `N = SIGNATURE - digest`, so `SIGNATURE mod N = digest`
4. Submit and get the flag

## Key Insight

The vulnerability is that the verifier accepts attacker-controlled public keys. In real certificate validation (like TLS), the public key is bound to a trusted certificate chain, preventing this attack.
