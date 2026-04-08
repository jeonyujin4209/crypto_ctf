# Vote for Pedro

## Challenge

Alice has RSA public key with e=3 (2048-bit N). The server verifies a "vote" by computing `vote^3 mod N`, converting to bytes, splitting on null bytes, and checking if the last segment is `VOTE FOR PEDRO`.

## Attack: Low-exponent signature forgery

Since e=3, we can forge a signature without knowing the private key.

The server checks: `long_to_bytes(vote^3 mod N).split(b'\x00')[-1] == b'VOTE FOR PEDRO'`

We need `vote^3` (as bytes) to end with `\x00VOTE FOR PEDRO` (15 bytes = 120 bits).

### Steps:

1. **Hensel lifting**: Find `x` such that `x^3 mod 2^120 = suffix_int` where `suffix_int = bytes_to_long(b'\x00VOTE FOR PEDRO')`. Start with `x mod 2` and iteratively lift to higher powers of 2.

2. **Set high bits**: Choose `vote = x + t * 2^120` for some `t`, ensuring `vote^3 < N` (so no modular reduction happens). Since N is 2048 bits, we can pick t up to about 2^562.

3. The resulting `vote^3` has the correct low bytes (`\x00VOTE FOR PEDRO`) and arbitrary high bytes, which the server ignores (it only checks the last null-separated segment).

## Key Insight

With e=3, we only need to control 120 bits of the cube, but we have ~683 bits of freedom in choosing the base. Hensel lifting efficiently solves `x^3 = c mod 2^k`.
