# Signing Server

## Challenge

The server provides three operations:
- `get_pubkey`: returns N, e
- `get_secret`: returns `secret^e mod N` (the encrypted secret message)
- `sign`: signs any message m by computing `m^d mod N`

## Attack

This is a textbook RSA signing oracle attack. The server will sign **any** message, including the ciphertext itself.

1. Get the encrypted secret: `c = secret^e mod N`
2. Ask the server to sign `c`: `sign(c) = c^d mod N = (secret^e)^d mod N = secret^(e*d) mod N = secret`

The signature of the ciphertext **is** the plaintext secret.

## Key Insight

RSA signing (m^d mod N) is mathematically identical to RSA decryption. A signing oracle that signs arbitrary messages is equivalent to a decryption oracle.
