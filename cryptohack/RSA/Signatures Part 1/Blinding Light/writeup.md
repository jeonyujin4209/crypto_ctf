# Blinding Light

## Challenge

The server signs any message except `admin=True`. The verify endpoint returns the flag if a valid signature for `admin=True` is provided.

## Attack: RSA Blinding

RSA signatures are multiplicatively homomorphic. We can "blind" the admin message so the server doesn't recognize it, get it signed, then "unblind" the signature.

1. Get public key (N, e)
2. Choose random r, compute: `blinded = r^e * m mod N` where m = bytes_to_long(b"admin=True")
3. Send `long_to_bytes(blinded)` for signing. Since blinded is random-looking, the server won't find "admin=True" in the bytes
4. Receive `blinded_sig = blinded^d mod N = r * m^d mod N`
5. Compute real signature: `sig = blinded_sig * r^(-1) mod N = m^d mod N`
6. Submit (admin=True, sig) to verify and get the flag

## Key Insight

The RSA homomorphic property: `(a*b)^d = a^d * b^d mod N` allows blinding attacks whenever an oracle signs arbitrary messages.
