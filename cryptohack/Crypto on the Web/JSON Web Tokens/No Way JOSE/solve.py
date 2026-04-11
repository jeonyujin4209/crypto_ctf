"""
No Way JOSE (20pts) — JWT / alg:none bypass

The server's `authorise` endpoint special-cases `alg == "none"` and
calls `jwt.decode(token, algorithms=["none"], options={"verify_signature": False})`,
happily accepting any payload without checking a signature. Forge a JWT
with `{"typ":"JWT","alg":"none"}` header and `{"admin": true}` payload and
submit it.
"""
import base64
import json

import requests

BASE = "https://web.cryptohack.org/no-way-jose"


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def main():
    header = {"typ": "JWT", "alg": "none"}
    payload = {"admin": True, "username": "admin"}
    token = f"{b64url(json.dumps(header).encode())}.{b64url(json.dumps(payload).encode())}."
    print(f"[*] token = {token}")
    r = requests.get(f"{BASE}/authorise/{token}/", timeout=15)
    print(f"[+] {r.json()}")


if __name__ == "__main__":
    main()
