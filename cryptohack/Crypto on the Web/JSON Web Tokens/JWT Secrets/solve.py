"""
JWT Secrets (25pts) — JWT / weak secret

The source has a revealing TODO:
    SECRET_KEY = ? # TODO: PyJWT readme key, change later

The canonical PyJWT README uses `"secret"` as the demo HMAC key. The
author forgot to rotate it. Forge an HS256 token signed with "secret" and
an {"admin": true} payload.
"""
import jwt
import requests

BASE = "https://web.cryptohack.org/jwt-secrets"


def main():
    token = jwt.encode(
        {"username": "admin", "admin": True}, "secret", algorithm="HS256"
    )
    print(f"[*] token = {token}")
    r = requests.get(f"{BASE}/authorise/{token}/", timeout=15)
    print(f"[+] {r.json()}")


if __name__ == "__main__":
    main()
