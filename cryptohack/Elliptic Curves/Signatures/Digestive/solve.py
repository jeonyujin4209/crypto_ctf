"""
Digestive (60pts) — EC / Signatures (web)

The web challenge:

    @chal.route('/digestive/sign/<username>/')
    def sign(username):
        msg = json.dumps({"admin": False, "username": <sanitized>})
        signature = SK.sign(msg.encode(), hashfunc=HashFunc)

    class HashFunc:
        def digest(self):
            return self.data        # identity "hash"

    @chal.route('/digestive/verify/<msg>/<signature>/')
    def verify(msg, signature):
        VK.verify(bytes.fromhex(signature), msg.encode(), hashfunc=HashFunc)
        if json.loads(msg)["admin"] == True: return FLAG

The "hash" is the raw msg bytes. NIST192p has baselen = 24, and the
python-ecdsa SK.sign() helper defaults `allow_truncate=True` — so the
digest is truncated to the **first 24 bytes** before signing/verifying.

The first 24 bytes of `'{"admin": false, "username": "..."}'` are exactly:

    '{"admin": false, "userna'

— and this prefix is **independent of the chosen username**. Every
signature returned by /sign/<u>/ is valid for the same 24-byte hash.

Forge: any JSON that begins with those 24 bytes (so the truncated hash
matches) and somewhere later sets `"admin": true`. Python's `json.loads`
takes the LAST occurrence of a duplicate key, so:

    forge_msg = '{"admin": false, "username": "x", "admin": true}'
                 |←  first 24 bytes = '{"admin": false, "userna' →|

decodes as `{"admin": True, "username": "x"}` → flag.
"""
import json
import sys
import urllib.parse

import requests

BASE = "https://web.cryptohack.org/digestive"


def main():
    # 1. Get any signature for any single-letter username
    r = requests.get(f"{BASE}/sign/x/", timeout=15)
    sig_data = r.json()
    sign_msg = sig_data["msg"]
    signature = sig_data["signature"]
    print(f"[1] sign('x'):")
    print(f"    msg = {sign_msg!r}")
    print(f"    first 24 bytes = {sign_msg.encode()[:24]!r}")
    print(f"    sig = {signature[:30]}...")

    # 2. Construct forge_msg with duplicate "admin" key
    forge_msg = '{"admin": false, "username": "x", "admin": true}'
    print(f"[2] forge_msg = {forge_msg!r}")
    print(f"    first 24 bytes = {forge_msg.encode()[:24]!r}")
    assert forge_msg.encode()[:24] == sign_msg.encode()[:24], "first 24 bytes mismatch"
    parsed = json.loads(forge_msg)
    print(f"    parses to: {parsed}")
    assert parsed["admin"] is True, "json parser doesn't pick last key"

    # 3. Submit verify
    forge_url = urllib.parse.quote(forge_msg, safe="")
    r = requests.get(f"{BASE}/verify/{forge_url}/{signature}/", timeout=15)
    print(f"[3] verify response: {r.text}")


if __name__ == "__main__":
    main()
