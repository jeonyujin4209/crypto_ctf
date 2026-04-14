import base64, hashlib, hmac, json, requests
import gmpy2
from Crypto.PublicKey import RSA as PycryptoRSA
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicNumbers
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend

BASE = "https://web.cryptohack.org/rsa-or-hmac-2"
E = 65537
SHA256_DIGEST_INFO = bytes.fromhex("3031300d060960864801650304020105000420")

def b64url_decode(s):
    return base64.urlsafe_b64decode(s + "=" * ((4 - len(s) % 4) % 4))

def b64url_encode(b):
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()

def emsa_pkcs1_sha256(signing_input, k):
    digest = hashlib.sha256(signing_input).digest()
    T = SHA256_DIGEST_INFO + digest
    ps_len = k - len(T) - 3
    return b"\x00\x01" + (b"\xff" * ps_len) + b"\x00" + T

# ── Capture tokens & recover N ───────────────────────────────────────────────
tokens = [requests.get(f"{BASE}/create_session/{u}/", timeout=15).json()["session"]
          for u in ("alice", "bob", "carol")]

pairs = [(f"{t.split('.')[0]}.{t.split('.')[1]}".encode(),
          b64url_decode(t.split('.')[2])) for t in tokens]
sig_mpz = [gmpy2.mpz(int.from_bytes(s, "big")) for _, s in pairs]

k = 256
diffs = []
for (si, _), s in zip(pairs, sig_mpz):
    m = gmpy2.mpz(int.from_bytes(emsa_pkcs1_sha256(si, k), "big"))
    diffs.append(gmpy2.sub(s ** E, m))

N = diffs[0]
for d in diffs[1:]: N = gmpy2.gcd(N, d)
for p in (2,3,5,7,11,13):
    while N % p == 0: N //= p
N = int(N)
print(f"[+] N = {N.bit_length()} bits")

# ── Build key variants using cryptography (OpenSSL backend) ──────────────────
pub_numbers = RSAPublicNumbers(e=E, n=N)
pub_key = pub_numbers.public_key(default_backend())

spki_pem = pub_key.public_bytes(serialization.Encoding.PEM,
                                 serialization.PublicFormat.SubjectPublicKeyInfo)
pkcs1_pem = pub_key.public_bytes(serialization.Encoding.PEM,
                                  serialization.PublicFormat.PKCS1)
der_spki  = pub_key.public_bytes(serialization.Encoding.DER,
                                  serialization.PublicFormat.SubjectPublicKeyInfo)
der_pkcs1 = pub_key.public_bytes(serialization.Encoding.DER,
                                  serialization.PublicFormat.PKCS1)

print(f"SPKI PEM  : {len(spki_pem)} bytes, first: {spki_pem[:27]}")
print(f"PKCS1 PEM : {len(pkcs1_pem)} bytes, first: {pkcs1_pem[:32]}")

# ── Forge JWT ────────────────────────────────────────────────────────────────
def forge(label, key_bytes, hdr=None, pay=None):
    if hdr is None: hdr = {"alg": "HS256", "typ": "JWT"}
    if pay is None: pay = {"username": "admin", "admin": True}
    h = b64url_encode(json.dumps(hdr, separators=(",",":")).encode())
    p = b64url_encode(json.dumps(pay, separators=(",",":")).encode())
    si = f"{h}.{p}".encode()
    sig = hmac.new(key_bytes, si, hashlib.sha256).digest()
    token = f"{h}.{p}.{b64url_encode(sig)}"
    r = requests.get(f"{BASE}/authorise/{token}/", timeout=15).json()
    ok = "flag" in str(r).lower()
    print(f"  [{'FLAG' if ok else '    '}] {label}: {r}")
    return ok

print("\n=== cryptography library variants ===")
for label, kb in [
    ("SPKI/as-is",       spki_pem),
    ("SPKI/+newline",    spki_pem + b"\n"),
    ("SPKI/stripped",    spki_pem.rstrip(b"\n")),
    ("PKCS1/as-is",      pkcs1_pem),
    ("PKCS1/+newline",   pkcs1_pem + b"\n"),
    ("PKCS1/stripped",   pkcs1_pem.rstrip(b"\n")),
    ("DER/SPKI",         der_spki),
    ("DER/PKCS1",        der_pkcs1),
]:
    if forge(label, kb): break
