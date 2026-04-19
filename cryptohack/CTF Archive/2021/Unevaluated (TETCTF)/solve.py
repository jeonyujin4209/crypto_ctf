"""
Unevaluated (TETCTF 2021)

Complex DH over Z[i]/(p^2) with order p*q*r (p,q,r all ~127-bit primes).
Key insight: private key k is only 256-bit, but order is ~384-bit.
Since k < 2^256 and p*q > 2^254, recovering k mod (p*q) + small brute force suffices.
Skip r entirely.

Steps:
1. k mod p via p-adic Hensel lift on norm:
   N(g^(qr)) = 1 + p*a, N(pub^(qr)) = 1 + p*b  →  k = b/a mod p
2. k mod q via F_p^* DLP:
   N(g^(pr)) and N(pub^(pr)) reduced mod p are in F_p^* with order q.
   Use Sage discrete_log (PARI znlog uses index calculus ~L_p(1/2), feasible for 128-bit p).
3. CRT to get k mod pq. Since k < 2^256 ~ 2*pq, try k, k+pq as AES key.

q here = (p-1)/2 (the LARGER 127-bit factor — p*q > 2^254 needed for brute-force to work).
"""
from math import isqrt
from collections import namedtuple
from Crypto.Cipher import AES

Complex = namedtuple("Complex", ["re", "im"])

def cmul(c1, c2, n):
    return Complex((c1.re * c2.re - c1.im * c2.im) % n,
                   (c1.re * c2.im + c1.im * c2.re) % n)

def cpow(c, e, n):
    r = Complex(1, 0)
    while e > 0:
        if e & 1: r = cmul(r, c, n)
        c = cmul(c, c, n); e >>= 1
    return r

def norm(c):
    return c.re * c.re + c.im * c.im

g = Complex(20878314020629522511110696411629430299663617500650083274468525283663940214962,
            16739915489749335460111660035712237713219278122190661324570170645550234520364)
pub = Complex(11048898386036746197306883207419421777457078734258168057000593553461884996107,
              34230477038891719323025391618998268890391645779869016241994899690290519616973)
n = 42481052689091692859661163257336968116308378645346086679008747728668973847769
encrypted_flag = b'\'{\xda\xec\xe9\xa4\xc1b\x96\x9a\x8b\x92\x85\xb6&p\xe6W\x8axC)\xa7\x0f(N\xa1\x0b\x05\x19@<T>L9!\xb7\x9e3\xbc\x99\xf0\x8f\xb3\xacZ:\xb3\x1c\xb9\xb7;\xc7\x8a:\xb7\x10\xbd\x07"\xad\xc5\x84'

p = isqrt(n)
assert p * p == n
q = (p - 1) // 2  # 127-bit prime (the larger one used for CRT)
r = (p + 1) // 12  # 124-bit prime (unused — too small: p*r < 2^256 brute force grows)

# === Step 1: k mod p via norm + Paillier-style log ===
gp = cpow(g, q * r, n)       # order p
pubp = cpow(pub, q * r, n)   # order p (or 1)
c1 = norm(gp) % (p * p)      # = 1 + p*a
c2 = norm(pubp) % (p * p)    # = 1 + p*b
a = (c1 - 1) // p % p
b = (c2 - 1) // p % p
assert a != 0
k_mod_p = b * pow(a, -1, p) % p
print(f"[+] k mod p = {k_mod_p}")

# === Step 2: k mod q via Sage discrete_log ===
gq = cpow(g, p * r, n)       # order q
pubq = cpow(pub, p * r, n)   # order q
Ng = norm(gq) % p            # in F_p^*, order q
Npub = norm(pubq) % p
print(f"[+] DLP input: N(g_q) = {Ng}")
print(f"[+] DLP input: N(pub_q) = {Npub}")
print(f"[+] p = {p}")
print(f"[+] q = {q}")
def sage_dlp(p_val, g_val, h_val, ord_val):
    """Call Sage via docker to solve DLP in F_p*. ~50s for 128-bit p with 127-bit prime order."""
    import subprocess, os, tempfile, textwrap
    script = textwrap.dedent(f"""\
        F = GF({p_val})
        print(F({h_val}).log(F({g_val}), {ord_val}))
    """)
    workdir = os.path.dirname(os.path.abspath(__file__))
    script_path = os.path.join(workdir, "_dlp.sage")
    with open(script_path, "w") as f:
        f.write(script)
    try:
        env = {**os.environ, "MSYS_NO_PATHCONV": "1"}
        mount = workdir.replace("/", "\\")
        out = subprocess.check_output(
            ["docker", "run", "--rm", "-v", f"{mount}:/work",
             "sagemath/sagemath:latest", "sage", "/work/_dlp.sage"],
            env=env, timeout=600, stderr=subprocess.STDOUT)
        return int(out.decode().strip().splitlines()[-1])
    finally:
        os.unlink(script_path)

print("[*] Running Sage discrete_log (~50s)...")
k_mod_q = sage_dlp(p, Ng, Npub, q)
print(f"[+] k mod q = {k_mod_q}")

# === Step 3: CRT + brute force ===
M = p * q
inv_p_mod_q = pow(p, -1, q)
x0 = (k_mod_p + p * ((k_mod_q - k_mod_p) * inv_p_mod_q % q)) % M
print(f"[+] k mod pq = {x0}")

for i in range((1 << 256) // M + 2):
    cand = x0 + i * M
    if cand >= 1 << 256:
        break
    flag = AES.new(cand.to_bytes(32, "big"), AES.MODE_ECB).decrypt(encrypted_flag)
    if b"TetCTF" in flag:
        print(f"[+] k = {cand}")
        print(f"[+] flag = {flag}")
        break
else:
    raise RuntimeError("flag not found — k_mod_q wrong")
