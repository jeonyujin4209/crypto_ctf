"""
Checkpoint — invalid-curve attack on ECDH (NIST P-256 with no on-curve check).

The server's `point_addition` uses only `(p, a)` (not `b`); so submitting a
(Qx, Qy) that lies on E': y^2 = x^3 + a*x + b' (any b') makes the server
compute s*Q on E' instead of P-256. Pick E' whose order has small prime
factors → recover s mod q via PH-style oracle brute force, then CRT.

Oracle per query: server sets shared_key = SHA256(str((s*Q).x))[:16] and
responds with AES_CBC(shared_key, "SERVER_TEST_MESSAGE"). Brute-force k in
[0, q) by recomputing (k*Q).x → key → decrypt → compare prefix.

After CRT yields s exactly, reuse the eavesdropped client_pub to compute
the real shared point on P-256 and decrypt the FLAG.
"""
from sage.all import *
import json, socket, sys, time, re
from hashlib import sha256
from Crypto.Cipher import AES

# NIST P-256
p_256 = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF
a_256 = p_256 - 3
b_256 = 0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B
Gx_256 = 0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296
Gy_256 = 0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5

F = GF(p_256)
E_real = EllipticCurve(F, [a_256, b_256])

with open('curves.json') as f:
    CURVES = json.load(f)

# Sort by q descending — query larger q first per failure skill recommendation
# (smaller q has higher s%q==0 probability but here s%q==0 is informative,
#  not fatal — still ordering by q desc lets us hit our bit target faster).
CURVES.sort(key=lambda c: -c['q'])

HOST = "socket.cryptohack.org"
PORT = int(13419)


def sock_connect():
    s = socket.create_connection((HOST, PORT), timeout=15)
    return s


def recv_until(sock, marker):
    buf = b""
    while marker not in buf:
        c = sock.recv(8192)
        if not c:
            break
        buf += c
    return buf


def send_json(sock, obj):
    sock.send((json.dumps(obj) + "\n").encode())


def recv_line(sock):
    buf = b""
    while not buf.endswith(b"\n"):
        c = sock.recv(8192)
        if not c:
            break
        buf += c
    return buf


def parse_greet(greet_text):
    """Extract client_pub Point and FLAG ciphertext from before_input text."""
    cp_match = re.search(r"client->server : Point\(x=(\d+), y=(\d+)\)", greet_text)
    flag_match = re.search(r"server->client : ([0-9a-f]+)\n", greet_text)
    cx = int(cp_match.group(1))
    cy = int(cp_match.group(2))
    flag_hex = flag_match.group(1)
    return cx, cy, bytes.fromhex(flag_hex)


def query_oracle(sock, Qx, Qy):
    """Send Q, return None if error / bytes test_ct otherwise."""
    send_json(sock, {
        "option": "start_key_exchange",
        "Qx": hex(Qx),
        "Qy": hex(Qy),
        "ciphersuite": "ECDHE_P256_WITH_AES_128",
    })
    r = json.loads(recv_line(sock).decode())
    if "error" in r.get("msg", "").lower():
        return None
    send_json(sock, {"option": "get_test_message"})
    r = json.loads(recv_line(sock).decode())
    return bytes.fromhex(r["msg"])


def brute_force_residue(bp, q, Qx, Qy, test_ct):
    """Find k in [0, q) such that (k*Q on E') gives the right shared_key."""
    iv = test_ct[:16]
    ct = test_ct[16:]
    Eb = EllipticCurve(F, [a_256, bp])
    Q = Eb(Qx, Qy)
    assert int(Q.order()) == q

    # k=0 corresponds to shared = O → server would have errored; skip
    P = Q
    t0 = time.time()
    for k in range(1, q):
        x = int(P[0])
        key = sha256(str(x).encode()).digest()[:16]
        cipher = AES.new(key, AES.MODE_CBC, iv)
        dec = cipher.decrypt(ct)
        if dec.startswith(b"SERVER_TEST_MESSAGE"):
            print(f"    [+] k={k}/{q} ({time.time()-t0:.1f}s)")
            return k
        P = P + Q
    return None


def main():
    sock = sock_connect()
    sock.settimeout(3)
    greet = b""
    try:
        while True:
            c = sock.recv(8192)
            if not c:
                break
            greet += c
    except socket.timeout:
        pass
    sock.settimeout(15)
    text = greet.decode(errors='replace')
    print(text)
    cx, cy, flag_ct = parse_greet(text)
    client_pub = E_real(cx, cy)
    print(f"[+] client_pub on real P-256 ✓")
    print(f"[+] flag ct {len(flag_ct)} bytes")

    residues = []  # list of (k, q)
    prod = Integer(1)

    for entry in CURVES:
        bp = entry['bp']
        q = entry['q']
        Qx = entry['Qx']
        Qy = entry['Qy']
        print(f"[*] querying b'={bp} q={q} ({q.bit_length()}b)...")
        test_ct = query_oracle(sock, Qx, Qy)
        if test_ct is None:
            print(f"    [-] server error — likely s%q == 0 → residue 0")
            residues.append((0, q))
        else:
            k = brute_force_residue(bp, q, Qx, Qy, test_ct)
            if k is None:
                print(f"    [-] no match — Q maybe wrong order")
                continue
            residues.append((int(k), q))
        prod *= q
        print(f"    accumulated bits = {prod.bit_length()}")
        if prod.bit_length() >= 257:
            print("[*] enough bits collected.")
            break

    sock.close()

    # X-only oracle gives ±(s mod q) ambiguity per residue. Iterate signs.
    print("[*] running CRT with sign disambiguation...")
    iv = flag_ct[:16]
    ct = flag_ct[16:]

    from itertools import product as iproduct
    n = len(residues)
    M = int(prod)

    # Optimization: fix the first residue's sign (overall sign global), iterate 2^(n-1)
    base_r, base_m = residues[0]
    other = residues[1:]

    found = False
    for signs in iproduct([1, -1], repeat=n-1):
        rs = [base_r] + [(s_ * r) % m for ((r, m), s_) in zip(other, signs)]
        ms = [base_m] + [m for (_, m) in other]
        s = int(CRT_list(rs, ms))
        # Try both s and M-s (global sign)
        for cand in (s, (M - s) % M):
            if cand == 0:
                continue
            shared = int(cand) * client_pub
            sx = int(shared[0])
            key = sha256(str(sx).encode()).digest()[:16]
            cipher = AES.new(key, AES.MODE_CBC, iv)
            pt = cipher.decrypt(ct)
            if pt.startswith(b"crypto{"):
                print(f"[+] FLAG = {pt}")
                print(f"[+] s = {cand}")
                found = True
                break
        if found:
            break
    if not found:
        print("[-] no valid s found")


main()
