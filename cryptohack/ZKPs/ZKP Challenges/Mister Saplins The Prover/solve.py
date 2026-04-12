"""
Mister Saplins The Prover (125pts) - Multi-connection Merkle tree leak

VULNERABILITY ANALYSIS:
========================
The Merkle tree uses datas = secret(17 bytes) + FLAG(47 bytes) = 64 bytes.
Leaves are hash of 8-byte chunks: leaf_i = SHA256(datas[8*i : 8*i+8])

Key observation about datas layout:
  datas[0:8]   = secret[0:8]   -> leaf0  (random)
  datas[8:16]  = secret[8:16]  -> leaf1  (random)
  datas[16:24] = secret[16] + FLAG[0:7] = secret[16] + b'crypto{' -> leaf2
  datas[24:32] = FLAG[7:15]    -> leaf3  (CONSTANT - no secret!)
  datas[32:40] = FLAG[15:23]   -> leaf4  (CONSTANT)
  datas[40:48] = FLAG[23:31]   -> leaf5  (CONSTANT)
  datas[48:56] = FLAG[31:39]   -> leaf6  (CONSTANT)
  datas[56:64] = FLAG[39:47]   -> leaf7  (CONSTANT)

Since leaf3-7 depend ONLY on the FLAG (not the random secret),
they are IDENTICAL across all TCP connections!

EXPLOIT STRATEGY:
=================
Step 1 - Collect constant leaves via separate connections:
  Connection 1: get_node(3) -> leaf3
  Connection 2: get_node(4) -> leaf4
  Connection 3: get_node(5) -> leaf5
  Connection 4: get_node(6) -> leaf6
  Connection 5: get_node(7) -> leaf7

  Compute: n1_2 = merge(leaf4, leaf5)
           n1_3 = merge(leaf6, leaf7)
           n2_1 = merge(n1_2, n1_3)   <- CONSTANT subtree root (right half)

Step 2 - Final connection: exploit negative-index bypass AND brute-force:
  get_node(-1) -> nodes[0][-1] = nodes[0][8] = nodes[1][0] = n1_0
    (negative indices satisfy `wanted_node < 8` condition, bypassing the
     normal 0-7 range restriction, giving access to the appended internal node)

  Now brute-force secret[16] (only 256 values):
    leaf2_candidate = SHA256(bytes([b]) + b'crypto{')
    n1_1_candidate  = merge(leaf2_candidate, leaf3)
    n2_0_candidate  = merge(n1_0, n1_1_candidate)
    root_candidate  = merge(n2_0_candidate, n2_1)

  Use do_proof(root_candidate) as oracle to confirm the correct root.
  do_proof can be called repeatedly (no state change on failure).
  At most 256 calls needed -> FLAG returned on success!
"""
import json
import socket
from hashlib import sha256

HOST = "socket.cryptohack.org"
PORT = 13432


# ── Crypto helpers ─────────────────────────────────────────────────────────────

def hash256(data: bytes) -> bytes:
    return sha256(data).digest()


def merge(a: bytes, b: bytes) -> bytes:
    return hash256(a + b)


# ── Network helpers ─────────────────────────────────────────────────────────────

def recv_line(sock, timeout: float = 8.0) -> str:
    sock.settimeout(timeout)
    buf = b""
    while not buf.endswith(b"\n"):
        chunk = sock.recv(4096)
        if not chunk:
            break
        buf += chunk
    return buf.decode()


def send_json(sock, obj: dict) -> None:
    sock.send((json.dumps(obj) + "\n").encode())


def get_one_leaf(leaf_index: int) -> bytes:
    """Open a fresh connection, fetch the leaf at leaf_index, close."""
    sock = socket.create_connection((HOST, PORT))
    recv_line(sock)  # welcome banner
    send_json(sock, {"option": "get_node", "node": leaf_index})
    resp = json.loads(recv_line(sock))
    sock.close()
    assert "msg" in resp, f"unexpected response: {resp}"
    return bytes.fromhex(resp["msg"])


# ── Step 1: Collect constant leaves (leaf3 – leaf7) via separate connections ───

print("[*] Step 1: Collecting constant leaves (depend only on FLAG, not secret)")
constant_leaves = {}
for i in range(3, 8):
    leaf = get_one_leaf(i)
    constant_leaves[i] = leaf
    print(f"    leaf{i} = {leaf.hex()[:16]}...")

leaf3 = constant_leaves[3]
leaf4 = constant_leaves[4]
leaf5 = constant_leaves[5]
leaf6 = constant_leaves[6]
leaf7 = constant_leaves[7]

# Compute the constant right-half subtree
n1_2 = merge(leaf4, leaf5)
n1_3 = merge(leaf6, leaf7)
n2_1 = merge(n1_2, n1_3)
print(f"[+] n2_1 (constant right subtree) = {n2_1.hex()[:16]}...")


# ── Step 2: Final connection – negative-index bypass + 256-guess brute-force ───

print("\n[*] Step 2: Final connection")
sock = socket.create_connection((HOST, PORT))
recv_line(sock)  # welcome banner

# Exploit: index -1 satisfies (wanted_node < 8) while giving nodes[0][8] = nodes[1][0]
send_json(sock, {"option": "get_node", "node": -1})
resp = json.loads(recv_line(sock))
assert "msg" in resp, f"get_node(-1) failed: {resp}"
n1_0 = bytes.fromhex(resp["msg"])
print(f"[+] n1_0 (via index -1) = {n1_0.hex()[:16]}...")

# Brute-force secret[16] (256 possibilities)
# leaf2 = SHA256(secret[16]  ||  b'crypto{')
# Only 1 byte of secret bleeds into leaf2; the other 7 bytes are known (FLAG prefix).
print("[*] Brute-forcing secret[16] (256 candidates)...")
flag = None
for b in range(256):
    leaf2_candidate = hash256(bytes([b]) + b"crypto{")
    n1_1_candidate  = merge(leaf2_candidate, leaf3)
    n2_0_candidate  = merge(n1_0, n1_1_candidate)
    root_candidate  = merge(n2_0_candidate, n2_1)

    send_json(sock, {"option": "do_proof", "root": root_candidate.hex()})
    resp = json.loads(recv_line(sock))

    if "msg" in resp and resp["msg"] != "you failed!":
        flag = resp["msg"]
        print(f"[+] Found! secret[16] = {b}")
        print(f"[+] Root = {root_candidate.hex()}")
        break
    # if "you failed!" we just try the next candidate

if flag:
    print(f"\n[*] FLAG: {flag}")
else:
    print("\n[-] Brute-force failed – unexpected (all 256 candidates exhausted)")

sock.close()
