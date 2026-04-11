"""
Stage 1: collect LWE samples + flag ciphertexts from the live server.
Saves to samples.json so the Sage solver (solve.sage) can do the BKZ.

Run:  python collect.py
Then: bash infra/sage-run.sh cryptohack/.../Noise\ Cheap/solve.sage
"""
import ast
import json
import socket
import sys

HOST = "socket.cryptohack.org"
PORT = 13413
N = 64
EXTRA = 60   # m extra samples for the lattice
FLAG_LEN = 32  # crypto{...} is 32 bytes


def query(f, payload):
    f.write((json.dumps(payload) + "\n").encode())
    line = f.readline()
    if not line:
        raise ConnectionError("server closed")
    return json.loads(line.decode())


def main():
    sock = socket.create_connection((HOST, PORT))
    sock.settimeout(15)
    f = sock.makefile("rwb", buffering=0)
    f.readline()  # greeting

    samples = []
    print(f"[*] collecting {N + EXTRA} m=0 LWE samples...")
    for _ in range(N + EXTRA):
        r = query(f, {"option": "encrypt", "message": 0})
        samples.append({"A": ast.literal_eval(r["A"]), "b": int(r["b"])})

    print(f"[*] collecting {FLAG_LEN} flag ciphertexts...")
    flag_cts = []
    for i in range(FLAG_LEN):
        r = query(f, {"option": "get_flag", "index": i})
        if "error" in r:
            break
        flag_cts.append({"A": ast.literal_eval(r["A"]), "b": int(r["b"])})

    sock.close()
    out = {"samples": samples, "flag_cts": flag_cts}
    with open("samples.json", "w") as fh:
        json.dump(out, fh)
    print(f"[+] wrote samples.json ({len(samples)} encs, {len(flag_cts)} flag bytes)")


if __name__ == "__main__":
    main()
