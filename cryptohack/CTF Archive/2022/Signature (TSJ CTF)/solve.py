"""Solve Signature (TSJ CTF 2022).

Challenge:
  ECDSA on secp256k1 where nonce is k = d XOR z (both 256-bit: private key XOR sha256 hash).
  Given 6 (z, r, s) triples and AES-CTR(key = sha256(str(d))[:16]) encrypted flag (nonce not printed).

Attack:
  k = z + Σ d_i · 2^i · (1 - 2·z_i) so sig equation s·k ≡ z + r·d mod q becomes a linear
  constraint mod q on unknown bits d_i ∈ {0,1}. 6 such equations with 256 binary unknowns →
  Kannan-embedding lattice, LLL directly recovers d (target vector ~ sqrt(popcount(d) + 1) ≪ GH).

Flag decryption:
  pycryptodome AES.new(key, MODE_CTR) with no nonce arg ⇒ random 8-byte nonce, 64-bit counter at 0.
  Nonce not in output.txt, but known plaintext prefix "Congrats! This is your flag: " gives
  keystream[:16]. AES_ECB_decrypt(key, keystream[:16]) = nonce || counter(=0). Verify last 8 bytes
  are zero, then decrypt rest.
"""
import ast
import os
import subprocess
import sys
import time
from hashlib import sha256
from Crypto.Cipher import AES


HERE = os.path.dirname(os.path.abspath(__file__))


def parse_output(path):
    sigs = []
    ct = None
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            if line.startswith("b'") or line.startswith('b"'):
                ct = ast.literal_eval(line)
            else:
                parts = line.split()
                if len(parts) == 3:
                    sigs.append(tuple(int(p) for p in parts))
    return sigs, ct


def run_sage(sigs, timeout=600):
    inp = "\n".join(f"{z} {r} {s}" for z, r, s in sigs) + "\n"
    wdir = HERE.replace("D:", "/d").replace("\\", "/")
    cmd = [
        "docker", "run", "--rm", "-i",
        "-v", f"{wdir}:/work", "-w", "/work",
        "sagemath/sagemath:latest", "sage", "solve.sage",
    ]
    env = os.environ.copy()
    env["MSYS_NO_PATHCONV"] = "1"
    res = subprocess.run(cmd, input=inp, capture_output=True, text=True, timeout=timeout, env=env)
    sys.stderr.write(res.stderr)
    if res.returncode != 0:
        raise RuntimeError(f"sage failed (rc={res.returncode})")
    return int(res.stdout.strip().split()[-1])


def decrypt(d, ct):
    key = sha256(str(d).encode()).digest()[:16]
    known = b"Congrats! This is your flag: "
    ks0 = bytes(a ^ b for a, b in zip(ct[:16], known[:16]))
    iv = AES.new(key, AES.MODE_ECB).decrypt(ks0)
    nonce, ctr_init = iv[:8], iv[8:]
    if ctr_init != b"\x00" * 8:
        raise RuntimeError(f"counter init not zero: {ctr_init.hex()}")
    cipher = AES.new(key, AES.MODE_CTR, nonce=nonce)
    return cipher.decrypt(ct)


def main():
    sigs, ct = parse_output(os.path.join(HERE, "output.txt"))
    assert len(sigs) == 6, f"expected 6 sigs, got {len(sigs)}"
    assert ct is not None
    print(f"[*] got {len(sigs)} sigs, ct={len(ct)} bytes")
    t0 = time.time()
    d = run_sage(sigs)
    print(f"[+] d recovered in {time.time()-t0:.1f}s")
    pt = decrypt(d, ct)
    print(pt.decode(errors="replace"))


if __name__ == "__main__":
    main()
