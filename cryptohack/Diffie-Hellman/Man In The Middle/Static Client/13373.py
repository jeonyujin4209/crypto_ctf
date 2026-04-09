"""
Local simulation of the Static Client (DH MITM) challenge.

The real CryptoHack server isn't shipped — only the README ever existed in the
public download. This file is a minimal *re-creation* faithful enough to test
the POC solver locally:

  * Bob has a STATIC private key `b` (drawn once when the listener starts and
    kept across reconnections — that is the bug we exploit).
  * On every connection, the server simulates a fresh Alice-to-Bob handshake
    over a fixed safe-prime DH group, encrypts the FLAG with the resulting
    shared secret (SHA-1(str(shared))[:16], AES-CBC), and prints the entire
    transcript as three JSON lines (Alice → Bob → Alice).
  * After printing the transcript, the server lets the client send its OWN
    {p, g, A} message and replies with B = g^b mod p — using the *same* static
    `b`. That is what we abuse with a smooth-prime DLP.

This simulation is the same shape as CryptoHack's official chall files
(uses utils.listener via builtins.Challenge) so it runs unmodified through
the local listener shim.
"""

import builtins
import hashlib
import json
import os
import secrets

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad

from utils import listener


FLAG = b"crypto{??????????????????????????????}"

# 1024-bit safe prime ( = 2 * Sophie-Germain + 1 ) used by the (sim) server.
# Generated once and pasted in for reproducibility — taken from RFC 2409 group 2
# (Oakley group 2). It's a true safe prime so subgroup of order q = (p-1)/2.
P_ORIG = int(
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E08"
    "8A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B"
    "302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9"
    "A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE6"
    "49286651ECE65381FFFFFFFFFFFFFFFF",
    16,
)
G_ORIG = 2

# Bob's STATIC long-term key — drawn once at process startup. Same value across
# every Challenge() instantiation. The vulnerability is: a real Bob would
# rotate this key and validate the prime, while the sim/CTF server doesn't.
# Match real CryptoHack: Bob's secret is smaller than the smooth prime the
# attacker will pick (~800 bits), so DLP mod p_smooth-1 fully recovers it.
BOB_PRIVATE = secrets.randbelow(1 << 256) + 2


class Challenge:
    def __init__(self):
        # Fresh Alice for this connection (only used to populate the eavesdrop).
        a = secrets.randbelow(P_ORIG - 2) + 2
        A = pow(G_ORIG, a, P_ORIG)
        B = pow(G_ORIG, BOB_PRIVATE, P_ORIG)

        shared = pow(A, BOB_PRIVATE, P_ORIG)
        key = hashlib.sha1(str(shared).encode("ascii")).digest()[:16]
        iv = os.urandom(16)
        encrypted = AES.new(key, AES.MODE_CBC, iv).encrypt(pad(FLAG, 16))

        # Three JSON lines, just like the original transcript dump.
        lines = [
            json.dumps({"p": hex(P_ORIG), "g": hex(G_ORIG), "A": hex(A)}),
            json.dumps({"B": hex(B)}),
            json.dumps({"iv": iv.hex(), "encrypted": encrypted.hex()}),
        ]
        self.before_input = "\n".join(lines) + "\n"

    def challenge(self, msg):
        # Client (us) plays Alice with arbitrary parameters.
        if not all(k in msg for k in ("p", "g", "A")):
            return {"error": "send {p, g, A}"}
        try:
            p = int(msg["p"], 16)
            g = int(msg["g"], 16)
            _A = int(msg["A"], 16)
        except (TypeError, ValueError):
            return {"error": "p, g, A must be hex strings"}
        # Bob's response: B = g^b mod p, with the SAME static b regardless of p.
        B = pow(g, BOB_PRIVATE, p)
        return {"B": hex(B)}


builtins.Challenge = Challenge
listener.start_server(port=13373)
