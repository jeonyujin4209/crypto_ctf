"""
MD0 (Length Extension) — POC solver

Hash construction in 13388.py:
    def hash(data):
        data = pad(data, 16)                                # PKCS7 to 16-byte multiples
        out = b"\\x00" * 16
        for blk in 16-byte chunks of data:
            out = AES_ECB(key=blk).encrypt(out) XOR out     # Davies-Meyer with AES
        return out

Sign oracle: sig = hash(KEY || data). KEY is 16 random bytes. We don't know KEY,
but we know its length is exactly 16, which lets us run a textbook length-extension.

Attack:
  1. Sign data = b"". The server hashes (KEY || b"").
     Because PKCS7 always adds at least one byte (and a full block when already
     aligned), the actual input is KEY || b"\\x10"*16 (length 32, two blocks).
     The returned state S is the hash *and also* the chaining value at the end of
     processing those 2 blocks. Since the next AES call only depends on S and the
     next block, we can extend it without knowing KEY.
  2. Choose admin_payload = b"admin=True;" + zero pad to 16 bytes.
  3. Send get_flag with
        data = b"\\x10"*16 || admin_payload
     The server now hashes (KEY || data) = KEY || b"\\x10"*16 || admin_payload,
     which is 48 bytes (multiple of 16). PKCS7 adds an extra block of b"\\x10"*16.
     Block stream: [KEY, b"\\x10"*16, admin_payload, b"\\x10"*16]
     After block 2 the chaining value equals S (which we already have).
     Blocks 3 and 4 are admin_payload and the trailing pad block — both known
     plaintext, so we can finish the chain locally.
  4. Submit (data, forged_sig). admin=True is in data, so the server returns FLAG.

POC: this script is identical against socket.cryptohack.org port 13388 — change HOST.
"""

import json
import socket
import sys
from Crypto.Cipher import AES

HOST = "socket.cryptohack.org"
PORT = 13388


def bxor(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))


def continue_hash(state: bytes, blocks: list[bytes]) -> bytes:
    """Davies-Meyer compression: out = AES_{blk}(out) XOR out, for each 16-byte blk."""
    for blk in blocks:
        assert len(blk) == 16
        state = bxor(AES.new(blk, AES.MODE_ECB).encrypt(state), state)
    return state


def recv_json_line(f) -> dict:
    line = f.readline()
    if not line:
        raise ConnectionError("server closed")
    return json.loads(line.decode())


def send_json(f, obj: dict) -> None:
    f.write((json.dumps(obj) + "\n").encode())


def main() -> None:
    sock = socket.create_connection((HOST, PORT))
    sock.settimeout(10)
    f = sock.makefile("rwb", buffering=0)

    greeting = f.readline()
    print("greeting:", greeting.decode().strip())

    # 1. Sign empty data → recover hash(KEY || b"") = chaining state after 2 blocks
    send_json(f, {"option": "sign", "message": ""})
    resp = recv_json_line(f)
    assert "signature" in resp, f"sign failed: {resp}"
    S = bytes.fromhex(resp["signature"])
    print("S = hash(KEY) =", S.hex())

    # 2. Forge a get_flag request
    admin_payload = b"admin=True;" + b"\x00" * (16 - len(b"admin=True;"))
    assert len(admin_payload) == 16

    data_forged = b"\x10" * 16 + admin_payload  # 32 bytes; (KEY || data) = 48 bytes
    pad_block = b"\x10" * 16  # PKCS7 of a 48-byte input

    sig_forged = continue_hash(S, [admin_payload, pad_block])
    print("forged sig    =", sig_forged.hex())
    print("forged data   =", data_forged.hex())

    # 3. Claim the flag
    send_json(f, {
        "option": "get_flag",
        "message": data_forged.hex(),
        "signature": sig_forged.hex(),
    })
    resp = recv_json_line(f)
    print("server reply  :", resp)
    if "flag" in resp:
        print()
        print("FLAG:", resp["flag"])
        return

    print("forge failed", file=sys.stderr)
    sys.exit(1)


if __name__ == "__main__":
    main()
