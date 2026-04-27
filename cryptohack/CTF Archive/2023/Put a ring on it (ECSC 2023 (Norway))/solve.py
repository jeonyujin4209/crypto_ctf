"""
Put a ring on it -- ECSC 2023 (Norway)

Vulnerability: Python loop variable scope leak in `ring_sign`.

After the for-loop ends, the variable `q` keeps the value from the LAST
iteration (i = RING_SIZE-1 = 15). The signer's response is then computed:
    sigr[my_index] = (q - sigc[my_index] * my_privkey) mod l

If my_index == 15, q is the signer's own nonce -> standard sig.
If my_index <  15, q is the q from the non-signer branch at i=15, which is
exactly sigr[15]. Hence:
    sigr[my_index] = sigr[15] - sigc[my_index] * sk   (mod l)
=>  sk = (sigr[15] - sigr[my_index]) * sigc[my_index]^{-1} mod l

For each candidate index in 0..14, derive sk, compute pk, compare with
public_keys[idx]. The match identifies my_index. If no match in 0..14, the
signer is index 15.

With my_index recovered for all 16 levels, AES-CBC key = first byte (hex pair)
of each my_pubkey concatenated. Decrypt -> flag.
"""
import json
import os
from hashlib import sha256
from Crypto.Cipher import AES

import ed25519

HERE = os.path.dirname(os.path.abspath(__file__))
RING_SIZE = 16


def hexlify(inp):
    return inp.encode('latin-1').hex()


def unhexlify(inp):
    return bytes.fromhex(inp).decode('latin-1')


def public_key(sk):
    return hexlify(ed25519.encodepoint(ed25519.scalarmultbase(sk)))


def main():
    with open(os.path.join(HERE, "data.json")) as f:
        data = json.load(f)

    l = ed25519.l
    my_indices = []

    for lvl_idx, level in enumerate(data["levels"]):
        image, sigc, sigr = level["signature"]
        pks = level["public_keys"]

        my_index = None
        for cand in range(RING_SIZE - 1):  # 0..14
            if sigc[cand] == 0:
                continue
            try:
                inv = pow(sigc[cand], -1, l)
            except ValueError:
                continue
            sk = (sigr[RING_SIZE - 1] - sigr[cand]) * inv % l
            pk = public_key(sk)
            if pk == pks[cand]:
                my_index = cand
                break

        if my_index is None:
            my_index = RING_SIZE - 1  # 15

        my_indices.append(my_index)
        print(f"level {lvl_idx}: my_index = {my_index}, first byte = {pks[my_index][:2]}")

    # AES-CBC decrypt
    aes_key = bytes.fromhex("".join(
        data["levels"][i]["public_keys"][my_indices[i]][:2]
        for i in range(len(data["levels"]))
    ))
    iv = bytes.fromhex(data["iv"])
    ct = bytes.fromhex(data["enc"])
    pt = AES.new(aes_key, AES.MODE_CBC, iv).decrypt(ct)
    print("AES key:", aes_key.hex())
    print("Flag:", pt)


if __name__ == "__main__":
    main()
