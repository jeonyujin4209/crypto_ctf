#!/usr/bin/env python3
from pwn import *
import json

context.log_level = 'error'
r = remote('socket.cryptohack.org', 13422)
r.recvline()

def send(obj):
    r.sendline(json.dumps(obj).encode())
    return json.loads(r.recvline().decode())

def count_false(crafted, cipher_block, n=10):
    data = (bytes(crafted) + cipher_block).hex()
    fc = 0
    for _ in range(n):
        if not send({"option": "unpad", "ct": data})["result"]:
            fc += 1
    return fc

resp = send({"option": "encrypt"})
ct = bytes.fromhex(resp["ct"])
iv, c1, c2 = ct[:16], ct[16:32], ct[32:48]

HEX_CHARS = b'0123456789abcdef'

def recover_block(prev_block, cipher_block):
    intermediary = [0] * 16
    plaintext = [0] * 16
    for bp in range(15, -1, -1):
        pv = 16 - bp
        crafted = bytearray(16)
        for k in range(bp + 1, 16):
            crafted[k] = intermediary[k] ^ pv
        best_fc = 999
        best = None
        for hc in HEX_CHARS:
            inter = hc ^ prev_block[bp]
            crafted[bp] = inter ^ pv
            fc = count_false(crafted, cipher_block)
            if fc < best_fc:
                best_fc = fc
                best = (inter, hc)
        intermediary[bp] = best[0]
        plaintext[bp] = best[1]
    return bytes(plaintext)

p2 = recover_block(c1, c2)
p1 = recover_block(iv, c1)
message = (p1 + p2).decode('ascii')
resp = send({"option": "check", "message": message})
print(resp)
r.close()
# crypto{even_a_faulty_oracle_leaks_all_information}
