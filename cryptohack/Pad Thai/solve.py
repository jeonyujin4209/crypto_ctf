#!/usr/bin/env python3
from pwn import *
import json

context.log_level = 'error'
r = remote('socket.cryptohack.org', 13421)
r.recvline()

def send(obj):
    r.sendline(json.dumps(obj).encode())
    return json.loads(r.recvline().decode())

resp = send({"option": "encrypt"})
ct = bytes.fromhex(resp["ct"])
iv, c1, c2 = ct[:16], ct[16:32], ct[32:48]

def check_pad(iv_block, ct_block):
    data = (iv_block + ct_block).hex()
    return send({"option": "unpad", "ct": data})["result"]

def recover_block(prev_block, cipher_block):
    intermediary = [0] * 16
    plaintext = [0] * 16
    for bp in range(15, -1, -1):
        pv = 16 - bp
        crafted = bytearray(16)
        for k in range(bp + 1, 16):
            crafted[k] = intermediary[k] ^ pv
        for guess in range(256):
            crafted[bp] = guess
            if check_pad(bytes(crafted), cipher_block):
                if pv == 1 and bp > 0:
                    verify = bytearray(crafted)
                    verify[bp - 1] ^= 1
                    if not check_pad(bytes(verify), cipher_block):
                        continue
                intermediary[bp] = guess ^ pv
                plaintext[bp] = intermediary[bp] ^ prev_block[bp]
                break
    return bytes(plaintext)

p2 = recover_block(c1, c2)
p1 = recover_block(iv, c1)
message = (p1 + p2).decode('ascii')

resp = send({"option": "check", "message": message})
print(resp)
r.close()
# crypto{if_you_ask_enough_times_you_usually_get_what_you_want}
