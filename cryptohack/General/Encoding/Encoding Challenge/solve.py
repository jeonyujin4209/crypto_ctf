#!/usr/bin/env python3

from pwn import *
import json, base64, codecs
from Crypto.Util.number import long_to_bytes

context.log_level = 'error'
r = remote('socket.cryptohack.org', 13377)

def json_recv():
    return json.loads(r.recvline().decode())

def json_send(obj):
    r.sendline(json.dumps(obj).encode())

def decode(t, encoded):
    if t == 'base64':
        return base64.b64decode(encoded).decode()
    elif t == 'hex':
        return bytes.fromhex(encoded).decode()
    elif t == 'rot13':
        return codecs.decode(encoded, 'rot_13')
    elif t == 'bigint':
        return long_to_bytes(int(encoded, 16)).decode()
    elif t == 'utf-8':
        return ''.join(chr(c) for c in encoded)

for i in range(100):
    data = json_recv()
    if 'flag' in data:
        print(data['flag'])
        break
    decoded = decode(data['type'], data['encoded'])
    json_send({'decoded': decoded})

final = json_recv()
print(final)
# {'flag': 'crypto{3nc0d3_d3c0d3_3nc0d3}'}
r.close()
