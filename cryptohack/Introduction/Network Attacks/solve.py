#!/usr/bin/env python3

from pwn import *
import json

context.log_level = 'error'
r = remote('socket.cryptohack.org', 11112)

for _ in range(4):
    r.readline()

request = json.dumps({"buy": "flag"}).encode()
r.sendline(request)

response = json.loads(r.readline().decode())
print(response)
# {'flag': 'crypto{sh0pp1ng_f0r_fl4g5}'}
r.close()
