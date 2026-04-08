# Parameter Injection (60pts) - MITM on DH
# Send B=1 to Alice → Alice computes shared = 1^a mod p = 1
# Decrypt flag with shared=1
import socket, json, re, hashlib, time
from Crypto.Cipher import AES

s = socket.socket()
s.connect(('socket.cryptohack.org', 13371))
s.settimeout(5)

# 1. Recv Alice's {p, g, A}
raw = b''
while True:
    try: raw += s.recv(8192); time.sleep(0.2)
    except: break
alice = json.loads(re.search(r'\{[^{}]+\}', raw.decode()).group())

# 2. Relay Alice to Bob unchanged
s.send(json.dumps(alice).encode() + b'\n')

# 3. Recv Bob's {B}
time.sleep(1)
raw = b''
while True:
    try: raw += s.recv(8192); time.sleep(0.2)
    except: break

# 4. Send B=1 to Alice → shared = 1
s.send(json.dumps({'B': '0x1'}).encode() + b'\n')

# 5. Recv encrypted flag
time.sleep(2)
raw = b''
for _ in range(3):
    try: raw += s.recv(8192)
    except: pass
    time.sleep(1)

msg = json.loads(re.search(r'\{[^{}]+\}', raw.decode()).group())

# Decrypt with shared=1
sha1 = hashlib.sha1()
sha1.update(b'1')
key = sha1.digest()[:16]
pt = AES.new(key, AES.MODE_CBC, bytes.fromhex(msg['iv'])).decrypt(bytes.fromhex(msg['encrypted_flag']))
print(pt.decode().rstrip('\x00'))
# crypto{n1c3_0n3_m4ll0ry!!!!!!!!}
s.close()
