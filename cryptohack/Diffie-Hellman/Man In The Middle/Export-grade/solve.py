# Export-grade (100pts) - Downgrade attack
# Force DH64 (weakest) → solve discrete log → decrypt
import socket, json, re, hashlib, time
from Crypto.Cipher import AES
from sympy.ntheory import discrete_log

def recv_all(s):
    data = b''
    while True:
        try:
            data += s.recv(8192)
            time.sleep(0.3)
        except: break
    return data.decode()

s = socket.socket()
s.connect(('socket.cryptohack.org', 13379))
s.settimeout(5)

# 1. Alice: supported DH groups
raw = recv_all(s)
print(f"[1] Alice: {raw.strip()}")
alice = json.loads(re.search(r'\{[^{}]+\}', raw).group())

# 2. Send only DH64 to Bob (downgrade)
s.send(json.dumps({"supported": ["DH64"]}).encode() + b'\n')
print("[2] → Bob: only DH64")

# 3. Bob chooses DH64, sends p, g, B
time.sleep(1)
raw = recv_all(s)
print(f"[3] Bob: {raw[:200]}")
bob = json.loads(re.search(r'\{[^{}]+\}', raw).group())

# 4. Relay Bob's choice to Alice
s.send(json.dumps(bob).encode() + b'\n')
print("[4] → Alice: relay Bob's params")

# 5. Alice sends A
time.sleep(1)
raw = recv_all(s)
print(f"[5] Alice: {raw[:200]}")
alice2 = json.loads(re.search(r'\{[^{}]+\}', raw).group())

# Relay A to Bob
s.send(json.dumps(alice2).encode() + b'\n')
print("[6] → Bob: relay Alice's A")

# Now we have p, g, A, B. Solve DLP on DH64 (64-bit prime - easy!)
p = int(bob['p'], 16)
g = int(bob['g'], 16)
B = int(bob['B'], 16)
A = int(alice2['A'], 16)

print(f"\n[*] p = {p} ({p.bit_length()} bits)")
print(f"[*] g = {g}")
print(f"[*] A = {A}")
print(f"[*] B = {B}")

# Solve DLP: find b such that g^b = B mod p
print("[*] Solving discrete log...")
b = discrete_log(p, B, g)
print(f"[*] b = {b}")

# shared = A^b mod p
shared = pow(A, b, p)
print(f"[*] shared = {shared}")

# 7. Get encrypted flag
time.sleep(2)
raw = recv_all(s)
print(f"\n[7] Encrypted: {raw[:300]}")

for m in re.finditer(r'\{[^{}]+\}', raw):
    msg = json.loads(m.group())
    if 'iv' in msg:
        for k, v in msg.items():
            if 'encrypt' in k.lower():
                sha1 = hashlib.sha1()
                sha1.update(str(shared).encode('ascii'))
                key = sha1.digest()[:16]
                pt = AES.new(key, AES.MODE_CBC, bytes.fromhex(msg['iv'])).decrypt(bytes.fromhex(v))
                print(f"[+] {pt}")

s.close()
