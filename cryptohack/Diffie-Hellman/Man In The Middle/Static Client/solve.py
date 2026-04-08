# Static Client (100pts)
# Send smooth prime where g=2 is primitive root → DLP solvable → recover b
import socket, json, re, hashlib, time, sys, random
from sympy import nextprime, isprime, discrete_log, factorint
from Crypto.Cipher import AES

def connect():
    s = socket.socket()
    s.connect(('socket.cryptohack.org', 13373))
    s.settimeout(5)
    return s

def recv(s):
    data = b''
    while True:
        try:
            chunk = s.recv(8192)
            if not chunk: break
            data += chunk
            time.sleep(0.3)
        except: break
    return data.decode()

def extract_jsons(text):
    return [json.loads(m.group()) for m in re.finditer(r'\{[^{}]+\}', text)]

# Step 0: Generate smooth prime where g=2 is primitive root
print("[0] Generating smooth prime (g=2 primitive root)..."); sys.stdout.flush()
while True:
    n = 2
    q = 2
    while n.bit_length() < 800:
        q = int(nextprime(q))
        n *= q
    for _ in range(random.randint(0, 30)):
        n *= random.choice([2, 3, 5, 7, 11, 13])
    p_smooth = n + 1
    if isprime(p_smooth):
        # Verify g=2 is primitive root
        factors = factorint(n)
        if all(pow(2, n // f, p_smooth) != 1 for f in factors):
            print(f"  Found: {p_smooth.bit_length()} bits"); sys.stdout.flush()
            break

# Step 1: Eavesdrop
print("[1] Eavesdropping..."); sys.stdout.flush()
s = connect()
raw = recv(s)
jsons = extract_jsons(raw)
p_orig = int(jsons[0]['p'], 16)
A_alice = int(jsons[0]['A'], 16)
B_bob = int(jsons[1]['B'], 16)
alice_iv = jsons[2]['iv']
alice_ct = jsons[2]['encrypted']
s.close()

# Step 2: Send smooth prime
print("[2] Sending smooth prime..."); sys.stdout.flush()
s = connect()
recv(s)
s.send(json.dumps({"p": hex(p_smooth), "g": "0x2", "A": "0x2"}).encode() + b'\n')

time.sleep(2)
raw2 = ''
for _ in range(5):
    raw2 += recv(s)
    time.sleep(0.5)
s.close()

B_smooth = None
for j in extract_jsons(raw2):
    if 'B' in j:
        B_smooth = int(j['B'], 16)
        break
print(f"  B_smooth received"); sys.stdout.flush()

# Step 3: Solve DLP
print("[3] Solving DLP (Pohlig-Hellman on smooth group)..."); sys.stdout.flush()
b = discrete_log(p_smooth, B_smooth, 2)
print(f"  b = {b} ({b.bit_length()} bits)"); sys.stdout.flush()

# Verify
B_check = pow(2, b, p_orig)
print(f"  Verify: g^b mod p_orig == B_bob? {B_check == B_bob}"); sys.stdout.flush()

# Step 4: Decrypt
shared = pow(A_alice, b, p_orig)
sha1 = hashlib.sha1()
sha1.update(str(shared).encode('ascii'))
key = sha1.digest()[:16]
pt = AES.new(key, AES.MODE_CBC, bytes.fromhex(alice_iv)).decrypt(bytes.fromhex(alice_ct))
print(f"[+] FLAG: {pt}"); sys.stdout.flush()
