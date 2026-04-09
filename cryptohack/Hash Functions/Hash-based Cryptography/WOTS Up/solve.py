import hashlib
import json
from Crypto.Cipher import AES

KEY_LEN = 32

def sha256hash(data):
    return hashlib.sha256(data).digest()

with open('data.json') as f:
    data = json.load(f)

signature1 = [bytes.fromhex(h) for h in data['signature']]
iv = bytes.fromhex(data['iv'])
enc = bytes.fromhex(data['enc'])
message1 = data['message'].encode()

h1 = bytearray(sha256hash(message1))
# h1[0] = 255, so sig1[0] = hash^0(priv[0]) = priv[0]!
# Recover all private keys: priv[i+1] = hash(priv[i])
priv_key = [signature1[0]]
for i in range(1, KEY_LEN):
    priv_key.append(sha256hash(priv_key[-1]))

# Compute signature for target message
message2 = b'Sign for flag'
h2 = bytearray(sha256hash(message2))
sig2 = []
for i in range(KEY_LEN):
    item = priv_key[i]
    for _ in range(255 - h2[i]):
        item = sha256hash(item)
    sig2.append(item)

aes_key = bytes([s[0] for s in sig2])
cipher = AES.new(aes_key, AES.MODE_CBC, iv)
print(cipher.decrypt(enc))
# ECSC{h4sh1ng_ch41n_r34ct1on_ff_}
