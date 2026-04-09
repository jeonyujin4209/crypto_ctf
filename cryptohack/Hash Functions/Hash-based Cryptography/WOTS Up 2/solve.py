import hashlib
import json
from Crypto.Cipher import AES

KEY_LEN = 32
BYTE_MAX = 255

def sha256hash(data):
    return hashlib.sha256(data).digest()

with open('data.json') as f:
    data = json.load(f)

pub_key = [bytes.fromhex(h) for h in data['public_key']]
signatures = data['signatures']
iv = bytes.fromhex(data['iv'])
enc = bytes.fromhex(data['enc'])

# Target message
message2 = f'{pub_key[0].hex()} sent 999999 WOTScoins to me'.encode()
h2 = bytearray(sha256hash(message2))

# For each byte position, find the signature with the largest hash byte
best_sig = [None] * KEY_LEN
best_h = [0] * KEY_LEN

for entry in signatures:
    msg = entry['message'].encode()
    sig = [bytes.fromhex(h) for h in entry['signature']]
    h = bytearray(sha256hash(msg))
    for i in range(KEY_LEN):
        if h[i] > best_h[i]:
            best_h[i] = h[i]
            best_sig[i] = sig[i]

# Forge signature by hashing forward
sig2 = []
for i in range(KEY_LEN):
    item = best_sig[i]
    for _ in range(best_h[i] - h2[i]):
        item = sha256hash(item)
    sig2.append(item)

aes_key = bytes([s[0] for s in sig2])
cipher = AES.new(aes_key, AES.MODE_CBC, iv)
print(cipher.decrypt(enc))
# ECSC{0ne_m0r3_t1m3_s1gn4tur3_ff}
