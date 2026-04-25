from hashlib import sha256
from Crypto.Cipher import AES
import json, sys

import os
os.chdir(os.path.dirname(os.path.abspath(__file__)))
with open('output.json') as f:
    data = json.load(f)

secret_bytes_hex = sys.argv[1]
secret_bytes = bytes.fromhex(secret_bytes_hex)
key = sha256(secret_bytes).digest()[:16]
print('key:', key.hex())

iv = bytes.fromhex(data['vault']['iv'])
body = bytes.fromhex(data['vault']['body'])
tag = bytes.fromhex(data['vault']['tag'])
print('iv len:', len(iv), 'body len:', len(body), 'tag len:', len(tag))

try:
    flag = AES.new(key, AES.MODE_GCM, nonce=iv).decrypt_and_verify(body, tag)
    print('FLAG:', flag.decode())
except Exception as e:
    print('FAIL:', type(e).__name__, e)
    pt = AES.new(key, AES.MODE_GCM, nonce=iv).decrypt(body)
    print('decrypted (no verify):', pt[:80])
