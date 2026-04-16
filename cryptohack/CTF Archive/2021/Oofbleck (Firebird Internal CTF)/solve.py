"""
Oofbleck (Firebird Internal CTF 2021) — OFB Key/IV Swap

Vulnerability:
  AES.new(iv, AES.MODE_OFB, key) — positional args swap iv and key.
  The random `iv` becomes the AES key, prepended to ciphertext (known!).
  The actual `key` becomes the OFB IV (unknown).

Attack:
  Flag = firebird{\w{58}} → 68 bytes → padded to 80 bytes (5 blocks).
  Last block: [w, w, w, '}', 0x0c * 12] — only 3 unknown bytes.
  Brute force 63^3 = 250K candidates for those 3 \w chars:
    1. Guess P_5, compute O_5 = C_5 XOR P_5
    2. Reverse OFB: O_4 = AES_decrypt(O_5), ..., O_1 = AES_decrypt(O_2)
    3. Check if decrypted block 1 starts with 'firebird{'
"""
import base64
import string
from Crypto.Cipher import AES

ct = base64.b64decode(
    "0UpFwNytjLbrytWyClHmBvJ3+umnEc1fcycgNeCtX9ZfcmqlCfkndC56aAwKGSjT"
    "55DKXCzQkh+TmAhshA08tSZPDLyuf3wdka0t1hRkdHLCPxIBjdGxx5tjF487G5a6"
)

aes_key = ct[:16]       # iv variable — actually used as AES key
enc = ct[16:]            # 80 bytes = 5 blocks
blocks = [enc[i:i+16] for i in range(0, 80, 16)]

cipher = AES.new(aes_key, AES.MODE_ECB)
w_chars = (string.ascii_letters + string.digits + '_').encode()

xor = lambda a, b: bytes(x ^ y for x, y in zip(a, b))

# Known tail of last plaintext block: '}' + PKCS7 padding (0x0c * 12)
known_tail = bytes([0x7d]) + bytes([0x0c]) * 12   # 13 bytes

for c1 in w_chars:
    for c2 in w_chars:
        for c3 in w_chars:
            p5 = bytes([c1, c2, c3]) + known_tail
            o5 = xor(blocks[4], p5)
            o4 = cipher.decrypt(o5)
            o3 = cipher.decrypt(o4)
            o2 = cipher.decrypt(o3)
            o1 = cipher.decrypt(o2)

            p1 = xor(blocks[0], o1)
            if p1[:9] == b'firebird{':
                plaintext = xor(enc, o1 + o2 + o3 + o4 + o5)
                flag = plaintext[:68].decode()
                print(flag)
                exit()

print("Not found!")
