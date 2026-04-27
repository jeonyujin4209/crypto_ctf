"""Local test version of chall.py - no PoW, longer alarm."""
from Crypto.Cipher import AES
from os import urandom
from signal import alarm
import sys

flag = "ictf{TEST_FLAG_LOCAL_ABC123}"

alarm(120)  # generous for local testing

gen = lambda: urandom(12)
randbit = lambda: gen()[0] & 1

key, nonce = urandom(16), gen()

new = lambda: AES.new(key, AES.MODE_GCM, nonce)
s = [gen(), gen()]

while True:
    try:
        cmd = input("> ")
    except EOFError:
        break
    if not cmd:
        break

    if cmd == "tag":
        cipher = new()
        cipher.update(s[0])
        cipher.encrypt(s[1])
        print(f"tag: {cipher.digest().hex()}")
        sys.stdout.flush()

    elif cmd == "u1":
        s[randbit()] = gen()

    elif cmd == "u2":
        s[randbit()] += gen()

actual = new().digest().hex()
print(f"DBG_S: {actual}", flush=True)
guess = input(f"tag: ")
if guess == actual:
    print(flag)
else:
    print(f"nope (expected {actual})")
sys.stdout.flush()
