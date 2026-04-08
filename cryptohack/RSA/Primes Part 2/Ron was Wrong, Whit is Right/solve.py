import math
import os
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP

keys_dir = r"C:\Users\SECUI\Documents\crypto_ctf\cryptohack\RSA\Primes Part 2\Ron was Wrong, Whit is Right\keys_and_messages"

# Load all keys
keys = {}
for i in range(1, 51):
    pem_path = os.path.join(keys_dir, f"{i}.pem")
    if os.path.exists(pem_path):
        with open(pem_path, "r") as f:
            key = RSA.importKey(f.read())
        keys[i] = key.n

print(f"Loaded {len(keys)} keys")

# Find shared factors using pairwise GCD
# More efficient: compute product tree GCD, but for 50 keys pairwise is fine
target = 21
target_n = keys[target]
target_p = None

for i in keys:
    for j in keys:
        if i >= j:
            continue
        g = math.gcd(keys[i], keys[j])
        if g > 1:
            print(f"Keys {i} and {j} share a factor!")
            if i == target:
                target_p = g
            elif j == target:
                target_p = g

if target_p is None:
    # Try just against target
    for i in keys:
        if i == target:
            continue
        g = math.gcd(target_n, keys[i])
        if g > 1:
            target_p = g
            print(f"Key {target} shares factor with key {i}")
            break

if target_p:
    p = target_p
    q = target_n // p
    print(f"p = {p}")
    print(f"q = {q}")

    e = 65537
    phi = (p - 1) * (q - 1)
    d = pow(e, -1, phi)

    # Read ciphertext
    ct_path = os.path.join(keys_dir, "21.ciphertext")
    with open(ct_path, "r") as f:
        ct = bytes.fromhex(f.read().strip())

    # Decrypt with OAEP
    priv_key = RSA.construct((target_n, e, int(d), int(p), int(q)))
    cipher = PKCS1_OAEP.new(priv_key)
    plaintext = cipher.decrypt(ct)
    print(plaintext.decode())
else:
    print("No shared factor found for key 21!")
