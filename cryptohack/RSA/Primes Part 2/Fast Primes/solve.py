from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP

# Parse the PEM key
with open(r"C:\Users\SECUI\Documents\crypto_ctf\cryptohack\RSA\Primes Part 2\Fast Primes\key_17a08b7040db46308f8b9a19894f9f95.pem", "r") as f:
    key = RSA.importKey(f.read())

n = key.n
e = key.e

# Read ciphertext
with open(r"C:\Users\SECUI\Documents\crypto_ctf\cryptohack\RSA\Primes Part 2\Fast Primes\ciphertext_98a448b6bbcd080909d235e5da5e9d56.txt", "r") as f:
    ct = bytes.fromhex(f.read().strip())

# Factors from factordb (n is only 511 bits, easily factored)
p = 51894141255108267693828471848483688186015845988173648228318286999011443419469
q = 77342270837753916396402614215980760127245056504361515489809293852222206596161

assert p * q == n

phi = (p - 1) * (q - 1)
d = pow(e, -1, phi)

priv_key = RSA.construct((n, e, int(d), int(p), int(q)))
cipher = PKCS1_OAEP.new(priv_key)
plaintext = cipher.decrypt(ct)
print(plaintext.decode())
