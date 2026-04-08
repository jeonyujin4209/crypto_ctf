import json

a = 288260533169915
p = 1007621497415251

with open(r"C:\Users\SECUI\Documents\crypto_ctf\cryptohack\Adrien's Signs\output_80fc6398d2fd9f272186d0af510323f9.txt") as f:
    ciphertext = json.loads(f.read().strip())

bits = ""
for c in ciphertext:
    legendre = pow(c, (p - 1) // 2, p)
    if legendre == 1:
        bits += "1"
    else:  # legendre == p - 1
        bits += "0"

flag = int(bits, 2).to_bytes(len(bits) // 8, "big").decode()
print(flag)

# crypto{p4tterns_1n_re5idu3s}
