import requests

BASE = "https://aes.cryptohack.org/forbidden_fruit"

def api_encrypt(pt_hex):
    return requests.get(f"{BASE}/encrypt/{pt_hex}/").json()

def api_decrypt(nonce, ct, tag, ad):
    return requests.get(f"{BASE}/decrypt/{nonce}/{ct}/{tag}/{ad}/").json()

# GF(2^128) arithmetic (GCM convention: MSB of first byte = x^0)
R_POLY = 0xe1 << 120

def gf_mul(X, Y):
    Z = 0
    V = Y
    for i in range(128):
        if (X >> (127 - i)) & 1:
            Z ^= V
        if V & 1:
            V = (V >> 1) ^ R_POLY
        else:
            V >>= 1
    return Z

def gf_inv(x):
    # x^(-1) = x^(2^128 - 2) by Fermat's little theorem in GF(2^128)
    exp = (1 << 128) - 2
    result = 1 << 127  # multiplicative identity in GCM representation
    base = x
    while exp > 0:
        if exp & 1:
            result = gf_mul(result, base)
        base = gf_mul(base, base)
        exp >>= 1
    return result

def to_int(h):
    return int(h, 16)

def to_hex(v):
    return format(v, '032x')

# Step 1: Encrypt "give me the flag" - returns ciphertext but no tag (blocked)
target_pt = b"give me the flag"  # 16 bytes
resp1 = api_encrypt(target_pt.hex())
print("Target:", resp1)
C_target = to_int(resp1["ciphertext"])

# Step 2: Encrypt known plaintext #1 (16 bytes, no 'flag')
resp2 = api_encrypt(b"aaaaaaaaaaaaaaaa".hex())
print("P2:", resp2)
C2 = to_int(resp2["ciphertext"])
Tag2 = to_int(resp2["tag"])
nonce = resp2["nonce"]
ad = resp2["associated_data"]

# Step 3: Encrypt known plaintext #2
resp3 = api_encrypt(b"bbbbbbbbbbbbbbbb".hex())
print("P3:", resp3)
C3 = to_int(resp3["ciphertext"])
Tag3 = to_int(resp3["tag"])

# Recover H^2 from nonce reuse:
# Tag_i = A*H^3 + C_i*H^2 + L*H + S  (same A, L, S for all)
# Tag2 ^ Tag3 = (C2 ^ C3) * H^2
# H^2 = (Tag2 ^ Tag3) * (C2 ^ C3)^(-1)
print("Computing H^2...")
H_sq = gf_mul(Tag2 ^ Tag3, gf_inv(C2 ^ C3))

# Forge tag for C_target:
# Forged_Tag = Tag2 ^ (C_target ^ C2) * H^2
Forged_Tag = Tag2 ^ gf_mul(C_target ^ C2, H_sq)

# Step 4: Decrypt with forged message
result = api_decrypt(nonce, to_hex(C_target), to_hex(Forged_Tag), ad)
print("Result:", result)

if "plaintext" in result:
    print("FLAG:", bytes.fromhex(result["plaintext"]).decode())
