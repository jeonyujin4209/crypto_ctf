#!/usr/bin/env python3
import requests

# Triple DES with custom xor-IV wrapper:
# encrypt(key, pt) = xor(E_3des(xor(pt, IV)), IV)
#
# DES weak keys: E_K(E_K(x)) = x (self-inverse)
# With K1=weak1, K2=weak2, K3=weak1:
# 3DES = E_K1(D_K2(E_K1(x)))
# For weak keys D_K = E_K, so: E_K1(E_K2(E_K1(x)))
# Double 3DES: E(E(x)) = E_K1(E_K2(E_K1( E_K1(E_K2(E_K1(x))) )))
#            = E_K1(E_K2( E_K1(E_K1) (E_K2(E_K1(x))) ))
#            = E_K1(E_K2(E_K2(E_K1(x))))  [E_K1(E_K1)=identity]
#            = E_K1(E_K1(x))               [E_K2(E_K2)=identity]
#            = x                            [E_K1(E_K1)=identity]
#
# So encrypt(encrypt(flag)) = flag!

k1 = "0101010101010101"  # DES weak key
k2 = "FEFEFEFEFEFEFEFE"  # DES weak key (different)
key = k1 + k2 + k1

r = requests.get(f"https://aes.cryptohack.org/triple_des/encrypt_flag/{key}/").json()
ct = r["ciphertext"]

r2 = requests.get(f"https://aes.cryptohack.org/triple_des/encrypt/{key}/{ct}/").json()
pt = bytes.fromhex(r2["ciphertext"])
print(pt.decode().rstrip("\x06"))
# crypto{n0t_4ll_k3ys_4r3_g00d_k3ys}
