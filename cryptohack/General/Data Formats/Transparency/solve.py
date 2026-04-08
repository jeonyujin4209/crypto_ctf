#!/usr/bin/env python3
# 1. PEM에서 공개키 추출
# 2. crt.sh (Certificate Transparency 로그) 에서 cryptohack.org 서브도메인 검색
# 3. thetransparencyflagishere.cryptohack.org 방문

from Crypto.PublicKey import RSA

with open("transparency_afff0345c6f99bf80eab5895458d8eab.pem") as f:
    key = RSA.importKey(f.read())

print(f"n = {key.n}")
print(f"e = {key.e}")
print()
print("crt.sh/?q=cryptohack.org 에서 서브도메인 검색")
print("-> thetransparencyflagishere.cryptohack.org")
print()
print("Flag: crypto{thx_redpwn_for_inspiration}")
