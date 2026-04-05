# Triple DES
- **출처**: CryptoHack - Symmetric Ciphers
- **난이도**: 60 pts
- **카테고리**: DES
- **technique**: des_weak_keys, triple_des_self_inverse

## 문제 요약
3DES에서 사용자가 키를 제어 가능. DES weak key로 E(E(x))=x 성질 이용.

## 풀이
1. DES weak key 2개 선택: K1=0101..01, K2=FEFE..FE
2. 3DES key = K1||K2||K1 → E(E(x)) = x (자기역원)
3. encrypt_flag(key) → 암호문
4. encrypt(key, 암호문) → 평문 복원

**원리**: DES weak key는 E_K = D_K. K1||K2||K1 구성의 3DES를 두 번 적용하면 항등 함수.

## 플래그
`crypto{n0t_4ll_k3ys_4r3_g00d_k3ys}`
